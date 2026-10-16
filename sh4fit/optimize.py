"""Code and data placement search.

For code, three stages follow MipsFit (MIT, Copyright (c) 2026 Kevin R.), which
follows the profile-guided layout literature, adapted to a linker script (units
keep their sizes and alignments; only their order changes):

1. Call-chain clustering (Ottoni & Maher, CGO 2017 "C3"): a hot unit joins its
   hottest caller's cluster while the cluster fits in the cache, and clusters
   are emitted densest first.
2. Slot-aware placement: clusters are laid down one at a time at the position
   whose cache slots collide least with what is already placed. Never-used
   units serve as free spacers.
3. Late-acceptance hill climbing over the resulting order.

Data regions (.rodata, .data, .bss) go through the same placement and
refinement against the operand cache, with each hot object as its own cluster
in order of access density, so small hot variables pack into shared lines.
Everything outside the region being placed (code and its literal pools, the
stack, the heap, other regions) is fixed occupancy.

Every stage scores layouts with the temporal-relationship-graph cost (trg.py);
candidates are then ranked by replaying the traces through both caches.
"""
from __future__ import annotations

from bisect import bisect_left
import random
import time

from . import cache, trg
from .layout import align, disruption, positions


class Layout:
    """Unit-index view of one region, with the rest of the image fixed at `base`."""

    def __init__(self, model, graph, region, base, pinned=(), line_align=False):
        units = model["units"]
        self.graph, self.index = graph, graph.index
        self.ids = [u["id"] for u in units]
        self.size = [u["size"] for u in units] + [0, 0]
        self.align = [max(1, u["align"]) for u in units] + [1, 1]
        self.original = list(base)
        members = [i for i, u in enumerate(units) if u["region"] == region]
        self.region = [i for i in members if not units[i].get("prefix")]
        pinned = set(pinned)
        self.movable = [i for i in self.region if units[i]["movable"] and i not in pinned]
        moving = set(self.movable)
        self.pinned = [i for i in self.region if i not in moving]
        self.start = min((self.original[i] for i in self.region), default=0)
        touches = graph.unit_touches
        self.hot = [i for i in self.movable if touches.get(i, 0.0) > 0]
        self.cold = [i for i in self.movable if touches.get(i, 0.0) <= 0]
        region_set = set(self.region)
        self.fixed_chunks = [c for c in graph.active if graph.unit[c] not in region_set]
        # hot objects of a line or more start on a line: fewer lines touched, and
        # the graph's 32-byte chunks then match the cache lines exactly
        self.aligned = [i for i in self.hot if line_align and self.size[i] >= 32 and self.align[i] < 32]
        for i in self.aligned:
            self.align[i] = 32

    def bases(self, order, padding=None):
        base = list(self.original)
        cursor = self.start
        size, alignment = self.size, self.align
        for i in order:
            if padding:
                cursor += padding.get(i, 0)
            cursor = align(cursor, alignment[i])
            base[i] = cursor
            cursor += size[i]
        return base

    def cost(self, order, padding=None, top=0):
        return trg.alias_cost(self.graph, self.bases(order, padding), top)


def clusters(lay, limit=8 * 1024, ratio=8.0):
    """C3: append a unit to its hottest caller's cluster, densest cluster first."""
    graph = lay.graph
    touches = graph.unit_touches
    hot = sorted(lay.hot, key=lambda i: (-touches.get(i, 0.0), i))
    hotset = set(hot)
    caller = {}
    for (a, b), weight in sorted(graph.transitions.items()):
        if a in hotset and b in hotset and a != b and weight > caller.get(b, (0.0, -1))[0]:
            caller[b] = (weight, a)
    group = {i: [i] for i in hot}
    owner = {i: i for i in hot}
    size = {i: max(1, align(lay.size[i], lay.align[i])) for i in hot}
    weight = {i: touches.get(i, 0.0) for i in hot}
    for unit in hot:
        found = caller.get(unit)
        if not found:
            continue
        target, source = owner[found[1]], owner[unit]
        if target == source or size[target] + size[source] > limit:
            continue
        # C3 also refuses merges that would dilute the caller cluster's density
        if weight[target] * size[source] > ratio * weight[source] * size[target]:
            continue
        group[target].extend(group.pop(source))
        size[target] += size.pop(source)
        weight[target] += weight.pop(source)
        for member in group[target]:
            owner[member] = target
    return sorted(group.values(), key=lambda members: (-weight[owner[members[0]]] / size[owner[members[0]]],
                                                       min(members)))


def density_groups(lay):
    """One cluster per hot data object, densest (accesses per byte) first."""
    touches = lay.graph.unit_touches
    return [[i] for i in sorted(lay.hot, key=lambda i: (-touches.get(i, 0.0) / max(1, lay.size[i]), i))]


def _group_cost(lay, group, cursor, occupancy, commit=False):
    graph = lay.graph
    offset, neighbors, chunks = graph.offset, graph.neighbors, graph.unit_chunks
    slot_of = lay.index.slot
    cost = 0.0
    local = {}
    for unit in group:
        cursor = align(cursor, lay.align[unit])
        base, cursor = cursor, cursor + lay.size[unit]
        for c in chunks.get(unit, ()):
            line = (base + offset[c]) >> 5
            slot = slot_of(line)
            near = neighbors[c]
            if near:
                for other, d in occupancy[slot]:
                    if other != line:
                        weight = near.get(d)
                        if weight:
                            cost += weight
                for other, d in local.get(slot, ()):
                    if other != line:
                        weight = near.get(d)
                        if weight:
                            cost += weight
            if commit:
                occupancy[slot].append((line, c))
            else:
                local.setdefault(slot, []).append((line, c))
    return cost, cursor


def _shift_options(lay, pool, count, pad_budget, pad_step=32):
    """Ways to shift the next cluster: nothing, a cold unit as spacer, or padding."""
    options = [((), 0)]
    if pool and count:
        sizes = sorted((lay.size[i], i) for i in pool)
        picked = []
        for target in [32 << k for k in range(count)]:
            j = bisect_left(sizes, (target, -1))
            for candidate in (sizes[j] if j < len(sizes) else None, sizes[j - 1] if j else None):
                if candidate and candidate[1] not in picked:
                    picked.append(candidate[1])
                    break
        options += [((i,), 0) for i in picked]
    if pad_budget >= pad_step:
        options += [((), pad) for pad in (pad_step, pad_step * 2, pad_step * 4) if pad <= pad_budget]
    return options


def place(lay, groups, beam=4, spacers=8, pad_budget=0):
    """Lay clusters down one at a time, each at its cheapest reachable offset."""
    graph = lay.graph
    occupancy = [[] for _ in range(lay.index.lines)]
    base = lay.original
    slot_of = lay.index.slot
    for c in lay.fixed_chunks:
        line = (base[graph.unit[c]] + graph.offset[c]) >> 5
        occupancy[slot_of(line)].append((line, c))
    # units the script cannot list follow the listed ones; estimate where they land
    cursor = lay.start
    for i in lay.movable:
        cursor = align(cursor, lay.align[i]) + lay.size[i]
    _group_cost(lay, lay.pinned, cursor, occupancy, commit=True)
    cursor = lay.start
    order, padding, used = [], {}, 0
    pool, remaining = list(lay.cold), list(groups)
    while remaining:
        options = _shift_options(lay, pool, spacers, pad_budget - used)
        best = None
        for index, group in enumerate(remaining[:beam]):
            for spacer, pad in options:
                start = cursor
                for unit in spacer:
                    start = align(start, lay.align[unit]) + lay.size[unit]
                cost, _ = _group_cost(lay, group, start + pad, occupancy)
                key = (cost, sum(lay.size[u] for u in spacer) + pad, index)
                if best is None or key < best[0]:
                    best = (key, index, spacer, pad)
            if best[0][0] == 0 and best[1] == 0 and not best[2] and not best[3]:
                break  # the densest cluster already fits without a conflict
        _, index, spacer, pad = best
        group = remaining.pop(index)
        for unit in spacer:
            pool.remove(unit)
            order.append(unit)
            cursor = align(cursor, lay.align[unit]) + lay.size[unit]
        if pad:
            padding[group[0]] = pad
            cursor += pad
            used += pad
        _, cursor = _group_cost(lay, group, cursor, occupancy, commit=True)
        order.extend(group)
    order.extend(pool)
    return order, padding


def refine(lay, order, padding, seconds, seed, pad_budget=0, history=64):
    """Late-acceptance hill climbing: accept anything no worse than the cost
    `history` steps ago, which escapes shallow local minima without a schedule."""
    rng = random.Random(seed)
    order, padding = list(order), dict(padding)
    current, _ = lay.cost(order + lay.pinned, padding)
    best, best_state = current, (list(order), dict(padding))
    memory = [current] * history
    deadline = time.monotonic() + seconds
    hot = lay.hot or lay.movable
    step = 0
    while hot and len(order) > 1 and time.monotonic() < deadline and best > 0:
        step += 1
        trial, pad = list(order), dict(padding)
        unit = hot[rng.randrange(len(hot))]
        i = trial.index(unit)
        choice = rng.random()
        if choice < 0.3:
            j = trial.index(hot[rng.randrange(len(hot))])
            trial[i], trial[j] = trial[j], trial[i]
        elif choice < 0.6:
            block = trial[i:i + rng.randint(1, 4)]
            target = hot[rng.randrange(len(hot))]
            if target in block:
                continue
            del trial[i:i + len(block)]
            j = trial.index(target)
            trial[j:j] = block
        elif choice < 0.8 and lay.cold:
            spacer = lay.cold[rng.randrange(len(lay.cold))]
            trial.remove(spacer)
            trial.insert(trial.index(unit), spacer)
        elif pad_budget:
            used = sum(pad.values()) - pad.get(unit, 0)
            value = max(0, pad.get(unit, 0) + (32 if rng.random() < 0.5 else -32))
            if used + value > pad_budget:
                continue
            if value:
                pad[unit] = value
            else:
                pad.pop(unit, None)
        else:
            continue
        value, _ = lay.cost(trial + lay.pinned, pad)
        if value <= current or value <= memory[step % history]:
            order, padding, current = trial, pad, value
            if value < best:
                best, best_state = value, (list(trial), dict(pad))
        memory[step % history] = current
    return best_state[0], best_state[1], best


def code_proposals(lay, search_seconds, seed, padding_budget, beam=4, rounds=3):
    """(method, movable order, padding) for the code region."""
    proposals = []
    if len(lay.movable) < 2:
        return proposals
    proposals.append(("hot clusters, densest first", [u for g in clusters(lay) for u in g] + lay.cold, {}))
    order, padding = place(lay, clusters(lay), beam=beam, pad_budget=padding_budget)
    proposals.append(("slot-aware placement", order, padding))
    if search_seconds > 0:
        for k in range(rounds):
            refined, pad, _ = refine(lay, order, padding, search_seconds / rounds, seed + k, padding_budget)
            proposals.append((f"refined placement (seed {seed + k})", refined, pad))
    return proposals


def data_proposals(lay, search_seconds, seed, padding_budget, beam=4):
    proposals = []
    if len(lay.movable) < 2 or not lay.hot:
        return proposals
    groups = density_groups(lay)
    proposals.append(("hot data first, densest first", [u for g in groups for u in g] + lay.cold, {}))
    order, padding = place(lay, groups, beam=beam, pad_budget=padding_budget)
    proposals.append(("slot-aware data placement", order, padding))
    if search_seconds > 0:
        refined, pad, _ = refine(lay, order, padding, search_seconds, seed, padding_budget)
        proposals.append(("refined data placement", refined, pad))
    return proposals


class Scorer:
    """Replays traces for a full address map and caches the results."""

    def __init__(self, model, traces, costs, budget=0):
        self.model, self.traces, self.costs = model, traces, costs
        self.windows = {t["name"]: cache.windows(t, budget) for t in traces}
        self.memo = {}

    def __call__(self, addresses, parts=("code", "data")):
        key = (tuple(sorted(addresses.items())), parts)
        if key in self.memo:
            return self.memo[key]
        base = cache.base_list(self.model, addresses)
        record = dict(traces={})
        rates = dict(ic_per_kinstr=[], oc_per_kinstr=[], wb_per_kinstr=[])
        for t in self.traces:
            frames = self.windows[t["name"]]
            code = cache.simulate_code(t, base, frames=frames) if "code" in parts else \
                dict(misses=0, frames=len(t["code_frames"]) + 1)
            data = cache.simulate_data(t, base, frames=frames) if "data" in parts else None
            summary = cache.summarize(t, code, data, self.costs, frames)
            record["traces"][t["name"]] = summary
            rates["ic_per_kinstr"].append((summary["ic_per_kinstr"], t["weight"]))
            if data:  # a capture without data accesses says nothing about the operand cache
                rates["oc_per_kinstr"].append((summary["oc_per_kinstr"], t["weight"]))
                rates["wb_per_kinstr"].append((summary["wb_per_kinstr"], t["weight"]))
        combined = {k: sum(r * w for r, w in v) / (sum(w for _, w in v) or 1.0) for k, v in rates.items()}
        combined["cycles_per_kinstr"] = (combined["ic_per_kinstr"] * self.costs["ic_miss"] +
                                         combined["oc_per_kinstr"] * self.costs["oc_miss"] +
                                         combined["wb_per_kinstr"] * self.costs["writeback"])
        record.update({k: round(v, 4) for k, v in combined.items()})
        self.memo[key] = record
        return record


def rank_key(record):
    return (record["cost"]["cycles_per_kinstr"], record["cost"].get("alias", 0.0), record["cost"]["disruption"])


def generate(model, code_graph, data_graph, traces, count=3, search_seconds=60.0, seed=0, padding_budget=0,
             sim_segments=0, costs=None, data=True, log=print):
    """Search for layouts; return the baseline and the best `count` alternatives."""
    costs = costs or cache.COSTS
    units = model["units"]
    index_of = {u["id"]: i for i, u in enumerate(units)}
    pinned = {i for t in traces for a, b, _ in t["fallthrough"] for i in (a, b)}
    score = Scorer(model, traces, costs, sim_segments)
    original = positions(model)
    baseline_base = cache.base_list(model, original)
    regions = model["regions"]
    text = next((name for name, r in regions.items() if r["kind"] == "code" and not r.get("blocked")), None)
    data_regions = [name for name, r in regions.items() if r["kind"] == "data" and not r.get("blocked")]
    data_share = 0.25 if data and data_graph and data_regions else 0.0
    code_seconds = search_seconds * (1 - data_share)

    # --- code ---------------------------------------------------------------
    code_options = [("original linker order", None, {})]
    if text:
        lay = Layout(model, code_graph, text, baseline_base, pinned)
        if len(lay.movable) > 1:
            code_options.append(("listed sections first, original order", lay.movable, {}))
            for method, order, padding in code_proposals(lay, code_seconds, seed, padding_budget):
                code_options.append((method, order, padding))
    scored = []
    for method, order, padding in code_options:
        orders = {text: [units[i]["id"] for i in order]} if order is not None else {}
        pad = {units[i]["id"]: n for i, n in padding.items()}
        addresses = positions(model, orders, pad)
        alias = trg.alias_cost(code_graph, cache.base_list(model, addresses))[0]
        record = score(addresses, ("code",))
        scored.append((record["ic_per_kinstr"], alias, method, orders, pad, addresses))
        log(f"  code: {method}: {record['ic_per_kinstr']:.4f} IC misses per 1k instructions "
            f"(graph cost {alias:,.0f})")
    baseline_code = scored[0]
    alternatives = sorted(scored[1:], key=lambda s: (s[0], s[1]))
    seen, kept = set(), []
    for item in alternatives:
        fingerprint = tuple(sorted(item[5].items()))
        if fingerprint not in seen and fingerprint != tuple(sorted(baseline_code[5].items())):
            seen.add(fingerprint)
            kept.append(item)
    code_kept = [baseline_code] + kept[:count]

    # --- data, against the best code layout ----------------------------------
    data_orders, data_padding, data_aligned, data_method = {}, {}, [], None
    if data_share and data_graph.active:
        best_code = min(code_kept, key=lambda s: (s[0], s[1]))
        context = positions(model, best_code[3], best_code[4])
        base = cache.base_list(model, context)
        seconds = search_seconds * data_share / max(1, len(data_regions))
        methods = []
        for name in sorted(data_regions, key=lambda r: -sum(data_graph.unit_touches.get(index_of[u["id"]], 0)
                                                             for u in units if u["region"] == r)):
            lay = Layout(model, data_graph, name, base, line_align=True)
            proposals = data_proposals(lay, seconds, seed, padding_budget)
            if not proposals:
                continue
            best = None
            for method, order, padding in proposals:
                cost = lay.cost(order + lay.pinned, padding)[0]
                if best is None or cost < best[0]:
                    best = (cost, method, order, padding)
            original_cost = trg.alias_cost(data_graph, base)[0]
            log(f"  data {name}: graph cost {original_cost:,.0f} -> {best[0]:,.0f} ({best[1]})")
            if best[0] >= original_cost:
                continue
            data_orders[name] = [units[i]["id"] for i in best[2]]
            data_padding.update({units[i]["id"]: n for i, n in best[3].items()})
            data_aligned.extend(units[i]["id"] for i in lay.aligned)
            base = lay.bases(best[2] + lay.pinned, best[3])
            methods.append(best[1])
        data_method = " + ".join(dict.fromkeys(methods)) or None

    # --- combine and rank by full replay ----------------------------------------
    candidates, seen = [], set()
    for ic_rate, alias, method, orders, pad, _ in code_kept:
        variants = [(orders, pad, [], method)]
        if data_orders:
            variants.append(({**orders, **data_orders}, {**pad, **data_padding}, data_aligned,
                             (method + "; " if orders else "") + f"data: {data_method}"))
        for o, p, al, m in variants:
            addresses = positions(model, o, p, al)
            fingerprint = tuple(sorted(addresses.items()))
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            record = dict(score(addresses))
            record.update(alias=round(alias, 3), padding_bytes=sum(p.values()), disruption=disruption(model, o))
            candidates.append(dict(method=m if o else "original linker layout", baseline=not o, orders=o,
                                   padding=p, aligned=al, addresses=addresses, cost=record))
            log(f"  candidate: {candidates[-1]['method']}: {record['cycles_per_kinstr']:.2f} estimated stall "
                f"cycles per 1k instructions")
    control = candidates[0]
    alternatives = sorted((c for c in candidates if not c["baseline"]), key=rank_key)[:count]
    for i, candidate in enumerate(alternatives):
        candidate["id"] = f"layout-{i + 1:02d}"
    control["id"] = "baseline"
    retained = sorted([control] + alternatives, key=lambda c: (rank_key(c), not c["baseline"]))
    for i, candidate in enumerate(retained):
        candidate["rank"] = i + 1
    return retained
