"""SH-4 (SH7750/SH7091) instruction- and operand-cache replay of imported traces.

Instruction cache: 8 KiB, 256 direct-mapped lines of 32 bytes, indexed by
A[12:5], or by A[25] and A[11:5] with CCR.IIX.

Operand cache: 16 KiB, 512 direct-mapped lines of 32 bytes, indexed by A[13:5],
or by A[25] and A[12:5] with CCR.OIX. With CCR.ORA, entries 128-255 and 384-511
become the on-chip RAM and the remaining 8 KiB of cache is indexed by A[13] (A[25]
with OIX) and A[11:5]. P1 is copy-back when CCR.CB is set, P0/P3 are
write-through when CCR.WT is set. Copy-back write misses allocate a line (fill,
then write); write-through write misses do not. `pref` fills without stalling,
`movca.l` allocates without filling, `ocbi`/`ocbp`/`ocbwb` invalidate/purge/
write back a matching line, and stores to the address arrays act as the
manual describes (associative writes compare the tag in the data).

Both caches are tagged with physical addresses, so P0/P1/P3 aliases of a line
share it. Replay follows CCR writes, address-array stores and resets in the
order the trace recorded them.
"""
from __future__ import annotations

from collections import Counter, OrderedDict

from . import sh4trace as fmt
from .trace import bounds

OCE, WT, CB, OCI, ORA, OIX, ICE, ICI, IIX = 1, 2, 4, 8, 32, 128, 256, 2048, 32768

# rough default costs in CPU cycles at 200 MHz; calibrate with the perf counters
# (PMCR_PIPELINE_FREEZE_BY_ICACHE_MISS_MODE / ..._DCACHE_MISS_MODE)
COSTS = dict(ic_miss=20, oc_miss=20, writeback=10)


class Index:
    """Cache slot of a physical line number (address >> 5)."""

    def __init__(self, lines, mask, high_shift=0, high_pos=0, name=""):
        self.lines, self.mask, self.high_shift, self.high_pos, self.name = lines, mask, high_shift, high_pos, name
        self.simple = not high_shift

    def slot(self, line):
        if self.simple:
            return line & self.mask
        return (line & self.mask) | ((line >> self.high_shift) & 1) << self.high_pos

    def __eq__(self, other):
        return isinstance(other, Index) and (self.lines, self.mask, self.high_shift, self.high_pos) == \
            (other.lines, other.mask, other.high_shift, other.high_pos)

    def __hash__(self):
        return hash((self.lines, self.mask, self.high_shift, self.high_pos))

    def describe(self):
        return dict(lines=self.lines, name=self.name)


def ic_index(ccr):
    if ccr & IIX:
        return Index(256, 127, 20, 7, "IC 8 KiB, IIX (A25, A11:5)")
    return Index(256, 255, name="IC 8 KiB (A12:5)")


def oc_index(ccr):
    if ccr & ORA:
        return Index(256, 127, 20 if ccr & OIX else 8, 7,
                     "OC 8 KiB + 8 KiB RAM, " + ("OIX (A25, A11:5)" if ccr & OIX else "index A13, A11:5"))
    if ccr & OIX:
        return Index(512, 255, 20, 8, "OC 16 KiB, OIX (A25, A12:5)")
    return Index(512, 511, name="OC 16 KiB (A13:5)")


def oc_entry_slot(entry, ccr):
    """Compact slot of a hardware OC entry (0..511), or None for an OCRAM entry."""
    if ccr & ORA:
        if entry & 0x80:
            return None
        return ((entry >> 8) & 1) << 7 | (entry & 127)
    return entry


def base_list(model, addresses, trace=None):
    """Physical base address per unit index, then FIXED (0) and HEAP (the image end)."""
    units = model["units"]
    missing = next((u["id"] for u in units if u["id"] not in addresses), None)
    if missing:
        raise ValueError(f"layout has no address for {missing}")
    data_end = addresses.get("_data_end", model["data_end"])
    return [addresses[u["id"]] & 0x1FFFFFFF for u in units] + [0, data_end & 0x1FFFFFFF]


def windows(trace, budget=0, span=3):
    """Frame windows (first, end, warmup frames) spread over the trace, covering
    about `budget` code segments plus data records. 0 means everything."""
    frames = len(trace["code_frames"]) + 1
    total = len(trace["segments"]) + len(trace["data"])
    if not budget or total <= budget or frames <= 2 * span:
        return None
    count = max(1, min(frames // span, budget * frames // (total * span)))
    step = frames / count
    return [(int(i * step), min(frames, int(i * step) + span), 0 if int(i * step) == 0 else 1)
            for i in range(count)]


def _events(events):
    it = iter(events)
    return [(p, k, a, b) for p, k, a, b in zip(it, it, it, it)]


# --- instruction cache -----------------------------------------------------------

def _code_table(trace, base, index, detail=False):
    """Per range id: ((slot, line), ...), or None if the range overlaps itself
    in the cache and repeats must be replayed pass by pass."""
    table, owners = [], []
    simple, mask = index.simple, index.mask
    for parts in trace["ranges"]:
        pairs, own = [], []
        for u, s, e in parts:
            b = base[u]
            for line in range((b + s) >> 5, ((b + e - 2) >> 5) + 1):
                pairs.append((line & mask if simple else index.slot(line), line))
                if detail:
                    own.append((u, (line << 5) - b))
        table.append(tuple(pairs))
        owners.append(own)
    big = {rid for rid, pairs in enumerate(table) if len({k for k, _ in pairs}) < len(pairs)}
    return table, owners, big


def simulate_code(trace, base, ccr=None, frames=None, detail=False, top_pairs=40):
    """Replay the instruction stream at `base`. Returns misses overall and per frame."""
    if detail and frames:
        raise ValueError("detailed replay covers the whole trace")
    ccr = trace["ccr"] if ccr is None else ccr
    index = ic_index(ccr)
    table, owners, big = _code_table(trace, base, index, detail)
    segs = trace["segments"]
    events = _events(trace["code_events"])
    frame_bounds = bounds(trace["code_frames"], len(segs))
    cache = [-1] * 256
    owner = [None] * 256
    enabled = bool(ccr & ICE)
    st = dict(first=0, conflict=0, capacity=0, disabled=0)
    seen, lru = set(), OrderedDict()
    pairs, unit_misses, line_misses = Counter(), Counter(), Counter()
    per_frame, working_set = [], []
    ei = 0

    def apply(kind, a, b):
        nonlocal index, table, owners, big, enabled, ccr
        if kind == fmt.RESET:
            cache[:] = [-1] * 256
            if detail:
                seen.clear()
                lru.clear()
        elif kind == fmt.CCR:
            enabled = bool(a & ICE)
            if a & ICI or (a & IIX) != (ccr & IIX):
                cache[:] = [-1] * 256
            if (a & IIX) != (ccr & IIX):
                index = ic_index(a)
                table, owners, big = _code_table(trace, base, index, detail)
            ccr = a
        elif kind == fmt.ARRAY and a >> 24 == 0xF0:
            entry = (a >> 5) & 0xFF
            tag = b & 0x1FFFFC00
            line = cache[entry]
            if a & 8:  # associative: invalidate a matching valid line
                if line >= 0 and (line << 5) & 0x1FFFFC00 == tag and not b & 1:
                    cache[entry] = -1
            else:
                cache[entry] = (tag >> 5) | (entry & 0x1F) if b & 1 else -1

    def run(start, end, touched):
        misses = 0
        if not enabled:
            for w in segs[start:end]:
                st["disabled"] += len(table[w >> 8])
            return 0
        if not detail:
            for w in segs[start:end]:
                rid = w >> 8
                for k, line in table[rid]:
                    if cache[k] != line:
                        cache[k] = line
                        misses += 1
                if rid in big:
                    for _ in range((w & 255) - 1):
                        for k, line in table[rid]:
                            if cache[k] != line:
                                cache[k] = line
                                misses += 1
            return misses
        for w in segs[start:end]:
            rid = w >> 8
            for _ in range((w & 255) if rid in big else 1):
                for (k, line), who in zip(table[rid], owners[rid]):
                    touched.add(line)
                    old = cache[k]
                    if old != line:
                        misses += 1
                        if line not in seen:
                            st["first"] += 1
                        elif line in lru:
                            st["conflict"] += 1
                            if old >= 0 and owner[k]:
                                pairs[who, owner[k]] += 1
                        else:
                            st["capacity"] += 1
                        unit_misses[who[0]] += 1
                        line_misses[who] += 1
                        cache[k] = line
                        owner[k] = who
                    seen.add(line)
                    if line in lru:
                        lru.move_to_end(line)
                    else:
                        lru[line] = None
                        if len(lru) > 256:
                            lru.popitem(last=False)
        return misses

    for first, end, warmup in frames or [(0, len(frame_bounds), 0)]:
        if first:
            cache[:] = [-1] * 256
            ei = 0
            while ei < len(events) and events[ei][0] < frame_bounds[first][0]:
                p, kind, a, b = events[ei]
                if kind == fmt.CCR:
                    apply(kind, a, b)
                ei += 1
        for f in range(first, end):
            start, stop = frame_bounds[f]
            n, touched = 0, set()
            while ei < len(events) and events[ei][0] < start:
                apply(*events[ei][1:])
                ei += 1
            pos = start
            while ei < len(events) and events[ei][0] < stop:
                p, kind, a, b = events[ei]
                n += run(pos, p, touched)
                apply(kind, a, b)
                pos = p
                ei += 1
            n += run(pos, stop, touched)
            if f - first >= warmup:
                per_frame.append(n)
                if detail:
                    working_set.append(len(touched))
    misses = sum(per_frame)
    result = dict(misses=misses, per_frame=per_frame, frames=len(per_frame), sampled=bool(frames),
                  index=index.describe(), disabled_lines=st["disabled"])
    if detail:
        result.update(first_misses=st["first"], conflict_misses=st["conflict"], capacity_misses=st["capacity"],
                      working_set=working_set, unit_misses=dict(unit_misses),
                      line_misses=line_misses, pairs=pairs.most_common(top_pairs))
    return result


# --- operand cache ---------------------------------------------------------------

LOAD, STORE, FIRST_STORE = fmt.LOAD, fmt.STORE, fmt.FIRST_STORE


def simulate_data(trace, base, ccr=None, frames=None, detail=False, top_pairs=40):
    """Replay the data stream at `base` through the operand cache."""
    if detail and frames:
        raise ValueError("detailed replay covers the whole trace")
    if not trace["has_data"]:
        return None
    ccr = trace["ccr"] if ccr is None else ccr
    words, offsets = trace["data"], trace["data_offsets"]
    events = _events(trace["data_events"])
    frame_bounds = bounds(trace["data_frames"], len(words))
    c = dict(read=0, write=0, wt_write=0, writeback=0, pref=0, movca=0, invalidated=0, disabled=0, hits=0)
    state = dict(ccr=ccr, index=oc_index(ccr))
    cache = [-1] * 512
    dirty = bytearray(512)
    owner = [None] * 512
    seen, lru = set(), OrderedDict()
    pairs, unit_misses, unit_writebacks, line_misses = Counter(), Counter(), Counter(), Counter()
    st = dict(first=0, conflict=0, capacity=0)
    per_frame, per_frame_wb, working_set = [], [], []

    def clear():
        cache[:] = [-1] * 512
        dirty[:] = bytes(512)

    def apply(kind, a, b):
        if kind == fmt.RESET:
            clear()
            if detail:
                seen.clear()
                lru.clear()
        elif kind == fmt.CCR:
            old = state["ccr"]
            if a & OCI or (a & (ORA | OIX)) != (old & (ORA | OIX)):
                clear()  # OCI invalidates without writing back
            state["ccr"], state["index"] = a, oc_index(a)
        elif kind == fmt.ARRAY and a >> 24 == 0xF4:
            k = oc_entry_slot((a >> 5) & 0x1FF, state["ccr"])
            if k is None:
                return
            line = cache[k]
            tag = b & 0x1FFFFC00
            if a & 8:  # associative
                if line >= 0 and (line << 5) & 0x1FFFFC00 == tag:
                    if dirty[k]:
                        c["writeback"] += 1
                        if detail and owner[k]:
                            unit_writebacks[owner[k][0]] += 1
                    dirty[k] = (b >> 1) & 1 if b & 1 else 0
                    if not b & 1:
                        cache[k] = -1
                        c["invalidated"] += 1
            else:
                if line >= 0 and dirty[k]:
                    c["writeback"] += 1
                    if detail and owner[k]:
                        unit_writebacks[owner[k][0]] += 1
                cache[k] = (tag >> 5) | ((a >> 5) & 0x1F) if b & 1 else -1
                dirty[k] = (b >> 1) & 1 if b & 1 else 0

    def run(start, end, touched):
        ccr_now = state["ccr"]
        index = state["index"]
        simple, mask = index.simple, index.mask
        hs, hp = index.high_shift, index.high_pos
        enabled = ccr_now & OCE
        wt_p0, wt_p1 = bool(ccr_now & WT), not ccr_now & CB
        any_wt = wt_p0 or wt_p1
        misses = writebacks = 0
        lru_size = index.lines
        for i in range(start, end):
            w = words[i]
            u = w & 0xFFFF
            off = offsets[i]
            line = (base[u] + off) >> 5
            k = line & mask if simple else (line & mask) | ((line >> hs) & 1) << hp
            op = (w >> 16) & 15
            if not enabled:
                c["disabled"] += 1
                continue
            if detail:
                touched.add(line)
                who = (u, (line << 5) - base[u])
            cur = cache[k]
            if op == 0:
                flags = (w >> 20) & 15
                wt = any_wt and (wt_p0 if w >> 24 & 1 else wt_p1)
                if cur == line:
                    c["hits"] += 1
                    if flags & STORE and not wt:
                        dirty[k] = 1
                    if detail:
                        _touch(line)
                    continue
                if wt and flags & FIRST_STORE:
                    c["wt_write"] += 1
                    if not flags & LOAD:
                        continue  # write-through store misses don't allocate
                if flags & FIRST_STORE and not wt:
                    c["write"] += 1
                else:
                    c["read"] += 1
                misses += 1
                if cur >= 0 and dirty[k]:
                    writebacks += 1
                    if detail and owner[k]:
                        unit_writebacks[owner[k][0]] += 1
                if detail:
                    _classify(line, cur, k, who)
                cache[k] = line
                dirty[k] = 1 if flags & STORE and not wt else 0
                if detail:
                    owner[k] = who
                    _touch(line)
            elif op == fmt.OP_PREF:
                if cur != line:
                    c["pref"] += 1
                    if cur >= 0 and dirty[k]:
                        writebacks += 1
                    cache[k] = line
                    dirty[k] = 0
                    if detail:
                        owner[k] = who
                        seen.add(line)
                        _touch(line)
            elif op == fmt.OP_MOVCA:
                if cur != line:
                    c["movca"] += 1
                    if cur >= 0 and dirty[k]:
                        writebacks += 1
                    cache[k] = line
                    if detail:
                        owner[k] = who
                        seen.add(line)
                        _touch(line)
                dirty[k] = 1
            elif cur == line:
                if op == fmt.OP_OCBWB:
                    if dirty[k]:
                        writebacks += 1
                        dirty[k] = 0
                elif op == fmt.OP_OCBP:
                    if dirty[k]:
                        writebacks += 1
                    cache[k] = -1
                    dirty[k] = 0
                    c["invalidated"] += 1
                elif op == fmt.OP_OCBI:
                    cache[k] = -1
                    dirty[k] = 0
                    c["invalidated"] += 1
        c["writeback"] += writebacks
        return misses, writebacks

    def _touch(line):
        seen.add(line)
        if line in lru:
            lru.move_to_end(line)
        else:
            lru[line] = None
            if len(lru) > state["index"].lines:
                lru.popitem(last=False)

    def _classify(line, cur, k, who):
        if line not in seen:
            st["first"] += 1
        elif line in lru:
            st["conflict"] += 1
            if cur >= 0 and owner[k]:
                pairs[who, owner[k]] += 1
        else:
            st["capacity"] += 1
        unit_misses[who[0]] += 1
        line_misses[who] += 1

    ei = 0
    for first, end, warmup in frames or [(0, len(frame_bounds), 0)]:
        if first:
            clear()
            ei = 0
            while ei < len(events) and events[ei][0] < frame_bounds[first][0]:
                p, kind, a, b = events[ei]
                if kind == fmt.CCR:
                    state["ccr"], state["index"] = a, oc_index(a)
                ei += 1
        for f in range(first, end):
            start, stop = frame_bounds[f]
            n = wb = 0
            touched = set()
            while ei < len(events) and events[ei][0] < start:
                apply(*events[ei][1:])
                ei += 1
            pos = start
            while ei < len(events) and events[ei][0] < stop:
                p, kind, a, b = events[ei]
                m, w = run(pos, p, touched)
                before = c["writeback"]
                apply(kind, a, b)
                n, wb = n + m, wb + w + c["writeback"] - before
                pos = p
                ei += 1
            m, w = run(pos, stop, touched)
            n, wb = n + m, wb + w
            if f - first >= warmup:
                per_frame.append(n)
                per_frame_wb.append(wb)
                if detail:
                    working_set.append(len(touched))
    result = dict(misses=sum(per_frame), writebacks=sum(per_frame_wb), per_frame=per_frame, frames=len(per_frame),
                  sampled=bool(frames), read_misses=c["read"], write_misses=c["write"],
                  wt_store_misses=c["wt_write"], pref_fills=c["pref"], movca_allocs=c["movca"],
                  invalidated=c["invalidated"], disabled=c["disabled"], hits=c["hits"],
                  index=state["index"].describe())
    if detail:
        result.update(first_misses=st["first"], conflict_misses=st["conflict"], capacity_misses=st["capacity"],
                      working_set=working_set, unit_misses=dict(unit_misses), unit_writebacks=dict(unit_writebacks),
                      line_misses=line_misses, pairs=pairs.most_common(top_pairs))
    return result


def evaluate(trace, base, costs=None, frames=None):
    """Instruction- and operand-cache replay of one layout, with a cycle estimate."""
    costs = costs or COSTS
    code = simulate_code(trace, base, frames=frames)
    data = simulate_data(trace, base, frames=frames)
    return summarize(trace, code, data, costs, frames)


def summarize(trace, code, data, costs, frames=None):
    instructions = trace["stats"]["instructions"]
    if frames:
        # sampled windows: scale the instruction count by the replayed share of frames
        total = len(trace["code_frames"]) + 1
        replayed = code["frames"]
        instructions = instructions * replayed / max(1, total)
    ic, oc = code["misses"], data["misses"] if data else 0
    wb = data["writebacks"] if data else 0
    cycles = ic * costs["ic_miss"] + oc * costs["oc_miss"] + wb * costs["writeback"]
    kilo = max(1.0, instructions / 1000.0)
    vblanks = code["frames"] if frames else max(1, len(trace["code_frames"]))
    return dict(ic_misses=ic, oc_misses=oc, writebacks=wb, stall_cycles=cycles,
                ic_per_kinstr=round(ic / kilo, 4), oc_per_kinstr=round(oc / kilo, 4),
                wb_per_kinstr=round(wb / kilo, 4), cycles_per_kinstr=round(cycles / kilo, 3),
                ic_per_vblank=round(ic / vblanks, 2), oc_per_vblank=round(oc / vblanks, 2),
                instructions=int(instructions), sampled=bool(frames), has_data=bool(data))
