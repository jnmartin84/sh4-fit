"""Cache problems that reordering alone cannot fix, and what is left after it.

Each finding names the code or data involved and says what to change. Figures
come from the detailed replays of the baseline and the best candidate; they are
measurements of the replay, so they hold for the captured workload only.
"""
from __future__ import annotations

from .model import unit_names


def _name(model, u):
    units = model["units"]
    if u < len(units):
        return unit_names(model, units[u])
    return "stack and other fixed memory" if u == len(units) else "heap"


def _where(model, who):
    """'pos_x +0x40', 'the stack/fixed memory at 0x8cffffc0' or 'heap +0x100'."""
    u, offset = who
    units = model["units"]
    if u == len(units):
        return f"fixed memory (stack, registers) at 0x{offset | 0x80000000:08x}"
    return f"{_name(model, u)} +0x{max(0, offset):x}"


def collect(model, traces, baseline, best):
    """`baseline`/`best`: per trace name, dict(code=detail replay, data=detail replay or None)."""
    units = model["units"]
    fixed = len(units)
    findings = []
    vblanks = {t["name"]: max(1, len(t["code_frames"])) for t in traces}

    # --- instruction cache working set -----------------------------------------
    peak = max((max(d["code"]["working_set"], default=0) for d in baseline.values()), default=0)
    if peak:
        state = "more than" if peak > 256 else "within"
        findings.append(dict(
            kind="ic-capacity", severity="info" if peak <= 256 else "warn",
            title=f"The busiest vblank touched {peak} instruction-cache lines, {state} the cache's 256",
            detail=("Code that runs within one vblank fits the 8 KiB instruction cache by line count, so a good "
                    "order can remove most conflict misses." if peak <= 256 else
                    "More code runs per vblank than the 8 KiB cache holds, so some misses remain whatever the "
                    "order. Shrinking hot code (-Os for cold paths, fewer inlined copies) is the lever."),
            items=[]))

    # --- hot code and data the script cannot move -------------------------------
    for kind, cache_name in (("code", "instruction"), ("data", "operand")):
        stuck = []
        for name, entry in baseline.items():
            replay = entry[kind]
            if not replay:
                continue
            for u, n in replay["unit_misses"].items():
                if u < fixed and not units[u]["movable"] and units[u]["kind"] == kind:
                    stuck.append((n / vblanks[name], u))
        stuck.sort(reverse=True)
        if stuck and stuck[0][0] >= 1:
            items = [f"{_name(model, u)} ({units[u]['section']}): {n:,.1f} misses per vblank; "
                     f"it stays put because {units[u]['reason'] or 'it is outside every region'}"
                     for n, u in stuck[:6]]
            findings.append(dict(
                kind=f"{kind}-pinned", severity="warn",
                title=f"{cache_name.capitalize()}-cache misses land in {len(stuck)} section(s) the script cannot move",
                detail=("Build every object with -ffunction-sections -fdata-sections (KallistiOS does by default), "
                        "give assembly functions their own .text.name sections, and avoid -fcommon, so each "
                        "function and object becomes a movable input section."),
                items=items))

    # --- operand-cache misses by kind of memory ---------------------------------
    for name, entry in baseline.items():
        replay = entry["data"]
        if not replay or not replay["misses"]:
            continue
        share = {"static data": 0, "code (literal pools, tables in .text)": 0, "stack and other fixed memory": 0,
                 "heap": 0}
        for u, n in replay["unit_misses"].items():
            if u == fixed:
                share["stack and other fixed memory"] += n
            elif u == fixed + 1:
                share["heap"] += n
            elif units[u]["kind"] == "code":
                share["code (literal pools, tables in .text)"] += n
            else:
                share["static data"] += n
        total = sum(share.values()) or 1
        dynamic = share["stack and other fixed memory"] + share["heap"]
        findings.append(dict(
            kind="oc-breakdown", severity="info",
            title=f"Where operand-cache misses land in {name}",
            detail=("Layout moves static data and code; stack and heap addresses are set at run time. "
                    + ("A large stack/heap share points at allocation: 32-byte-align hot buffers, reuse them "
                       "instead of reallocating, or prefetch (pref) streams one line ahead."
                       if dynamic > 0.3 * total else "")),
            items=[f"{k}: {v:,} misses ({100 * v / total:.0f}%)" for k, v in share.items() if v]))
        if replay["writebacks"] > 0.25 * max(1, replay["misses"]):
            top = sorted(replay["unit_writebacks"].items(), key=lambda kv: -kv[1])[:5]
            findings.append(dict(
                kind="oc-writebacks", severity="info",
                title=f"{replay['writebacks']:,} dirty lines were written back in {name}",
                detail=("Each eviction of a line the program stored to costs a write burst. Conflicts between "
                        "written objects double the cost of a miss; buffers written once and sent elsewhere "
                        "(e.g. to the PVR) can use the store queues or movca.l instead of allocating lines."),
                items=[f"{_name(model, u)}: {n:,} writebacks" for u, n in top]))

    # --- code that falls through into the next section --------------------------
    seen = set()
    for t in traces:
        for a, b, n in t["fallthrough"]:
            if (a, b) in seen:
                continue
            seen.add((a, b))
            findings.append(dict(
                kind="fallthrough", severity="warn",
                title=f"Execution runs straight from {_name(model, a)} into {_name(model, b)}",
                detail="These sections are kept in their original order, since separating them would break the "
                       "program. Usually this is assembly without a final branch; give it one.",
                items=[f"{units[a]['id']} -> {units[b]['id']} ({n} times)"]))

    # --- large hot units / sparse hot code ---------------------------------------
    for i, u in enumerate(units):
        if u["kind"] != "code":
            continue
        spans = []
        for t in traces:
            spans.extend(t["coverage"].get(str(i), []))
        if not spans:
            continue
        spans.sort()
        executed, end = 0, -1
        for s, e in spans:
            s = max(s, end)
            if e > s:
                executed += e - s
                end = e
        span = spans[-1][1] - spans[0][0]
        if u["size"] >= 4096 and executed >= 512:
            findings.append(dict(
                kind="large-unit", severity="info",
                title=f"{_name(model, i)} is one {u['size']:,}-byte section ({u['size'] // 32} cache lines)",
                detail=f"{executed:,} of its bytes ran. It moves as a whole, which limits how its hot parts can be "
                       "placed. Splitting it, or moving rare paths into separate noinline functions, frees the search.",
                items=[]))
        elif span >= 1024 and executed * 2 < span and executed >= 128:
            findings.append(dict(
                kind="sparse", severity="info",
                title=f"{_name(model, i)} spreads {executed:,} executed bytes over {span:,}",
                detail="Cold blocks between hot ones take cache slots the hot code could use. Moving rare paths "
                       "into separate cold (noinline, __attribute__((cold))) functions packs the hot code.",
                items=[]))

    # --- what is left after the best candidate ----------------------------------
    for kind, label in (("code", "instruction"), ("data", "operand")):
        for name, entry in best.items():
            replay = entry[kind]
            if not replay or not replay["pairs"]:
                continue
            rows = []
            for (a, b), n in replay["pairs"][:6]:
                rows.append(f"{_where(model, a)} evicted {_where(model, b)}: {n / vblanks[name]:,.1f} times per vblank")
            findings.append(dict(
                kind=f"{kind}-residual", severity="info",
                title=f"Strongest {label}-cache conflicts left in the best layout ({name})",
                detail=f"{replay['conflict_misses']:,} conflict misses remain (misses a fully associative cache "
                       "of the same size would not take). Shrinking one side, or more --search-seconds, may help.",
                items=rows))
    return findings
