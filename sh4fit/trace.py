"""Import SH4XTRC1 captures onto placement units.

Every executed range and every data access is re-expressed relative to the
placement unit containing it, so one capture replays against any order of
those units (cache.py). Addresses outside every unit keep their physical
address under a FIXED pseudo-unit; data at or above the end of the program's
image (heap, thread stacks) is relative to that end under a HEAP pseudo-unit,
so it follows the end if a layout moves it. The main stack at the top of RAM
stays fixed.

Instruction fetches are stored as ids into a table of distinct ranges (a tight
loop is one id with a repeat count), data accesses as (unit | op << 16, offset)
word pairs, one per run on a cache line.
"""
from __future__ import annotations

from array import array
import bisect
from collections import defaultdict
import json
import math
from pathlib import Path
import re
import sys

from . import sh4trace as fmt
from .elf import Elf

IMPORTED_VERSION = 1
STACK_FLOOR = 0x0CFF0000  # physical; KallistiOS's main stack is the top 64 KiB of 16 MiB RAM
ARRAYS = ("segments", "code_frames", "code_events", "data", "data_offsets", "data_frames", "data_events")
EVENT_WORDS = 4  # (position, kind, a, b)
REPEAT_CAP = 255  # repeat counts stored per segment saturate here; exact totals are kept per range


def parse_spec(spec):
    """'capture.sh4trace=2.5' -> (path, 2.5); a plain path has weight 1."""
    path, sep, weight = spec.rpartition("=")
    if not sep:
        return spec, 1.0
    try:
        value = float(weight)
    except ValueError:
        raise ValueError(f"trace weight must be a finite positive number: {spec}") from None
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"trace weight must be a finite positive number: {spec}")
    return path, value


def pseudo_units(model):
    n = len(model["units"])
    return n, n + 1  # FIXED, HEAP


class CodeLocator:
    """Split physical address ranges at code-unit boundaries."""

    def __init__(self, units, fixed):
        code = [(i, u) for i, u in enumerate(units) if u["kind"] == "code"]
        self.fixed = fixed
        self.starts = [u["address"] & 0x1FFFFFFF for _, u in code]
        self.ends = [s + u["size"] for s, (_, u) in zip(self.starts, code)]
        self.index = [i for i, _ in code]
        self.lo = min(self.starts, default=0)
        self.hi = max(self.ends, default=0)
        table = array("i", [-1]) * ((self.hi - self.lo + 1) // 2)
        for k, (a, b) in enumerate(zip(self.starts, self.ends)):
            first, last = (a - self.lo) // 2, (b - self.lo + 1) // 2
            table[first:last] = array("i", [k]) * (last - first)
        self.table = table

    def split(self, a, b):
        parts = []
        while a < b:
            k = self.table[(a - self.lo) >> 1] if self.lo <= a < self.hi else -1
            if k >= 0:
                base = self.starts[k]
                end = min(b, self.ends[k])
                parts.append((self.index[k], a - base, end - base))
            else:
                i = bisect.bisect_right(self.starts, a)
                end = min(b, self.starts[i]) if i < len(self.starts) else b
                parts.append((self.fixed, a, end))
            a = end
        return tuple(parts)


class DataLocator:
    """Physical data address -> (unit, offset); literal pools resolve to code units."""

    def __init__(self, units, fixed, heap, data_end):
        order = sorted(range(len(units)), key=lambda i: units[i]["address"])
        self.starts = [units[i]["address"] & 0x1FFFFFFF for i in order]
        self.ends = [s + units[i]["size"] for s, i in zip(self.starts, order)]
        self.order = order
        self.fixed, self.heap = fixed, heap
        self.data_end = data_end & 0x1FFFFFFF
        self.memo = {}

    def locate(self, address):
        line = address >> 5
        hit = self.memo.get(line)
        if hit is not None:
            u, base = hit
            return u, address - base
        i = bisect.bisect_right(self.starts, address) - 1
        if i >= 0 and address < self.ends[i]:
            u, base = self.order[i], self.starts[i]
            if base <= line << 5 and (line + 1) << 5 <= self.ends[i]:
                self.memo[line] = (u, base)
            return u, address - base
        if self.data_end <= address < STACK_FLOOR:
            u, base = self.heap, self.data_end
        else:
            u, base = self.fixed, 0
        # only memoize lines no unit touches
        j = bisect.bisect_right(self.starts, (line + 1) << 5) - 1
        if j < 0 or self.ends[j] <= line << 5:
            self.memo[line] = (u, base)
        return u, address - base


def import_trace(model, path, name=None, weight=1.0, elf=None, progress=None):
    path = Path(path).resolve()
    with open(path, "rb") as f:
        header = fmt.read_header(f.read(fmt.HEADER_BYTES))
    units = model["units"]
    if len(units) + 2 >= 1 << 16:
        raise ValueError("too many placement units for trace import")
    fixed, heap = pseudo_units(model)
    elf = elf or Elf.read(model["elf"])
    code_loc = CodeLocator(units, fixed)
    data_loc = DataLocator(units, fixed, heap, model["data_end"])
    name = re.sub(r"[^A-Za-z0-9_-]+", "_", name or path.stem).strip("_") or "trace"

    segments, code_frames, code_events = array("I"), array("I"), array("I")
    data, offsets, data_frames, data_events = array("I"), array("I"), array("I"), array("I")
    ranges, range_ids, range_touches = [], {}, []
    unit_instructions = [0] * (heap + 1)
    unit_accesses = [0] * (heap + 1)
    unit_stores = [0] * (heap + 1)
    transitions = defaultdict(int)
    fallthrough = defaultdict(int)
    totals = {}
    instructions = uncached_instructions = 0
    accesses = records = 0
    code_checked = code_matched = 0
    mismatch = None
    exceptions = 0
    prev_unit = -1
    ops = [0] * 8
    locate = data_loc.locate
    for stream, words in fmt.blocks(path):
        it = iter(words)
        if stream == fmt.INSTRUCTIONS:
            for a, b, t in zip(it, it, it):
                kind = t >> 28
                if kind == fmt.RANGE:
                    if b <= a or (a | b) & 1:
                        raise ValueError(f"{path.name}: corrupt range {a:#010x}-{b:#010x}")
                    n = t & 0x0FFFFFFF
                    key = a << 32 | b
                    rid = range_ids.get(key)
                    if rid is None:
                        parts = code_loc.split(a & 0x1FFFFFFF, (a & 0x1FFFFFFF) + (b - a))
                        rid = range_ids[key] = len(ranges)
                        ranges.append(parts)
                        range_touches.append(0)
                        for (u1, _, _), (u2, _, _) in zip(parts, parts[1:]):
                            if u1 != fixed and u2 != fixed:
                                fallthrough[u1, u2] += 1
                    parts = ranges[rid]
                    count = n * ((b - a) >> 1)
                    instructions += count
                    for u, s, e in parts:
                        unit_instructions[u] += n * ((e - s) >> 1)
                    if not fmt.cacheable(a):
                        uncached_instructions += count
                        continue
                    range_touches[rid] += n
                    u = parts[0][0]
                    if u != prev_unit:
                        if prev_unit >= 0 and prev_unit != fixed and u != fixed:
                            transitions[prev_unit << 16 | u] += 1
                    prev_unit = parts[-1][0]
                    if len(parts) > 1 and n > 1:
                        # a repeated run across units: keep every pass, the units may separate
                        for _ in range(n):
                            segments.append(rid << 8 | 1)
                    else:
                        segments.append(rid << 8 | min(n, REPEAT_CAP))
                elif kind == fmt.FRAME:
                    code_frames.append(len(segments))
                elif kind in (fmt.CCR, fmt.ARRAY, fmt.RESET):
                    code_events.extend((len(segments), kind, a, b))
                    if kind == fmt.RESET:
                        prev_unit = -1
                elif kind == fmt.CODE:
                    expected = elf.halfword(a)
                    if expected is not None:
                        code_checked += 1
                        if expected == b:
                            code_matched += 1
                        elif mismatch is None:
                            mismatch = (a, b, expected)
                elif kind == fmt.EXCEPT:
                    exceptions += 1
                elif kind == fmt.TOTALS:
                    totals[t & 15] = (a, b)
                else:
                    raise ValueError(f"{path.name}: record kind {kind} in the instruction stream")
        else:
            append, append_offset = data.append, offsets.append
            for a, b, t in zip(it, it, it):
                kind = t >> 28
                if kind == fmt.DATA:
                    op = (t >> 24) & 15
                    records += 1
                    if op == fmt.OP_ARRAY:
                        data_events.extend((len(data), fmt.ARRAY, a, b))
                        ops[op] += 1
                        continue
                    count = t & 0xFFFFF
                    flags = (t >> 20) & 15
                    accesses += count
                    ops[op] += count
                    u, off = locate(a & 0x1FFFFFFF)
                    unit_accesses[u] += count
                    if flags & fmt.STORE:
                        unit_stores[u] += 1
                    # P0/P3 follow CCR.WT, P1 follows CCR.CB
                    append(u | op << 16 | flags << 20 | (0 if a >> 29 == 4 else 1) << 24)
                    append_offset(off)
                elif kind == fmt.FRAME:
                    data_frames.append(len(data))
                elif kind in (fmt.CCR, fmt.RESET):
                    data_events.extend((len(data), kind, a, b))
                else:
                    raise ValueError(f"{path.name}: record kind {kind} in the data stream")
        if progress:
            progress(len(segments), len(data))
    if not {0, 1, 2}.issubset(totals):
        raise ValueError(f"{path.name}: incomplete trace (no totals); let the capture reach its frame count")
    total_instructions = totals[0][0] | totals[0][1] << 32
    if total_instructions != instructions:
        raise ValueError(f"{path.name}: {instructions} instructions in ranges, totals say {total_instructions}")
    if header["data"] and (totals[1][0] | totals[1][1] << 32) != accesses:
        raise ValueError(f"{path.name}: data access count does not match the trace totals")
    if mismatch:
        address, found, expected = mismatch
        raise ValueError(f"{path.name} was captured from a different build: the trace fetched 0x{found:04x} at "
                         f"0x{address:08x} where {Path(model['elf']).name} has 0x{expected:04x}")
    if not code_checked:
        raise ValueError(f"{path.name}: none of the code it ran is in {Path(model['elf']).name}; wrong ELF?")
    end_flags, frames = totals[2]

    coverage = defaultdict(list)
    for parts in ranges:
        for u, s, e in parts:
            if u != fixed:
                coverage[u].append((s, e))
    merged_coverage = {}
    for u, items in coverage.items():
        items.sort()
        merged = []
        for s, e in items:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        merged_coverage[str(u)] = merged

    warnings = []
    if end_flags & fmt.LIMIT:
        warnings.append(f"{path.name}: the capture hit its size limit; only its beginning is analyzed")
    if not header["data"]:
        warnings.append(f"{path.name}: captured without data accesses (DEVCAST_TRACE_DATA=0); "
                        "operand-cache analysis is unavailable for it")
    if header["mmucr"] & 1:
        warnings.append(f"{path.name}: the MMU was on; addresses are virtual and may not be physical tags")
    if not code_frames:
        warnings.append(f"{path.name}: no vblank marks; per-frame figures cover the whole capture")
    stats = dict(instructions=instructions, uncached_instructions=uncached_instructions,
                 outside_units=unit_instructions[fixed], segments=len(segments), unique_ranges=len(ranges),
                 data_accesses=accesses, data_records=len(data), heap_accesses=unit_accesses[heap],
                 fixed_accesses=unit_accesses[fixed], frames=frames, truncated=bool(end_flags & fmt.LIMIT),
                 exceptions=exceptions, code_lines_checked=code_checked,
                 uncached_data=(totals[3][0] | totals[3][1] << 32) if 3 in totals else 0,
                 ops={fmt.OP_NAMES[k]: v for k, v in enumerate(ops) if v and k in fmt.OP_NAMES})
    return dict(version=IMPORTED_VERSION, name=name, weight=weight, source=str(path), elf_sha256=model["elf_sha256"],
                ccr=header["ccr"], has_data=header["data"], trigger=header["trigger"], start_pc=header["start_pc"],
                units=[u["id"] for u in units], data_end=model["data_end"], ranges=[list(map(list, p)) for p in ranges],
                range_touches=range_touches, unit_instructions=unit_instructions, unit_accesses=unit_accesses,
                unit_stores=unit_stores,
                transitions=[[k >> 16, k & 0xFFFF, n] for k, n in sorted(transitions.items())],
                fallthrough=[[a, b, n] for (a, b), n in sorted(fallthrough.items())],
                coverage=merged_coverage, warnings=warnings, stats=stats,
                segments=segments, code_frames=code_frames, code_events=code_events,
                data=data, data_offsets=offsets, data_frames=data_frames, data_events=data_events)


def save(trace, out):
    """Write trace-<name>.json (metadata) and trace-<name>.bin (arrays)."""
    out = Path(out)
    stem = "trace-" + trace["name"]
    with open(out / (stem + ".bin"), "wb") as f:
        for key in ARRAYS:
            data = trace[key]
            if sys.byteorder == "big":
                data = array("I", data)
                data.byteswap()
            data.tofile(f)
    meta = {k: v for k, v in trace.items() if k not in ARRAYS}
    meta.update(data_file=stem + ".bin", arrays={k: len(trace[k]) for k in ARRAYS})
    (out / (stem + ".json")).write_text(json.dumps(meta), encoding="utf-8")
    return stem + ".json"


def load(path):
    path = Path(path)
    trace = json.loads(path.read_text(encoding="utf-8"))
    if trace.get("version") != IMPORTED_VERSION:
        raise ValueError(f"{path.name}: incompatible imported trace; rerun analyze with the original capture")
    with open(path.parent / trace.pop("data_file"), "rb") as f:
        for key, length in trace.pop("arrays").items():
            data = array("I")
            data.fromfile(f, length)
            if sys.byteorder == "big":
                data.byteswap()
            trace[key] = data
    trace["ranges"] = [tuple(tuple(p) for p in parts) for parts in trace["ranges"]]
    return trace


def bounds(marks, total):
    """[start, end) intervals per frame: one before each vblank mark and a final
    (possibly empty) one after the last, so both streams have the same frames."""
    result, start = [], 0
    for mark in marks:
        result.append((start, mark))
        start = mark
    result.append((start, total))
    return result
