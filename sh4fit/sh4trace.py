"""Reader for SH4XTRC1 execution traces written by the devcast sh4trace hook.

The file is a 64-byte header followed by blocks of 12-byte records, each block
tagged with the stream it belongs to (0 instruction fetches, 1 data accesses).
Records within one stream are in execution order; see devcast/README.md for
the layout of each record kind.
"""
from __future__ import annotations

from array import array
from collections import Counter
import struct
import sys

MAGIC = b"SH4XTRC1"
VERSION = 1
HEADER_BYTES = 64
INSTRUCTIONS, ACCESSES = 0, 1
RANGE, FRAME, RESET, CCR, EXCEPT, CODE, DATA, ARRAY, TOTALS = 0, 1, 4, 5, 6, 7, 8, 9, 15
OP_ACCESS, OP_PREF, OP_MOVCA, OP_OCBI, OP_OCBP, OP_OCBWB, OP_ARRAY = range(7)
LOAD, STORE, FIRST_STORE = 1, 2, 4  # DATA record flags for OP_ACCESS
OP_NAMES = {OP_ACCESS: "load/store", OP_PREF: "pref", OP_MOVCA: "movca.l", OP_OCBI: "ocbi",
            OP_OCBP: "ocbp", OP_OCBWB: "ocbwb", OP_ARRAY: "cache array store"}
HAS_DATA, INTERPRETER, AT_PC, AT_MARKER, AT_FRAME = 1, 2, 4, 8, 16
LIMIT, STOPPED = 1, 2
STREAM_KINDS = {INSTRUCTIONS: {RANGE, FRAME, RESET, CCR, EXCEPT, CODE, ARRAY, TOTALS},
                ACCESSES: {DATA, FRAME, RESET, CCR}}


def read_header(data):
    if len(data) < HEADER_BYTES or data[:8] != MAGIC:
        raise ValueError("not an SH4XTRC1 trace (record one with DEVCAST_TRACE in the patched devcast)")
    version, header_bytes, flags, ccr, mmucr, vblank = struct.unpack_from("<6I", data, 8)
    cycle, start_pc = struct.unpack_from("<QI", data, 32)
    if version != VERSION or header_bytes != HEADER_BYTES:
        raise ValueError(f"unsupported SH4XTRC1 version {version}")
    trigger = ("START_PC" if flags & AT_PC else "START_MARKER" if flags & AT_MARKER
               else "START_FRAME" if flags & AT_FRAME else "boot")
    return dict(flags=flags, data=bool(flags & HAS_DATA), interpreter=bool(flags & INTERPRETER),
                ccr=ccr, mmucr=mmucr, vblank=vblank, cycle=cycle, start_pc=start_pc, trigger=trigger)


def blocks(path, chunk=1 << 24):
    """Yield (stream, words) per block; `words` holds three u32 per record."""
    with open(path, "rb") as f:
        read_header(f.read(HEADER_BYTES))
        while True:
            head = f.read(8)
            if not head:
                return
            if len(head) != 8:
                raise ValueError(f"{path}: trace ends inside a block header")
            stream, count = struct.unpack("<2I", head)
            if stream not in STREAM_KINDS:
                raise ValueError(f"{path}: unknown stream {stream}")
            remaining = count * 12
            while remaining:
                data = f.read(min(remaining, chunk * 12))
                if not data or len(data) % 12:
                    raise ValueError(f"{path}: trace ends inside a block")
                remaining -= len(data)
                words = array("I")
                words.frombytes(data)
                if sys.byteorder == "big":
                    words.byteswap()
                yield stream, words


def decode_ccr(value):
    names = dict(OCE=0, WT=1, CB=2, OCI=3, ORA=5, OIX=7, ICE=8, ICI=11, IIX=15)
    return [name for name, bit in names.items() if value >> bit & 1]


def cacheable(address):
    """Whether an access at `address` can use the caches (P0, P1, P3 outside area 7)."""
    top = address >> 29
    return top not in (5, 7) and (address & 0x1FFFFFFF) < 0x1C000000


def area(address):
    """Cacheability of an instruction or data address with the MMU off."""
    top = address >> 29
    if top == 5:
        return "P2"
    if top == 7:
        return "P4"
    if (address & 0x1FFFFFFF) >= 0x1C000000:
        return "area7"
    return "P1" if top == 4 else "P3" if top == 6 else "P0"


def summarize(path, elf=None):
    """Validate a trace end to end and summarize it. `elf` (an elf.Elf) adds an
    exact provenance check of the CODE records against the executable."""
    with open(path, "rb") as f:
        header = read_header(f.read(HEADER_BYTES))
    instructions = fetched_uncached = ranges = range_records = 0
    data_total = data_records = 0
    frame_instructions, frame_cycles, frame_marks = [], [], 0
    current_frame = 0
    exceptions, ccr_writes, ops, areas = Counter(), [], Counter(), Counter()
    resets = ic_array = 0
    code = {}
    totals = {}
    data_frames = 0
    lines = set()
    for stream, words in blocks(path):
        it = iter(words)
        if stream == INSTRUCTIONS:
            for a, b, t in zip(it, it, it):
                kind = t >> 28
                if kind not in STREAM_KINDS[stream]:
                    raise ValueError(f"record kind {kind} in the instruction stream")
                if kind == RANGE:
                    count = t & 0x0FFFFFFF
                    if b <= a or (a | b) & 1 or not count:
                        raise ValueError(f"corrupt range {a:#010x}-{b:#010x} x{count}")
                    n = (b - a) >> 1
                    instructions += n * count
                    current_frame += n * count
                    ranges += count
                    range_records += 1
                    if area(a) == "P2":
                        fetched_uncached += n * count
                elif kind == FRAME:
                    frame_marks += 1
                    frame_instructions.append(current_frame)
                    frame_cycles.append(b)
                    current_frame = 0
                elif kind == EXCEPT:
                    exceptions[t & 0xFFF] += 1
                elif kind == CCR:
                    ccr_writes.append((a, b))
                elif kind == RESET:
                    resets += 1
                elif kind == ARRAY:
                    ic_array += 1
                elif kind == CODE:
                    code.setdefault(a, b)
                elif kind == TOTALS:
                    totals[t & 15] = (a, b)
        else:
            for a, b, t in zip(it, it, it):
                kind = t >> 28
                if kind not in STREAM_KINDS[stream]:
                    raise ValueError(f"record kind {kind} in the data stream")
                if kind == DATA:
                    op, count = (t >> 24) & 15, t & 0xFFFFF
                    if op not in OP_NAMES or not count:
                        raise ValueError(f"corrupt data record op {op} x{count}")
                    data_records += 1
                    ops[op] += count
                    if op != OP_ARRAY:
                        data_total += count
                        areas[area(a)] += count
                        lines.add((a & 0x1FFFFFFF) >> 5)
                elif kind == FRAME:
                    data_frames += 1
    if not {0, 1, 2}.issubset(totals):
        raise ValueError(f"{path}: incomplete trace (no totals); let the capture reach its frame count "
                         "or stop emulation before quitting")
    total_instructions = totals[0][0] | totals[0][1] << 32
    total_data = totals[1][0] | totals[1][1] << 32
    flags, frames = totals[2]
    if total_instructions != instructions:
        raise ValueError(f"{path}: {instructions} instructions in ranges, totals say {total_instructions}")
    if header["data"] and total_data != data_total:
        raise ValueError(f"{path}: {data_total} data accesses in records, totals say {total_data}")
    if frames != frame_marks or (header["data"] and data_frames != frame_marks):
        raise ValueError(f"{path}: frame marks disagree with totals ({frame_marks}, {data_frames}, {frames})")
    result = dict(header=header, ccr_flags=decode_ccr(header["ccr"]), frames=frames,
                  truncated=bool(flags & LIMIT), stopped_early=bool(flags & STOPPED),
                  instructions=instructions, range_records=range_records, ranges=ranges,
                  uncached_instructions=fetched_uncached, after_last_frame=current_frame,
                  frame_instructions=frame_instructions, frame_cycles=frame_cycles,
                  exceptions=dict(exceptions), ccr_writes=ccr_writes, resets=resets, code_lines=len(code),
                  ic_array_writes=ic_array,
                  data_accesses=data_total, data_records=data_records, data_ops={OP_NAMES[k]: v for k, v in ops.items()},
                  data_areas=dict(areas), data_lines=len(lines),
                  uncached_data=(totals[3][0] | totals[3][1] << 32) if 3 in totals else None)
    if elf is not None:
        checked = matched = 0
        mismatches = []
        for address, value in sorted(code.items()):
            expected = elf.halfword(address)
            if expected is None:
                continue
            checked += 1
            if expected == value:
                matched += 1
            elif len(mismatches) < 5:
                mismatches.append((address, value, expected))
        result["provenance"] = dict(checked=checked, matched=matched, mismatches=mismatches)
    return result
