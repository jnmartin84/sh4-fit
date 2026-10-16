"""Shared helpers: synthetic SH4XTRC1 files for tests."""
import struct

from sh4fit import sh4trace as t


def record(kind, a=0, b=0, low=0):
    return (a, b, kind << 28 | low)


def write_trace(path, fetches, accesses=(), flags=t.HAS_DATA | t.INTERPRETER, ccr=0x105, totals=True,
                block=None):
    """Write an SH4XTRC1 file; totals are computed from the records unless
    `totals` is a tuple (instructions, data accesses, flags, frames)."""
    fetches, accesses = list(fetches), list(accesses)
    if totals is True:
        instructions = sum(((b - a) >> 1) * (k & 0x0FFFFFFF) for a, b, k in fetches if k >> 28 == t.RANGE)
        data = sum(k & 0xFFFFF for a, b, k in accesses if k >> 28 == t.DATA and (k >> 24) & 15 != t.OP_ARRAY)
        frames = sum(1 for _, _, k in fetches if k >> 28 == t.FRAME)
        totals = (instructions, data, 0, frames)
    if totals:
        instructions, data, end_flags, frames = totals
        fetches += [record(t.TOTALS, instructions & 0xFFFFFFFF, instructions >> 32, 0),
                    record(t.TOTALS, data & 0xFFFFFFFF, data >> 32, 1),
                    record(t.TOTALS, end_flags, frames, 2), record(t.TOTALS, 0, 0, 3)]
    header = bytearray(64)
    header[:8] = t.MAGIC
    struct.pack_into("<6I", header, 8, 1, 64, flags, ccr, 0, 7)
    with open(path, "wb") as f:
        f.write(header)
        for stream, records in ((1, accesses), (0, fetches)):
            size = block or max(1, len(records))
            for i in range(0, len(records), size):
                chunk = records[i:i + size]
                f.write(struct.pack("<2I", stream, len(chunk)))
                for r in chunk:
                    f.write(struct.pack("<3I", *r))
    return path
