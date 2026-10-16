import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from sh4fit import sh4trace as t
from sh4fit.elf import Elf

from tracefile import record, write_trace

ROOT = Path(__file__).resolve().parent.parent


def tiny_elf(address, halfwords):
    """A minimal little-endian SH ELF with one executable .text section."""
    text = struct.pack(f"<{len(halfwords)}H", *halfwords)
    names = b"\0.text\0.shstrtab\0"
    text_offset = 52
    names_offset = text_offset + len(text)
    shoff = (names_offset + len(names) + 3) & ~3
    header = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    header += struct.pack("<HHIIIIIHHHHHH", 2, 42, 1, address, 0, shoff, 0, 52, 0, 0, 40, 3, 2)
    sections = bytes(40)
    sections += struct.pack("<10I", 1, 1, 6, address, text_offset, len(text), 0, 0, 2, 0)
    sections += struct.pack("<10I", 7, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0)
    data = header + text + names
    return Elf(data + bytes(shoff - len(data)) + sections, "tiny.elf")


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="sh4fit-trace-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def test_ranges_repeats_and_frames(self):
        fetches = [record(t.CODE, 0x8c010000, 0xd706), record(t.RANGE, 0x8c010000, 0x8c010010, 1),
                   record(t.RANGE, 0x8c010008, 0x8c010010, 62), record(t.FRAME, 1, 3_000_000),
                   record(t.EXCEPT, 0x8c010010, 0x8c000100, 0x160), record(t.RANGE, 0xac000000, 0xac000004, 1),
                   record(t.FRAME, 2, 3_000_000)]
        accesses = [record(t.DATA, 0x8c012840, 0x8c010002, t.LOAD << 20 | 3), record(t.FRAME, 1, 3_000_000),
                    record(t.DATA, 0x8c012820, 0x8c010004, t.OP_OCBWB << 24 | 1),
                    record(t.DATA, 0xf4000000, 0, t.OP_ARRAY << 24 | t.STORE << 20 | 1), record(t.FRAME, 2, 3_000_000)]
        s = t.summarize(write_trace(self.dir / "a.sh4trace", fetches, accesses, block=2))
        self.assertEqual(s["instructions"], 8 + 62 * 4 + 2)
        self.assertEqual(s["ranges"], 64)
        self.assertEqual(s["range_records"], 3)
        self.assertEqual(s["frames"], 2)
        self.assertEqual(s["frame_instructions"], [8 + 62 * 4, 2])
        self.assertEqual(s["uncached_instructions"], 2)
        self.assertEqual(s["exceptions"], {0x160: 1})
        self.assertEqual(s["data_accesses"], 4)   # array stores aren't accesses
        self.assertEqual(s["data_ops"], {"load/store": 3, "ocbwb": 1, "cache array store": 1})
        self.assertEqual(s["data_lines"], 2)
        self.assertEqual(s["ccr_flags"], ["OCE", "CB", "ICE"])

    def test_incomplete_and_inconsistent_traces_are_rejected(self):
        fetches = [record(t.RANGE, 0x8c010000, 0x8c010010, 1), record(t.FRAME, 1, 0)]
        with self.assertRaisesRegex(ValueError, "incomplete"):
            t.summarize(write_trace(self.dir / "b.sh4trace", fetches, totals=False))
        with self.assertRaisesRegex(ValueError, "instructions in ranges"):
            t.summarize(write_trace(self.dir / "c.sh4trace", fetches, totals=(9, 0, 0, 1)))
        with self.assertRaisesRegex(ValueError, "frame marks"):
            # the data stream lacks the FRAME that the instruction stream has
            t.summarize(write_trace(self.dir / "d.sh4trace", fetches, accesses=[]))
        path = write_trace(self.dir / "e.sh4trace", fetches, flags=t.INTERPRETER)
        path.write_bytes(path.read_bytes()[:-6])
        with self.assertRaisesRegex(ValueError, "ends inside"):
            t.summarize(path)
        with self.assertRaisesRegex(ValueError, "not an SH4XTRC1"):
            t.read_header(b"P64XTRC1" + bytes(56))

    def test_corrupt_records_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "corrupt range"):
            t.summarize(write_trace(self.dir / "f.sh4trace", [record(t.RANGE, 0x8c010010, 0x8c010000, 1)],
                                    flags=t.INTERPRETER, totals=(0, 0, 0, 0)))
        with self.assertRaisesRegex(ValueError, "data stream"):
            t.summarize(write_trace(self.dir / "g.sh4trace", [], [record(t.RANGE, 0, 2, 1)]))

    def test_provenance_matches_and_mismatches(self):
        elf = tiny_elf(0x8c010000, [0xd706, 0xe300, 0xe240, 0x000b])
        fetches = [record(t.CODE, 0x8c010000, 0xd706), record(t.CODE, 0xac010004, 0xe240),  # P2 alias
                   record(t.CODE, 0x8c020000, 0x1234),  # outside the ELF: ignored
                   record(t.RANGE, 0x8c010000, 0x8c010008, 1)]
        s = t.summarize(write_trace(self.dir / "h.sh4trace", fetches, flags=t.INTERPRETER), elf)
        self.assertEqual(s["provenance"], dict(checked=2, matched=2, mismatches=[]))
        fetches[0] = record(t.CODE, 0x8c010000, 0xd707)
        s = t.summarize(write_trace(self.dir / "i.sh4trace", fetches, flags=t.INTERPRETER), elf)
        self.assertEqual(s["provenance"]["matched"], 1)
        self.assertEqual(s["provenance"]["mismatches"], [(0x8c010000, 0xd707, 0xd706)])

    def test_areas(self):
        self.assertEqual(t.area(0x8c010000), "P1")
        self.assertEqual(t.area(0xac010000), "P2")
        self.assertEqual(t.area(0x0c010000), "P0")
        self.assertEqual(t.area(0xffe8000c), "P4")
        self.assertEqual(t.area(0x7c000000), "area7")


PREFIX = os.environ.get("SH_TOOL_PREFIX", "/opt/toolchains/dc/sh-elf/bin/sh-elf-")


@unittest.skipUnless(shutil.which(PREFIX + "gcc"), "set SH_TOOL_PREFIX to build the devcast test program")
class TestProgramTests(unittest.TestCase):
    def test_test_program_layout(self):
        with tempfile.TemporaryDirectory(prefix="sh4fit-prog-") as directory:
            build = Path(directory) / "test"
            shutil.copytree(ROOT / "devcast" / "test", build)
            subprocess.run(["make", "-s", f"PREFIX={PREFIX}"], cwd=build, check=True, capture_output=True)
            elf = Elf.read(build / "trace-test.elf")
            symbols = {s["name"]: s["address"] for s in elf.symbols}
            # hot_a and hot_b share every instruction-cache slot
            self.assertEqual(symbols["_hot_b"] - symbols["_hot_a"], 8192)
            first = elf.halfword(symbols["_hot_a"])
            self.assertIsNotNone(first)
            self.assertEqual(elf.halfword(symbols["_hot_a"] | 0x20000000), first)  # P2 alias


if __name__ == "__main__":
    unittest.main()
