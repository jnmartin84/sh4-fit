import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from array import array

from sh4fit import cache, sh4trace as t
from sh4fit.elf import Elf
from sh4fit.layout import positions, script_variant
from sh4fit.model import Inventory, _known_alignment, parse_map, selector_for, statement_patterns

from tracefile import record, write_trace

ROOT = Path(__file__).resolve().parent.parent
PREFIX = os.environ.get("SH_TOOL_PREFIX", "/opt/toolchains/dc/sh-elf/bin/sh-elf-")
FIXED = 0  # with no units, the FIXED pseudo-unit is index 0 and HEAP index 1
BASE = [0, 0x0C100000]


def fake(code=(), data=(), ccr=0x105, code_events=(), data_events=()):
    """An imported trace over absolute addresses: `code` is a list of
    (start, end) fetch runs, `data` a list of (op, flags, address, p0)."""
    ranges, ids, segments = [], {}, array("I")
    for a, b in code:
        if (a, b) not in ids:
            ids[a, b] = len(ranges)
            ranges.append(((FIXED, a, b),))
        segments.append(ids[a, b] << 8 | 1)
    words, offsets = array("I"), array("I")
    for op, flags, address, p0 in data:
        words.append(FIXED | op << 16 | flags << 20 | p0 << 24)
        offsets.append(address)
    return dict(ccr=ccr, has_data=True, ranges=ranges, segments=segments, code_frames=array("I"),
                code_events=array("I", [x for e in code_events for x in e]),
                data=words, data_offsets=offsets, data_frames=array("I"),
                data_events=array("I", [x for e in data_events for x in e]),
                stats=dict(instructions=1000), weight=1.0, name="t")


A, B4, B8, B16 = 0x0C010000, 0x0C011000, 0x0C012000, 0x0C014000  # +0, +4 KiB, +8 KiB, +16 KiB
LOAD, STORE, FIRST = t.LOAD, t.STORE, t.FIRST_STORE


def misses(trace, ccr=None):
    return cache.simulate_code(trace, BASE, ccr=ccr)["misses"]


def oc(trace):
    return cache.simulate_data(trace, BASE)


class InstructionCacheTests(unittest.TestCase):
    def test_lines_8k_apart_share_a_slot(self):
        self.assertEqual(misses(fake([(A, A + 32), (B8, B8 + 32)] * 10)), 20)
        self.assertEqual(misses(fake([(A, A + 32), (B4, B4 + 32)] * 10)), 2)
        self.assertEqual(misses(fake([(A, A + 64)] * 5)), 2)  # one run of two lines, then hits

    def test_iix_halves_the_index(self):
        self.assertEqual(misses(fake([(A, A + 32), (B4, B4 + 32)] * 10, ccr=0x105 | cache.IIX)), 20)

    def test_address_array_and_ici_invalidate(self):
        flush = (1, t.ARRAY, 0xF0000008 | (A & 0x1FE0), A & 0x1FFFFC00)  # before the 2nd run
        self.assertEqual(misses(fake([(A, A + 32)] * 3, code_events=[flush])), 2)
        other = (1, t.ARRAY, 0xF0000008 | (A & 0x1FE0), B8 & 0x1FFFFC00)  # tag differs: no effect
        self.assertEqual(misses(fake([(A, A + 32)] * 3, code_events=[other])), 1)
        ici = (2, t.CCR, 0x105 | cache.ICI, 0)
        self.assertEqual(misses(fake([(A, A + 32)] * 3, code_events=[ici])), 2)

    def test_disabled_cache_counts_no_misses(self):
        result = cache.simulate_code(fake([(A, A + 32)] * 3), BASE, ccr=0x005)
        self.assertEqual((result["misses"], result["disabled_lines"]), (0, 3))


class OperandCacheTests(unittest.TestCase):
    def test_copy_back_conflicts_write_back_dirty_lines(self):
        r = oc(fake(data=[(0, STORE | FIRST, A, 0), (0, LOAD, B16, 0), (0, LOAD, A, 0)]))
        self.assertEqual((r["misses"], r["write_misses"], r["read_misses"], r["writebacks"]), (3, 1, 2, 1))
        r = oc(fake(data=[(0, LOAD, A, 0), (0, LOAD, B8, 0), (0, LOAD, A, 0)]))
        self.assertEqual(r["misses"], 2)  # 8 KiB apart: different slots in a 16 KiB cache

    def test_write_through_store_misses_do_not_allocate(self):
        wt = 0x105 | cache.WT  # P0/P3 write-through
        r = oc(fake(data=[(0, STORE | FIRST, A, 1), (0, LOAD, A, 1)], ccr=wt))
        self.assertEqual((r["wt_store_misses"], r["misses"], r["writebacks"]), (1, 1, 0))
        r = oc(fake(data=[(0, STORE | FIRST, A, 0), (0, LOAD, A, 0)], ccr=wt))  # P1 stays copy-back
        self.assertEqual((r["wt_store_misses"], r["misses"]), (0, 1))
        r = oc(fake(data=[(0, STORE | FIRST, A, 0), (0, LOAD, B16, 0)], ccr=0x101))  # CB off: P1 write-through
        self.assertEqual((r["wt_store_misses"], r["writebacks"]), (1, 0))

    def test_cache_instructions(self):
        r = oc(fake(data=[(t.OP_MOVCA, 0, A, 0), (0, LOAD, A, 0), (0, LOAD, B16, 0)]))
        self.assertEqual((r["movca_allocs"], r["misses"], r["writebacks"]), (1, 1, 1))
        r = oc(fake(data=[(0, STORE | FIRST, A, 0), (t.OP_OCBI, 0, A, 0), (0, LOAD, A, 0)]))
        self.assertEqual((r["misses"], r["writebacks"], r["invalidated"]), (2, 0, 1))
        r = oc(fake(data=[(0, STORE | FIRST, A, 0), (t.OP_OCBP, 0, A, 0), (0, LOAD, A, 0)]))
        self.assertEqual((r["misses"], r["writebacks"]), (2, 1))
        r = oc(fake(data=[(0, STORE | FIRST, A, 0), (t.OP_OCBWB, 0, A, 0), (0, LOAD, A, 0), (0, LOAD, B16, 0)]))
        self.assertEqual((r["misses"], r["writebacks"]), (2, 1))
        r = oc(fake(data=[(t.OP_PREF, 0, A, 0), (0, LOAD, A, 0)]))
        self.assertEqual((r["pref_fills"], r["misses"]), (1, 0))
        r = oc(fake(data=[(t.OP_OCBI, 0, B16, 0), (0, LOAD, A, 0)]))  # ocbi of another line: no effect
        self.assertEqual(r["invalidated"], 0)

    def test_address_array_stores(self):
        entry = 0xF4000000 | (A & 0x3FE0)
        purge = (1, t.ARRAY, entry | 8, A & 0x1FFFFC00)  # associative, V=0: write back and invalidate
        r = oc(fake(data=[(0, STORE | FIRST, A, 0), (0, LOAD, A, 0)], data_events=[purge]))
        self.assertEqual((r["misses"], r["writebacks"], r["invalidated"]), (2, 1, 1))
        clear = (1, t.ARRAY, entry, 0)  # non-associative store of 0, as dcache_purge_all() does
        r = oc(fake(data=[(0, STORE | FIRST, A, 0), (0, LOAD, A, 0)], data_events=[clear]))
        self.assertEqual((r["misses"], r["writebacks"]), (2, 1))
        oci = (1, t.CCR, 0x105 | cache.OCI, 0)  # OCI drops dirty data without writing it back
        r = oc(fake(data=[(0, STORE | FIRST, A, 0), (0, LOAD, A, 0)], data_events=[oci]))
        self.assertEqual((r["misses"], r["writebacks"]), (2, 0))

    def test_ocram_mode_index(self):
        ora = 0x105 | cache.ORA
        r = oc(fake(data=[(0, LOAD, A, 0), (0, LOAD, B4, 0)] * 4, ccr=ora))
        self.assertEqual(r["misses"], 8)  # A12 is not part of the index with ORA
        r = oc(fake(data=[(0, LOAD, A, 0), (0, LOAD, B8, 0)] * 4, ccr=ora))
        self.assertEqual(r["misses"], 2)  # A13 is
        self.assertEqual(cache.oc_entry_slot(0x80, ora), None)  # entries 128-255 are the RAM
        self.assertEqual(cache.oc_entry_slot(0x100, ora), 128)


def synthetic_model():
    def unit(name, address, size, region, **extra):
        return dict(dict(id=name, section=name, address=address, size=size, align=4, region=region, output=extra.pop(
            "output", ".text"), kind="code", movable=True, selector=f"*({name})", reason="", symbols=[], nobits=False),
            **extra)
    units = [unit(".text.start", 0x8C010000, 0x10, ".text", prefix=True, movable=False, selector="*start.o(.text)"),
             unit(".text.a", 0x8C010010, 0x30, ".text"), unit(".text.b", 0x8C010040, 0x40, ".text"),
             unit(".text.c", 0x8C010080, 0x20, ".text", movable=False, selector=None, reason="pinned"),
             unit(".gnu.warning", 0x8C0100A0, 0x10, None),
             unit(".bss.x", 0x8C0100C0, 0x40, ".bss", output=".bss", kind="data", nobits=True)]
    outputs = {".text": dict(name=".text", address=0x8C010000, size=0xB0, align=4, kind="code", nobits=False),
               ".bss": dict(name=".bss", address=0x8C0100C0, size=0x40, align=32, kind="data", nobits=True)}
    regions = {".text": dict(name="text", output=".text", text="*(.text .stub .text.* .gnu.linkonce.t.*)",
                             kind="code", start=0x8C010000, end=0x8C0100A0),
               ".bss": dict(name="bss", output=".bss", text="*(.bss .bss.*)", kind="data", start=0x8C0100C0,
                            end=0x8C010100)}
    return dict(units=units, outputs=outputs, regions=regions, data_end=0x8C010100, warnings=[])


SCRIPT = """SECTIONS
{
  . = 0x8c010000;
  .text           :
  {
    *(.text .stub .text.* .gnu.linkonce.t.*)
    /* .gnu.warning sections are handled specially by elf32.em.  */
    *(.gnu.warning)
  } =0x0009
  .bss : { *(.bss .bss.*) *(COMMON) }
}
"""


class LayoutTests(unittest.TestCase):
    def test_positions_reorder_pad_and_keep_the_rest_in_place(self):
        model = synthetic_model()
        same = positions(model, {".text": [".text.b", ".text.a"]})
        self.assertEqual([same[k] for k in (".text.start", ".text.b", ".text.a", ".text.c", ".gnu.warning")],
                         [0x8C010000, 0x8C010010, 0x8C010050, 0x8C010080, 0x8C0100A0])
        self.assertEqual((same[".bss.x"], same["_data_end"]), (0x8C0100C0, 0x8C010100))
        padded = positions(model, {".text": [".text.b", ".text.a"]}, {".text.a": 32})
        self.assertEqual((padded[".text.a"], padded[".text.c"], padded[".gnu.warning"]),
                         (0x8C010070, 0x8C0100A0, 0x8C0100C0))
        self.assertEqual((padded[".bss.x"], padded["_data_end"]), (0x8C0100E0, 0x8C010120))
        aligned = positions(model, {".text": [".text.a", ".text.b"]}, aligned=[".text.b"])
        self.assertEqual(aligned[".text.b"], 0x8C010040)
        aligned = positions(model, {".text": [".text.b", ".text.a"]}, aligned=[".text.b"])
        self.assertEqual(aligned[".text.b"], 0x8C010020)

    def test_positions_of_merged_away_sections(self):
        # ld places a merged-away string section, which takes no space, at the
        # location counter without aligning it; nothing after it moves
        model = synthetic_model()
        units = model["units"]
        units[2]["size"] = 0x3E  # .text.b now ends at ...7e
        units[3:3] = [dict(units[2], id=".text.s.str1.4", section=".text.s.str1.4", address=0x8C01007E,
                           size=0, align=4, movable=False, selector=None, reason="mergeable")]
        same = positions(model)
        self.assertEqual(same[".text.s.str1.4"], 0x8C01007E)
        self.assertEqual([same[k] for k in (".text.b", ".text.c", ".bss.x")], [0x8C010040, 0x8C010080, 0x8C0100C0])

    def test_script_variant_lists_sections_before_the_wildcard(self):
        model = synthetic_model()
        out = script_variant(SCRIPT, model, dict(orders={".text": [".text.b", ".text.a"]},
                                                 padding={".text.a": 32}))
        body = out[out.index(".text           :"):out.index("} =0x0009")]
        lines = [line.strip() for line in body.splitlines()]
        start = lines.index("*start.o(.text)")
        self.assertEqual(lines[start:start + 6], [
            "*start.o(.text)", "*(.text.b)", ". = . + 32;  /* Sh4Fit: cache slot offset */", "*(.text.a)",
            "*(.text .stub .text.* .gnu.linkonce.t.*)",
            ". = MAX(., 0xa0);  /* Sh4Fit: keeps what follows this region in place */"])
        self.assertIn("*(.gnu.warning)", lines)
        self.assertEqual(script_variant(SCRIPT, model, dict(baseline=True)), SCRIPT)
        with self.assertRaisesRegex(ValueError, "cannot be moved"):
            script_variant(SCRIPT, model, dict(orders={".text": [".text.c"]}))
        with self.assertRaisesRegex(ValueError, "statement"):
            script_variant(SCRIPT.replace(" .stub", ""), model, dict(orders={".text": [".text.a"]}))
        # a one-line output section, as the .bss here
        out = script_variant(SCRIPT, model, dict(orders={".bss": [".bss.x"]}, aligned=[".bss.x"]))
        self.assertIn("*(.bss.x)", out)
        self.assertIn(". = ALIGN(32);", out)

    def test_selectors_follow_ld_matching(self):
        inv = Inventory()

        class Obj:
            def __init__(self, *names):
                self.names = names

            def allocated(self):
                return [dict(name=n, size=4, align=4, flags=2) for n in self.names]
        inv.add("main.o", "", Obj(".text.main", ".text"))
        inv.add("game/ai.o", "", Obj(".text.think", ".text"))
        inv.add("/sdk/lib/libgcc.a", "_div_table.o", Obj(".text"))
        inv.add("/sdk/lib/libc.a", "lib_a-memcpy.o", Obj(".text"))
        inv.add("/sdk/lib/libc.a", "main.o", Obj(".text"))  # same member name as a standalone object
        self.assertEqual(selector_for(inv, "main.o", "", ".text.main"), "*(.text.main)")
        self.assertEqual(selector_for(inv, "game/ai.o", "", ".text"), "*ai.o(.text)")
        self.assertEqual(selector_for(inv, "/sdk/lib/libgcc.a", "_div_table.o", ".text"),
                         "*libgcc.a:_div_table.o(.text)")
        # 'main.o' alone would also match libc.a's member main.o; ':' restricts it to plain files
        self.assertEqual(selector_for(inv, "main.o", "", ".text"), ":*main.o(.text)")
        self.assertEqual(selector_for(inv, "/sdk/lib/libc.a", "main.o", ".text"), "*libc.a:main.o(.text)")
        self.assertIsNone(selector_for(inv, "main.o", "", "COMMON"))
        self.assertEqual(len(inv.matches("*main.o", ".text")), 2)

    def test_statement_patterns(self):
        self.assertEqual(statement_patterns("*(.text .stub .text.* .gnu.linkonce.t.*)"),
                         [".text", ".stub", ".text.*", ".gnu.linkonce.t.*"])
        self.assertEqual(statement_patterns("KEEP (*(SORT_NONE(.init)))"), [".init"])

    def test_map_parsing(self):
        text = """Archive member included to satisfy reference by file (symbol)

/sdk/libgcc.a(_div_table.o)
                              ai.o (__sdivsi3_i4i)

Discarded input sections

 .text.unused   0x00000000       0x10 ai.o

Linker script and memory map

LOAD start.o
LOAD ai.o
LOAD /sdk/libgcc.a

.text           0x8c010000      0x450
 *(.text .stub .text.* .gnu.linkonce.t.*)
 .text          0x8c010000       0x10 start.o
                0x8c010000                start
 .text.a_rather_long_function_name
                0x8c010010       0x20 ai.o
 *fill*         0x8c010030        0x4
 .text          0x8c010034      0x41c /sdk/libgcc.a(_div_table.o)
 *(.gnu.warning)

.bss            0x8c010450       0x20
 *(.bss .bss.*)
 .bss.state     0x8c010450       0x10 ai.o
 *(COMMON)
 COMMON         0x8c010460       0x10 ai.o
"""
        parsed = parse_map(text)
        rows = [(r["section"], r["address"], r["size"], r["owner"], parsed["statements"][r["statement"]]["text"])
                for r in parsed["rows"]]
        self.assertEqual(rows, [
            (".text", 0x8C010000, 0x10, "start.o", "*(.text .stub .text.* .gnu.linkonce.t.*)"),
            (".text.a_rather_long_function_name", 0x8C010010, 0x20, "ai.o", "*(.text .stub .text.* .gnu.linkonce.t.*)"),
            (".text", 0x8C010034, 0x41C, "/sdk/libgcc.a(_div_table.o)", "*(.text .stub .text.* .gnu.linkonce.t.*)"),
            (".bss.state", 0x8C010450, 0x10, "ai.o", "*(.bss .bss.*)"),
            ("COMMON", 0x8C010460, 0x10, "ai.o", "*(COMMON)")])
        self.assertEqual(parsed["outputs"][".text"]["size"], 0x450)
        self.assertIn("/sdk/libgcc.a(_div_table.o)", parsed["owners"])

    def test_merged_sections_and_common_symbols(self):
        # As ld 2.4x prints an LTO link: merged string sections keep their own
        # sizes but share an address, and one of them (here libm's, the first
        # loaded) holds all the merged strings.
        text = """Allocating common symbols
Common symbol       size              file

__fpscr_values      0x8               /sdk/libgcc.a(_set_fpscr.o)

Discarded input sections

Linker script and memory map

.rodata         0x8c020000      0x160
 *(.rodata .rodata.* .gnu.linkonce.r.*)
 .rodata.A.str1.4
                0x8c020000       0x12 out.elf.ltrans0.ltrans.o
 .rodata.B.str1.4
                0x8c020000       0x37 out.elf.ltrans0.ltrans.o
 .rodata.table  0x8c020000       0x20 out.elf.ltrans0.ltrans.o
 .rodata.C.str1.4
                0x8c020020        0x9 out.elf.ltrans1.ltrans.o
 *fill*         0x8c020020        0x4
 .rodata.log.str1.4
                0x8c020024      0x100 /sdk/libm.a(w_log.o)
 .rodata.last.str1.4
                0x8c020124       0x40 /sdk/libm.a(w_log.o)
                0x8c020124        0x4 LONG 0x1 ALIGNOF (.tdata)
                0x8c020128                        . = ALIGN (0x4)
 .rodata.tail   0x8c020128       0x38 /sdk/libm.a(w_log.o)
"""
        parsed = parse_map(text)
        extents = {r["section"]: (r["address"], r["size"], r["extent"]) for r in parsed["rows"]}
        self.assertEqual(extents[".rodata.A.str1.4"], (0x8C020000, 0x12, 0))
        self.assertEqual(extents[".rodata.B.str1.4"], (0x8C020000, 0x37, 0))
        self.assertEqual(extents[".rodata.table"], (0x8C020000, 0x20, 0x20))
        self.assertEqual(extents[".rodata.C.str1.4"][2], 0)       # followed by fill
        self.assertEqual(extents[".rodata.log.str1.4"][2], 0x100)  # the merged strings
        self.assertEqual(extents[".rodata.last.str1.4"][2], 0)     # followed by a data statement
        self.assertEqual(extents[".rodata.tail"][2], 0x38)         # last: up to the output's end
        self.assertIn("/sdk/libgcc.a(_set_fpscr.o)", parsed["owners"])
        self.assertFalse(any("0x8" in owner for owner in parsed["owners"]))

    def test_alignment_of_unverified_sections(self):
        # .eh_frame inputs that ld rewrote: no more than the output section's 4,
        # however aligned their address happens to be
        self.assertEqual(_known_alignment(0x8C082DE0, 4), 4)
        self.assertEqual(_known_alignment(0x8C082DE2, 4), 2)
        self.assertEqual(_known_alignment(0x8C082DE0, 64), 32)

    def test_lto_partition_selectors(self):
        inv = Inventory()

        class Obj:
            def allocated(self):
                return [dict(name=".text.null_write", size=4, align=4, flags=6)]
        inv.add("build/game.elf.ltrans0.ltrans.o", "", Obj())
        inv.add("build/game.elf.ltrans3.ltrans.o", "", Obj())
        # GCC names partitions after the output (or a temporary file); the number stays
        self.assertEqual(selector_for(inv, "build/game.elf.ltrans3.ltrans.o", "", ".text.null_write"),
                         "*.ltrans3.ltrans.o(.text.null_write)")


def demo_trace(path, elf, game_frames=40, per_vblank=4):
    """A synthetic capture of the demo's frame loop: the hot functions in turn,
    and their arrays' lines read and written alternately."""
    sym = {s["name"]: s for s in elf.symbols if s["type"] in (1, 2)}
    # an LTO build inlines some of these into main
    hot = [n for n in ("_physics_step", "_ai_update", "_render_build", "_audio_mix", "_main") if n in sym]
    fetches, accesses = [], []
    for name in hot:
        address = sym[name]["address"]
        fetches.append(record(t.CODE, address, elf.halfword(address)))
    for frame in range(game_frames):
        for name in hot:
            s = sym[name]
            fetches.append(record(t.RANGE, s["address"], s["address"] + (s["size"] & ~1), 4))
        for i in range(0, 1024, 32):
            for array_name, flags in (("_pos_x", LOAD | STORE), ("_vel_x", LOAD), ("_pos_y", LOAD | STORE),
                                      ("_vel_y", LOAD)):
                accesses.append(record(t.DATA, sym[array_name]["address"] + i, sym["_physics_step"]["address"],
                                       t.OP_ACCESS << 24 | flags << 20 | 2))
        if frame % per_vblank == per_vblank - 1:
            fetches.append(record(t.FRAME, frame // per_vblank, 3_000_000))
            accesses.append(record(t.FRAME, frame // per_vblank, 3_000_000))
    return write_trace(path, fetches, accesses)


@unittest.skipUnless(shutil.which(PREFIX + "gcc"), "set SH_TOOL_PREFIX to build the demo program")
class EndToEndTests(unittest.TestCase):
    def test_analyze_relink_verify(self):
        with tempfile.TemporaryDirectory(prefix="sh4fit-e2e-") as directory:
            work = Path(directory) / "demo"
            shutil.copytree(ROOT / "examples" / "demo", work, ignore=shutil.ignore_patterns("*.o", "*.elf", "*.map"))
            subprocess.run(["make", "-s", f"PREFIX={PREFIX}"], cwd=work, check=True, capture_output=True)
            elf = Elf.read(work / "demo.elf")
            trace = demo_trace(work / "demo.sh4trace", elf)
            out = work / "out"
            run = lambda *args: subprocess.run([sys.executable, "-m", "sh4fit", *map(str, args)], cwd=ROOT,
                                               capture_output=True, text=True)
            result = run("analyze", work / "demo.elf", "--map", work / "demo.map", "--trace", trace,
                         "--linker-script", work / "demo.ld", "--out", out, "--search-seconds", "2", "--no-source",
                         "--quiet")
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            candidates = json.loads((out / "candidates.json").read_text())
            best, base = candidates[0], next(c for c in candidates if c["baseline"])
            self.assertFalse(best["baseline"])
            self.assertLess(best["cost"]["oc_per_kinstr"], base["cost"]["oc_per_kinstr"] / 10)
            self.assertLess(best["cost"]["ic_per_kinstr"], base["cost"]["ic_per_kinstr"])
            self.assertTrue((out / "report.html").is_file())
            subprocess.run(["make", "-s", f"PREFIX={PREFIX}", f"LAYOUT={out / (best['id'] + '.ld')}",
                            "ELF=relinked.elf"], cwd=work, check=True, capture_output=True)
            result = run("simulate", out, "--elf", work / "relinked.elf", "--map", work / "relinked.map")
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn(f"every section is where {best['id']} predicted", result.stdout)
            relinked = Elf.read(work / "relinked.elf")
            self.assertEqual(relinked.entry, elf.entry)
            # a trace from the original build is refused for the relinked ELF
            result = run("trace-info", trace, "--elf", work / "relinked.elf")
            self.assertNotEqual(result.returncode, 0)

    def test_lto_build(self):
        """With -flto the map names GCC's partitions (kept by -save-temps), and
        merged strings share one address; a relink re-runs LTO."""
        with tempfile.TemporaryDirectory(prefix="sh4fit-lto-") as directory:
            work = Path(directory) / "demo"
            shutil.copytree(ROOT / "examples" / "demo", work, ignore=shutil.ignore_patterns("*.o", "*.elf", "*.map"))
            subprocess.run(["make", "-s", f"PREFIX={PREFIX}", "LTO=1"], cwd=work, check=True, capture_output=True)
            self.assertIn(".ltrans0.ltrans.o", (work / "demo.map").read_text())
            elf = Elf.read(work / "demo.elf")
            trace = demo_trace(work / "demo.sh4trace", elf)
            out = work / "out"
            run = lambda *args: subprocess.run([sys.executable, "-m", "sh4fit", *map(str, args)], cwd=ROOT,
                                               capture_output=True, text=True)
            result = run("analyze", work / "demo.elf", "--map", work / "demo.map", "--trace", trace,
                         "--linker-script", work / "demo.ld", "--out", out, "--search-seconds", "2", "--no-source",
                         "--quiet")
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            model = json.loads((out / "model.json").read_text())
            movable = [u for u in model["units"] if u["movable"]]
            self.assertTrue(movable)
            # the fat objects' own sections are never placed, so names alone are unique
            self.assertTrue(all(u["selector"] == f"*({u['section']})" for u in movable),
                            [u["selector"] for u in movable if u["selector"] != f"*({u['section']})"])
            candidate = next(c for c in json.loads((out / "candidates.json").read_text()) if not c["baseline"])
            subprocess.run(["make", "-s", f"PREFIX={PREFIX}", "LTO=1", f"LAYOUT={out / (candidate['id'] + '.ld')}",
                            "ELF=relinked.elf"], cwd=work, check=True, capture_output=True)
            result = run("simulate", out, "--elf", work / "relinked.elf", "--map", work / "relinked.map")
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn(f"every section is where {candidate['id']} predicted", result.stdout)


if __name__ == "__main__":
    unittest.main()
