# Sh4Fit

Sh4Fit is a cache-layout optimizer for Dreamcast homebrew. It reorders
independently linkable code and data sections so they collide less in the
SH-4's caches:

- the 8 KiB direct-mapped **instruction cache** (256 lines of 32 bytes), and
- the 16 KiB direct-mapped **operand cache** (512 lines; 8 KiB with OCRAM).

It is the SH-4 counterpart of [MipsFit](MipsFit/README.md), the N64 tool by
Kevin R., and follows its method: execution traces, Gloy & Smith temporal
relationship graphs, call-chain clustering, slot-aware placement and
late-acceptance hill climbing, ranked by replaying the traces through a cache
model. Sh4Fit adds the operand cache: it replays every data access, including
`pref`, `movca.l`, `ocbi`/`ocbp`/`ocbwb`, address-array stores and copy-back
writebacks, and places `.rodata`/`.data`/`.bss` objects as well as functions.

Traces come from devcast, skmp's Reicast fork, with the patches in
[`devcast/`](devcast/README.md). Sh4Fit never changes your ELF, objects or
linker script. It writes candidate linker scripts and a report into an output
directory.

```text
build with a map ─> capture in devcast ─> sh4fit analyze ─> relink with layout-01.ld
                                                        └─> sh4fit simulate --elf (verify)
                                                        └─> kos/sh4fit_perf.h (measure on hardware)
```

## Requirements

- Python 3.10 or newer, with no other dependencies.
- The SH binutils (`sh-elf-`); only `addr2line` is used, for source lines, and
  `--no-source` skips it.
- devcast built with `devcast/sh4trace.patch`, `devcast/kos-fixes.patch` (which
  KallistiOS 2.2 games need to get past startup) and, on macOS,
  `devcast/macos-background.patch`; see [`devcast/README.md`](devcast/README.md).

Run it from a checkout with `python3 -m sh4fit`, or install it with
`python3 -m pip install -e .` to get an `sh4fit` command.

## 1. Build with a map

Sections can only move if each function and object has its own input
section. KallistiOS already compiles with `-ffunction-sections
-fdata-sections` and links with `--gc-sections`. Add a map to the link:

```make
LDFLAGS += -Wl,-Map=game.map
```

With link-time optimization (`-flto`, which KallistiOS's sample `environ.sh`
turns on), the code that is placed comes from GCC's LTO partitions, which
it normally deletes after the link. Add `-save-temps` to the link so they stay
next to the ELF (`game.elf.ltrans0.ltrans.o` and so on). Sh4Fit names their
sections by name, or by partition number where a name repeats, so a relink
with a different output name still matches. The partitions are generated again
by every link, and come out the same when the inputs are the same:

```make
LDFLAGS += -Wl,-Map=game.map -save-temps
```

## 2. Capture

```sh
DEVCAST_TRACE_FRAMES=600 DEVCAST_TRACE_START_MARKER="entering gameplay" \
  devcast/sh4trace-capture.sh path/to/devcast/build/reicast game.elf gameplay.sh4trace
python3 -m sh4fit trace-info gameplay.sh4trace --elf game.elf
```

Capture the part of the game you want to be fast. A start marker printed by
the game (`printf` reaches devcast's serial console) or `DEVCAST_TRACE_START_PC`
skips loading screens. Several captures of different scenes can be combined
with weights. Analysis time and memory grow linearly with the capture: on the
demo, 300 vblanks (138 million instructions, 30 million data access runs)
took 96 seconds and 460 MB.

## 3. Analyze

```sh
python3 -m sh4fit analyze game.elf --map game.map \
    --trace gameplay.sh4trace --trace menus.sh4trace=0.25 \
    --linker-script $KOS_BASE/utils/ldscripts/shlelf.xc \
    --out sh4fit-out
```

The output directory holds `report.html`, `baseline.ld` (your script,
unchanged), `layout-01.ld` through `layout-03.ld`, and the JSON and imported
trace data that `simulate` uses.

| Option | Default | Purpose |
|---|---|---|
| `--map FILE` | required | The link's GNU ld map |
| `--trace FILE[=W]` | required | devcast capture; repeat for several scenes, with optional weights |
| `--linker-script FILE` | none | The script the ELF was linked with. Without it, no scripts are written |
| `--build-dir DIR` | map's directory | Where the linker ran, for relative paths in the map |
| `--out DIR` | required | Output directory |
| `--candidates N` | 3 | Alternatives to keep beside the baseline |
| `--search-seconds S` | 60 | Hill-climbing time, three quarters for code and a quarter for data |
| `--padding-budget B` | 0 | Bytes of explicit padding a layout may insert |
| `--no-data` | off | Leave data sections alone |
| `--sim-segments N` | 0 (all) | Rank candidates on sampled vblank windows covering about N records |
| `--graph-segments N` | 4,000,000 | Records used to build the relationship graphs |
| `--ic-miss-cycles N` | 20 | Stall cycles per instruction-cache miss, for ranking |
| `--oc-miss-cycles N` | 20 | Stall cycles per operand-cache miss |
| `--writeback-cycles N` | 10 | Cycles per dirty-line writeback |
| `--seed N` | 0 | Random seed for the hill climbing |
| `--tool-prefix P` | `sh-elf-` | Where `addr2line` is |

Candidates are ranked by estimated stall cycles per 1,000 instructions,
combining both caches with the three costs above. The default costs are rough
figures for a 200 MHz SH-4 on the Dreamcast's 100 MHz bus. To measure them on
your console, see step 5.

## 4. Relink with a candidate

KallistiOS passes `-T $KOS_BASE/utils/ldscripts/shlelf.xc` in `KOS_LDFLAGS`,
which `kos-cc` adds to every link (`environ_base.sh` puts it there). For one
link, swap in the generated script there. A Makefile can do it like this:

```make
ifdef SH4FIT_LAYOUT
export KOS_LDFLAGS := $(subst $(KOS_BASE)/utils/ldscripts/shlelf.xc,$(SH4FIT_LAYOUT),$(KOS_LDFLAGS))
game.elf: $(SH4FIT_LAYOUT)
endif
```

```sh
rm game.elf && make SH4FIT_LAYOUT=$PWD/sh4fit-out/layout-01.ld
```

The generated script is your script with two changes in each region it
reorders. It lists the region's sections ahead of the region's wildcard, and it
adds `. = MAX(., old end)` after the wildcard. Everything else is kept: other
output sections, `KEEP`s, constructors, linker symbols and garbage
collection. The padding keeps what follows each region, and so the heap
start at `end`, where it was whenever the new order is no larger.

A script is only valid for the inputs it was generated from. `simulate`
checks the input files' hashes, so reanalyze after changing code.

## 5. Verify

```sh
python3 -m sh4fit simulate sh4fit-out --elf game.elf --map game.map
```

This checks that every section landed where the candidate predicted, and that
the entry point didn't move. It then replays the analysis traces at the new
addresses. It exits with 2 if the placement matches no candidate, which
usually means the link didn't use the script. Without `--elf`, it replays every
saved candidate.

For an independent check, capture the relinked ELF again and compare
`analyze` or `simulate` figures. On the demo, the re-capture's replay matched
the prediction to within one miss (below).

On hardware, `kos/sh4fit_perf.h` counts instruction- or operand-cache misses
per 1,000 issued instructions with the SH-4 performance counters, in the
same units as the report. It prints through `printf` (to dcload or serial).
Its stall mode reports the cycles the pipeline froze on misses. Divide those by
the miss counts to get your console's `--ic-miss-cycles` and
`--oc-miss-cycles`. It borrows PRFC0 from KallistiOS's nanosecond timer while
it measures.

## What can move

A *region* is the set of input sections one wildcard statement of the
linker script places. In KallistiOS's script, that is
`*(.text .stub .text.* .gnu.linkonce.t.*)` in `.text`, and the corresponding
`.rodata.*`, `.data.*` and `.bss.*` statements. A section in a region moves if
Sh4Fit can name it with a selector that matches only it:

- `*(.text.name)` when the section name is unique in the link;
- otherwise one qualified by file, such as `*libgcc.a:_div_table.o(.text)`
  or `:*main.o(.text)`. This also makes plain `.text` sections of assembly
  and library members movable, e.g. libgcc's division routines and newlib's
  `memcpy`.

Selectors are checked against every allocated input section the link loaded,
using ld's matching rules. A section stays where it is when:

- it holds the entry point or comes before it, which keeps `startup.o` at
  0x8c010000;
- its input object can't be read, or its size differs from the map's;
- it is mergeable (`.rodata.str1.4`, `.rodata.cst*`) or `COMMON`. ld merges
  all strings of one kind into the first such section it loaded (in an LTO
  build often a libc or libm one), and the rest take no space. Sh4Fit reads
  each one's real extent from the map, so the merged strings count as one
  section where they really are;
- the trace shows execution falling through from it into the next section.

Hot data objects of 32 bytes or more are placed on cache-line boundaries
(`. = ALIGN(32)`).

## How the replay works

`cache.py` models both caches with physical tags, so P0, P1 and P3 aliases
share lines. It follows the trace's CCR writes (enable bits, ICI, OCI, ORA,
OIX, IIX, WT, CB), copy-back write-allocate and write-through no-allocate,
`pref`, `movca.l`, the `ocb*` instructions, and associative and plain stores
to both address arrays, as KallistiOS's `icache_flush_range` and
`dcache_purge_all` issue them.

Data addresses are classified into four kinds:

- inside a section, which moves with it (literal pools and tables in
  `.text` included);
- from the end of the image up to the top 64 KiB of RAM: the heap and
  KallistiOS thread stacks, which move with the image end;
- the main stack in that top 64 KiB, which stays fixed;
- anything else, which stays fixed.

The report compares each layout with a fully associative LRU cache of the same
size, to split misses into first-touch, conflict and capacity misses.

## Demo

`examples/demo` is a bare-metal toy "game frame" with a KallistiOS-shaped
linker script. Cold menu and loader code and a save buffer separate its hot
functions and arrays, so in link order they share cache slots. It also calls
libgcc's division, whose lookup table lives in `.text`. Captured for 60 vblanks
in devcast:

| | IC misses | OC misses | Writebacks | Stall cycles per 1k instructions |
|---|---:|---:|---:|---:|
| original link order | 5,951 | 481,219 | 238,133 | 439.8 |
| `layout-01` (predicted) | 26 | 1,895 | 1,582 | 1.97 |
| `layout-01`, relinked and captured again | 26 | 1,896 | 1,583 | 1.97 |

```sh
make -C examples/demo
DEVCAST_TRACE_FRAMES=60 DEVCAST_TRACE_START_MARKER="SH4FIT-DEMO start" \
  devcast/sh4trace-capture.sh path/to/reicast examples/demo/demo.elf demo.sh4trace
python3 -m sh4fit analyze examples/demo/demo.elf --map examples/demo/demo.map \
  --trace demo.sh4trace --linker-script examples/demo/demo.ld --out demo-out
make -C examples/demo LAYOUT=$PWD/demo-out/layout-01.ld ELF=demo-opt.elf
python3 -m sh4fit simulate demo-out --elf examples/demo/demo-opt.elf --map examples/demo/demo-opt.map
```

## Doom 64

[Doom 64 for Dreamcast](https://github.com/jnmartin84/doom64-dc), built
against KallistiOS 2.2.2 with KOS's sample `environ.sh` (`-Os -flto=auto
-ffat-lto-objects`) and linked with `shlelf.xc`, is the first real game run
through Sh4Fit. The capture is 300 vblanks of the title map (MAP33, a level
rendered in demo playback), from the first call to `P_Drawer`: 135 million
instructions and 43 million data accesses. Of 2,912 input sections, 2,655
can move: 1,546 functions (383 KB) and the static data in `.rodata`, `.data`
and `.bss`. Analysis with `--search-seconds 240` took 6 minutes and 1.1 GB.

| | IC misses | OC misses | Writebacks | Stall cycles per 1k instructions |
|---|---:|---:|---:|---:|
| original link order | 1,505,115 | 2,156,558 | 842,486 | 602.8 |
| `layout-01` (predicted) | 599,403 | 1,969,008 | 792,826 | 437.7 |
| `layout-01`, relinked and captured again | 599,430 | 1,990,651 | 793,560 | 441.0 |

The relinked build placed every section where `simulate` predicted, and its
re-capture executed 281 fewer instructions out of 135 million (one timer
interrupt fewer), which accounts for the 1% difference in operand-cache misses.

Instruction-cache misses fall by 60%, almost all conflict misses (1.18 million
to 0.30 million). The rest is capacity: the busiest vblank runs code from
about 1,370 different lines, more than five times the cache. Operand-cache
misses fall by 9%. The worst static data conflicts mostly go (`pvr_state`
from 234 misses per vblank to 33, `R_SectorLightColor` from 122 to 8), but
half of all operand-cache misses land in Doom's zone heap, which no link
order moves, and 1.24 million of the 1.97 million left are capacity misses,
such as streaming through the 1.5 MB `tr_buf`. The report's findings name the
largest hot functions (`R_RenderPlayerView`, 11 KB, `P_Ticker`, 8 KB) as the
next lever for the instruction cache.

To build it this way, doom64-dc's link line needs `$(LDFLAGS)`, and the
Makefile the snippet from step 4:

```make
$(TARGET): wadtool $(O_FILES) | buildtarget
	kos-cc -o ${BUILD_DIR}/$@ $(O_FILES) array_fast_copy.o $(LDFLAGS)

LDFLAGS += -Wl,-Map=$(BUILD_DIR)/doom64.map -save-temps
ifdef SH4FIT_LAYOUT
export KOS_LDFLAGS := $(subst $(KOS_BASE)/utils/ldscripts/shlelf.xc,$(SH4FIT_LAYOUT),$(KOS_LDFLAGS))
$(TARGET): $(SH4FIT_LAYOUT)
endif
```

```sh
DEVCAST_TRACE_FRAMES=300 \
DEVCAST_TRACE_START_PC=0x$(sh-elf-nm build/doom64.elf | awk '$3 == "_P_Drawer" {print $1}') \
  devcast/sh4trace-capture.sh --disc doom64.cdi path/to/reicast build/doom64.elf title.sh4trace
python3 -m sh4fit analyze build/doom64.elf --map build/doom64.map --build-dir . \
  --trace title.sh4trace --linker-script $KOS_BASE/utils/ldscripts/shlelf.xc \
  --search-seconds 240 --out sh4fit-out
make BUILD_DIR=build-opt SH4FIT_LAYOUT=$PWD/sh4fit-out/layout-01.ld
python3 -m sh4fit simulate sh4fit-out --elf build-opt/doom64.elf --map build-opt/doom64.map
```

`doom64.cdi` is doom64-dc's `make cdi` image; the capture boots the ELF and
reads the game's data from the disc. `--build-dir .` is needed because the
map's paths are relative to where the linker ran, not to `build/`.

## Limitations

- **One KallistiOS game so far.** Sh4Fit has run on Doom 64 (C, LTO,
  `shlelf.xc`, KOS 2.2.2) as well as the demo, but not on a C++ build. The
  script rewriting fails loudly, rather than guessing, when it can't find a
  region's wildcard statement.
- **Not measured on hardware.** All figures are replays of devcast traces
  through Sh4Fit's cache model. `kos/sh4fit_perf.h` is how to confirm them on a
  console, and it hasn't been run on one yet.
- **Timing.** Rates are per 1,000 instructions because the devcast interpreter
  runs about 500,000 instructions per vblank, a fraction of real hardware.
  "Per vblank" figures are per vblank of emulated time.
- **Approximations in the search.** The graphs use 32-byte chunks of each
  section, which straddle two lines when the section isn't line-aligned.
  The data layout is searched against the best code layout only. Final
  rankings come from exact replays, so these errors affect which layouts are
  found, not the figures reported for them.
- **The heap model** assumes allocation is deterministic and that heap
  addresses follow the image end.
- **The MMU must be off.** Trace addresses are virtual.
- **No static mode.** MipsFit can fall back to a static call graph; Sh4Fit
  needs a trace.

## Development

```sh
python3 -m unittest discover -s tests -v
```

The end-to-end test builds the demo with the SH toolchain
(`SH_TOOL_PREFIX`, default `/opt/toolchains/dc/sh-elf/bin/sh-elf-`). It
analyzes a synthetic trace, relinks the demo with the generated script and
checks the placement. It doesn't need devcast.

## Credits

The method and much of the search code follow
[MipsFit](https://github.com/Byterset/MipsFit) by Kevin R. (MIT License, see
`LICENSE-MipsFit`): Gloy & Smith's temporal relationship graphs, Ottoni &
Maher's C3 clustering, slot-aware placement and late-acceptance hill climbing.
The `MipsFit` submodule pins the version this port follows
(`git submodule update --init`). devcast is by skmp and contributors (BSD-3).
