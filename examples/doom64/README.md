# Doom 64 example

Patches for [Doom 64 for Dreamcast](https://github.com/jnmartin84/doom64-dc)
that build it for Sh4Fit and measure a relinked build against the original on
hardware, plus the layout from that run. Tested on doom64-dc `b1ed4db`, built
with KallistiOS 2.2.2's sample `environ.sh` (`-Os -flto=auto`).

| File | What it does |
|---|---|
| `sh4fit-build.patch` | Makefile: writes `build/doom64.map`, keeps the LTO partitions (`-save-temps`) and links with `SH4FIT_LAYOUT` in place of `shlelf.xc` when it is set. Any Sh4Fit run needs this. |
| `sh4fit-measure.patch` | Makefile: turns on `OSDSHOWFPS` and `SH4FIT_PERF`. `src/d_main.c`: a hook in `MiniLoop` that prints CPU time per frame and the SH-4 performance counters. Needs `kos/sh4fit_perf.h` copied into `src/`. |
| `layout-01.ld` | The layout Sh4Fit generated for `b1ed4db` with both patches, from the title map and DEMO1. It fits only that exact build. |

```sh
cd doom64-dc
git apply path/to/sh4-fit/examples/doom64/sh4fit-build.patch \
          path/to/sh4-fit/examples/doom64/sh4fit-measure.patch
cp path/to/sh4-fit/kos/sh4fit_perf.h src/
make
```

## What the hook prints

At the start of each `MiniLoop` (title map, demo, level or menu screen) it
prints a start line. The DEMO1 capture below uses that line as its start
marker:

```text
sh4fit pass 0 session 3 map 3 demo start
```

Then, every 300 game tics (10 s) and when the loop ends, it prints one line to
the dcload console or serial port:

```text
sh4fit pass 0 session 3 map 3 demo tics 300-600 cpu … us/frame (ticker … drawer …): … frames, … instructions, … IC misses = … per 1k instructions
```

- **`cpu … us/frame`** is the time spent in `ticker()` and `drawer()` per drawn
  frame, measured with the TMU timer. It leaves out `pvr_scene_begin`,
  `pvr_list_finish` and `pvr_scene_finish`. It is the number to compare between
  two builds, and it still works when demos are locked to 30 Hz.
- **The counter** changes on each attract-mode pass, that is each time
  `D_TitleMap` starts. Pass 0 counts instruction-cache misses, pass 1
  operand-cache misses and pass 2 the cycles the pipeline froze on each kind of
  miss. Dividing the stall cycles by the miss counts gives the real cost of a
  miss, for `--ic-miss-cycles` and `--oc-miss-cycles`.
- **Demos are deterministic**, so the same pass, session and tic window shows
  the same scene in both builds. Let each build loop three times and compare
  window by window.
- **The FPS overlay** replaces the ammo counter. `P_Drawer` skips `ST_Drawer` in
  demo playback, so it only shows when you play.

Side effects, the same in both builds:

- While the counters run, KallistiOS's `perf_cntr_timer_ns()`, which
  `MiniLoop` uses for frame pacing, falls back to the 80 ns TMU timer.
- Printing over dcload every 10 s can cause a one-frame hitch.

devcast doesn't emulate the performance counters, which read 0 there. It
doesn't model cache timing either, so the CPU times are identical for both
layouts and the difference only shows on hardware. The counter readings
haven't been checked on hardware yet.

## Making the A/B pair

Sh4Fit needs to be installed (`python3 -m pip install -e path/to/sh4-fit`),
devcast built with the patches in `devcast/`, and `doom64.cdi` made by
doom64-dc's `make cdi`. The captures boot the ELF and read the game's data
from the disc.

```sh
SH4FIT=path/to/sh4-fit
make                                     # build/doom64.elf, original link order
DEVCAST_TRACE_FRAMES=300 \
DEVCAST_TRACE_START_PC=0x$(sh-elf-nm build/doom64.elf | awk '$3 == "_P_Drawer" {print $1}') \
  $SH4FIT/devcast/sh4trace-capture.sh --config config:Debug.SerialConsoleEnabled=1 \
  --disc doom64.cdi path/to/reicast build/doom64.elf title.sh4trace
DEVCAST_TRACE_FRAMES=600 DEVCAST_TRACE_START_MARKER="map 3 demo start" \
  $SH4FIT/devcast/sh4trace-capture.sh --timeout 3600 --config config:Debug.SerialConsoleEnabled=1 \
  --disc doom64.cdi path/to/reicast build/doom64.elf demo1.sh4trace
sh4fit analyze build/doom64.elf --map build/doom64.map --build-dir . \
  --trace title.sh4trace=1 --trace demo1.sh4trace=2 \
  --linker-script $KOS_BASE/utils/ldscripts/shlelf.xc --search-seconds 240 --out sh4fit-out
make BUILD_DIR=build-opt SH4FIT_LAYOUT=$PWD/sh4fit-out/layout-01.ld
sh4fit simulate sh4fit-out --elf build-opt/doom64.elf --map build-opt/doom64.map
```

`build/doom64.elf` and `build-opt/doom64.elf` are the pair. The two links
produce byte-identical LTO partitions, so the code is the same and only its
addresses differ. On `b1ed4db`, built with KallistiOS 2.2.2 and GCC 14.3.0,
relinking with the `layout-01.ld` here skips the captures and the analysis and
reproduces the run below exactly.

## The run

The title map is 300 vblanks from the first `P_Drawer` call, 135 million
instructions. DEMO1 (MAP03) is 600 vblanks from the start of its loop, 271
million instructions, with DEMO1 weighted 2. Both played at the default ultra
quality, with dynamic lights and bump mapping. Analysis took 10 minutes and
2 GB. All 2,929 sections landed where `simulate` predicted.

| Trace | Layout | IC misses /1k | OC misses /1k | Stall cycles /1k instructions |
|---|---|---:|---:|---:|
| Title map | original order | 12.50 | 16.63 | 646 |
| Title map | `layout-01` | 8.03 | 15.10 | 523 |
| DEMO1 | original order | 13.60 | 7.50 | 460 |
| DEMO1 | `layout-01` | 2.95 | 5.85 | 202 |

Stall cycles use the default estimates of 20 cycles per miss and 10 per
writeback. The refined data placement scored worse than the original data
order on this run: operand-cache misses rose from 8.9 to 14.9 per 1k
instructions with the same code order. `layout-01` therefore keeps static data
in link order. Demos run at a fixed 30 Hz without interpolation, and they
don't draw the status bar, so that code was placed without trace data.
