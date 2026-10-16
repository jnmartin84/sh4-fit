# devcast SH4 trace hook

Patches for [devcast](https://gitlab.com/skmp/devcast) (skmp's Reicast fork,
BSD-3) that record SH-4 execution traces for Sh4Fit, the Dreamcast counterpart
of MipsFit. A trace (`SH4XTRC1`) holds every instruction fetch, every cacheable
data access, the cache control operations, CCR writes, exceptions and vblank
marks. devcast doesn't emulate the caches, and it doesn't need to: Sh4Fit
replays the trace through its own IC/OC model, so one capture can score any
code or data layout.

| File | Purpose |
|---|---|
| `sh4trace.patch` | The hook: interpreter fetches, data accesses, `pref`/`movca.l`/`ocb*`, CCR, exceptions, vblank, serial start marker |
| `macos-background.patch` | `DEVCAST_BACKGROUND=1` for the macOS frontend: no window on screen, no Dock icon, never takes focus, no App Nap |
| `kos-fixes.patch` | Emulation fixes that KallistiOS 2.2 games need under reios (below) |
| `sh4trace-capture.sh` | Runs one capture safely (scratch config dir, timeout, cleanup, startup-abort retry) |
| `test/` | Bare-metal test program used to validate the hook |

The patches apply to devcast commit `c6acbc24` (2025-05-09), separately or
together.

## Build

```sh
git clone https://gitlab.com/skmp/devcast.git && cd devcast
git checkout c6acbc247520536a202ed12ba3a0ab52b9400055
git apply /path/to/Sh4Fit/devcast/sh4trace.patch /path/to/Sh4Fit/devcast/macos-background.patch \
          /path/to/Sh4Fit/devcast/kos-fixes.patch
```

`kos-fixes.patch` fixes three things that stop a KallistiOS 2.2 game, such as
Doom 64 for Dreamcast, from getting past startup under stock devcast:

- **DMA.** devcast only ran PVR and TA DMA when DMAOR was exactly `0x8201`.
  KallistiOS sets `0x8001`, which differs only in channel priority, so every
  transfer was dropped and the game waited for it forever. Now only DDT, NMIF,
  AE and DME are checked.
- **BIOS font.** reios's font syscall did nothing, so `syscall_font_lock()`
  returned garbage and `bfont` spun in its lock loop. It now returns the font
  address and succeeds at locking and unlocking. Without a BIOS image the
  glyphs are blank.
- **GD-ROM request IDs.** reios handed out request IDs counting down from
  `0xF0FFFFFF`, which are negative as `int`. KallistiOS 2.2 treats a
  request ID `<= 0` as failure, so `cdrom_reinit()` failed and `/cd` was
  unusable. IDs now count up from 1, as the BIOS's do.

On current macOS, devcast's bundled zlib and libpng don't build against the
SDK (zlib defines `fdopen` as a macro, libpng wants `<fp.h>`). Neither patch
touches this. Work around it from the build directory:

```sh
mkdir -p shim build && printf '#include <math.h>\n' > shim/fp.h && cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS_RELEASE="-O3 -DNDEBUG -Dfdopen=fdopen -I$PWD/../shim" ..
ninja        # produces ./reicast and Reicast.app
```

devcast's config overwrites `CMAKE_C_FLAGS`, which is why the flags go in
`CMAKE_C_FLAGS_RELEASE`.

## Capture

```sh
# 10 seconds of the game loop, starting when main() is entered
DEVCAST_TRACE_FRAMES=600 \
DEVCAST_TRACE_START_PC=0x$(sh-elf-nm game.elf | awk '$3 == "_main" {print $1}') \
  ./sh4trace-capture.sh build/reicast game.elf game.sh4trace

# start when the game prints a line on the serial console; mount its disc
DEVCAST_TRACE_START_MARKER="entering gameplay" \
  ./sh4trace-capture.sh --disc game.cdi build/reicast game.elf game.sh4trace

# Doom 64: 300 vblanks from the first frame drawn in a level (the title map),
# with the game's serial output copied into the log
DEVCAST_TRACE_FRAMES=300 \
DEVCAST_TRACE_START_PC=0x$(sh-elf-nm build/doom64.elf | awk '$3 == "_P_Drawer" {print $1}') \
  ./sh4trace-capture.sh --config config:Debug.SerialConsoleEnabled=1 \
      --disc doom64.cdi build/reicast build/doom64.elf title.sh4trace
```

The script runs devcast in the background: nothing appears on screen, focus
stays where it is, there's no audio and no frame limiter. `--show` runs it
normally. devcast's config, VMU and nvmem files go to a temporary directory,
or to `--workdir DIR`, never to `~/.reicast`. The emulator is always killed
on Ctrl-C or after `--timeout` (600 s by default), so an invisible devcast
can't be left running.

An ELF is booted directly by reios, devcast's HLE BIOS, just as dcload
would. Pass `--disc` (a CDI from `mkdcdisc`, or GDI/CHD) when the program
needs `/cd`. The disc is mounted, but the ELF still boots directly.
`--config SECTION:KEY=VALUE` passes any devcast setting.
`config:Debug.SerialConsoleEnabled=1` copies the game's serial output (KOS
`printf`/`dbgio`) into the log next to the trace, which shows how far a
game got.

Capture settings are environment variables, read by the patched devcast:

| Variable | Meaning |
|---|---|
| `DEVCAST_TRACE=FILE` | Enables a capture (the script sets it) |
| `DEVCAST_TRACE_FRAMES=N` | Vblanks to record (default 600) |
| `DEVCAST_TRACE_START_FRAME=N` | Start after N vblanks |
| `DEVCAST_TRACE_START_PC=ADDR` | Start when execution branches, calls or jumps to ADDR (a function entry works; a mid-run address does not) |
| `DEVCAST_TRACE_START_MARKER=TEXT` | Start once TEXT appears on the serial console (SCIF output, i.e. KOS `printf`) |
| `DEVCAST_TRACE_DATA=0` | Instruction fetches only; much smaller |
| `DEVCAST_TRACE_MAX_MB=N` | Stop at the first vblank after about N MiB (default 4096) |
| `DEVCAST_TRACE_EXIT=1` | Quit devcast once the trace is written (the script sets it) |
| `DEVCAST_BACKGROUND=1` | macOS frontend background mode (the script sets it unless `--show`) |

Recording starts at the first start condition that is met, or at boot when
none is set. It ends after the frame count, at the size limit, or when
emulation stops (pause, menu, quit), whichever comes first. A capture forces
devcast's SH4 interpreter, since the recompiler isn't hooked.

## Check

```sh
python3 -m sh4fit trace-info game.sh4trace --elf game.elf
```

This validates every record and the totals, and summarizes the capture. It
also compares the code the trace actually fetched with the ELF. The hook
stores the instruction word found at the first fetch from each 32-byte line,
so a trace from a different build is caught exactly rather than heuristically.
`sh4fit analyze` does the same check and refuses a trace from another build.
See the [top-level README](../README.md) for the rest of the workflow.

## What a trace contains

A 64-byte header (CCR and MMUCR at the start, the start trigger, vblank and
cycle counters) is followed by blocks of 12-byte records `(a, b, t)`, where
`t >> 28` is the record kind. Each block belongs to one of two streams, and
records within a stream are in execution order. The full layout is in the
comment at the top of `libswirl/hw/sh4/sh4_trace.cpp`; the reader is
`sh4fit/sh4trace.py`.

- **Instruction stream.** A `RANGE` record is a run of sequential fetches
  `[a, b)`, with a repeat count, so a tight loop body is one record. A run ends
  after a taken branch's delay slot or a taken `bt`/`bf`, and `EXCEPT`,
  `FRAME`, `CCR`, `ARRAY` and `RESET` records split the run in progress.
  `ARRAY` records are stores to the instruction-cache address array
  (`0xF0xxxxxx`, e.g. KallistiOS's `icache_flush_range()`), so the
  instruction-cache replay sees flushes exactly where they happened. `CODE`
  records carry the provenance words described under Check.
- **Data stream.** A `DATA` record is a run of consecutive loads/stores to
  one 32-byte line, with its first address, its PC, load/store flags and a
  count. Uncached traffic (P2, store queues, registers) is counted but not
  recorded, and doesn't break a run. `pref`, `movca.l`, `ocbi`, `ocbp` and
  `ocbwb` get their own records, and so do stores to the cache address/data
  arrays (`0xF0/F1/F4/F5xxxxxx`), which KOS's flush/purge routines use. Literal
  pool loads (`mov.l @(disp,PC)`) are data accesses into `.text`, so the
  operand-cache cost of code layout is visible too.

## Known limitations

- **Frames are vblanks of emulated time.** The interpreter retires about
  500,000 SH-4 instructions per vblank (about 6.7 cycles per instruction,
  against about 1–1.5 on hardware). A game frame heavier than that spans
  several vblanks in the capture. The instruction stream is still what the
  game executes; only per-vblank rates are off. Prefer normalizing by
  instructions or by a game-side marker.
- **Apple Silicon:** stock devcast's ARM7 recompiler segfaults as soon as
  emulation starts. It crashes right after mapping its `MAP_JIT` code buffer,
  probably on the first write, which Apple Silicon only allows after
  `pthread_jit_write_protect_np(0)`. The script passes
  `-config config:Dynarec.ScpuEnabled=0 -config config:Dynarec.DspEnabled=0`;
  the DSP recompiler uses the same setup and is turned off untested.
- **macOS startup abort:** devcast's frontend occasionally dies while it
  creates its window, before emulation starts (2 of about 85 background
  launches here; the stock build does it too). It bypasses signal handlers, so
  the cause isn't identified yet. The script relaunches when this happens.
- **Disc-only boot:** booting a mkdcdisc CDI on its own runs IP.BIN under
  reios, which stops at devcast's "Full MMU support needed" FPU check. Boot the
  ELF and pass the disc with `--disc` instead; with `kos-fixes.patch`, Doom 64
  loads all its data from `/cd` that way.
- **Incomplete captures:** a capture that never reaches its end (e.g. devcast
  is killed) has no totals, and the reader rejects it.
- **MMU:** addresses are virtual. If the header shows MMUCR.AT set, the
  replay's physical tags may be wrong for remapped code.
- **Trace size:** the test program's tight loop produces about 1.1 MB per
  vblank with data accesses and about 90 KB without. Real games vary.

## Test program

`test/` builds a bare-metal program (no KOS) with `hot_a` and `hot_b` exactly
8 KiB apart, so they share every instruction-cache slot. Its loop does data
accesses, each cache op, and a `trapa`, and it prints a serial marker. Every
record count in its traces matches the disassembly by hand: 806 instructions
and 142 data accesses per iteration, the 62 repeats of each inner loop folded
into one `RANGE`, an `EXCEPT` to `VBR+0x100` with event `0x160`, and the
CCR write `0x90d` at `0x8c01004e` when captured from boot.

```sh
make -C test PREFIX=/opt/toolchains/dc/sh-elf/bin/sh-elf-
```
