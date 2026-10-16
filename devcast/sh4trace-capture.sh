#!/bin/bash
# Record an SH4XTRC1 trace with a devcast built from sh4trace.patch.
#
# usage: sh4trace-capture.sh [--show] [--timeout SECONDS] [--workdir DIR] \
#            [--disc IMAGE] [--config SECTION:KEY=VALUE]... \
#            <devcast binary> <game.elf | disc image> <out.sh4trace>
#
# An ELF boots directly through reios. --disc mounts a disc image as well, so
# the program can read /cd; booting a disc image alone runs its IP.BIN under
# reios, which fails for some bootstraps (an ELF plus --disc avoids that).
# --config passes a devcast setting, e.g. config:Debug.SerialConsoleEnabled=1
# to copy the game's serial output (dbgio/printf) into the log.
#
# Capture settings come from the environment and are passed through:
#   DEVCAST_TRACE_FRAMES (default 600), DEVCAST_TRACE_START_FRAME,
#   DEVCAST_TRACE_START_PC, DEVCAST_TRACE_START_MARKER, DEVCAST_TRACE_DATA,
#   DEVCAST_TRACE_MAX_MB
#
# By default devcast runs in the background (needs macos-background.patch on
# macOS): no window, no Dock icon, no focus, no audio and no frame limiter.
# --show runs it normally. devcast's config lives in a scratch directory
# (or --workdir, e.g. one holding BIOS files), never in ~/.reicast.
set -u

show=0
timeout=600
workdir=""
disc=""
extra=()
while [ $# -gt 0 ]; do
    case "$1" in
        --show) show=1; shift ;;
        --timeout) timeout=$2; shift 2 ;;
        --workdir) workdir=$2; shift 2 ;;
        --disc) disc=$2; shift 2 ;;
        --config) extra+=(-config "$2"); shift 2 ;;
        -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
        --) shift; break ;;
        -*) echo "unknown option $1" >&2; exit 2 ;;
        *) break ;;
    esac
done
if [ $# -ne 3 ]; then
    sed -n '4,6p' "$0" >&2
    exit 2
fi

absolute() { (cd "$(dirname "$1")" && echo "$(pwd -P)/$(basename "$1")"); }
devcast=$(absolute "$1") || exit 1
game=$(absolute "$2") || exit 1
out=$(absolute "$3") || exit 1
log="$out.log"
[ -x "$devcast" ] || { echo "not executable: $devcast" >&2; exit 1; }
[ -f "$game" ] || { echo "no such game: $game" >&2; exit 1; }
if [ -n "$disc" ]; then
    disc=$(absolute "$disc") || exit 1
    [ -f "$disc" ] || { echo "no such disc image: $disc" >&2; exit 1; }
fi

cleanup_dir=""
if [ -z "$workdir" ]; then
    workdir=$(mktemp -d "${TMPDIR:-/tmp}/sh4trace.XXXXXX") || exit 1
    cleanup_dir=$workdir
fi
mkdir -p "$workdir" || exit 1

args=(-portable)
if [ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ]; then
    # devcast's ARM7 and DSP recompilers crash on Apple Silicon
    args+=(-config config:Dynarec.ScpuEnabled=0 -config config:Dynarec.DspEnabled=0)
fi
if [ $show = 0 ]; then
    export DEVCAST_BACKGROUND=1
    args+=(-config audio:backend=none -config config:aica.LimitFPS=0)
fi
args+=(${extra[@]+"${extra[@]}"} "$game")
case "$game" in
    *.elf|*.ELF|*.bin|*.BIN)
        # reios boots the program right away; a disc image (or "nodisk") is what
        # makes the frontend start emulation without waiting in its menu
        if [ -n "$disc" ]; then args+=("$disc"); else args+=(nodisk); fi ;;
    *) [ -z "$disc" ] || { echo "--disc needs an ELF to boot" >&2; exit 2; } ;;
esac

export DEVCAST_TRACE="$out" DEVCAST_TRACE_EXIT=1 CFFIXED_USER_HOME="$workdir"

# A finished trace ends with the last TOTALS record (kind 15, selector 3).
complete() { [ -s "$out" ] && [ "$(tail -c 4 "$out" | od -An -tx4 | tr -d ' ')" = f0000003 ]; }

# devcast's macOS frontend sometimes aborts while it sets up its window, before
# emulation starts; that leaves no trace file, so launch again.
for attempt in 1 2 3; do
    rm -f "$out"
    (cd "$workdir" && exec "$devcast" "${args[@]}") > "$log" 2>&1 &
    pid=$!
    # A background devcast is invisible, so never leave one running.
    trap 'kill $pid $watchdog 2>/dev/null; wait $pid 2>/dev/null; echo "sh4trace-capture: interrupted" >&2; exit 130' INT TERM
    (
        sleep "$timeout" &
        trap 'kill $! 2>/dev/null; exit 0' TERM
        wait $!
        kill $pid 2>/dev/null
    ) < /dev/null > /dev/null 2>&1 &
    watchdog=$!
    wait $pid 2>/dev/null
    status=$?
    kill $watchdog 2>/dev/null
    wait $watchdog 2>/dev/null
    trap - INT TERM
    # 134 is SIGABRT; anything else, or an abort after recording began, is final
    [ $status = 134 ] && [ ! -e "$out" ] || break
    echo "sh4trace-capture: devcast aborted during startup; retrying" >&2
done
[ -n "$cleanup_dir" ] && rm -rf "$cleanup_dir"

grep -o 'sh4trace: .*' "$log"
if ! complete; then
    echo "sh4trace-capture: no complete trace (devcast exit status $status); see $log" >&2
    exit 1
fi
echo "wrote $out"
echo "check it with: python3 -m sh4fit trace-info '$out' --elf <the game's ELF>"
