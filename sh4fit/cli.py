from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import subprocess
import sys
import time

from . import cache, findings as findings_module, optimize, sh4trace, trace as trace_module, trg
from .elf import Elf, sha256
from .layout import actual_addresses, check_inputs, script_blocker, script_variant
from .model import make_model
from .report import write_report


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=1) + "\n", encoding="utf-8")


def trace_info(args):
    elf = Elf.read(args.elf) if args.elf else None
    s = sh4trace.summarize(args.trace, elf)
    h = s["header"]
    print(f"{args.trace}: SH4XTRC1, started at {h['trigger']}"
          + (f" 0x{h['start_pc']:08x}" if h["trigger"] == "START_PC" else "")
          + f" (vblank {h['vblank']}), {'interpreter' if h['interpreter'] else 'recompiler'}")
    print(f"  CCR 0x{h['ccr']:08x} [{' '.join(s['ccr_flags']) or 'caches off'}]"
          + ("; MMU on, addresses are virtual" if h["mmucr"] & 1 else ""))
    end = " (size limit reached)" if s["truncated"] else " (emulation stopped early)" if s["stopped_early"] else ""
    print(f"  {s['frames']} frames{end}, {s['instructions']:,} instructions in {s['range_records']:,} range records "
          f"({s['ranges']:,} runs)")
    if s["frame_instructions"]:
        per = s["frame_instructions"]
        cycles = s["frame_cycles"]
        print(f"  per frame: {min(per):,} to {max(per):,} instructions, mean {sum(per) / len(per):,.0f}; "
              f"mean {sum(cycles) / len(cycles):,.0f} SH4 cycles between marks")
    if s["uncached_instructions"]:
        print(f"  {s['uncached_instructions']:,} instructions fetched from P2 (uncached)")
    if s["exceptions"]:
        print("  exceptions/interrupts: " + ", ".join(f"0x{k:03x} x{v}" for k, v in sorted(s["exceptions"].items())))
    for value, pc in s["ccr_writes"][:8]:
        print(f"  CCR write 0x{value:08x} [{' '.join(sh4trace.decode_ccr(value))}] at 0x{pc:08x}")
    if s["ic_array_writes"]:
        print(f"  {s['ic_array_writes']:,} instruction-cache address-array stores (icache flushes)")
    if s["resets"]:
        print(f"  {s['resets']} machine resets")
    if h["data"]:
        print(f"  {s['data_accesses']:,} cacheable data accesses in {s['data_records']:,} records, "
              f"{s['data_lines']:,} distinct lines; {s['uncached_data'] or 0:,} uncached")
        print("  data ops: " + ", ".join(f"{k} {v:,}" for k, v in sorted(s["data_ops"].items())))
        print("  data areas: " + ", ".join(f"{k} {v:,}" for k, v in sorted(s["data_areas"].items())))
    else:
        print("  no data stream (captured with DEVCAST_TRACE_DATA=0)")
    print(f"  {s['code_lines']:,} code lines sampled for provenance")
    if "provenance" in s:
        p = s["provenance"]
        if not p["checked"]:
            print(f"  ELF check: none of the sampled lines fall inside {args.elf}")
            return 1
        print(f"  ELF check: {p['matched']}/{p['checked']} sampled instruction words match {args.elf}")
        for address, value, expected in p["mismatches"]:
            print(f"    0x{address:08x}: trace 0x{value:04x}, ELF 0x{expected:04x}")
        if p["matched"] != p["checked"]:
            print("  the trace was captured from a different build")
            return 1
    return 0


def _costs(args):
    return dict(ic_miss=args.ic_miss_cycles, oc_miss=args.oc_miss_cycles, writeback=args.writeback_cycles)


def _details(model, traces, addresses):
    base = cache.base_list(model, addresses)
    return {t["name"]: dict(code=cache.simulate_code(t, base, detail=True),
                            data=cache.simulate_data(t, base, detail=True)) for t in traces}


def analyze(args):
    started = time.monotonic()
    model = make_model(args.elf, args.map, args.build_dir, args.tool_prefix, not args.no_source)
    script = None
    if args.linker_script:
        script = Path(args.linker_script).read_text(encoding="utf-8")
        for name, region in model["regions"].items():
            if region.get("blocked"):
                continue
            try:
                script_variant(script, model, dict(orders={name: []}))
            except ValueError as exc:
                region["blocked"] = f"cannot rewrite the linker script here: {exc}"
                for unit in model["units"]:
                    if unit["region"] == name and unit["movable"]:
                        unit["movable"], unit["reason"] = False, region["blocked"]
        if all(r.get("blocked") for r in model["regions"].values()):
            raise ValueError("no region of this link can be reordered: " + (script_blocker(model) or "unknown"))
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    movable = sum(u["movable"] for u in model["units"])
    print(f"{Path(args.elf).name}: {len(model['units'])} input sections, {movable} movable, regions: "
          + ", ".join(f"{n}{' (fixed: ' + r['blocked'] + ')' if r.get('blocked') else ''}"
                      for n, r in model["regions"].items()))

    traces, names = [], set()
    for spec in args.trace:
        path, weight = trace_module.parse_spec(spec)
        print(f"Importing {path} ...", flush=True)
        imported = trace_module.import_trace(model, path, weight=weight)
        while imported["name"] in names:
            imported["name"] += "-2"
        names.add(imported["name"])
        traces.append(imported)
        st = imported["stats"]
        print(f"  {st['frames']} vblanks, {st['instructions']:,} instructions, {st['data_accesses']:,} data accesses "
              f"({st['segments']:,} fetch runs, {st['data_records']:,} data runs)")
        for warning in imported["warnings"]:
            print("  Note:", warning)
    for t in traces:
        for a, b, n in t["fallthrough"]:
            for u in (a, b):
                unit = model["units"][u]
                if unit["movable"]:
                    unit["movable"] = False
                    unit["reason"] = "execution falls through between it and a neighbouring section"
            model["warnings"].append(f"{model['units'][a]['id']} falls through into {model['units'][b]['id']}; "
                                     "both stay in order")
    ccr = traces[0]["ccr"]
    if any(t["ccr"] != ccr for t in traces):
        model["warnings"].append("traces start with different CCR values; the search uses the first trace's")
    code_graph = trg.build(traces, "code", cache.ic_index(ccr),
                           frames={t["name"]: cache.windows(t, args.graph_segments) for t in traces})
    data_graph = None
    if not args.no_data and any(t["has_data"] for t in traces):
        data_graph = trg.build(traces, "data", cache.oc_index(ccr),
                               frames={t["name"]: cache.windows(t, args.graph_segments // 2) for t in traces})
    print(f"Graphs: {len(code_graph.active):,} interleaving code chunks"
          + (f", {len(data_graph.active):,} data chunks" if data_graph else ""), flush=True)

    costs = _costs(args)
    candidates = optimize.generate(model, code_graph, data_graph, traces, count=args.candidates,
                                   search_seconds=args.search_seconds, seed=args.seed,
                                   padding_budget=args.padding_budget, sim_segments=args.sim_segments,
                                   costs=costs, data=not args.no_data,
                                   log=(lambda *a: None) if args.quiet else print)
    baseline = next(c for c in candidates if c["baseline"])
    best = candidates[0]
    details = dict(baseline=_details(model, traces, baseline["addresses"]))
    details["best"] = details["baseline"] if best["baseline"] else _details(model, traces, best["addresses"])
    found = findings_module.collect(model, traces, details["baseline"], details["best"])

    scripts = {}
    if script is not None:
        for c in candidates:
            name = c["id"] + ".ld"
            (out / name).write_text(script_variant(script, model, c), encoding="utf-8")
            scripts[c["id"]] = name
        model["linker_script"] = dict(path=str(Path(args.linker_script).resolve()), sha256=sha256(args.linker_script))
    model["traces"] = []
    for t in traces:
        model["traces"].append(dict(name=t["name"], file=trace_module.save(t, out), weight=t["weight"],
                                    stats=t["stats"], warnings=t["warnings"]))
    model["costs"] = costs
    write_json(out / "model.json", model)
    write_json(out / "candidates.json", candidates)
    write_report(out, model, candidates, traces, dict(code=code_graph, data=data_graph), details, found, costs,
                 scripts)
    print(f"\n{'#':>2} {'layout':10} {'IC/1k':>8} {'OC/1k':>8} {'WB/1k':>8} {'stall cycles/1k':>16}  method")
    for c in candidates:
        k = c["cost"]
        print(f"{c['rank']:>2} {c['id']:10} {k['ic_per_kinstr']:8.3f} {k['oc_per_kinstr']:8.3f} "
              f"{k['wb_per_kinstr']:8.3f} {k['cycles_per_kinstr']:16.2f}  {c['method']}")
    print(f"\nWrote {out / 'report.html'}" + (f" and {len(scripts)} linker scripts" if scripts else "")
          + f" in {time.monotonic() - started:.0f} s")
    if script is None:
        print("No --linker-script given, so no scripts were written.")
    for warning in model["warnings"][:8]:
        print("Note:", warning)
    return 0


def simulate_cmd(args):
    analysis = Path(args.analysis).resolve()
    model = read_json(analysis / "model.json")
    traces = [trace_module.load(analysis / entry["file"]) for entry in model["traces"]]
    candidates = read_json(analysis / "candidates.json")
    costs = model.get("costs") or cache.COSTS
    rows, actual = [], None
    if args.elf:
        if not args.map:
            raise ValueError("--elf needs the new link's map (--map)")
        check_inputs(model)
        fresh = make_model(args.elf, args.map, model["build_dir"], source_lookup=False)
        addresses = actual_addresses(model, fresh)
        actual = dict(elf=str(Path(args.elf).resolve()), elf_sha256=fresh["elf_sha256"], addresses=addresses)
        for c in candidates:
            wrong = [uid for uid, a in c["addresses"].items() if uid in addresses and addresses[uid] != a]
            if not wrong:
                actual["matches"] = c["id"]
                break
            if len(wrong) < actual.get("closest", (None, 1 << 30, None))[1]:
                actual["closest"] = (c["id"], len(wrong), wrong[:3])
        rows = [("baseline (analyzed)", next(c for c in candidates if c["baseline"])["addresses"]),
                (f"linked {Path(args.elf).name}", addresses)]
    else:
        rows = [(c["id"], c["addresses"]) for c in candidates]
    print(f"{'layout':26} {'trace':14} {'IC/1k':>8} {'OC/1k':>8} {'WB/1k':>8} {'stall/1k':>9} {'IC misses':>10} "
          f"{'OC misses':>10}")
    results = []
    for name, addresses in rows:
        base = cache.base_list(model, addresses)
        for t in traces:
            s = cache.summarize(t, cache.simulate_code(t, base), cache.simulate_data(t, base), costs)
            results.append(dict(layout=name, trace=t["name"], **s))
            print(f"{name:26} {t['name'][:14]:14} {s['ic_per_kinstr']:8.3f} {s['oc_per_kinstr']:8.3f} "
                  f"{s['wb_per_kinstr']:8.3f} {s['cycles_per_kinstr']:9.2f} {s['ic_misses']:10,} {s['oc_misses']:10,}")
    print("full-trace replay through the SH-4 instruction and operand cache models")
    if actual:
        if "matches" in actual:
            print(f"Placement verified: every section is where {actual['matches']} predicted.")
        else:
            name, count, examples = actual["closest"]
            print(f"The link matches no candidate exactly; closest is {name}, with {count} sections elsewhere "
                  f"(e.g. {', '.join(examples)}). Check that the link used the generated script.")
        actual["results"] = results
        if args.out:
            write_json(args.out, actual)
        return 0 if "matches" in actual else 2
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="sh4fit", description="SH-4 cache layout tools for Dreamcast homebrew")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("trace-info", help="validate and summarize an SH4XTRC1 trace from devcast")
    p.add_argument("trace", help="trace file written by DEVCAST_TRACE")
    p.add_argument("--elf", metavar="FILE", help="check the trace's sampled code against this ELF")
    p.set_defaults(func=trace_info)

    p = sub.add_parser("analyze", help="search for code and data layouts that miss less in the SH-4 caches")
    p.add_argument("elf", help="unstripped, linked ELF the traces were captured from")
    p.add_argument("--map", required=True, metavar="FILE", help="the link's GNU ld map (-Wl,-Map=FILE)")
    p.add_argument("--trace", action="append", required=True, metavar="FILE[=WEIGHT]",
                   help="devcast SH4XTRC1 capture; repeat to combine scenarios, with optional positive weights")
    p.add_argument("--linker-script", metavar="FILE",
                   help="the script the ELF was linked with (KallistiOS: $KOS_BASE/utils/ldscripts/shlelf.xc); "
                        "candidate scripts are written next to the report, the original is never changed")
    p.add_argument("--build-dir", metavar="DIR",
                   help="directory the linker ran in, for relative paths in the map (default: the map's directory)")
    p.add_argument("--out", required=True, metavar="DIR", help="output directory")
    p.add_argument("--candidates", type=int, default=3, help="alternative layouts to keep (default: 3)")
    p.add_argument("--search-seconds", type=float, default=60.0, metavar="SECONDS",
                   help="hill-climbing budget, shared between code and data; 0 disables refinement (default: 60)")
    p.add_argument("--seed", type=int, default=0, help="random seed for refinement (default: 0)")
    p.add_argument("--padding-budget", type=int, default=0, metavar="BYTES",
                   help="bytes of explicit padding a layout may add in front of sections (default: 0)")
    p.add_argument("--sim-segments", type=int, default=0, metavar="N",
                   help="replay about N trace records per trace to rank candidates, in sampled vblank windows; "
                        "0 replays everything (default)")
    p.add_argument("--graph-segments", type=int, default=4_000_000, metavar="N",
                   help="trace records used to build the relationship graphs (default: 4000000; 0 = all)")
    p.add_argument("--no-data", action="store_true", help="leave data sections alone (instruction cache only)")
    p.add_argument("--ic-miss-cycles", type=float, default=cache.COSTS["ic_miss"], metavar="N",
                   help=f"stall cycles per instruction-cache miss in the ranking (default: {cache.COSTS['ic_miss']})")
    p.add_argument("--oc-miss-cycles", type=float, default=cache.COSTS["oc_miss"], metavar="N",
                   help=f"stall cycles per operand-cache miss (default: {cache.COSTS['oc_miss']})")
    p.add_argument("--writeback-cycles", type=float, default=cache.COSTS["writeback"], metavar="N",
                   help=f"cycles per dirty-line writeback (default: {cache.COSTS['writeback']})")
    p.add_argument("--tool-prefix", default="sh-elf-", metavar="PREFIX",
                   help="prefix or path of the SH binutils, for addr2line (default: sh-elf-)")
    p.add_argument("--no-source", action="store_true", help="skip addr2line source lookups")
    p.add_argument("--quiet", action="store_true", help="don't list every layout the search tries")
    p.set_defaults(func=analyze)

    p = sub.add_parser("simulate", help="replay an analysis's traces for its layouts or a relinked ELF")
    p.add_argument("analysis", help="output directory of sh4fit analyze")
    p.add_argument("--elf", metavar="FILE", help="ELF relinked with a generated script, to verify and replay")
    p.add_argument("--map", metavar="FILE", help="that link's map")
    p.add_argument("--out", metavar="FILE", help="write the verification and replay results as JSON")
    p.set_defaults(func=simulate_cmd)
    args = parser.parse_args(argv)
    try:
        for name in ("candidates",):
            if getattr(args, name, 1) < 1:
                raise ValueError(f"--{name} must be positive")
        if hasattr(args, "search_seconds") and (not math.isfinite(args.search_seconds) or args.search_seconds < 0):
            raise ValueError("--search-seconds must be finite and nonnegative")
        for name in ("padding_budget", "sim_segments", "graph_segments", "ic_miss_cycles", "oc_miss_cycles",
                     "writeback_cycles"):
            if getattr(args, name, 0) < 0:
                raise ValueError(f"--{name.replace('_', '-')} must be nonnegative")
        return args.func(args)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as exc:
        print(f"sh4fit: {exc}", file=sys.stderr)
        return 1
