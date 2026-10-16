"""Self-contained HTML report: candidates, findings, cache maps, hot code and data."""
from __future__ import annotations

from collections import defaultdict
import html
import json
from pathlib import Path

from .model import unit_names


def _slot_map(model, graph, base, replay, vblanks):
    """Per cache slot: misses per vblank and the units with hot lines there."""
    if graph is None or replay is None:
        return None
    units = model["units"]
    fixed = len(units)
    index = graph.index
    slots = [dict(m=0.0, u={}) for _ in range(index.lines)]
    label = {}

    def name(u):
        if u not in label:
            label[u] = unit_names(model, units[u], 2) if u < fixed else ("stack/fixed" if u == fixed else "heap")
        return label[u]

    for c in graph.active:
        u = graph.unit[c]
        if graph.touches[c] <= 0:
            continue
        k = index.slot((base[u] + graph.offset[c]) >> 5)
        entry = slots[k]["u"].setdefault(name(u), [0.0, 0.0])
        entry[0] += graph.touches[c]
    for (u, off), n in replay["line_misses"].items():
        k = index.slot((base[u] + off) >> 5)
        slots[k]["m"] += n / vblanks
        entry = slots[k]["u"].setdefault(name(u), [0.0, 0.0])
        entry[1] += n / vblanks
    return [[round(s["m"], 2), sorted(([n, round(t, 1), round(m, 2)] for n, (t, m) in s["u"].items()),
                                      key=lambda r: (-r[2], -r[1]))[:6]] for s in slots]


def write_report(out, model, candidates, traces, graphs, details, findings, costs, scripts):
    """`details`: {'baseline'|'best': {trace name: dict(code=..., data=...)}} detailed replays."""
    out = Path(out)
    units = model["units"]
    fixed = len(units)
    baseline = next(c for c in candidates if c["baseline"])
    best = candidates[0]
    from .cache import base_list
    maps = {}
    for t in traces:
        vblanks = max(1, len(t["code_frames"]))
        maps[t["name"]] = {}
        for which, candidate in (("baseline", baseline), ("best", best)):
            base = base_list(model, candidate["addresses"])
            entry = details[which][t["name"]]
            maps[t["name"]][which] = dict(ic=_slot_map(model, graphs["code"], base, entry["code"], vblanks),
                                          oc=_slot_map(model, graphs["data"], base, entry["data"], vblanks))

    def per_unit(which, kind, key="unit_misses"):
        """Per-unit counts per vblank, weighted over the traces that have them."""
        totals = defaultdict(float)
        replays = [(t, details[which][t["name"]][kind]) for t in traces]
        replays = [(t, r) for t, r in replays if r]
        total = sum(t["weight"] for t, _ in replays) or 1.0
        for t, replay in replays:
            share = t["weight"] / total / max(1, len(t["code_frames"]))
            for u, n in replay[key].items():
                totals[u] += n * share
        return totals

    weight = sum(t["weight"] for t in traces) or 1.0
    data_weight = sum(t["weight"] for t in traces if t["has_data"]) or 1.0
    instructions, accesses = defaultdict(float), defaultdict(float)
    for t in traces:
        vblanks = max(1, len(t["code_frames"]))
        for u, n in enumerate(t["unit_instructions"]):
            instructions[u] += n * t["weight"] / weight / vblanks
        if t["has_data"]:
            for u, n in enumerate(t["unit_accesses"]):
                accesses[u] += n * t["weight"] / data_weight / vblanks
    ic_base, ic_best = per_unit("baseline", "code"), per_unit("best", "code")
    oc_base, oc_best = per_unit("baseline", "data"), per_unit("best", "data")
    wb_base = per_unit("baseline", "data", "unit_writebacks")

    def row(u, kind):
        unit = units[u] if u < fixed else None
        return dict(name=unit_names(model, unit, 3) if unit else ("stack and other fixed memory" if u == fixed
                                                                  else "heap"),
                    section=unit["section"] if unit else "", size=unit["size"] if unit else 0,
                    address=f"0x{unit['address']:08x}" if unit else "",
                    moved=f"0x{best['addresses'][unit['id']]:08x}" if unit and
                    best["addresses"][unit["id"]] != unit["address"] else "",
                    movable=bool(unit and unit["movable"]), reason=unit["reason"] if unit else "set at run time",
                    instructions=round(instructions.get(u, 0.0), 1), accesses=round(accesses.get(u, 0.0), 1),
                    ic=[round(ic_base.get(u, 0.0), 2), round(ic_best.get(u, 0.0), 2)],
                    oc=[round(oc_base.get(u, 0.0), 2), round(oc_best.get(u, 0.0), 2)],
                    wb=round(wb_base.get(u, 0.0), 2))

    code_rows = sorted((row(u, "code") for u in range(fixed) if units[u]["kind"] == "code" and
                        (instructions.get(u) or ic_base.get(u))),
                       key=lambda r: (-r["ic"][0], -r["instructions"]))[:300]
    data_rows = sorted((row(u, "data") for u in range(fixed + 2) if accesses.get(u) or oc_base.get(u)),
                       key=lambda r: (-r["oc"][0], -r["accesses"]))[:300]
    summary = {which: dict(id=c["id"], cost=c["cost"]) for which, c in (("baseline", baseline), ("best", best))}
    breakdown = {}
    for t in traces:
        breakdown[t["name"]] = {}
        for which in ("baseline", "best"):
            code, data = details[which][t["name"]]["code"], details[which][t["name"]]["data"]
            breakdown[t["name"]][which] = dict(
                ic=dict(first=code["first_misses"], conflict=code["conflict_misses"],
                        capacity=code["capacity_misses"], working_set=max(code["working_set"], default=0)),
                oc=dict(first=data["first_misses"], conflict=data["conflict_misses"],
                        capacity=data["capacity_misses"], writebacks=data["writebacks"],
                        read=data["read_misses"], write=data["write_misses"]) if data else None)
    data = dict(
        elf=model["elf"], traces=[dict(name=t["name"], weight=t["weight"], stats=t["stats"], warnings=t["warnings"],
                                       ccr=f"0x{t['ccr']:08x}") for t in traces],
        costs=costs, summary=summary, breakdown=breakdown,
        candidates=[dict(id=c["id"], rank=c["rank"], method=c["method"], cost=c["cost"], script=scripts.get(c["id"]),
                         baseline=c["baseline"]) for c in candidates],
        maps=maps, index=dict(ic=graphs["code"].index.describe() if graphs["code"] else None,
                              oc=graphs["data"].index.describe() if graphs["data"] else None),
        code=code_rows, data=data_rows, findings=findings, warnings=model["warnings"])
    blob = json.dumps(data).replace("<", "\\u003c")
    page = PAGE.replace("@@TITLE@@", html.escape(Path(model["elf"]).name)).replace("@@DATA@@", blob)
    (out / "report.html").write_text(page, encoding="utf-8")


PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sh4Fit report: @@TITLE@@</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--ink:#1c2430;--muted:#5d6b7c;--line:#d9dee5;--accent:#2563eb;--good:#15803d;--bad:#b91c1c;
--cold:#e8ecf1;--used:#b9c7d8;--h1:#fde68a;--h2:#f59e0b;--h3:#dc2626;--hot:#7f1d1d;--chip:#eef2f7}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#0f141a;--panel:#161d26;--ink:#e3e9f0;--muted:#97a6b6;
--line:#2a3542;--accent:#60a5fa;--good:#4ade80;--bad:#f87171;--cold:#1f2833;--used:#3b4b5e;--h1:#a16207;--h2:#ea580c;--h3:#dc2626;--hot:#fecaca;--chip:#1f2833}}
:root[data-theme="dark"]{--bg:#0f141a;--panel:#161d26;--ink:#e3e9f0;--muted:#97a6b6;--line:#2a3542;--accent:#60a5fa;--good:#4ade80;
--bad:#f87171;--cold:#1f2833;--used:#3b4b5e;--h1:#a16207;--h2:#ea580c;--h3:#dc2626;--hot:#fecaca;--chip:#1f2833}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,sans-serif}
main{max-width:1180px;margin:0 auto;padding:20px 16px 60px}h1{font-size:22px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 10px}
h3{font-size:15px;margin:16px 0 6px}.muted{color:var(--muted)}.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px;margin:10px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
.card .v{font-size:22px;font-weight:600}.good{color:var(--good)}.bad{color:var(--bad)}
nav{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0}nav button{font:inherit;padding:6px 12px;border-radius:6px;border:1px solid var(--line);background:var(--panel);color:var(--ink);cursor:pointer}
nav button[aria-selected=true]{border-color:var(--accent);color:var(--accent);font-weight:600}
section[hidden]{display:none}.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;white-space:nowrap}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}code{font-size:12.5px;background:var(--chip);padding:1px 4px;border-radius:4px;overflow-wrap:anywhere}
.finding{border-left:4px solid var(--accent)}.finding.warn{border-left-color:var(--h2)}.finding ul{margin:6px 0 0;padding-left:20px}
.grid{display:grid;gap:2px;margin:8px 0}.cell{aspect-ratio:1;border-radius:2px;background:var(--cold);cursor:default}
#tip{position:fixed;z-index:5;pointer-events:none;display:none;max-width:360px;background:var(--panel);border:1px solid var(--line);
border-radius:6px;padding:8px 10px;font-size:13px;box-shadow:0 4px 14px rgba(0,0,0,.18)}.legend{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:13px}
.sw{display:inline-block;width:12px;height:12px;border-radius:2px;vertical-align:middle;margin-right:4px}
select{font:inherit;padding:4px 8px;border-radius:6px;border:1px solid var(--line);background:var(--panel);color:var(--ink)}
code.flag{white-space:nowrap;overflow-wrap:normal}.tag{font-size:12px;padding:1px 6px;border-radius:10px;background:var(--chip);white-space:nowrap}
</style></head><body><main>
<h1>Sh4Fit cache layout report</h1><div id="sub" class="muted"></div>
<div id="cards" class="cards" style="margin-top:14px"></div>
<nav role="tablist"><button data-tab="cands" aria-selected="true">Layouts</button><button data-tab="finds">Findings</button>
<button data-tab="maps">Cache maps</button><button data-tab="code">Code</button><button data-tab="data">Data</button><button data-tab="about">Method</button></nav>
<section id="cands"></section><section id="finds" hidden></section><section id="maps" hidden></section>
<section id="code" hidden></section><section id="data" hidden></section><section id="about" hidden></section>
<div id="tip"></div>
<script>
const D = @@DATA@@;
const $ = s => document.querySelector(s), esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const f = (x, d=2) => {
  if (x == null) return '–';
  const v = Number(x), a = Math.abs(v);
  // keep two significant digits for small rates instead of rounding them to 0
  const digits = a > 0 && a < 1 ? Math.max(d, Math.min(6, 1 - Math.floor(Math.log10(a)))) : d;
  return v.toLocaleString(undefined, {maximumFractionDigits: digits, minimumFractionDigits: 0});
};
const pct = (a, b) => b ? ((a - b) / b * 100) : 0;
function show(tab) {
  document.querySelectorAll('nav button').forEach(x => x.setAttribute('aria-selected', x.dataset.tab === tab));
  document.querySelectorAll('main > section').forEach(s => s.hidden = s.id !== tab);
}
document.querySelectorAll('nav button').forEach(b => b.onclick = () => { show(b.dataset.tab); history.replaceState(null, '', '#' + b.dataset.tab); });
const base = D.summary.baseline, best = D.summary.best;
$('#sub').textContent = `${D.elf} · ${D.traces.map(t => `${t.name} (${f(t.stats.instructions,0)} instructions, ${t.stats.frames} vblanks, CCR ${t.ccr})`).join(', ')}`;
function card(label, a, b, unit) {
  const change = pct(b, a), cls = b < a ? 'good' : b > a ? 'bad' : '';
  return `<div class="card"><div class="muted">${label}</div><div class="v">${f(a)} → <span class="${cls}">${f(b)}</span></div>
  <div class="muted">${unit}${a ? ` · <span class="${cls}">${change > 0 ? '+' : ''}${f(change,1)}%</span>` : ''}</div></div>`;
}
$('#cards').innerHTML = card('Estimated stall cycles', base.cost.cycles_per_kinstr, best.cost.cycles_per_kinstr, `per 1,000 instructions, ${esc(best.id)} vs baseline`)
  + card('Instruction-cache misses', base.cost.ic_per_kinstr, best.cost.ic_per_kinstr, 'per 1,000 instructions')
  + card('Operand-cache misses', base.cost.oc_per_kinstr, best.cost.oc_per_kinstr, 'per 1,000 instructions')
  + card('Dirty writebacks', base.cost.wb_per_kinstr, best.cost.wb_per_kinstr, 'per 1,000 instructions');
// --- layouts
{
  let h = `<div class="panel scroll"><table><thead><tr><th>#</th><th>Layout</th><th>Method</th><th class="n">IC misses</th><th class="n">OC misses</th><th class="n">Writebacks</th><th class="n">Stall cycles</th><th class="n">Moved</th><th>Script</th></tr></thead><tbody>`;
  for (const c of D.candidates) h += `<tr><td>${c.rank}</td><td><b>${esc(c.id)}</b></td><td>${esc(c.method)}</td><td class="n">${f(c.cost.ic_per_kinstr,3)}</td>
    <td class="n">${f(c.cost.oc_per_kinstr,3)}</td><td class="n">${f(c.cost.wb_per_kinstr,3)}</td><td class="n">${f(c.cost.cycles_per_kinstr)}</td>
    <td class="n">${f(c.cost.disruption,0)}</td><td>${c.script ? `<code>${esc(c.script)}</code>` : '–'}</td></tr>`;
  h += `</tbody></table><p class="muted">Rates are per 1,000 instructions${D.candidates.some(c => c.cost.traces && Object.values(c.cost.traces).some(t => t.sampled)) ? ', from sampled windows of the trace' : ''}.
  Stall cycles weigh an instruction-cache miss at ${D.costs.ic_miss}, an operand-cache miss at ${D.costs.oc_miss} and a writeback at ${D.costs.writeback} cycles; change them with <code class="flag">--ic-miss-cycles</code>, <code class="flag">--oc-miss-cycles</code> and <code class="flag">--writeback-cycles</code>.
  "Moved" sums how far sections moved in each region's order.</p></div>`;
  const names = D.traces.map(t => t.name);
  const pick = id => names.length > 1 ? `<label>Trace <select id="${id}">${names.map(n => `<option>${esc(n)}</option>`).join('')}</select></label>` : '';
  h += `<div class="panel"><h3>Miss breakdown</h3>${pick('bdtrace')}<div id="breakdown"></div></div>`;
  $('#cands').innerHTML = h;
  const rows = [['First-touch misses', 'first'], ['Conflict misses', 'conflict'], ['Capacity misses', 'capacity']];
  function breakdown() {
    const name = $('#bdtrace') ? $('#bdtrace').value : names[0], b = D.breakdown[name].baseline, x = D.breakdown[name].best;
    let t = `<div class="scroll"><table><thead><tr><th>${esc(name)}</th><th class="n">IC baseline</th><th class="n">IC ${esc(best.id)}</th><th class="n">OC baseline</th><th class="n">OC ${esc(best.id)}</th></tr></thead><tbody>`;
    for (const [label, k] of rows) t += `<tr><td>${label}</td><td class="n">${f(b.ic[k],0)}</td><td class="n">${f(x.ic[k],0)}</td><td class="n">${b.oc ? f(b.oc[k],0) : '–'}</td><td class="n">${x.oc ? f(x.oc[k],0) : '–'}</td></tr>`;
    t += `<tr><td>Writebacks</td><td></td><td></td><td class="n">${b.oc ? f(b.oc.writebacks,0) : '–'}</td><td class="n">${x.oc ? f(x.oc.writebacks,0) : '–'}</td></tr>`;
    t += `</tbody></table></div><p class="muted">Counts over the whole capture. A conflict miss is one a fully associative LRU cache of the same size would have hit; a capacity miss is one it would also have taken.
    ${b.oc ? '' : 'This capture has no data accesses (DEVCAST_TRACE_DATA=0). '}The busiest vblank touched ${x.ic.working_set} of 256 instruction-cache lines.</p>`;
    $('#breakdown').innerHTML = t;
  }
  if ($('#bdtrace')) $('#bdtrace').onchange = breakdown;
  breakdown();
}
// --- findings
$('#finds').innerHTML = D.findings.length ? D.findings.map(x => `<div class="panel finding ${x.severity}"><b>${esc(x.title)}</b><div>${esc(x.detail)}</div>
  ${x.items.length ? `<ul>${x.items.map(i => `<li>${esc(i)}</li>`).join('')}</ul>` : ''}</div>`).join('') : '<p class="muted">Nothing to report.</p>';
// --- cache maps
{
  const tip = $('#tip');
  function grid(map, cols, max) {
    if (!map) return '<p class="muted">No data for this cache.</p>';
    let h = `<div class="grid" style="grid-template-columns:repeat(${cols},1fr)">`;
    map.forEach((s, i) => {
      // decades below the busiest slot: a game's misses span orders of magnitude
      const r = s[0] / max, used = s[1].length;
      const bg = s[0] <= 0 ? (used ? 'var(--used)' : 'var(--cold)') : r < .01 ? 'var(--h1)' : r < .1 ? 'var(--h2)' : r < .5 ? 'var(--h3)' : 'var(--hot)';
      h += `<div class="cell" data-i="${i}" style="background:${bg}"></div>`;
    });
    return h + '</div>';
  }
  function render() {
    const which = $('#mapwhich').value, cache = $('#mapcache').value;
    const maps = D.maps[$('#maptrace') ? $('#maptrace').value : D.traces[0].name];
    const map = maps[which][cache], cols = 32;
    // one colour scale for both layouts, so a better layout looks better
    const scale = Math.max(1e-9, ...['baseline', 'best'].flatMap(w => (maps[w][cache] || []).map(s => s[0])));
    $('#mapgrid').innerHTML = grid(map, cols, scale);
    $('#mapgrid').onmousemove = e => {
      const c = e.target.closest('.cell'); if (!c) { tip.style.display = 'none'; return; }
      const s = map[+c.dataset.i];
      tip.innerHTML = `<b>slot ${c.dataset.i}</b> · ${f(s[0])} misses per vblank<br>` + (s[1].length ? s[1].map(r => `${esc(r[0])}: ${f(r[2])} misses`).join('<br>') : '<span class="muted">no hot lines</span>');
      tip.style.display = 'block'; tip.style.left = Math.min(e.clientX + 14, innerWidth - 370) + 'px'; tip.style.top = (e.clientY + 14) + 'px';
    };
    $('#mapgrid').onmouseleave = () => tip.style.display = 'none';
  }
  const idx = D.index;
  const traceNames = D.traces.map(t => t.name);
  $('#maps').innerHTML = `<div class="panel"><div class="legend">${traceNames.length > 1 ? `<label>Trace <select id="maptrace">${traceNames.map(n => `<option>${esc(n)}</option>`).join('')}</select></label>` : ''}<label>Layout <select id="mapwhich"><option value="baseline">baseline</option><option value="best" selected>${esc(best.id)}</option></select></label>
  <label>Cache <select id="mapcache"><option value="ic">instruction (${idx.ic ? esc(idx.ic.name) : '–'})</option><option value="oc">operand (${idx.oc ? esc(idx.oc.name) : '–'})</option></select></label>
  <span><span class="sw" style="background:var(--cold)"></span>unused</span><span><span class="sw" style="background:var(--used)"></span>hot lines, no misses</span>
  <span><span class="sw" style="background:var(--h1)"></span>under 1% of the busiest slot</span><span><span class="sw" style="background:var(--h2)"></span>1–10%</span><span><span class="sw" style="background:var(--h3)"></span>10–50%</span><span><span class="sw" style="background:var(--hot)"></span>50% or more</span></div>
  <div id="mapgrid"></div><p class="muted">One cell per cache slot (32 per row). Colours compare each slot's misses with the busiest slot of either layout, so a better layout looks better. Hover a slot for the code or data with hot lines there.</p></div>`;
  $('#mapwhich').onchange = render; $('#mapcache').onchange = render;
  if ($('#maptrace')) $('#maptrace').onchange = render;
  render();
}
// --- tables
function table(rows, kind) {
  const ic = kind === 'code';
  let h = `<div class="panel scroll"><table><thead><tr><th>${ic ? 'Function(s)' : 'Object(s)'}</th><th>Section</th><th class="n">Bytes</th><th class="n">${ic ? 'Instructions' : 'Accesses'}</th>
  <th class="n">${ic ? 'IC' : 'OC'} misses</th><th class="n">${esc(best.id)}</th>${ic ? '' : '<th class="n">Writebacks</th>'}<th>Address</th><th>Moves?</th></tr></thead><tbody>`;
  for (const r of rows) {
    const m = ic ? r.ic : r.oc;
    h += `<tr><td>${esc(r.name)}</td><td>${r.section ? `<code>${esc(r.section)}</code>` : ''}</td><td class="n">${f(r.size,0)}</td><td class="n">${f(ic ? r.instructions : r.accesses,1)}</td>
    <td class="n">${f(m[0])}</td><td class="n ${m[1] < m[0] ? 'good' : m[1] > m[0] ? 'bad' : ''}">${f(m[1])}</td>${ic ? '' : `<td class="n">${f(r.wb)}</td>`}
    <td>${r.address ? `<code>${esc(r.address)}</code>` : ''}${r.moved ? ` → <code>${esc(r.moved)}</code>` : ''}</td><td>${r.movable ? '<span class="tag">movable</span>' : `<span class="muted">${esc(r.reason)}</span>`}</td></tr>`;
  }
  return h + `</tbody></table><p class="muted">Per vblank of emulated time, weighted across traces. Instruction counts are per vblank too.</p></div>`;
}
$('#code').innerHTML = table(D.code, 'code');
$('#data').innerHTML = table(D.data, 'data');
$('#about').innerHTML = `<div class="panel"><p>Sh4Fit replays devcast traces through models of the SH-4's caches: an 8 KiB direct-mapped instruction cache of 256 lines and a 16 KiB direct-mapped operand cache of 512 lines (8 KiB with CCR.ORA), both with 32-byte lines and physical tags. The replay follows CCR writes, cache-array stores, pref, movca.l and the ocb* instructions, copy-back and write-through policies, and dirty writebacks.</p>
<p>Layouts are searched with temporal relationship graphs (Gloy &amp; Smith) over 32-byte chunks, call-chain clustering for code (C3), slot-aware placement with cold sections as spacers, and late-acceptance hill climbing, then ranked by replaying the traces. The method follows MipsFit by Kevin R. (MIT License).</p>
<p>Only input sections a selector can name uniquely move. Stack and heap addresses are fixed by the program at run time; the heap follows the end of the image, which the generated scripts keep in place.</p>
${D.warnings.length ? `<h3>Warnings</h3><ul>${D.warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}
${D.traces.flatMap(t => t.warnings).length ? `<h3>Trace notes</h3><ul>${D.traces.flatMap(t => t.warnings).map(w => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}</div>`;
if (document.getElementById(location.hash.slice(1))) show(location.hash.slice(1));
</script></main></body></html>
'''
