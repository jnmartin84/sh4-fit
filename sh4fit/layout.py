"""Address prediction, GNU ld script generation and relink verification.

A layout lists, per region, the movable units in their new order (with optional
padding in front of some). The generated script puts explicit selectors for
them ahead of the region's wildcard statement, which still places everything
else in its original order, and then pads the output section back to the
region's old end (`. = MAX(., old end)`) so that whatever follows it, and the
heap at the end of the image, stays where it was whenever the new order is no
larger.
"""
from __future__ import annotations

import re

from .elf import sha256


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def region_members(model, region):
    return [u for u in model["units"] if u["region"] == region]


LINE = 32
LTRANS_ID = re.compile(r"^.*(\.ltrans\d+\.ltrans\.o)((?:\([^()]*\))?:.*)$")


def positions(model, orders=None, padding=None, aligned=()):
    """Predicted address of every unit (and '_data_end') for `orders`
    ({region output name: [unit ids]}) with `padding` ({unit id: bytes}) and the
    listed units in `aligned` starting on a cache line."""
    orders, padding, aligned = orders or {}, padding or {}, set(aligned or ())
    units = model["units"]
    by_id = {u["id"]: u for u in units}
    addresses = {}
    outputs = sorted(model["outputs"].values(), key=lambda o: o["address"])
    members = {o["name"]: [] for o in outputs}
    for u in units:
        if u["output"] in members:
            members[u["output"]].append(u)
    previous_old_end = previous_new_end = None
    final_shift = 0
    for out in outputs:
        old_start = out["address"]
        if previous_new_end is None or not 0x0C000000 <= old_start & 0x1FFFFFFF < 0x10000000:
            new_start = old_start
        else:
            gap = old_start - align(previous_old_end, out["align"])
            new_start = align(previous_new_end, out["align"]) + max(0, gap)
        shift = new_start - old_start
        region = model["regions"].get(out["name"])
        order = orders.get(out["name"]) if region else None
        inside = {u["id"] for u in members[out["name"]] if region and u["region"] == out["name"]}
        placed_region = False
        for u in members[out["name"]]:
            if u["id"] in inside and order is not None:
                if placed_region:
                    continue
                placed_region = True
                # prefix, then the explicit order, then the rest of the region as before
                listed = set(order)
                rest = [m for m in members[out["name"]] if m["id"] in inside and m["id"] not in listed]
                prefix = [m for m in rest if m.get("prefix")]
                pinned = [m for m in rest if not m.get("prefix")]
                cursor = None
                for m in prefix:
                    cursor = align(m["address"] + shift, m["align"]) if m["size"] else m["address"] + shift
                    addresses[m["id"]] = cursor
                    cursor += m["size"]
                if cursor is None:
                    cursor = region["start"] + shift
                for uid in order:
                    m = by_id[uid]
                    cursor += padding.get(uid, 0)
                    cursor = align(cursor, max(m["align"], LINE) if uid in aligned else m["align"])
                    addresses[uid] = cursor
                    cursor += m["size"]
                for m in pinned:
                    if m["size"]:  # merged-away sections take no space and no alignment
                        cursor = align(cursor, m["align"])
                    addresses[m["id"]] = cursor
                    cursor += m["size"]
                cursor = max(cursor, region["end"] + shift)  # the generated script pads to the old end
                shift = cursor - region["end"]
                continue
            if not u["size"]:  # merged away: ld neither aligns nor advances for it
                addresses[u["id"]] = u["address"] + shift
                continue
            new = align(u["address"] + shift, u["align"])
            addresses[u["id"]] = new
            shift = new - u["address"]
        previous_old_end = old_start + out["size"]
        previous_new_end = previous_old_end + shift
        if 0x0C000000 <= old_start & 0x1FFFFFFF < 0x10000000:
            final_shift = shift
    for u in units:
        addresses.setdefault(u["id"], u["address"])
    addresses["_data_end"] = model["data_end"] + final_shift
    return addresses


def disruption(model, orders):
    """Sum of absolute index changes against the original order, over all regions."""
    total = 0
    for region, order in orders.items():
        original = [u["id"] for u in region_members(model, region) if u["id"] in set(order)]
        index = {uid: i for i, uid in enumerate(original)}
        total += sum(abs(index[uid] - i) for i, uid in enumerate(order))
    return total


def script_blocker(model, region=None):
    """Why no script can reorder `region` (or any region), in terms of what to change."""
    unreadable = [w for w in model["warnings"] if w.startswith("Cannot read linker input ")]
    regions = [model["regions"][region]] if region else list(model["regions"].values())
    if not regions:
        return ("the map shows no reorderable wildcard: expected a statement such as "
                "*(.text .stub .text.* .gnu.linkonce.t.*) inside .text")
    reasons = [f"{r['output']}: {r['blocked']}" for r in regions if r.get("blocked")]
    if unreadable:
        reasons.append(f"{len(unreadable)} input file(s) unreadable; pass the linker's working directory "
                       "as --build-dir")
    return "; ".join(reasons) or None


def _block(script, output):
    """(body start, body end) of the output section statement `output` in `script`."""
    pattern = re.compile(r"(?m)^[ \t]*" + re.escape(output) + r"(?=[\s:(])[^:{};\n]*:[^{;]*\{")
    matches = list(pattern.finditer(script))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {output} output section in the linker script, found {len(matches)}")
    start = matches[0].end()
    depth, i = 1, start
    while depth and i < len(script):
        ch = script[i]
        if script.startswith("/*", i):
            end = script.find("*/", i + 2)
            i = len(script) if end < 0 else end + 2
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    if depth:
        raise ValueError(f"unbalanced braces in the {output} output section")
    return start, i - 1


def _statement(script, start, end, text):
    """Span of the input statement `text` (as the map prints it) inside [start, end)."""
    compact = re.sub(r"\s+", "", text)
    pattern = r"\s*".join(re.escape(ch) for ch in compact)
    body = script[start:end]
    # ignore matches inside comments
    hits = [m for m in re.finditer(pattern, body)
            if body.rfind("/*", 0, m.start()) <= body.rfind("*/", 0, m.start())]
    if len(hits) != 1:
        raise ValueError(f"expected the statement {text} once in its output section, found {len(hits)}")
    return start + hits[0].start(), start + hits[0].end()


def script_variant(script, model, candidate, name="Sh4Fit"):
    """The linker script with `candidate`'s order. The baseline returns `script`."""
    if candidate.get("baseline"):
        return script
    units = {u["id"]: u for u in model["units"]}
    padding = candidate.get("padding") or {}
    aligned = set(candidate.get("aligned") or ())
    edits = []
    for output, order in sorted((candidate.get("orders") or {}).items()):
        region = model["regions"].get(output)
        if not region:
            raise ValueError(f"no reorderable region in {output}")
        if region.get("blocked"):
            raise ValueError(f"{output}: {region['blocked']}")
        members = region_members(model, output)
        if any(uid not in units or not units[uid]["movable"] or units[uid]["region"] != output for uid in order):
            raise ValueError(f"the {output} order lists a unit that cannot be moved")
        selectors = [units[uid]["selector"] for uid in order]
        if len(set(selectors)) != len(selectors):
            raise ValueError("ambiguous section selectors")
        start, end = _block(script, output)
        s0, s1 = _statement(script, start, end, region["text"])
        line_start = script.rfind("\n", 0, s0) + 1
        indent = script[line_start:s0] if not script[line_start:s0].strip() else "    "
        keep = region["text"].lstrip().startswith("KEEP")
        wrap = (lambda s: f"KEEP ({s})") if keep else (lambda s: s)
        lines = [f"/* {name}: explicit order for {output}; the original statement below places the rest */"]
        lines += [wrap(u["selector"]) for u in members if u.get("prefix")]
        for uid in order:
            pad = padding.get(uid, 0)
            if pad:
                if pad < 0 or pad % 2:
                    raise ValueError("padding must be a non-negative, even number of bytes")
                lines.append(f". = . + {pad};  /* {name}: cache slot offset */")
            if uid in aligned and units[uid]["align"] < LINE:
                lines.append(f". = ALIGN({LINE});  /* {name}: start on a cache line */")
            lines.append(wrap(units[uid]["selector"]))
        old_end = region["end"] - model["outputs"][output]["address"]
        text = "".join(f"{line}\n{indent}" for line in lines) + script[s0:s1] + \
            f"\n{indent}. = MAX(., 0x{old_end:x});  /* {name}: keeps what follows this region in place */"
        edits.append((s0, s1, text))
    for s0, s1, text in sorted(edits, reverse=True):
        script = script[:s0] + text + script[s1:]
    return script


def check_inputs(model):
    for item in model["inputs"]:
        if sha256(item["path"]) != item["sha256"]:
            raise ValueError(f"input changed since analysis: {item['path']}; reanalyze before relinking")


def _link_key(uid):
    """A unit id that survives relinking: GCC names LTO partitions after the
    output, so they are matched by partition number."""
    match = LTRANS_ID.match(uid)
    return f"*{match[1]}{match[2]}" if match else uid


def actual_addresses(model, fresh):
    """Where each analyzed unit ended up in a freshly linked model of the same inputs."""
    new = {_link_key(u["id"]): u for u in fresh["units"]}
    addresses = {}
    for old in model["units"]:
        u = new.pop(_link_key(old["id"]), None)
        if not u or u["size"] != old["size"]:
            raise ValueError(f"input section missing or changed in the new link: {old['id']}")
        addresses[old["id"]] = u["address"]
    extra = set(new)
    if extra:
        raise ValueError(f"the new link has input sections the analysis did not: {sorted(extra)[:3]}")
    if model["entry"] != fresh["entry"]:
        raise ValueError(f"the entry point moved from 0x{model['entry']:08x} to 0x{fresh['entry']:08x}")
    addresses["_data_end"] = fresh["data_end"]
    return addresses
