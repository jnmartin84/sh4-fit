"""Placement units: the input sections of a linked SH-4 executable.

A unit is one input section as the GNU ld map places it. Units are grouped into
*regions*: the input sections that one wildcard statement of the linker script
places (KallistiOS's `*(.text .stub .text.* .gnu.linkonce.t.*)` in `.text`, and
the `.rodata.*`, `.data.*` and `.bss.*` statements for data). A region's units
can be reordered by listing them, with selectors that match exactly one input
section each, ahead of that wildcard.

Structure follows MipsFit's model (MIT, Copyright (c) 2026 Kevin R.), extended
to data sections, archive members and file-qualified selectors.
"""
from __future__ import annotations

import bisect
from collections import Counter, defaultdict
from fnmatch import fnmatchcase
from pathlib import Path
import re
import subprocess

from .elf import (Elf, SHF_ALLOC, SHF_EXECINSTR, SHF_MERGE, SHT_NOBITS, STT_FUNC, STT_OBJECT, input_elfs,
                  sha256)

# -function-sections / -fdata-sections names a wildcard statement must cover for
# its output section to become a reorderable region.
REGION_PATTERNS = {".text.*": "code", ".rodata.*": "data", ".data.*": "data", ".bss.*": "data"}
SAFE_NAME = re.compile(r"[.A-Za-z0-9_$@+-]+")
SAFE_PATH = re.compile(r"[A-Za-z0-9_./+@-]+")
LTRANS = re.compile(r"\.ltrans\d+\.ltrans\.o$")


def run_tool(prefix, name, args, stdin=None):
    result = subprocess.run([prefix + name, *map(str, args)], input=stdin, text=True,
                            encoding="utf-8", errors="replace", capture_output=True, timeout=120)
    if result.returncode:
        raise ValueError(f"{name}: {result.stderr.strip()}")
    return result.stdout


def physical(address):
    return address & 0x1FFFFFFF


def parse_map(text):
    """Placed input sections, the statements that placed them, output sections,
    and every input file the link loaded."""
    if "Linker script and memory map" not in text:
        raise ValueError("expected a GNU ld map with 'Linker script and memory map' (link with -Wl,-Map=FILE)")
    head, body = text.split("Linker script and memory map", 1)
    owners = set()
    # "Archive member included ...", the common symbol table and "Discarded input
    # sections" name loaded inputs too.
    common = False
    for line in head.splitlines():
        if line.startswith(("Allocating common symbols", "Discarded input sections")):
            common = line.startswith("Allocating")
            continue
        if common:
            match = re.match(r"^(?:\S+)?\s+0x[\da-fA-F]+\s+(\S.*?)\s*$", line)  # symbol, size, file
            if match:
                owners.add(match[1])
            continue
        match = re.match(r"^(\S.*\([^()]+\))\s*$", line)
        if match and not line.startswith(("Archive member", "Discarded", "Memory", "Name")):
            owners.add(match[1])
        match = re.match(r"^ \S+\s+0x[\da-fA-F]+\s+0x[\da-fA-F]+\s+(.+?)\s*$", line)
        if match:
            owners.add(match[1])
    rows, loads, outputs, statements, markers = [], [], {}, [], []
    pending, output, statement = None, None, None
    row = re.compile(r"^ (\.\S+|COMMON)\s+(0x[\da-fA-F]+)\s+(0x[\da-fA-F]+)\s+(.+?)\s*$")
    # alignment fill and data statements also occupy the output section
    marker = re.compile(r"^ (?:\*fill\*)?\s+(0x[\da-fA-F]+)\s+(0x[\da-fA-F]+)\s*(?:$|BYTE|SHORT|LONG|QUAD|SQUAD|FILL)")
    name_only = re.compile(r"^ (\.\S+|COMMON)\s*$")
    continuation = re.compile(r"^\s+(0x[\da-fA-F]+)\s+(0x[\da-fA-F]+)\s+(.+?)\s*$")
    header = re.compile(r"^(\.\S+)(?:\s+(0x[\da-fA-F]+)\s+(0x[\da-fA-F]+))?\s*$")
    header_pending = None
    for seq, line in enumerate(body.splitlines()):
        if line.startswith("Cross Reference Table"):
            break
        if line.startswith("LOAD "):
            loads.append(line[5:].strip())
            continue
        if header_pending:
            match = re.match(r"^\s+(0x[\da-fA-F]+)\s+(0x[\da-fA-F]+)\s*$", line)
            if match:
                outputs[header_pending].update(address=int(match[1], 16), size=int(match[2], 16))
                header_pending = None
                continue
            header_pending = None
        match = header.match(line)
        if match:
            output, statement = match[1], None
            outputs[output] = dict(name=output, address=int(match[2], 16) if match[2] else None,
                                   size=int(match[3], 16) if match[3] else 0, order=len(outputs))
            if not match[2]:
                header_pending = output
            pending = None
            continue
        if output and not pending and (match := marker.match(line)) and int(match[2], 16):
            markers.append(dict(address=int(match[1], 16), output=output, seq=seq))
            continue
        match = row.match(line)
        if match:
            name, address, size, owner = match.groups()
        elif pending and (match := continuation.match(line)):
            name = pending
            address, size, owner = match.groups()
        else:
            match = name_only.match(line)
            pending = match[1] if match else None
            if not match and output and re.match(r"^ [^\s.\[0-9][^\s]*.*\)\s*$", line) and "(" in line:
                statement = len(statements)
                statements.append(dict(output=output, text=line.strip()))
            continue
        pending = None
        if owner.startswith(("load address", "0x")):
            continue
        owners.add(owner)
        if int(size, 16):
            rows.append(dict(section=name, address=int(address, 16), size=int(size, 16), owner=owner,
                             output=output, statement=statement, seq=seq))
    _extents(rows, markers, outputs)
    return dict(rows=rows, loads=list(dict.fromkeys(loads)), outputs=outputs, statements=statements,
                owners=owners | set(loads))


def _extents(rows, markers, outputs):
    """Set each row's `extent`: the bytes it really occupies, up to whatever the
    map places next. ld prints a mergeable section (`.rodata.*.str1.4`,
    `.rodata.cst4`) with its unmerged size, but after merging one input section
    of each kind holds the merged contents and the rest take no space, so the
    map shows them all at the same address."""
    items = defaultdict(list)
    for item in rows + markers:
        items[item["output"]].append(item)
    for name, seq in items.items():
        seq.sort(key=lambda item: item["seq"])
        out = outputs.get(name) or {}
        end = (out["address"] + out["size"]) if out.get("address") is not None else None
        for item, after in zip(seq, seq[1:] + [None]):
            if "size" not in item:
                continue
            following = after["address"] if after else end
            item["extent"] = (item["size"] if following is None or following < item["address"]
                              else min(item["size"], following - item["address"]))


def split_owner(owner):
    """'lib/libfoo.a(bar.o)' -> ('lib/libfoo.a', 'bar.o'); 'x.o' -> ('x.o', '')."""
    match = re.match(r"^(.*)\(([^()]*)\)$", owner)
    return (match[1], match[2]) if match else (owner, "")


def resolve(path, build_dir):
    p = Path(path.replace("\\", "/"))
    return (p if p.is_absolute() else Path(build_dir) / p).resolve()


def statement_patterns(text):
    """Section-name patterns of an input statement as the map prints it:
    'KEEP (*(SORT_NONE(.init)))' -> ['.init'], '*(.text .text.*)' -> ['.text', '.text.*']."""
    keywords = {"KEEP", "SORT", "SORT_NONE", "SORT_BY_NAME", "SORT_BY_ALIGNMENT", "SORT_BY_INIT_PRIORITY",
                "EXCLUDE_FILE", "REVERSE"}
    tokens = [t for t in re.sub(r"[()]", " ", text).split() if t not in keywords]
    return tokens[1:]  # the first token is the file pattern


class Inventory:
    """Every allocated input section of the files the link loaded, under the
    names ld matched them by (the map's spelling), so a selector can be checked
    to pick up exactly one input section the way ld will."""

    def __init__(self):
        self.sections = []          # (file as ld names it, archive member or "", section name)
        self.by_key = defaultdict(list)
        self.name_counts = Counter()

    def add(self, name, member, elf):
        for section in elf.allocated():
            key = (name, member, section["name"])
            self.sections.append(key)
            self.by_key[key].append(section)
            self.name_counts[section["name"]] += 1

    def matches(self, file_pattern, section):
        """Input sections the ld selector `file_pattern(section)` picks up.
        'archive:member' matches archive members, ':file' only files outside
        archives, and a plain pattern both files and archive members by name."""
        found = []
        archive = member_pattern = None
        if ":" in file_pattern:
            archive, member_pattern = file_pattern.split(":", 1)
        for name, member, sec in self.sections:
            if sec != section:
                continue
            if archive is None:
                hit = fnmatchcase(member, file_pattern) if member else fnmatchcase(name, file_pattern)
            elif not archive:
                hit = not member and fnmatchcase(name, member_pattern)
            else:
                hit = bool(member) and fnmatchcase(name, archive) and fnmatchcase(member, member_pattern or "*")
            if hit:
                found.append((name, member, sec))
        return found


def selector_for(inventory, name, member, section):
    """The simplest ld input-section description that selects only this section."""
    if not SAFE_NAME.fullmatch(section) or section == "COMMON":
        return None
    if inventory.name_counts[section] == 1:
        return f"*({section})"
    if member:
        if not SAFE_PATH.fullmatch(member) or not SAFE_PATH.fullmatch(name):
            return None
        options = [f"*{Path(name).name}:{member}", f"*{name}:{member}"]
    else:
        if not SAFE_PATH.fullmatch(name):
            return None
        options = [f"*{Path(name).name}", f"*{name}", f":*{Path(name).name}", f":*{name}"]
        lto = LTRANS.search(name)
        if lto:
            # GCC names LTO partitions after the output (or a temporary file); the
            # partition number is what stays the same when the inputs do.
            options.insert(0, f"*{lto[0]}")
    for pattern in options:
        if inventory.matches(pattern, section) == [(name, member, section)]:
            return f"{pattern}({section})"
    return None


def function_ranges(elf, kinds=(STT_FUNC,), sections=None):
    """Named symbol ranges, merged where symbols overlap."""
    wanted = {s["index"]: s for s in (sections or elf.executable())}
    by_address = defaultdict(list)
    for symbol in elf.symbols:
        if symbol["type"] in kinds and symbol["section"] in wanted and symbol["name"]:
            by_address[symbol["address"]].append(symbol)
    ranges = []
    addresses = sorted(by_address)
    for i, address in enumerate(addresses):
        symbols = by_address[address]
        section = wanted[symbols[0]["section"]]
        size = max(s["size"] for s in symbols)
        inferred = size == 0
        if inferred:
            limit = section["address"] + section["size"]
            if i + 1 < len(addresses):
                limit = min(limit, addresses[i + 1])
            size = limit - address
        if size <= 0 or address + size > section["address"] + section["size"]:
            continue
        names = sorted(set(s["name"] for s in symbols))
        item = dict(address=address, size=size, names=names, name=names[0], inferred_size=inferred)
        if ranges and address < ranges[-1]["address"] + ranges[-1]["size"]:
            prev = ranges[-1]
            prev["size"] = max(prev["size"], address + size - prev["address"])
            prev["names"] += names
        else:
            ranges.append(item)
    return ranges


def display_name(symbol):
    """The C name: SH ELF prefixes every C symbol with an underscore."""
    return symbol[1:] if symbol.startswith("_") else symbol


def make_model(elf_path, map_path, build_dir=None, prefix="sh-elf-", source_lookup=True):
    elf_path = Path(elf_path).resolve()
    elf = Elf.read(elf_path)
    if elf.type != 2 or not elf.symbols:
        raise ValueError("analysis requires an unstripped, linked executable ELF")
    parsed = parse_map(Path(map_path).read_text(encoding="utf-8", errors="replace"))
    build_dir = Path(build_dir or Path(map_path).resolve().parent).resolve()
    warnings = []

    # --- read every loaded input once -----------------------------------------
    loaded = defaultdict(set)   # file as ld names it -> loaded archive members ("" for objects)
    for owner in parsed["owners"]:
        name, member = split_owner(owner)
        loaded[name].add(member)
    placed = {split_owner(row["owner"]) for row in parsed["rows"]}
    inventory, inputs, unreadable = Inventory(), [], set()
    for name in sorted(loaded):
        path = resolve(name, build_dir)
        try:
            for member, obj in input_elfs(path):
                # An LTO object that placed nothing was claimed by the LTO plugin:
                # its code comes from the ltrans objects, and ld never matches its
                # own (fat) sections.
                claimed = ((name, member) not in placed
                           and any(s["name"].startswith(".gnu.lto_") for s in obj.sections))
                if (member in loaded[name] or (not member and "" in loaded[name])) and not claimed:
                    inventory.add(name, member, obj)
            if not LTRANS.search(name):  # LTO partitions are outputs of each link, not inputs
                inputs.append(dict(path=str(path), sha256=sha256(path)))
        except (OSError, ValueError) as exc:
            unreadable.add(name)
            warnings.append(f"Cannot read linker input {path}: {exc}")

    # --- output sections and regions ------------------------------------------
    by_name = {s["name"]: s for s in elf.sections}
    outputs = {}
    for name, out in parsed["outputs"].items():
        section = by_name.get(name)
        if not section or not section["flags"] & SHF_ALLOC or not section["size"]:
            continue
        outputs[name] = dict(name=name, address=section["address"], size=section["size"],
                             align=max(1, section["align"]), nobits=section["type"] == SHT_NOBITS,
                             kind="code" if section["flags"] & SHF_EXECINSTR else "data")
    regions = {}
    for index, st in enumerate(parsed["statements"]):
        out = outputs.get(st["output"])
        if not out or st["output"] in regions:
            continue
        patterns = statement_patterns(st["text"])
        kinds = {REGION_PATTERNS[p] for p in patterns if p in REGION_PATTERNS}
        if out["kind"] in kinds:
            regions[st["output"]] = dict(name=st["output"].lstrip(".") or st["output"], output=st["output"],
                                         statement=index, text=st["text"], kind=out["kind"])

    # --- units ----------------------------------------------------------------
    units, seen = [], Counter()
    for row in parsed["rows"]:
        out = outputs.get(row["output"])
        if not out:
            continue
        name, member = split_owner(row["owner"])
        path = str(resolve(name, build_dir))
        uid = f"{path}({member}):{row['section']}" if member else f"{path}:{row['section']}"
        seen[uid] += 1
        if seen[uid] > 1:
            uid += f"#{seen[uid]}"
        found = inventory.by_key.get((name, member, row["section"]), [])
        info = found[0] if len(found) == 1 else None
        # the map gives a mergeable section's merged size, or its own when merged away
        verified = bool(info and (info["size"] == row["size"] or info["flags"] & SHF_MERGE))
        info = info if verified else None
        region = regions.get(row["output"])
        in_region = bool(region and row["statement"] == region["statement"])
        unit = dict(id=uid, section=row["section"], owner=row["owner"], path=path, member=member,
                    output=row["output"], address=row["address"], size=row["extent"],
                    align=max(1, info["align"]) if info else _known_alignment(row["address"], out["align"]),
                    kind=out["kind"],
                    region=region["output"] if in_region else None, verified=verified,
                    merge=bool(info and info["flags"] & SHF_MERGE), nobits=out["nobits"],
                    selector=None, movable=False, reason="", symbols=[])
        if row["section"] == "COMMON":
            unit["reason"] = "COMMON symbols (build with -fno-common)"
        elif not verified:
            unit["reason"] = ("its input object could not be read" if name in unreadable
                              else "the map's size does not match its input object")
        elif unit["merge"]:
            unit["reason"] = "a mergeable constant/string section (its size changes when merged)"
        elif not in_region:
            unit["reason"] = (f"placed by a different statement than the {region['text']} wildcard" if region
                              else f"{row['output']} has no reorderable wildcard")
        else:
            unit["selector"] = selector_for(inventory, name, member, row["section"])
            if not unit["selector"]:
                unit["reason"] = "no linker-script selector matches only this section"
        unit["movable"] = not unit["reason"]
        units.append(unit)
    units.sort(key=lambda u: (u["address"], u["kind"]))
    for a, b in zip(units, units[1:]):
        if a["address"] + a["size"] > b["address"] and a["kind"] == b["kind"] and not (a["nobits"] or b["nobits"]):
            raise ValueError(f"overlapping input sections {a['id']} and {b['id']}; unsupported map")

    # The region holding the entry point keeps everything up to it in place
    # (KallistiOS's startup.o must stay at the load address).
    entry_unit = next((u for u in units if u["address"] <= elf.entry < u["address"] + u["size"]), None)
    for region in regions.values():
        members = [u for u in units if u["region"] == region["output"]]
        region["start"] = members[0]["address"] if members else None
        region["end"] = max((u["address"] + u["size"] for u in members), default=None)
        if entry_unit in members:
            for u in members[:members.index(entry_unit) + 1]:
                u["prefix"] = True
                u["movable"] = False
                u["reason"] = "holds the entry point (or precedes it), which must stay at the load address"
                if not u["selector"]:
                    region["blocked"] = (f"{u['id']} precedes the entry point but no selector matches only it, "
                                         "so a generated script cannot keep it first")

    # --- names for reports ----------------------------------------------------
    starts = [u["address"] for u in units]
    alloc = elf.allocated()
    functions = function_ranges(elf, (STT_FUNC,), elf.executable())
    objects = function_ranges(elf, (STT_OBJECT,), [s for s in alloc if not s["flags"] & SHF_EXECINSTR])
    for kind, items in (("code", functions), ("data", objects)):
        for item in items:
            i = bisect.bisect_right(starts, item["address"]) - 1
            while i >= 0 and units[i]["address"] == item["address"] and units[i]["kind"] != kind:
                i -= 1
            if i >= 0 and item["address"] < units[i]["address"] + units[i]["size"]:
                units[i]["symbols"].append(display_name(item["name"]))
    if source_lookup and functions:
        try:
            text = run_tool(prefix, "addr2line", ["-e", elf_path, "-f"],
                            "".join(f"0x{f['address']:x}\n" for f in functions)).splitlines()
            if len(text) == 2 * len(functions):
                for i, f in enumerate(functions):
                    f["source"] = text[2 * i + 1]
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            warnings.append(f"Source lookup skipped: {exc}")
    for f in functions:
        f["name"] = display_name(f["name"])
        f.setdefault("source", "??:0")

    ram = [s for s in alloc if 0x0C000000 <= physical(s["address"]) < 0x10000000]
    data_end = max((s["address"] + s["size"] for s in ram), default=0)
    special = {name: s["address"] for s in elf.symbols for name in ("start", "_start", "_end", "end")
               if s["name"] == name}
    for name, region in regions.items():
        if not any(u["movable"] for u in units if u["region"] == name):
            region["blocked"] = region.get("blocked") or "no input section in it can be moved"
    if unreadable:
        warnings.append(f"{len(unreadable)} linker input(s) unreadable; their sections stay in place. "
                        "Pass the directory the linker ran in as --build-dir.")
    return dict(version=1, elf=str(elf_path), elf_sha256=sha256(elf_path), map=str(Path(map_path).resolve()),
                build_dir=str(build_dir), entry=elf.entry, special_symbols=special, data_end=data_end,
                outputs=outputs, regions=regions, units=units, functions=functions, objects=objects,
                inputs=inputs, warnings=warnings)


def _known_alignment(address, output_align):
    """The most an input section unread (or edited by ld, like .eh_frame) can be
    aligned to: no more than its output section, which takes its inputs' largest
    alignment, and no more than its address shows."""
    return max(1, min(output_align, address & -address if address else output_align))


def unit_names(model, unit, limit=3):
    names = unit["symbols"] or [unit["section"]]
    text = ", ".join(names[:limit])
    return text + (f" +{len(names) - limit} more" if len(names) > limit else "")
