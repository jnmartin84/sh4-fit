"""Temporal relationship graphs over 32-byte chunks of code or data.

Gloy & Smith ("Procedure Placement Using Temporal-Ordering Information",
TOPLAS 1999): the weight between two chunks is how often one of them is used
between two uses of the other. Chunks that interleave that way evict each other
whenever a layout maps them to the same cache slot, so the weighted sum over
slot-sharing pairs estimates a layout's conflict misses without replaying it.
The same construction works for the operand cache, with one chunk per data
access run instead of per fetched line.

Adapted from MipsFit's trg.py (MIT, Copyright (c) 2026 Kevin R.).
"""
from __future__ import annotations

from collections import defaultdict
import heapq

try:  # C helper behind Counter.update; keeps the inner loop out of Python
    from collections import _count_elements
except ImportError:  # pragma: no cover
    def _count_elements(mapping, iterable):
        for item in iterable:
            mapping[item] = mapping.get(item, 0) + 1

from . import sh4trace as fmt
from .trace import bounds

CHUNK_SPAN = 1 << 25  # chunk keys per unit: enough for physical line numbers


class Graph:
    """Parallel unit/offset arrays identify each chunk; the FIXED and HEAP
    pseudo-units (the last two unit indices) hold everything outside units."""

    def __init__(self, source, index, kind):
        self.source, self.index, self.kind = source, index, kind
        self.ids = {}
        self.unit, self.offset, self.touches, self.neighbors = [], [], [], []
        self.transitions = defaultdict(float)
        self.unit_touches = defaultdict(float)
        self.active = []

    def chunk(self, unit, offset):
        key = unit * CHUNK_SPAN + (offset >> 5)
        index = self.ids.get(key)
        if index is None:
            index = self.ids[key] = len(self.unit)
            self.unit.append(unit)
            self.offset.append(offset >> 5 << 5)
            self.touches.append(0.0)
            self.neighbors.append({})
        return index

    def connect(self, a, b, weight):
        if a == b or not weight:
            return
        na, nb = self.neighbors[a], self.neighbors[b]
        na[b] = na.get(b, 0.0) + weight
        nb[a] = nb.get(a, 0.0) + weight

    def finish(self):
        self.active = [c for c, n in enumerate(self.neighbors) if n]
        self.unit_touches = defaultdict(float)
        for c, weight in enumerate(self.touches):
            self.unit_touches[self.unit[c]] += weight
        self.unit_chunks = defaultdict(list)
        for c in range(len(self.unit)):
            self.unit_chunks[self.unit[c]].append(c)
        return self


def _frames(trace, marks, total, frames):
    b = bounds(marks, total)
    for first, end, _ in frames or [(0, len(b), 0)]:
        yield [b[f] for f in range(first, end)]


def code_sequence(graph, trace, frames=None):
    """Chunk ids with -1 at window boundaries and resets; touch counts per chunk."""
    chunk = graph.chunk
    table = [[chunk(u, o) for u, s, e in parts for o in range(s >> 5 << 5, ((e - 2) >> 5 << 5) + 1, 32)]
             for parts in trace["ranges"]]
    segs = trace["segments"]
    resets = {p for p, k in zip(trace["code_events"][0::4], trace["code_events"][1::4]) if k == fmt.RESET}
    sequence, weights = [], defaultdict(float)
    append = sequence.append
    for window in _frames(trace, trace["code_frames"], len(segs), frames):
        append(-1)
        last = -1
        for start, stop in window:
            for index in range(start, stop):
                if index in resets:
                    append(-1)
                    last = -1
                w = segs[index]
                n = w & 255
                for c in table[w >> 8]:
                    weights[c] += n
                    if c != last:
                        append(c)
                        last = c
    return sequence, weights


def data_sequence(graph, trace, frames=None):
    chunk = graph.chunk
    words, offsets = trace["data"], trace["data_offsets"]
    resets = {p for p, k in zip(trace["data_events"][0::4], trace["data_events"][1::4]) if k == fmt.RESET}
    sequence, weights = [], defaultdict(float)
    append = sequence.append
    memo = {}
    for window in _frames(trace, trace["data_frames"], len(words), frames):
        append(-1)
        last = -1
        for start, stop in window:
            for index in range(start, stop):
                if index in resets:
                    append(-1)
                    last = -1
                w = words[index]
                if (w >> 16) & 15 > fmt.OP_MOVCA:
                    continue  # ocbi/ocbp/ocbwb manage lines, they do not use them
                key = (w & 0xFFFF) * CHUNK_SPAN + (offsets[index] >> 5)
                c = memo.get(key)
                if c is None:
                    c = memo[key] = chunk(w & 0xFFFF, offsets[index])
                weights[c] += 1
                if c != last:
                    append(c)
                    last = c
    return sequence, weights


def _hot(weights, coverage=0.99999, minimum=2):
    total = sum(weights.values())
    keep, seen = set(), 0.0
    for c, n in sorted(weights.items(), key=lambda item: (-item[1], item[0])):
        if n < minimum or seen >= coverage * total:
            break
        keep.add(c)
        seen += n
    return keep


def _temporal(graph, sequence, scale, recency):
    """Count, for every chunk, which other chunks were used since its previous use."""
    pairs = defaultdict(dict)
    stack, window = [], set()
    index, insert, pop = stack.index, stack.insert, stack.pop
    for x in sequence:
        if x < 0:
            stack.clear()
            window.clear()
            continue
        if x in window:
            i = index(x)
            if i:
                _count_elements(pairs[x], stack[:i])
                del stack[i]
                insert(0, x)
        else:
            insert(0, x)
            window.add(x)
            if len(stack) > recency:
                window.discard(pop())
    for x, others in pairs.items():
        for y, n in others.items():
            graph.connect(x, y, n * scale)


def build(traces, kind, index, frames=None, coverage=0.99999):
    """The graph for `kind` ('code' or 'data') from imported traces. `frames`
    maps a trace name to frame windows (cache.windows), or None for everything."""
    graph = Graph("trace", index, kind)
    for trace in traces:
        if kind == "data" and not trace["has_data"]:
            continue
        windows = (frames or {}).get(trace["name"])
        sequence, weights = (code_sequence if kind == "code" else data_sequence)(graph, trace, windows)
        replayed = sum(e - f for f, e, _ in windows) if windows else len(trace["code_frames"]) + 1
        scale = trace["weight"] / max(1, replayed)
        for c, n in weights.items():
            graph.touches[c] += n * scale
        keep = _hot(weights, coverage)
        hot, last = [], -1
        for c in sequence:
            if c < 0:
                hot.append(c)
                last = -1
            elif c in keep and c != last:
                hot.append(c)
                last = c
        _temporal(graph, hot, scale, index.lines)
        if kind == "code":
            total = max(1, len(trace["code_frames"]) + 1)
            for a, b, n in trace["transitions"]:
                graph.transitions[a, b] += n * trace["weight"] / total
    return graph.finish()


def lines(graph, base):
    return [(base[u] + offset) >> 5 for u, offset in zip(graph.unit, graph.offset)]


def alias_pairs(graph, base):
    """Yield (weight, chunk, chunk) once per edge between chunks that share a
    cache slot while holding different lines."""
    line = lines(graph, base)
    slot = graph.index.slot
    slots = defaultdict(list)
    for c in graph.active:
        slots[slot(line[c])].append(c)
    neighbors = graph.neighbors
    for members in slots.values():
        count = len(members)
        if count < 2:
            continue
        for i in range(count):
            a = members[i]
            la, na = line[a], neighbors[a]
            for j in range(i + 1, count):
                b = members[j]
                if line[b] != la:
                    weight = na.get(b)
                    if weight:
                        yield weight, a, b


def alias_cost(graph, base, top=0):
    """Weighted interleaving between slot-sharing chunks: estimated conflict misses."""
    cost = 0.0
    worst = []
    for weight, a, b in alias_pairs(graph, base):
        cost += weight
        if top:
            worst.append((weight, a, b))
    if not top:
        return cost, []
    return cost, heapq.nlargest(top, worst)


def describe(graph, units, pairs, base):
    """(weight, chunk, chunk) tuples as report rows."""
    line = lines(graph, base)
    fixed = len(units)

    def side(c):
        u = graph.unit[c]
        name = units[u]["id"] if u < fixed else ("fixed" if u == fixed else "heap")
        return dict(unit=name, offset=graph.offset[c], line=line[c])

    return [dict(weight=round(w, 3), a=side(a), b=side(b), slot=graph.index.slot(line[a])) for w, a, b in pairs]
