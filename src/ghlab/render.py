"""Render a call tree as DOT, Mermaid or a self-contained SVG.

No Ghidra and no third-party dependency: the graph JSON that `cmd_graph` already
returns is enough. SVG is laid out by BFS level (columns) so it opens in any browser
and can be dropped into a report.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from xml.sax.saxutils import escape

RENDERERS: dict[str, Callable[[dict[str, Any]], str]] = {}


def _levels(result: dict[str, Any]) -> dict[str, int]:
    root = result.get("root") or ""
    adj: dict[str, list[str]] = {}
    for edge in result.get("edges") or []:
        adj.setdefault(edge["from"], []).append(edge["to"])
    level = {root: 0}
    frontier = [root]
    while frontier:
        nxt: list[str] = []
        for name in frontier:
            for child in adj.get(name, []):
                if child not in level:
                    level[child] = level[name] + 1
                    nxt.append(child)
        frontier = nxt
    for node in result.get("nodes") or []:
        level.setdefault(node["name"], 0)
    return level


def _label(node: dict[str, Any]) -> str:
    return f"{node['name']} ({node.get('size', 0)}b)"


def _quoted(text: str) -> str:
    """A DOT/Mermaid string literal: quotes and newlines would end the label early."""
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


def _mermaid(text: str) -> str:
    """Mermaid escapes a quote as an entity, not with a backslash."""
    newline = chr(10)
    return '"' + text.replace('"', "#quot;").replace(newline, " ") + '"'


def dot(result: dict[str, Any]) -> str:
    lines = ["digraph calls {", "  rankdir=LR;", "  node [shape=box, fontname=monospace];"]
    for node in result.get("nodes") or []:
        style = (
            ", style=filled, fillcolor=lightyellow" if node["name"] == result.get("root") else ""
        )
        lines.append(f"  {_quoted(node['name'])} [label={_quoted(_label(node))}{style}];")
    for edge in result.get("edges") or []:
        lines.append(f"  {_quoted(edge['from'])} -> {_quoted(edge['to'])};")
    lines.append("}")
    return "\n".join(lines)


def mermaid(result: dict[str, Any]) -> str:
    lines = ["flowchart LR"]
    ids = {node["name"]: f"n{i}" for i, node in enumerate(result.get("nodes") or [])}
    for node in result.get("nodes") or []:
        lines.append(f"  {ids[node['name']]}[{_mermaid(_label(node))}]")
    for edge in result.get("edges") or []:
        if edge["from"] in ids and edge["to"] in ids:
            lines.append(f"  {ids[edge['from']]} --> {ids[edge['to']]}")
    return "\n".join(lines)


def svg(result: dict[str, Any]) -> str:
    nodes = result.get("nodes") or []
    edges = result.get("edges") or []
    level = _levels(result)
    by_level: dict[int, list[dict[str, Any]]] = {}
    for node in nodes:
        by_level.setdefault(level.get(node["name"], 0), []).append(node)

    box_h, gap_y, gap_x, pad = 30, 14, 70, 24
    char_w = 7.2
    widths = {node["name"]: max(120.0, len(_label(node)) * char_w + 18) for node in nodes}
    col_w = {lvl: max(widths[n["name"]] for n in group) for lvl, group in by_level.items()}
    x_of: dict[int, float] = {}
    x = pad
    for lvl in sorted(by_level):
        x_of[lvl] = x
        x += col_w[lvl] + gap_x
    width = x - gap_x + pad
    height = max((len(g) for g in by_level.values()), default=1) * (box_h + gap_y) - gap_y + 2 * pad

    pos: dict[str, tuple[float, float]] = {}
    for lvl, group in by_level.items():
        total = len(group) * (box_h + gap_y) - gap_y
        y = (height - total) / 2
        for node in group:
            w = widths[node["name"]]
            pos[node["name"]] = (x_of[lvl] + (col_w[lvl] - w) / 2, y)
            y += box_h + gap_y

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
        f'viewBox="0 0 {width:.0f} {height:.0f}">',
        '<defs><marker id="a" markerWidth="10" markerHeight="7" refX="9" refY="3.5" '
        'orient="auto"><path d="M0,0 L10,3.5 L0,7 z" fill="#666"/></marker></defs>',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{pad}" y="16" font-family="monospace" font-size="12" fill="#333">'
        f"{escape(result.get('root') or '')} ({result.get('direction', 'calling')})</text>",
    ]
    for edge in edges:
        if edge["from"] not in pos or edge["to"] not in pos:
            continue
        x1, y1 = pos[edge["from"]]
        x2, y2 = pos[edge["to"]]
        x1 += widths[edge["from"]]
        y1 += box_h / 2
        y2 += box_h / 2
        out.append(
            f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2 - 2:.0f}" y2="{y2:.0f}" '
            'stroke="#666" stroke-width="1" marker-end="url(#a)"/>'
        )
    for node in nodes:
        x, y = pos[node["name"]]
        w = widths[node["name"]]
        root = node["name"] == result.get("root")
        out.append(
            f'<rect x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{box_h}" rx="4" '
            f'fill="{"#fff8dc" if root else "#f7f7f7"}" stroke="#444"/>'
        )
        out.append(
            f'<text x="{x + w / 2:.0f}" y="{y + box_h / 2 + 4:.0f}" text-anchor="middle" '
            f'font-family="monospace" font-size="11" fill="#111">{escape(_label(node))}</text>'
        )
    out.append("</svg>")
    return "\n".join(out)


RENDERERS.update({"dot": dot, "mermaid": mermaid, "svg": svg})
