"""Campaign clustering: group every program in the project by what it *does*.

The unit of comparison is the whole program (union of its function fingerprints),
not a function. Two samples land in the same cluster when they share enough imports
and strings, which is usually enough to separate families/loaders from unrelated
tools without symbols or database access.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def jaccard(a: Iterable[Any], b: Iterable[Any]) -> float:
    a, b = set(a), set(b)
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def pair_score(a: dict[str, Any], b: dict[str, Any], import_weight: float = 0.6) -> float:
    """Blend imports and strings; imports are the stronger signal in practice."""
    imports = jaccard(a.get("imports", ()), b.get("imports", ()))
    strings = jaccard(a.get("strings", ()), b.get("strings", ()))
    return round(import_weight * imports + (1.0 - import_weight) * strings, 4)


def _cluster_order(cluster: dict[str, Any]) -> tuple[int, float, str]:
    """Biggest cluster first, then best internal score, then a stable name."""
    return (-int(cluster["size"]), -float(cluster["max_score"]), str(cluster["members"][0]))


def _one_line(value: str, width: int = 60) -> str:
    """Collapse whitespace and truncate, so evidence stays one line per string."""
    text = " ".join(str(value).split())
    return text if len(text) <= width else text[: width - 1] + "~"


def _string_evidence(values: set[str], limit: int = 5) -> list[str]:
    """The most telling shared strings: long first, placeholders and padding dropped."""
    useful = [v for v in values if len(v.strip()) >= 4]
    useful.sort(key=len, reverse=True)
    return [_one_line(v) for v in useful[:limit]]


def cluster_programs(
    profiles: dict[str, dict[str, Any]],
    min_score: float = 0.35,
) -> list[dict[str, Any]]:
    """Single-linkage clustering over pairwise scores.

    Single linkage is deliberate: a packer stub between two samples should still
    pull them into one cluster, and with a handful of programs the transitive
    chaining risk is smaller than the cost of missing a family.
    """
    names = sorted(profiles)
    parent = {name: name for name in names}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[max(rx, ry)] = min(rx, ry)

    edges: list[tuple[str, str, float]] = []
    for i, a in enumerate(names):
        for b in names[i + 1 :]:
            score = pair_score(profiles[a], profiles[b])
            if score >= min_score:
                union(a, b)
                edges.append((a, b, score))

    groups: dict[str, list[str]] = {}
    for name in names:
        groups.setdefault(find(name), []).append(name)

    clusters: list[dict[str, Any]] = []
    for members in groups.values():
        members = sorted(members)
        shared_imports: set[str] = (
            set.intersection(*(set(profiles[m].get("imports", ())) for m in members))
            if len(members) > 1
            else set()
        )
        shared_strings: set[str] = (
            set.intersection(*(set(profiles[m].get("strings", ())) for m in members))
            if len(members) > 1
            else set()
        )
        best = max(
            (
                pair_score(profiles[x], profiles[y])
                for i, x in enumerate(members)
                for y in members[i + 1 :]
            ),
            default=0.0,
        )
        clusters.append(
            {
                "size": len(members),
                "members": members,
                "max_score": round(best, 3),
                "shared_imports": sorted(shared_imports)[:8],
                "shared_strings": _string_evidence(shared_strings),
            }
        )
    clusters.sort(key=_cluster_order)
    return clusters


def profile_from_fingerprints(prints: dict[str, Any]) -> dict[str, Any]:
    """Flatten one program's function fingerprints into a program-level profile."""
    imports: set[str] = set()
    strings: set[str] = set()
    for fp in prints.get("functions", {}).values():
        imports.update(fp.get("imports") or ())
        strings.update(fp.get("strings") or ())
    return {
        "imports": imports,
        "strings": strings,
        "functions": len(prints.get("functions") or {}),
        "md5": prints.get("md5"),
        "size": prints.get("size"),
    }
