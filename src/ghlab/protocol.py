"""Wire protocol for ghlab: one JSON object per POST, one JSON object back.

Request  {"cmd": "<name>", ...params}
Success  {"ok": true,  "result": {...}, "ms": 123}
Failure  {"ok": false, "error": "Type: message", "trace": "..."}

This module has no Ghidra dependency so it can be imported (and unit tested)
anywhere.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

DEFAULT_PORT = 8765
DEFAULT_HOST = "127.0.0.1"


class ProtocolError(ValueError):
    """Bad request: unknown command, missing/extra parameter, wrong type."""


@dataclass(frozen=True)
class Spec:
    """Declared parameters of one command."""

    name: str
    required: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()
    summary: str = ""

    def check(self, params: dict[str, Any]) -> dict[str, Any]:
        missing = [k for k in self.required if k not in params]
        if missing:
            raise ProtocolError(f"{self.name}: missing {missing}")
        allowed = set(self.required) | set(self.optional)
        unknown = sorted(k for k in params if k not in allowed)
        if unknown:
            raise ProtocolError(
                f"{self.name}: unknown parameter(s) {unknown}; allowed={sorted(allowed)}"
            )
        return dict(params)


_SPECS = [
    Spec("ping", summary="liveness + project info"),
    Spec("binaries", summary="list programs in the project"),
    Spec("import", ("path",), ("analyze",), "import + analyze a binary"),
    Spec("info", ("binary",), summary="metadata for one program"),
    Spec(
        "analyze",
        ("binary",),
        ("addr", "full"),
        "re-analyze a program: everything, or just these addresses",
    ),
    Spec(
        "functions",
        ("binary",),
        ("match", "limit", "offset"),
        "list functions, optional regex on name",
    ),
    Spec(
        "decompile",
        ("binary",),
        (
            "targets",
            "target",
            "match",
            "limit",
            "grep",
            "max_lines",
            "include_callees",
            "include_callers",
            "include_code",
            "timeout",
            "refresh",
            "sig",
        ),
        "decompile one/many functions (sig: signatures only, no decompiler)",
    ),
    Spec(
        "imports",
        ("binary",),
        ("match", "query", "group", "limit"),
        "imports with caller counts and risk group",
    ),
    Spec(
        "strings",
        ("binary",),
        ("query", "limit", "offset", "refs"),
        "search string data (refs: which functions use it)",
    ),
    Spec(
        "scan",
        ("binary", "offset"),
        ("range", "func", "limit", "op", "stack"),
        "instructions that touch a struct field offset (displacement search)",
    ),
    Spec("xrefs", ("binary",), ("target", "targets"), "references to address/function"),
    Spec("bytes", ("binary", "addr"), ("size",), "raw memory bytes as hex+ascii"),
    Spec("rename", ("binary", "target", "new"), summary="rename a function"),
    Spec("comment", ("binary", "target", "text"), ("type",), "set a listing/decompiler comment"),
    Spec(
        "graph",
        ("binary", "target"),
        ("direction", "depth", "limit", "format", "out"),
        "call tree, optionally rendered as dot/mermaid/svg",
    ),
    Spec(
        "digest",
        ("binary",),
        ("top", "strings"),
        "one-shot triage: entry chain, risk-grouped imports, API combos, strings, hubs, sizes",
    ),
    Spec(
        "index",
        ("binary",),
        ("refresh",),
        "build or reuse the persistent per-function fact index",
    ),
    Spec(
        "find",
        ("binary",),
        ("import", "string", "calls", "limit", "any"),
        "locate candidate functions by imports/strings/calls instead of by name",
    ),
    Spec(
        "diff",
        ("a", "b"),
        ("match", "limit", "min_score", "detail"),
        "compare two programs: added/removed/changed functions and sections",
    ),
    Spec(
        "emulate",
        ("binary", "target"),
        ("args", "max_insns", "ms", "dump", "buffer", "seed"),
        "run one function on the P-code emulator: seeded args, tracked writes, return value",
    ),
    Spec(
        "decrypt",
        (),
        ("binary", "addr", "len", "hex", "ciphers", "min_printable", "limit"),
        "break a blob: xor/add/rot/utf16/base64 candidates ranked by printability",
    ),
    Spec(
        "patch",
        ("binary", "addr"),
        ("bytes", "nop", "expect"),
        "overwrite bytes at an address (hex or --nop), optionally verifying the old bytes",
    ),
    Spec(
        "set_type",
        ("binary", "target", "decl"),
        (),
        "apply a prototype ('int f(char *s, unsigned n)') or a data type ('char[64]', 'void*')",
    ),
    Spec(
        "bookmark",
        ("binary",),
        ("action", "addr", "target", "type", "category", "comment", "limit"),
        "add/list/remove Ghidra bookmarks so findings are visible in the GUI",
    ),
    Spec(
        "note",
        ("binary", "text"),
        ("at", "addr", "tag", "assert", "delete"),
        "append a durable finding (JSON on disk + bookmark), with claims",
    ),
    Spec(
        "verify",
        ("binary",),
        ("id",),
        "re-run the claims of stored findings and report pass/fail",
    ),
    Spec(
        "map",
        ("binary",),
        ("from", "op", "grep", "limit", "hits"),
        "run one operation over a set of functions, return only the matches",
    ),
    Spec(
        "types",
        ("binary", "from"),
        ("dry_run",),
        "bulk-apply a signature/type map file (JSON or `target = decl` text)",
    ),
    Spec(
        "pdb",
        ("binary", "file"),
        ("untrusted",),
        "apply a matching PDB (symbols and types) via Ghidra's PdbUniversalAnalyzer",
    ),
    Spec(
        "notes",
        ("binary",),
        ("tag", "at", "query", "limit"),
        "list stored findings with optional filters",
    ),
    Spec(
        "family",
        (),
        ("binary", "min_score", "limit"),
        "cross-sample report for one family: per-program profile, shared evidence, notes",
    ),
    Spec("overview", summary="one line per program: size, facts, notes, last change"),
    Spec(
        "audit",
        (),
        ("binary",),
        "re-check every stored claim in the project; list what no longer holds",
    ),
    Spec(
        "journal",
        (),
        ("binary", "op", "since", "limit"),
        "mutation log: what was renamed, patched, typed or noted, and when",
    ),
    Spec(
        "report",
        ("binary",),
        ("top",),
        "markdown report: digest + findings",
    ),
    Spec(
        "cross_xref",
        ("query",),
        ("binary", "limit"),
        "search a string/import across every program in the project",
    ),
    Spec(
        "slice",
        ("binary", "to"),
        ("from", "depth", "limit", "code", "direction"),
        "shortest call path that reaches an import or function (direction=forward: "
        "what this function can reach)",
    ),
    Spec(
        "similar",
        ("binary", "target"),
        ("against", "limit", "min_score"),
        "rank functions of another program by fingerprint similarity",
    ),
    Spec(
        "campaign",
        (),
        ("binary", "min_score", "limit"),
        "cluster all programs by shared imports/strings (family triage)",
    ),
]
SPECS: dict[str, Spec] = {s.name: s for s in _SPECS}
COMMAND_NAMES = sorted(SPECS)


def validate(request: dict[str, Any]) -> tuple[Spec, dict[str, Any]]:
    if not isinstance(request, dict):
        raise ProtocolError("request must be a JSON object")
    cmd = request.get("cmd")
    if not isinstance(cmd, str) or cmd not in SPECS:
        raise ProtocolError(f"unknown cmd {cmd!r}; known={COMMAND_NAMES}")
    params = {k: v for k, v in request.items() if k != "cmd"}
    return SPECS[cmd], SPECS[cmd].check(params)


@dataclass
class Ok:
    result: Any
    ms: int = 0
    ok: bool = field(default=True, init=False)

    def to_bytes(self) -> bytes:
        return json.dumps(
            {"ok": True, "ms": self.ms, "result": self.result}, ensure_ascii=False
        ).encode()


@dataclass
class Err:
    error: str
    trace: str = ""
    ok: bool = field(default=False, init=False)

    def to_bytes(self) -> bytes:
        return json.dumps(
            {"ok": False, "error": self.error, "trace": self.trace}, ensure_ascii=False
        ).encode()


Handler = Callable[[dict[str, Any]], Any]
