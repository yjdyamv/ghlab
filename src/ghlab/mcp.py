"""A small MCP server that fronts the ghlab daemon.

Deliberately *not* one tool per Ghidra action: ten entry points that each answer a
question ("what is this binary", "what changed", "where is this called from"), plus
resources for state that is nicer to attach than to ask for. Every call is forwarded
to the warm daemon over HTTP, so the MCP process itself never starts a JVM and can be
killed/restarted by the client at will.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable, TextIO

from . import __version__
from .client import Client, RemoteError

PROTOCOL_VERSION = "2025-06-18"

_BIN = {"type": "string", "description": "program name in the project (unique substring is enough)"}
_LIMIT = {"type": "integer", "minimum": 1, "description": "max results"}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "ghlab_digest",
        "description": (
            "One-shot triage of a binary (~450 tokens): entry chain, imports grouped by risk "
            "(inject/exec/network/file/registry/crypto/anti), capability combos, string clusters, "
            "call-graph hubs and size distribution. Call this before any other analysis step."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"binary": _BIN, "top": _LIMIT, "strings": _LIMIT},
            "required": ["binary"],
        },
    },
    {
        "name": "ghlab_find",
        "description": (
            "Locate candidate functions by structure instead of by name: who imports these APIs, "
            "who references these strings, who calls these functions. All given conditions must "
            "hold unless `any` is true."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "import": {"type": "array", "items": {"type": "string"}},
                "string": {"type": "array", "items": {"type": "string"}},
                "calls": {"type": "array", "items": {"type": "string"}},
                "any": {"type": "boolean", "description": "OR instead of AND"},
                "limit": _LIMIT,
            },
            "required": ["binary"],
        },
    },
    {
        "name": "ghlab_decompile",
        "description": (
            "Decompile one function, a name regex, or a batch; `grep` filters server-side and "
            "returns only matching lines. Results are cached, so repeats are ~13x faster."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "target": {"type": "string", "description": "function name or 0x address"},
                "targets": {"type": "array", "items": {"type": "string"}},
                "match": {"type": "string", "description": "regex over function names"},
                "grep": {"type": "string", "description": "regex over decompiled text (no code returned)"},
                "max_lines": {"type": "integer", "minimum": 0},
                "limit": _LIMIT,
                "include_callees": {"type": "boolean"},
                "include_callers": {"type": "boolean"},
                "refresh": {"type": "boolean", "description": "bypass the decompiler cache"},
            },
            "required": ["binary"],
        },
    },
    {
        "name": "ghlab_diff",
        "description": (
            "Functional difference between two programs: matched functions (by signature, address, "
            "name or similarity), added/removed ones, and per-function deltas (size, instructions, "
            "blocks, strings, imports, constants) plus section hashes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": _BIN,
                "b": _BIN,
                "match": {"type": "string", "description": "regex filter on function names"},
                "limit": _LIMIT,
                "min_score": {"type": "number"},
            },
            "required": ["a", "b"],
        },
    },
    {
        "name": "ghlab_slice",
        "description": (
            "Reverse call-graph slice: shortest chain of callers from an import/function back to "
            "entry/main. Tells you whether a code path is reachable at all (`reaches_entry`)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "to": {"type": "string", "description": "import or function name (regex)"},
                "from": {"type": "string", "description": "stop at a caller matching this"},
                "depth": {"type": "integer", "minimum": 1},
                "limit": _LIMIT,
                "code": {"type": "boolean", "description": "include the caller's decompiled body"},
            },
            "required": ["binary", "to"],
        },
    },
    {
        "name": "ghlab_emulate",
        "description": (
            "Run one function on the P-code emulator with seeded arguments (Win64 ABI) and report "
            "the return value, memory writes and a scratch buffer. Use for string decryption or "
            "config parsing without a debugger; imported calls are stubbed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "target": {"type": "string"},
                "args": {"type": "array", "items": {"type": "string"}},
                "max_insns": {"type": "integer", "minimum": 1},
                "buffer": {"type": "integer", "description": "scratch bytes to allocate and dump"},
                "dump": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["binary", "target"],
        },
    },
    {
        "name": "ghlab_cross_xref",
        "description": (
            "Search string data across every program in the project and list the functions that "
            "reference each hit. Answers 'which other samples talk to this host / use this config'."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}, "binary": _BIN, "limit": _LIMIT},
            "required": ["query"],
        },
    },
    {
        "name": "ghlab_similar",
        "description": (
            "Find the same logic in other programs: compare a function's strings/imports/constants/"
            "size fingerprint against every other program and rank matches."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "target": {"type": "string"},
                "against": _BIN,
                "limit": _LIMIT,
                "min_score": {"type": "number"},
            },
            "required": ["binary", "target"],
        },
    },
    {
        "name": "ghlab_note",
        "description": (
            "Record a durable finding: appends to `<project>/.ghlab/notes/<binary>.json` and mirrors "
            "it as a Ghidra bookmark so a human in the GUI sees the same thing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "text": {"type": "string"},
                "at": {"type": "string", "description": "function name or 0x address"},
                "tag": {"type": "string", "description": "grouping label, e.g. c2/crypto/loader"},
            },
            "required": ["binary", "text"],
        },
    },
    {
        "name": "ghlab_report",
        "description": "Markdown report for one binary: digest summary, hubs, size buckets and findings.",
        "inputSchema": {
            "type": "object",
            "properties": {"binary": _BIN, "top": _LIMIT},
            "required": ["binary"],
        },
    },
]

# tool name -> daemon command
_COMMANDS = {
    "ghlab_digest": "digest",
    "ghlab_find": "find",
    "ghlab_decompile": "decompile",
    "ghlab_diff": "diff",
    "ghlab_slice": "slice",
    "ghlab_emulate": "emulate",
    "ghlab_cross_xref": "cross_xref",
    "ghlab_similar": "similar",
    "ghlab_note": "note",
    "ghlab_report": "report",
}

_LIST_KEYS = {"import", "string", "calls", "targets", "args", "dump"}


def _as_params(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Tool arguments are the daemon's parameters, with a few small normalisations."""
    params: dict[str, Any] = {}
    for key, value in (args or {}).items():
        if value is None:
            continue
        if key in _LIST_KEYS and isinstance(value, str):
            value = [value]
        if key == "from":  # `from` is legal in JSON, but keep parity with the CLI shim
            params["from"] = value
            continue
        params[key] = value
    return params


def _text(payload: Any) -> dict[str, Any]:
    body = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=2)
    return {"content": [{"type": "text", "text": body}]}


def _error(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def call_tool(name: str, args: dict[str, Any], call: Callable[..., Any]) -> dict[str, Any]:
    if name not in _COMMANDS:
        return _error(f"unknown tool {name!r}")
    try:
        return _text(call(_COMMANDS[name], **_as_params(name, args)))
    except RemoteError as ex:
        return _error(f"{name} failed: {ex}")
    except Exception as ex:  # noqa: BLE001
        return _error(f"{name} failed: {type(ex).__name__}: {ex}")


def _resource_uris(call: Callable[..., Any]) -> list[dict[str, str]]:
    out = [
        {"uri": "ghlab://programs", "name": "programs", "mimeType": "application/json"},
        {
            "uri": "ghlab://protocol",
            "name": "protocol",
            "mimeType": "application/json",
            "description": "self-describing command table of the daemon",
        },
    ]
    try:
        for binfo in call("binaries").get("binaries", []):
            name = binfo.get("name") if isinstance(binfo, dict) else str(binfo or "")
            if not name:
                continue
            for kind in ("digest", "notes"):
                out.append(
                    {
                        "uri": f"ghlab://program/{name}/{kind}",
                        "name": f"{name} {kind}",
                        "mimeType": "application/json",
                    }
                )
    except Exception:  # noqa: BLE001 - resources are best effort
        pass
    return out


def read_resource(uri: str, call: Callable[..., Any]) -> dict[str, Any]:
    if uri == "ghlab://programs":
        return _text(call("binaries"))
    if uri == "ghlab://protocol":
        return _text(call("ping"))
    parts = uri.removeprefix("ghlab://program/").split("/")
    if len(parts) != 2:
        raise ValueError(f"unknown resource {uri!r}")
    name, kind = parts
    if kind == "digest":
        return _text(call("digest", binary=name))
    if kind == "notes":
        return _text(call("notes", binary=name))
    raise ValueError(f"unknown resource {uri!r}")


def handle(msg: dict[str, Any], call: Callable[..., Any]) -> dict[str, Any] | None:
    """One JSON-RPC message in, one (or no) response out."""
    method = msg.get("method")
    mid = msg.get("id")
    params = msg.get("params") or {}
    if method is None:  # a response; we never send requests
        return None
    if mid is None:  # notification
        return None

    def ok(result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def fail(code: int, text: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": text}}

    if method == "initialize":
        return ok(
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}, "resources": {"subscribe": False}},
                "serverInfo": {"name": "ghlab", "version": __version__},
                "instructions": (
                    "Ghidra-backed RE tools. Start with ghlab_digest, then narrow with ghlab_find / "
                    "ghlab_slice before decompiling; record conclusions with ghlab_note."
                ),
            }
        )
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name") or ""
        return ok(call_tool(name, params.get("arguments") or {}, call))
    if method == "resources/list":
        return ok({"resources": _resource_uris(call)})
    if method == "resources/read":
        try:
            return ok(read_resource(str(params.get("uri") or ""), call))
        except Exception as ex:  # noqa: BLE001
            return fail(-32000, f"{type(ex).__name__}: {ex}")
    return fail(-32601, f"method not found: {method}")


def serve(
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    call: Callable[..., Any] | None = None,
) -> int:
    """Newline-delimited JSON-RPC over stdio, until EOF."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for stream in (stdout,):
        # MCP is UTF-8 on the wire; a Windows console default (cp936) would raise
        # UnicodeEncodeError the first time a binary contains a non-ASCII string.
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except Exception:  # noqa: BLE001
                pass
    if call is None:
        client = Client()
        call_fn: Callable[..., Any] = lambda cmd, **params: client.call(cmd, **params)  # noqa: E731
    else:
        call_fn = call

    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as ex:
            reply: dict[str, Any] | None = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"parse error: {ex}"},
            }
        else:
            reply = (
                handle(msg, call_fn)
                if isinstance(msg, dict)
                else {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "invalid request: not an object"},
                }
            )
        if reply is not None:
            stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
