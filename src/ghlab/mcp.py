"""A small MCP server that fronts the ghlab daemon.

Deliberately *not* one tool per Ghidra action: ten entry points that each answer a
question ("what is this binary", "what changed", "where is this called from"), plus
resources for state that is nicer to attach than to ask for. Every call is forwarded
to the warm daemon over HTTP, so the MCP process itself never starts a JVM and can be
killed/restarted by the client at will.
"""

from __future__ import annotations

import contextlib
import json
import sys
from collections.abc import Callable
from typing import Any, TextIO

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
        "name": "ghlab_imports",
        "description": (
            "Drill into imports: for each API, how many distinct functions call it, the biggest "
            "callers, and its risk group. Use after digest when a group looks interesting "
            "(e.g. group='registry' or match='^Reg')."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "match": {"type": "string", "description": "regex on import or library name"},
                "group": {
                    "type": "string",
                    "description": "anti, crypto, exec, file, inject, network, registry, ui",
                },
                "limit": _LIMIT,
            },
            "required": ["binary"],
        },
    },
    {
        "name": "ghlab_scan",
        "description": (
            "Displacement search: which instructions read/write struct field +0xNN. Use it when "
            "you know a struct layout but not its consumers (decompiled text grep misses XMM "
            "operands). Filter by mnemonic with `op`, narrow with `func` or `range`."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "offset": {"type": "string", "description": "field offset, e.g. '0x54'"},
                "range": {"type": "string", "description": "0xSTART-0xEND to limit the sweep"},
                "func": {"type": "string", "description": "only scan one function's body"},
                "op": {"type": "string", "description": "regex on the mnemonic, e.g. '^MOVSS$'"},
                "stack": {"type": "boolean", "description": "also report [RSP/RBP+..] locals"},
                "limit": _LIMIT,
            },
            "required": ["binary", "offset"],
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
                "grep": {
                    "type": "string",
                    "description": "regex over decompiled text (no code returned)",
                },
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
                "assert": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "checkable claims about that function, e.g. const=0x41, string=Autosave, "
                        "import=RegSetValueExW, calls=FUN_140010350, size>=200"
                    ),
                },
            },
            "required": ["binary", "text"],
        },
    },
    {
        "name": "ghlab_verify",
        "description": (
            "Re-run every claim stored by ghlab_note and report pass/fail. Use it before you "
            "trust your own earlier conclusions, and before writing them into a report."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "id": {"type": "array", "items": {"type": "integer"}},
            },
            "required": ["binary"],
        },
    },
    {
        "name": "ghlab_map",
        "description": (
            "Batch primitive: pick a set of functions with `from` (name:/import:/calls:/string:/"
            "const:/addr:), then either decompile them or collect their strings/imports/calls/"
            "constants. `grep` keeps only matching lines, so a 200-function sweep costs one "
            "call and returns only the hits. Use this instead of looping ghlab_decompile."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "from": {"type": "string", "description": "selector, default all"},
                "op": {
                    "type": "string",
                    "enum": ["decompile", "strings", "imports", "calls", "consts"],
                },
                "grep": {"type": "string", "description": "regex over source lines / entries"},
                "limit": _LIMIT,
                "hits": {"type": "integer", "description": "max hits per function"},
            },
            "required": ["binary"],
        },
    },
    {
        "name": "ghlab_decrypt",
        "description": (
            "Break a small blob of ciphertext: tries single-byte xor/add/rot, utf-16 and base64, "
            "keeps only candidates that look like real strings, and ranks them. Pass `hex` or a "
            "`binary` plus `addr`/`len` to read it from program memory. Use this instead of "
            "guessing keys or writing a script for a 20-byte blob."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "hex": {"type": "string", "description": "ciphertext as hex"},
                "binary": _BIN,
                "addr": {"type": "string", "description": "where the blob lives"},
                "len": {"type": "integer", "description": "bytes to read, default 64"},
                "ciphers": {"type": "array", "items": {"type": "string"}},
                "min_printable": {"type": "number"},
                "limit": _LIMIT,
            },
        },
    },
    {
        "name": "ghlab_types",
        "description": (
            "Bulk-apply external knowledge: a map file of `target = C declaration` pairs "
            "(signatures when it contains parentheses, data types otherwise) from headers, "
            "PDB dumps or a colleague's notes. One transaction, one save, per-item failures "
            "reported instead of aborting."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "from": {"type": "string", "description": "path to .json or `target = decl` text"},
                "dry_run": {"type": "boolean"},
            },
            "required": ["binary", "from"],
        },
    },
    {
        "name": "ghlab_pdb",
        "description": (
            "Apply a matching PDB: symbols and types come from the debug symbols instead of "
            "guessing. Refuses cleanly (functions unchanged) when the PDB does not match."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "file": {"type": "string", "description": "path to the .pdb"},
                "untrusted": {"type": "boolean", "description": "allow unsigned/untrusted pdb"},
            },
            "required": ["binary", "file"],
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
    "ghlab_imports": "imports",
    "ghlab_scan": "scan",
    "ghlab_decompile": "decompile",
    "ghlab_diff": "diff",
    "ghlab_slice": "slice",
    "ghlab_emulate": "emulate",
    "ghlab_cross_xref": "cross_xref",
    "ghlab_similar": "similar",
    "ghlab_note": "note",
    "ghlab_verify": "verify",
    "ghlab_map": "map",
    "ghlab_types": "types",
    "ghlab_pdb": "pdb",
    "ghlab_decrypt": "decrypt",
    "ghlab_report": "report",
}

_LIST_KEYS = {"import", "string", "calls", "targets", "args", "dump", "assert", "id"}


def _as_params(_name: str, args: dict[str, Any]) -> dict[str, Any]:
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
    body = (
        payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=2)
    )
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


def programs(call: Callable[..., Any]) -> list[dict[str, Any]]:
    """Program names plus the cheap facts a client wants before it asks anything."""
    out: list[dict[str, Any]] = []
    names = call("binaries").get("binaries") or []
    for binfo in names:
        name = binfo.get("name") if isinstance(binfo, dict) else str(binfo or "")
        if not name:
            continue
        row: dict[str, Any] = {"name": name}
        try:
            info = call("info", binary=name)
            row["md5"] = info.get("md5")
            row["language"] = info.get("language")
            row["compiler"] = info.get("compiler")
            row["functions"] = info.get("functions")
        except Exception:  # noqa: BLE001 - listing must survive a half-broken project
            pass
        out.append(row)
    return out


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
        for row in programs(call):
            name = row["name"]
            hint = ", ".join(
                str(row[k]) for k in ("language", "functions") if row.get(k) not in (None, "")
            )
            for kind, what in (("digest", "one-shot triage"), ("notes", "recorded findings")):
                out.append(
                    {
                        "uri": f"ghlab://program/{name}/{kind}",
                        "name": f"{name} {kind}",
                        "mimeType": "application/json",
                        "description": f"{what} for {name}" + (f" ({hint})" if hint else ""),
                    }
                )
    except Exception:  # noqa: BLE001 - resources are best effort
        pass
    return out


def read_resource(uri: str, call: Callable[..., Any]) -> dict[str, Any]:
    if uri == "ghlab://programs":
        return _text({"programs": programs(call)})
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


PROMPTS: list[dict[str, Any]] = [
    {
        "name": "triage",
        "description": (
            "Triage a binary: the digest is fetched and inlined, followed by the next steps in "
            "token order (find -> slice -> decompile -> note -> report)."
        ),
        "arguments": [{"name": "binary", "required": True, "description": _BIN["description"]}],
    },
    {
        "name": "diff-review",
        "description": "Explain what changed between two builds, with the diff already attached.",
        "arguments": [
            {"name": "a", "required": True, "description": "original program"},
            {"name": "b", "required": True, "description": "changed program"},
        ],
    },
]


def _inline(call: Callable[..., Any], cmd: str, formatter: str = "", **params: Any) -> str:
    """Render a daemon answer for a prompt.

    Human formatters are preferred: the CLI's digest is ~450 tokens, while the same
    payload pretty-printed as JSON is four times that.
    """
    try:
        result = call(cmd, **params)
    except Exception as ex:  # noqa: BLE001
        return f"(daemon could not answer {cmd}: {type(ex).__name__}: {ex})"
    if formatter:
        try:
            from . import cli

            return str(getattr(cli, formatter)(result))
        except Exception:  # noqa: BLE001 - fall through to raw JSON
            pass
    return json.dumps(result, ensure_ascii=False)


def get_prompt(name: str, args: dict[str, Any], call: Callable[..., Any]) -> dict[str, Any]:
    """Prompt templates exist so a client can start correctly without reading docs."""
    args = args or {}
    if name == "triage":
        binary = str(args.get("binary") or "").strip()
        if not binary:
            raise ValueError("the triage prompt needs a `binary` argument")
        lines = [
            f"Triage {binary}. Weigh behaviour over strings; say `unknown` rather than guess.",
            "",
            f"Digest for {binary}, already fetched - do not call ghlab_digest again:",
            "```",
            _inline(call, "digest", "fmt_digest", binary=binary),
            "```",
            "",
            "Work in this order and stop as soon as the question is answered:",
            "1. ghlab_find on the imports that matter (persistence, network, crypto, injection).",
            "2. ghlab_slice from those imports to check they are reachable from entry.",
            "3. ghlab_decompile only the functions the two steps surfaced; try `grep` before whole bodies.",
            "4. Persist reusable conclusions with ghlab_note (tag: c2 / crypto / loader / anti).",
            "5. Finish with ghlab_report and cite note ids as evidence.",
        ]
        return {
            "description": f"triage {binary}",
            "messages": [
                {"role": "user", "content": {"type": "text", "text": chr(10).join(lines)}}
            ],
        }
    if name == "diff-review":
        a, b = str(args.get("a") or ""), str(args.get("b") or "")
        if not a or not b:
            raise ValueError("the diff-review prompt needs `a` and `b` arguments")
        lines = [
            f"Explain what changed between {a} (before) and {b} (after).",
            "",
            "Diff already computed - do not call ghlab_diff again:",
            "```",
            _inline(call, "diff", "fmt_diff", a=a, b=b, limit=5),
            "```",
            "",
            "Then: decompile the changed functions on both sides (same names usually survive),",
            "say which change is functional and which is noise (addresses, constants, inlining),",
            "and if this looks like a security fix, name the bug class and the guard that was added.",
        ]
        return {
            "description": f"diff {a} -> {b}",
            "messages": [
                {"role": "user", "content": {"type": "text", "text": chr(10).join(lines)}}
            ],
        }
    raise ValueError(f"unknown prompt {name!r}")


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
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"subscribe": False},
                    "prompts": {"listChanged": False},
                },
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
    if method == "prompts/list":
        return ok({"prompts": PROMPTS})
    if method == "prompts/get":
        try:
            return ok(
                get_prompt(str(params.get("name") or ""), params.get("arguments") or {}, call)
            )
        except Exception as ex:  # noqa: BLE001
            return fail(-32000, f"{type(ex).__name__}: {ex}")
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
        # Not every TextIO implements reconfigure (a StringIO in tests does not).
        reconfigure = getattr(stream, "reconfigure", None)
        with contextlib.suppress(Exception):
            if reconfigure is not None:
                reconfigure(encoding="utf-8")
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
