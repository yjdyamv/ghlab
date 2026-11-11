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
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from . import router as routing
from .client import RemoteError

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
        "name": "ghlab_names",
        "description": (
            "Recover method names from assertion strings (Class::Method : failure). Cheap way "
            "to turn 70k anonymous functions into a named map; filter with a regex."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "query": {"type": "string", "description": "regex on the recovered name"},
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
        "name": "ghlab_exports",
        "description": (
            "What this binary offers to callers (PE exports, ELF .dynsym), each with its "
            "demangled C++ name. The mirror of ghlab_imports: use it on a DLL/SO to see its API "
            "surface, or on a plugin to find the entry point the host calls."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "match": {
                    "type": "string",
                    "description": "regex on the mangled or demangled name",
                },
                "limit": _LIMIT,
            },
            "required": ["binary"],
        },
    },
    {
        "name": "ghlab_offsets",
        "description": (
            "Attribute every [base + constant] access in a function to the parameter or local "
            "it comes from. An offset alone is not a fact: ctx+0x178 and doc+0x178 are different "
            "fields in different objects."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "target": {"type": "string", "description": "function name or 0x address"},
                "offset": {"type": "string", "description": "only this offset, e.g. 0x178"},
                "limit": _LIMIT,
            },
            "required": ["binary", "target"],
        },
    },
    {
        "name": "ghlab_struct",
        "description": (
            "Infer a C struct from one function's [base + offset] accesses: width vote per "
            "offset, gaps materialised so offsets stay true, `--create` installs the type. "
            "Faster and more honest than guessing a layout from a decompiled listing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "target": {"type": "string", "description": "function name or 0x address"},
                "base": {"type": "string", "description": "base variable (default: busiest param)"},
                "offset": {"type": "string", "description": "only this field, e.g. 0x18"},
                "name": {"type": "string", "description": "type name"},
                "types": {
                    "type": "string",
                    "description": "override widths: 0x18=float,0x20=void *",
                },
                "pointer": {
                    "type": "string",
                    "description": "offsets that are pointers: 0x20,0x28",
                },
                "create": {"type": "boolean", "description": "install the type in the program"},
                "limit": _LIMIT,
            },
            "required": ["binary", "target"],
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
                "offset": {
                    "type": "string",
                    "description": "field offset, e.g. '0x54' (omit when using `hex`)",
                },
                "hex": {
                    "type": "string",
                    "description": "byte pattern with ?? wildcards, e.g. '48 8B ?? 05' (alternative to `offset`)",
                },
                "range": {"type": "string", "description": "0xSTART-0xEND to limit the sweep"},
                "func": {"type": "string", "description": "only scan one function's body"},
                "op": {"type": "string", "description": "regex on the mnemonic, e.g. '^MOVSS$'"},
                "stack": {"type": "boolean", "description": "also report [RSP/RBP+..] locals"},
                "imm": {
                    "type": "string",
                    "description": "only instructions whose last operand is this immediate: '4', '0x4' or '0..5'",
                },
                "writes": {
                    "type": "boolean",
                    "description": "only instructions that write the field, not just touch it",
                },
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
        "name": "ghlab_fid",
        "description": (
            "Identify library functions with the user's FunctionID databases (.fidb): matched "
            "functions are renamed to their library name. Changes the project, so it is refused "
            "under GHLAB_READONLY. `list: true` shows which databases are installed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "list": {"type": "boolean", "description": "list the .fidb libraries instead"},
                "limit": {"type": "integer", "description": "renames to return (default 200)"},
            },
            "required": [],
        },
    },
    {
        "name": "ghlab_job",
        "description": (
            "Run a command in the background and return at once, for work that takes minutes "
            "(full decompiles, scans, analysis): `run` names the command, `args` carries its "
            "parameters as key=value pairs split on ';'. Then poll with `list: true` or "
            '`id: "j3"`; stop it with ghlab_cancel. Errors in the parameters come back '
            "immediately, not as a failed job."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "run": {"type": "string", "description": "command to run, e.g. decompile"},
                "binary": _BIN,
                "args": {
                    "type": "string",
                    "description": "its params as key=value pairs split on ';', e.g. targets=main;grep=memcpy",
                },
                "list": {"type": "boolean", "description": "list the jobs instead of starting one"},
                "id": {"type": "string", "description": "return this job's result"},
                "wait": {"type": "boolean", "description": "block until it finishes"},
            },
            "required": [],
        },
    },
    {
        "name": "ghlab_cancel",
        "description": (
            "Ask a running or queued job to stop. Ghidra checks its monitor between steps, so "
            "this stops between steps: one long decompile finishes first."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "job id, e.g. j3"},
                "all": {"type": "boolean", "description": "stop everything queued or running"},
            },
            "required": [],
        },
    },
    {
        "name": "ghlab_projects",
        "description": (
            "List the configured Ghidra projects, which daemons are up, and the binaries each "
            "one owns. Use it to find which project holds a binary before naming it; every other "
            "tool accepts project=<name> when a binary name exists in more than one project."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"refresh": {"type": "boolean", "description": "drop cached lists"}},
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
    {
        "name": "ghlab_notes",
        "description": (
            "Read back stored findings (the project's long-term memory) with filters. "
            "Use this before re-deriving something an earlier session already established."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "tag": {"type": "string", "description": "only findings with this tag"},
                "at": {"type": "string", "description": "only findings at this address/symbol"},
                "query": {"type": "string", "description": "regex over the finding text"},
                "limit": _LIMIT,
            },
        },
    },
    {
        "name": "ghlab_audit",
        "description": (
            "Re-check every stored claim across the project and list the ones that no longer "
            "hold: the evidence layer's own regression test."
        ),
        "inputSchema": {"type": "object", "properties": {"binary": _BIN}},
    },
    {
        "name": "ghlab_overview",
        "description": "One line per program in the project: facts, notes, failing claims, last change.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "ghlab_strings",
        "description": (
            "String data in one binary, filtered by a regex; `refs` answers the follow-up question "
            "(which functions use it) in the same call. Start here when what you have is a literal "
            "(a URL, a registry key, a format string) rather than an imported API."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "query": {"type": "string", "description": "regex over the string value"},
                "refs": {"type": "boolean", "description": "add the functions that use each hit"},
                "limit": _LIMIT,
                "offset": {"type": "integer", "description": "skip this many hits"},
                "refresh": {"type": "boolean", "description": "rebuild the string index"},
            },
            "required": ["binary"],
        },
    },
    {
        "name": "ghlab_xrefs",
        "description": (
            "Who references this address, function or symbol: call sites and data reads. The "
            "reverse edge of ghlab_graph — use it when you already know the target and want its "
            "callers, instead of walking the call tree down from a guess."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "target": {"type": "string", "description": "address, function name or symbol"},
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "several targets in one call",
                },
                "limit": _LIMIT,
            },
            "required": ["binary"],
        },
    },
    {
        "name": "ghlab_functions",
        "description": (
            "The function roster: address, size and prototype, filtered by a regex on the name. "
            "Cheaper than ghlab_digest when you only need to know what exists before picking targets."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "match": {"type": "string", "description": "regex over function names"},
                "limit": _LIMIT,
                "offset": {"type": "integer", "description": "skip this many functions"},
            },
            "required": ["binary"],
        },
    },
    {
        "name": "ghlab_info",
        "description": (
            "Program metadata: format, language, compiler, image base, entry points, section and "
            "hash facts. Ask this before interpreting an address — a DLL and a raw dump need "
            "different reading."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"binary": _BIN},
            "required": ["binary"],
        },
    },
    {
        "name": "ghlab_journal",
        "description": (
            "What was already changed in this project and when (import/analyze/rename/comment/"
            "patch/set_type/types/pdb/note), newest last. Check it before concluding that the "
            "code you are reading is the vendor's."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "op": {"type": "string", "description": "only this command's entries"},
                "since": {"type": "string", "description": "only entries at/after this time"},
                "limit": _LIMIT,
            },
        },
    },
    {
        "name": "ghlab_graph",
        "description": (
            "Call tree from one function, with depth and direction, optionally rendered as "
            "dot/mermaid/svg (`out` writes the file and returns its path). Use it to find the "
            "few hubs worth reading instead of decompiling everything."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "target": {"type": "string", "description": "function name or address"},
                "direction": {"type": "string", "enum": ["down", "up", "both"]},
                "depth": {"type": "integer", "description": "levels to walk, default 3"},
                "format": {"type": "string", "enum": ["dot", "mermaid", "svg", "json"]},
                "out": {"type": "string", "description": "write the rendered graph here"},
                "limit": _LIMIT,
            },
            "required": ["binary", "target"],
        },
    },
    {
        "name": "ghlab_bytes",
        "description": (
            "Raw memory as hex+ascii (capped at 64 KiB, `truncated` when the block ends first). "
            "Use it to confirm one constant or struct field without paying for a full decompile."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": _BIN,
                "addr": {"type": "string", "description": "start address"},
                "size": {"type": "integer", "description": "bytes to read (capped at 65536)"},
            },
            "required": ["binary", "addr"],
        },
    },
]

# tool name -> daemon command
_COMMANDS = {
    "ghlab_digest": "digest",
    "ghlab_find": "find",
    "ghlab_names": "names",
    "ghlab_imports": "imports",
    "ghlab_exports": "exports",
    "ghlab_scan": "scan",
    "ghlab_offsets": "offsets",
    "ghlab_struct": "struct",
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
    "ghlab_fid": "fid",
    "ghlab_job": "job",
    "ghlab_cancel": "cancel",
    "ghlab_projects": "projects",
    "ghlab_decrypt": "decrypt",
    "ghlab_report": "report",
    "ghlab_notes": "notes",
    "ghlab_audit": "audit",
    "ghlab_overview": "overview",
    "ghlab_strings": "strings",
    "ghlab_xrefs": "xrefs",
    "ghlab_functions": "functions",
    "ghlab_info": "info",
    "ghlab_journal": "journal",
    "ghlab_graph": "graph",
    "ghlab_bytes": "bytes",
}

_LIST_KEYS = {
    "import",
    "string",
    "calls",
    "targets",
    "args",
    "dump",
    "assert",
    "id",
    "seed",
    "stub",
}


def _autostart_enabled() -> bool:
    return os.environ.get("GHLAB_AUTOSTART", "").strip().lower() in {"1", "true", "yes", "on"}


def _start_target(target: Any) -> bool:
    """Bring one project's daemon up on first use, so an agent needs no shell step.

    Called only after a call has already failed: starting eagerly would block the
    MCP `initialize` handshake for the 30-45 s of a cold JVM.
    """
    from argparse import Namespace

    from . import cli

    tail = str(target.url).rsplit(":", 1)[-1].strip("/")
    args = Namespace(
        host=str(target.url).split("//")[-1].rsplit(":", 1)[0] or "127.0.0.1",
        port=int(tail) if tail.isdigit() else 8765,
        project_dir=target.project_dir or str(Path.home() / "re" / "proj"),
        project_name=target.project_name or target.name,
        wait=400,
    )
    sys.stderr.write(
        f"ghlab.mcp: {target.name} daemon is down, starting it (once per session){chr(10)}"
    )
    sys.stderr.flush()
    try:
        return cli.cmd_start(args) == 0
    except Exception as ex:  # noqa: BLE001 - a failed autostart must not kill the MCP server
        sys.stderr.write(
            f"ghlab.mcp: autostart of {target.name} failed: {type(ex).__name__}: {ex}{chr(10)}"
        )
        sys.stderr.flush()
        return False


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
        # One MCP entry serves every configured project: the router picks the
        # daemon from the binary a tool already names, and starts it if it is down.
        router = routing.from_config(start=_start_target, autostart=_autostart_enabled())
        call_fn: Callable[..., Any] = router.call
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
