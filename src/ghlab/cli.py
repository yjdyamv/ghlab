"""`ghlab` command line: daemon lifecycle plus one-shot queries."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

from . import session
from .client import Client, RemoteError
from .protocol import DEFAULT_HOST, DEFAULT_PORT

REPO = Path(__file__).resolve().parents[2]
LOGDIR = Path.home() / "re" / "logs"


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


# ------------------------------------------------------------------ formatting


def fmt_binaries(r: dict[str, Any]) -> str:
    names = r.get("binaries") or []
    return "\n".join(names) if names else "(project is empty — use `ghlab import PATH`)"


def fmt_info(r: dict[str, Any]) -> str:
    keys = (
        "name",
        "executable_path",
        "language",
        "compiler",
        "image_base",
        "md5",
        "functions",
        "symbols",
    )
    lines = [f"{k:15} {r.get(k)}" for k in keys]
    lines.append(f"{'memory_blocks':15} {', '.join(r.get('memory_blocks') or [])}")
    return "\n".join(lines)


def fmt_functions(r: dict[str, Any]) -> str:
    rows = [f"{f['addr']}  {f['size']:>6}  {f['name']}" for f in r.get("functions") or []]
    head = f"# {r.get('matched')} matched, showing {len(rows)}"
    return "\n".join([head, *rows])


def fmt_decompile(r: dict[str, Any]) -> str:
    if not r.get("results"):
        return "(no function matched; widen -m/-g or raise -n)"
    out = []
    for item in r.get("results") or []:
        if item.get("error"):
            out.append(f"!! {item.get('target')}: {item['error']}")
            continue
        out.append(
            f"== {item['name']} @ {item['addr']}  ({item['lines']} lines)  {item['prototype']}"
        )
        if item.get("grep_hits") is not None:
            out.append(f"   match: {item['grep_hits']} line(s)")
            for hit in item.get("matched") or []:
                out.append(f"   L{hit['line']:<4} {hit['text']}")
        if item.get("code"):
            out.append(item["code"].rstrip())
        for key in ("callees", "callers"):
            if item.get(key):
                out.append(f"   {key}: {', '.join(item[key])}")
    return "\n".join(out)


def fmt_strings(r: dict[str, Any]) -> str:
    body = [f"{s['addr']}  {s['value']}" for s in r.get("strings") or []]
    head = f"# {r.get('matched')} match(es), {r.get('defined_data_scanned')} data items scanned"
    return "\n".join([head, *body])


def fmt_xrefs(r: dict[str, Any]) -> str:
    out = []
    for item in r.get("results") or []:
        out.append(f"== {item['target']} @ {item['addr']}: {len(item['xrefs'])} xref(s)")
        for x in item["xrefs"]:
            out.append(f"   {x['from']}  {x['type']:<16} {x['in_function'] or '-'}")
    return "\n".join(out)


def fmt_graph(r: dict[str, Any]) -> str:
    out = [
        f"# {r['direction']} {r['root']}: {len(r.get('nodes') or [])} node(s)",
    ]
    for e in r.get("edges") or []:
        out.append(f"   {e['from']} -> {e['to']}")
    return "\n".join(out)


def fmt_emulate(r: dict[str, Any]) -> str:
    args = "  ".join(
        f"{a['kind']}:{a.get('value')}" + (f"@{a['addr']}" if a.get("addr") else "")
        for a in r.get("args") or []
    )
    out = [
        f"# {r['function']} @ {r['entry']}  {r['arch']}  ({r['insns']} insns, "
        f"{r['elapsed_ms']}ms, stop={r['stop']})",
        f"   prototype {r['prototype']}",
    ]
    if args:
        out.append(f"   args      {args}")
    out.append(f"   return    {r['ret']['rax_hex']} ({r['ret']['rax']})")
    if r.get("stubs"):
        seen: dict[str, int] = {}
        for s in r["stubs"]:
            seen[s["fn"]] = seen.get(s["fn"], 0) + 1
        summary = ", ".join(f"{k}x{v}" for k, v in sorted(seen.items()))
        out.append(f"   stubs     {len(r['stubs'])} external call(s) answered: {summary}")
    wr = r.get("writes") or {}
    out.append(f"   writes    {wr.get('tracked', 0)} byte(s)")
    for w in wr.get("ranges") or []:
        out.append(f"     {w['addr']}  {w['size']}b  {w['hex'][:64]}")
        if w.get("ascii"):
            out.append(f"       |{w['ascii']}|")
    buf = r.get("buffer")
    for d in r.get("dump") or []:
        label = "buffer" if buf and d["addr"] == buf["addr"] else "dump"
        out.append(f"   {label} {d['addr']} {d['size']}b")
        out.append(_hexblock(d["hex"], d["ascii"]))
    if r.get("skips"):
        ops = Counter(s["op"] for s in r["skips"])
        out.append(
            "   skipped   "
            + ", ".join(f"{k}x{v}" for k, v in sorted(ops.items()))
            + " instruction(s) (p-code op not emulated)"
        )
    f = r.get("fault")
    if f:
        out.append(
            f"   !! fault at {f['pc']} ({'mapped' if f['mapped'] else 'unmapped'}) "
            f"after call to {f.get('callee') or '?'} at {f['call_site']}"
        )
        out.append(f"      {f['error']}")
        if f.get("on_instruction") is False:
            out.append(
                "      note: PC is not on a decoded instruction — a stubbed call returned 0 "
                "and the code branched on it; give inputs with --arg or expect the fault"
            )
    return "\n".join(out)


def _hexblock(hexstr: str, ascii_: str, width: int = 16) -> str:
    data = bytes.fromhex(hexstr)
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = ascii_[off : off + width]
        lines.append(f"     {off:04x}  {hexpart}  |{text}|")
    return "\n".join(lines)


def fmt_find(r: dict[str, Any]) -> str:
    filters = " ".join(f"{k}={v}" for k, v in (r.get("filters") or {}).items())
    out = [f"# {r.get('candidates')} candidate(s) mode={r.get('mode')} {filters}"]
    if not r.get("functions"):
        out.append("   (nothing matched; loosen the patterns or use --any)")
    for f in r.get("functions") or []:
        why = " | ".join(
            f"{k}: {', '.join(v)}" for k, v in (f.get("matched") or {}).items()
        )
        out.append(f"   {f['addr']}  {f['size']:>5}b  {f['name']:<28} {why}")
    return "\n".join(out)


def fmt_digest(r: dict[str, Any]) -> str:
    imp = r.get("imports") or {}
    st = r.get("strings") or {}
    chain = " -> ".join(f"{c['name']}@{c['addr']}" for c in r.get("entry") or [])
    libs_all = list((imp.get("libs") or {}).items())
    libs = ", ".join(f"{k}:{v}" for k, v in libs_all[:5])
    if len(libs_all) > 5:
        libs += f" +{len(libs_all) - 5} libs"
    out = [
        f"== {r['binary']}  {r['language']}  base {r['image_base']}",
        f"   md5 {r['md5']}  compiler {r.get('compiler')}",
        f"   entry {chain or '-'}",
        f"   {r.get('functions')} functions | {st.get('total', 0)} strings | "
        f"{imp.get('total', 0)} imports ({libs})",
    ]
    combos = r.get("combos") or []
    if combos:
        out.append("combos")
        for c in combos:
            out.append(f"   !! {c['label']}: {', '.join(c['hits'])}")
    groups = imp.get("groups") or {}
    if groups:
        out.append("imports by risk")
        for kind, names in groups.items():
            more = f" +{len(names)}..." if len(names) >= 12 else ""
            out.append(f"   {kind:<9} {', '.join(names[:12])}{more}")
    counts = st.get("counts") or {}
    samples = st.get("samples") or {}
    if counts:
        out.append("strings")
        for kind, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            vals = " | ".join(s["value"] for s in (samples.get(kind) or []))
            out.append(f"   {kind:<8}({n}) {vals}")
    hubs = r.get("hubs") or []
    if hubs:
        out.append("hubs (most callers)")
        for h in hubs:
            out.append(f"   {h['callers']:>3}x  {h['addr']}  {h['name']}  ({h['size']}b)")
    sizes = r.get("sizes") or {}
    if sizes:
        out.append("sizes   " + "  ".join(f"{k}:{v}" for k, v in sizes.items()))
    body = "\n".join(out)
    return f"{body}\n~{len(body) // 4} tokens"
FORMATTERS = {
    "binaries": fmt_binaries,
    "info": fmt_info,
    "functions": fmt_functions,
    "decompile": fmt_decompile,
    "strings": fmt_strings,
    "xrefs": fmt_xrefs,
    "graph": fmt_graph,
    "digest": fmt_digest,
    "find": fmt_find,
    "emulate": fmt_emulate,
}


# ------------------------------------------------------------- daemon lifecycle


def _ghidra_env_ok() -> bool:
    if os.environ.get("GHIDRA_INSTALL_DIR"):
        return True
    print(
        "ghlab: GHIDRA_INSTALL_DIR is not set (e.g. 'C:\\ghidra_12.2_PUBLIC')",
        file=sys.stderr,
    )
    return False


def cmd_serve(args) -> int:
    from .server import serve

    if not _ghidra_env_ok():
        return 2
    serve(args.host, args.port, args.project_dir, args.project_name)
    return 0


def cmd_start(args) -> int:
    client = Client(f"http://{args.host}:{args.port}/")
    if client.alive():
        print(f"already up on {args.host}:{args.port}")
        return 0
    if not _ghidra_env_ok():
        return 2
    LOGDIR.mkdir(parents=True, exist_ok=True)
    log = open(LOGDIR / "ghlab.log", "ab")
    cmd = [
        sys.executable,
        "-m",
        "ghlab",
        "serve",
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--project-dir",
        args.project_dir,
        "--project-name",
        args.project_name,
    ]
    kwargs: dict[str, Any] = {
        "stdout": log,
        "stderr": log,
        "stdin": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "nt":
        kwargs["creationflags"] = (
            subprocess.DETACHED_PROCESS
            | subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.CREATE_NO_WINDOW
        )
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(cmd, **kwargs)
    print(f"ghlab: spawning pid {proc.pid}, log {LOGDIR / 'ghlab.log'}")
    deadline = time.time() + args.wait
    while time.time() < deadline:
        if client.alive():
            print(f"ready on http://{args.host}:{args.port}/")
            return 0
        if proc.poll() is not None:
            print(f"ghlab: daemon exited with {proc.returncode}", file=sys.stderr)
            return 3
        print(".", end="", flush=True)
        time.sleep(2)
    print(f"\nghlab: not ready after {args.wait}s", file=sys.stderr)
    return 4


def cmd_stop(args) -> int:
    pid_path = Path(args.project_dir).expanduser() / ".ghlab.pid"
    if not pid_path.exists():
        print("ghlab: no pidfile; nothing to stop")
        return 0
    pid = int(pid_path.read_text().strip())
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        print(f"ghlab: pid {pid} already gone")
    except PermissionError as ex:
        print(f"ghlab: cannot signal pid {pid}: {ex}", file=sys.stderr)
        return 1
    else:
        print(f"ghlab: signalled pid {pid}")
    pid_path.unlink(missing_ok=True)
    return 0


def cmd_status(args) -> int:
    client = Client(f"http://{args.host}:{args.port}/")
    try:
        print(json.dumps(client.info(), indent=2, ensure_ascii=False))
        return 0
    except Exception as ex:  # noqa: BLE001
        print(f"ghlab: down ({type(ex).__name__}: {ex})")
        return 1


# --------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--url", default=os.environ.get("GHLAB_URL"))
    common.add_argument("--json", action="store_true", help="emit raw JSON")

    daemon = argparse.ArgumentParser(add_help=False)
    daemon.add_argument("--host", default=DEFAULT_HOST)
    daemon.add_argument("--port", type=int, default=DEFAULT_PORT)
    daemon.add_argument("--project-dir", default=str(Path.home() / "re" / "proj"))
    daemon.add_argument("--project-name", default="ghlab")

    ap = argparse.ArgumentParser(
        prog="ghlab",
        description="Warm Ghidra bridge: persistent headless Ghidra behind a JSON API.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve", parents=[daemon], help="run the daemon in the foreground")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("start", parents=[daemon], help="start the daemon detached")
    p.add_argument("--wait", type=int, default=120)
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("stop", parents=[daemon], help="stop a detached daemon")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("status", parents=[daemon], help="daemon health")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("ping", parents=[common], help="daemon + project summary")
    p.set_defaults(func=lambda a: _call(a, "ping"))

    p = sub.add_parser("binaries", parents=[common], help="list programs")
    p.set_defaults(func=lambda a: _call(a, "binaries"))

    p = sub.add_parser("import", parents=[common], help="import + analyze a binary")
    p.add_argument("path")
    p.add_argument("--no-analyze", action="store_true")
    p.set_defaults(func=lambda a: _call(a, "import", {"path": a.path, "analyze": not a.no_analyze}))

    p = sub.add_parser("info", parents=[common], help="program metadata")
    p.add_argument("binary")
    p.set_defaults(func=lambda a: _call(a, "info", {"binary": a.binary}))

    p = sub.add_parser("functions", parents=[common], help="list functions")
    p.add_argument("binary")
    p.add_argument("-m", "--match", default=None, help="regex on function name")
    p.add_argument("-n", "--limit", type=int, default=60)
    p.set_defaults(
        func=lambda a: _call(
            a, "functions", {"binary": a.binary, "match": a.match, "limit": a.limit}
        )
    )

    p = sub.add_parser("decompile", parents=[common], help="decompile one or many functions")
    p.add_argument("binary")
    p.add_argument("-t", "--target", action="append", default=[], help="symbol or 0xaddr")
    p.add_argument("-m", "--match", default=None, help="regex: decompile every matching function")
    p.add_argument("-g", "--grep", default=None, help="keep only lines matching this regex")
    p.add_argument("-n", "--limit", type=int, default=25, help="max functions")
    p.add_argument("--max-lines", type=int, default=0)
    p.add_argument("--code", action="store_true", help="include full source even when grepping")
    p.add_argument("--callees", action="store_true")
    p.add_argument("--callers", action="store_true")
    p.set_defaults(
        func=lambda a: _call(
            a,
            "decompile",
            {
                "binary": a.binary,
                "targets": a.target or None,
                "match": a.match,
                "grep": a.grep,
                "limit": a.limit,
                "max_lines": a.max_lines,
                "include_code": True if (a.code or a.max_lines) else None,
                "include_callees": a.callees,
                "include_callers": a.callers,
            },
        )
    )

    p = sub.add_parser("strings", parents=[common], help="search string data")
    p.add_argument("binary")
    p.add_argument("-q", "--query", default=None)
    p.add_argument("-n", "--limit", type=int, default=80)
    p.set_defaults(
        func=lambda a: _call(
            a, "strings", {"binary": a.binary, "query": a.query, "limit": a.limit}
        )
    )

    p = sub.add_parser("xrefs", parents=[common], help="references to address/function")
    p.add_argument("binary")
    p.add_argument("target", nargs="+")
    p.set_defaults(
        func=lambda a: _call(a, "xrefs", {"binary": a.binary, "targets": a.target})
    )

    p = sub.add_parser("bytes", parents=[common], help="raw memory")
    p.add_argument("binary")
    p.add_argument("addr")
    p.add_argument("--size", type=int, default=64)
    p.set_defaults(
        func=lambda a: _call(
            a, "bytes", {"binary": a.binary, "addr": a.addr, "size": a.size}
        )
    )

    p = sub.add_parser("rename", parents=[common], help="rename a function")
    p.add_argument("binary")
    p.add_argument("target")
    p.add_argument("new")
    p.set_defaults(
        func=lambda a: _call(
            a, "rename", {"binary": a.binary, "target": a.target, "new": a.new}
        )
    )

    p = sub.add_parser("comment", parents=[common], help="set a comment")
    p.add_argument("binary")
    p.add_argument("target")
    p.add_argument("text")
    p.add_argument("--type", default="plate")
    p.set_defaults(
        func=lambda a: _call(
            a,
            "comment",
            {"binary": a.binary, "target": a.target, "text": a.text, "type": a.type},
        )
    )

    p = sub.add_parser("graph", parents=[common], help="call tree")
    p.add_argument("binary")
    p.add_argument("target")
    p.add_argument("-d", "--depth", type=int, default=2)
    p.add_argument("--direction", choices=("calling", "called"), default="calling")
    p.set_defaults(
        func=lambda a: _call(
            a,
            "graph",
            {
                "binary": a.binary,
                "target": a.target,
                "depth": a.depth,
                "direction": a.direction,
            },
        )
    )
    p = sub.add_parser("emulate", parents=[common], help="run a function on the P-code emulator")
    p.add_argument("binary")
    p.add_argument("target")
    p.add_argument(
        "--arg",
        dest="args",
        action="append",
        default=[],
        metavar="V",
        help='repeatable: 123, 0x40, "text", L"wide text", null (string args are placed in memory)',
    )
    p.add_argument("--max-insns", type=int, default=200000)
    p.add_argument("--ms", type=int, default=5000, help="wall-clock budget")
    p.add_argument(
        "--buffer",
        type=int,
        default=0,
        metavar="SIZE",
        help="reserve a zeroed output buffer (read back after the run; pass its address as an arg)",
    )
    p.add_argument(
        "--dump",
        dest="dump",
        action="append",
        default=[],
        metavar="ADDR[:SIZE]",
        help="read this memory range back afterwards (repeatable)",
    )
    p.set_defaults(
        func=lambda a: _call(
            a,
            "emulate",
            {
                "binary": a.binary,
                "target": a.target,
                "args": a.args,
                "max_insns": a.max_insns,
                "ms": a.ms,
                "dump": a.dump,
                "buffer": a.buffer,
            },
        )
    )

    p = sub.add_parser("digest", parents=[common], help="one-shot triage report")
    p.add_argument("binary")
    p.add_argument("--top", type=int, default=8, help="how many call-graph hubs")
    p.add_argument("--strings", type=int, default=3, help="samples per string kind")
    p.set_defaults(
        func=lambda a: _call(a, "digest", {"binary": a.binary, "top": a.top, "strings": a.strings})
    )

    p = sub.add_parser("find", parents=[common], help="locate candidates by structure")
    p.add_argument("binary")
    p.add_argument("-i", "--import", dest="import_", action="append", default=[],
                   help="regex on imported symbol names (repeatable)")
    p.add_argument("-s", "--string", action="append", default=[],
                   help="regex on string data (repeatable)")
    p.add_argument("-c", "--calls", action="append", default=[],
                   help="regex on callee names (repeatable)")
    p.add_argument("-n", "--limit", type=int, default=20)
    p.add_argument("--any", action="store_true", help="any filter instead of all")
    p.set_defaults(
        func=lambda a: _call(
            a,
            "find",
            {
                "binary": a.binary,
                "import": a.import_ or None,
                "string": a.string or None,
                "calls": a.calls or None,
                "limit": a.limit,
                "any": a.any,
            },
        )
    )
    return ap


def _call(args, cmd: str, params: dict[str, Any] | None = None) -> int:
    params = {k: v for k, v in (params or {}).items() if v is not None}
    client = Client(args.url)
    try:
        result = client.call(cmd, **params)
    except RemoteError as ex:
        print(f"ghlab: {ex}", file=sys.stderr)
        if ex.trace and os.environ.get("GHLAB_DEBUG"):
            print(ex.trace, file=sys.stderr)
        return 1
    if getattr(args, "json", False) or cmd not in FORMATTERS:
        _print_json(result)
    else:
        print(FORMATTERS[cmd](result))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # `--json` is accepted before or after the subcommand.
    global_json = "--json" in argv
    if global_json:
        argv = [a for a in argv if a != "--json"]
    parser = build_parser()
    args = parser.parse_args(argv)
    if global_json:
        args.json = True
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
