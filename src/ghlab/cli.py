"""`ghlab` command line: daemon lifecycle plus one-shot queries."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
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


FORMATTERS = {
    "binaries": fmt_binaries,
    "info": fmt_info,
    "functions": fmt_functions,
    "decompile": fmt_decompile,
    "strings": fmt_strings,
    "xrefs": fmt_xrefs,
    "graph": fmt_graph,
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
