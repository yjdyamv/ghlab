"""HTTP front-end: one request at a time, so Ghidra transactions stay safe."""

from __future__ import annotations

import json
import os
import socket
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import protocol, session


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ghlab/0.1"

    def _send(self, body: bytes, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        started = time.monotonic()
        try:
            request = json.loads(raw or b"{}")
            spec, params = protocol.validate(request)
            result = session.dispatch(spec.name, params)
            payload = protocol.Ok(result, int(1000 * (time.monotonic() - started)))
            self._send(payload.to_bytes())
        except protocol.ProtocolError as ex:
            self._send(protocol.Err(f"ProtocolError: {ex}").to_bytes(), 400)
        except Exception as ex:  # noqa: BLE001 - every failure must reach the client
            err = protocol.Err(f"{type(ex).__name__}: {ex}", traceback.format_exc()[-2000:])
            self._send(err.to_bytes(), 500)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") in ("/health", "/ping"):
            try:
                body = json.dumps({"ok": True, "result": session.ping({})}).encode()
            except Exception as ex:  # noqa: BLE001
                body = json.dumps({"ok": False, "error": f"{type(ex).__name__}: {ex}"}).encode()
        else:
            body = json.dumps(
                {
                    "ok": True,
                    "service": "ghlab",
                    "usage": 'POST / with {"cmd": "<name>", ...}',
                    "cmds": {
                        name: {"required": s.required, "optional": s.optional, "summary": s.summary}
                        for name, s in protocol.SPECS.items()
                    },
                },
                ensure_ascii=False,
            ).encode()
        self._send(body)

    def log_message(self, fmt: str, *args) -> None:  # quieter default logging
        if os.environ.get("GHLAB_VERBOSE"):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


class Server(HTTPServer):
    # Windows allows a second bind when SO_REUSEADDR is set; a duplicate daemon
    # silently serving stale code is a nasty failure mode, so refuse it.
    allow_reuse_address = False
    daemon_threads = False


def pidfile() -> "os.PathLike[str]":
    base = session._project_dir or "."
    return os.path.join(str(base), ".ghlab.pid")


def serve(host: str, port: int, project_dir: str, project_name: str) -> None:
    session.configure(project_dir, project_name)
    print("ghlab: starting Ghidra (JVM boot takes ~30-45s)…", flush=True)
    session.boot()
    session.project()
    with open(pidfile(), "w", encoding="utf-8") as fh:
        fh.write(str(os.getpid()))
    try:
        httpd = Server((host, port), Handler)
    except OSError as ex:
        print(f"ghlab: cannot bind {host}:{port} ({ex})", file=sys.stderr, flush=True)
        raise SystemExit(2)
    print(
        f"ghlab: listening on http://{host}:{port}/ project={session.project_location()} "
        f"binaries={session.binary_names()}",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def free_port(host: str = "127.0.0.1", start: int = protocol.DEFAULT_PORT) -> int:
    for port in range(start, start + 50):
        with socket.socket() as s:
            if s.connect_ex((host, port)) != 0:
                return port
    raise RuntimeError("no free port found")
