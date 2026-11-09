"""HTTP front-end: one request at a time, so Ghidra transactions stay safe."""

from __future__ import annotations

import contextlib
import json
import os
import socket
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import protocol, session

# Requests slower than this get a SLOW marker in the log (milliseconds).
SLOW_MS = int(os.environ.get("GHLAB_SLOW_MS", "5000"))
STARTED = time.time()


def _log(line: str) -> None:
    sys.stderr.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {line}\n")
    sys.stderr.flush()


def _describe(params: dict[str, Any]) -> str:
    """Compact argument summary: keys always, values only when short and safe."""
    bits = []
    for key in sorted(params):
        if key == "binary":
            continue
        value = params[key]
        if isinstance(value, (int, float)) or (isinstance(value, str) and len(value) <= 40):
            bits.append(f"{key}={value}")
        elif isinstance(value, list):
            bits.append(f"{key}[{len(value)}]")
    return " ".join(bits)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ghlab/0.1"

    def setup(self) -> None:
        super().setup()
        # A client that vanishes mid-response must not pin the single server
        # thread forever; the timeout also bounds half-open reads.
        with contextlib.suppress(OSError):
            self.connection.settimeout(float(os.environ.get("GHLAB_SOCKET_TIMEOUT", "900")))

    def _send(self, body: bytes, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(body)

    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        started = time.monotonic()
        cmd = "?"
        params: dict[str, Any] = {}
        status = 200
        note = ""
        try:
            request = json.loads(raw or b"{}")
            cmd = str(request.get("cmd") or "?")
            spec, params = protocol.validate(request)
            result = session.dispatch(spec.name, params)
            payload = protocol.Ok(result, int(1000 * (time.monotonic() - started)))
            self._send(payload.to_bytes())
        except protocol.ProtocolError as ex:
            status, note = 400, f"ProtocolError: {ex}"
            self._send(protocol.Err(note).to_bytes(), 400)
        except Exception as ex:  # noqa: BLE001 - every failure must reach the client
            status, note = 500, f"{type(ex).__name__}: {ex}"
            err = protocol.Err(note, traceback.format_exc()[-2000:])
            self._send(err.to_bytes(), 500)
        finally:
            ms = int(1000 * (time.monotonic() - started))
            marker = " SLOW" if ms >= SLOW_MS else ""
            _log(f"cmd={cmd} ms={ms}{marker} status={status} {_describe(params)} {note}".rstrip())

    def do_GET(self) -> None:
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
                    "pid": os.getpid(),
                    "uptime_s": round(time.time() - STARTED, 1),
                    "busy": session.in_flight(),
                    "usage": 'POST / with {"cmd": "<name>", ...}',
                    "cmds": {
                        name: {"required": s.required, "optional": s.optional, "summary": s.summary}
                        for name, s in protocol.SPECS.items()
                    },
                },
                ensure_ascii=False,
            ).encode()
        self._send(body)

    def log_message(self, format: str, *args: Any) -> None:
        if os.environ.get("GHLAB_VERBOSE"):
            sys.stderr.write(f"{self.address_string()} - {format % args}\n")


class Server(ThreadingHTTPServer):
    # Windows allows a second bind when SO_REUSEADDR is set; a duplicate daemon
    # silently serving stale code is a nasty failure mode, so refuse it.
    allow_reuse_address = False
    # Requests run on their own threads but every Ghidra call takes session.LOCK,
    # so the work is still strictly serial. The point of threading is that GET /
    # (health, busy, command list) answers *while* a long job holds the lock.
    daemon_threads = True


def pidfile() -> str:
    base = session._project_dir or "."
    return os.path.join(str(base), ".ghlab.pid")


def serve(host: str, port: int, project_dir: str, project_name: str) -> None:
    session.configure(project_dir, project_name)
    print("ghlab: starting Ghidra (JVM boot takes ~30-45s)…", flush=True)
    session.boot()
    session.project()
    with open(pidfile(), "w", encoding="utf-8") as fh:
        json.dump(
            {
                "pid": os.getpid(),
                "parent": os.getppid(),
                "stamp": session.code_stamp(),
                "port": port,
                "project": str(session.project_location()),
            },
            fh,
        )
    try:
        httpd = Server((host, port), Handler)
    except OSError as ex:
        print(f"ghlab: cannot bind {host}:{port} ({ex})", file=sys.stderr, flush=True)
        raise SystemExit(2) from ex
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
