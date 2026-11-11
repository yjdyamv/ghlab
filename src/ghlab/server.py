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
# GET serves only these: the commands that answer a question asked by naming
# nothing. Argument-free project-wide scans (audit re-checks every claim,
# campaign clusters every program) stay POST-only, because a single stray GET --
# a browser address bar, a link prefetch -- would otherwise start a job that
# runs for minutes.
GET_COMMANDS = ("ping", "binaries", "overview")
# A daemon that can patch bytes must not answer cross-site "simple" requests: a
# text/plain POST skips the CORS preflight, so any page the user visits could
# otherwise drive `patch`/`rename`/`note`. application/json forces a preflight,
# and every first-party client (Client, MCP) already sends exactly that.
JSON_CONTENT_TYPE = "application/json"
# A request body is a command and its arguments; 8 MiB is orders of magnitude more
# than the largest real one (bulk `types` maps) and small enough that an uploaded
# body cannot be used to park a thread.
MAX_BODY = 8 * 1024 * 1024
# How long a client may take to send that body. Separate from
# GHLAB_SOCKET_TIMEOUT, which must stay long: decompiling a big binary writes tens
# of megabytes back to a slow client and a short write timeout would cut it off.
READ_TIMEOUT = 30.0
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


def _info_body() -> bytes:
    """The self-describing help page: GET / returns it, HEAD / advertises its size."""
    return json.dumps(
        {
            "ok": True,
            "service": "ghlab",
            "pid": os.getpid(),
            "uptime_s": round(time.time() - STARTED, 1),
            "busy": session.in_flight(),
            "readonly": session.readonly(),
            "usage": 'POST / with {"cmd": "<name>", ...}, or GET /<name> for the '
            "commands that take no arguments (ping, binaries, overview, ...)",
            "cmds": {
                name: {"required": s.required, "optional": s.optional, "summary": s.summary}
                for name, s in protocol.SPECS.items()
            },
        },
        ensure_ascii=False,
    ).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ghlab/0.1"

    def setup(self) -> None:
        super().setup()
        # A client that vanishes mid-response must not pin the single server
        # thread forever; the timeout also bounds half-open reads.
        with contextlib.suppress(OSError):
            self.connection.settimeout(float(os.environ.get("GHLAB_SOCKET_TIMEOUT", "900")))

    def _send(self, body: bytes, code: int = 200, head_only: bool = False) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if head_only:
            return
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(body)

    def _read_body(self, n: int) -> bytes:
        """Read exactly n bytes of request body, under a deadline of its own."""
        read_timeout = float(os.environ.get("GHLAB_READ_TIMEOUT", str(READ_TIMEOUT)))
        with contextlib.suppress(OSError):
            self.connection.settimeout(read_timeout)
        try:
            return self.rfile.read(n) if n else b"{}"
        finally:
            with contextlib.suppress(OSError):
                self.connection.settimeout(float(os.environ.get("GHLAB_SOCKET_TIMEOUT", "900")))

    def _reject(self, code: int, note: str) -> None:
        """Refuse without reading the body, then close so the body is not re-parsed."""
        self._send(protocol.Err(note).to_bytes(), code)
        self.close_connection = True
        # Log before draining: a delayed line would land in the next test's capture.
        _log(f"cmd=? ms=0 status={code} {note}")
        self._drain()

    def _drain(self, budget: float = 0.2) -> None:
        """Swallow what the client is still sending, so the close is not an RST.

        Closing a socket with unread bytes in the receive buffer makes Windows
        answer with RST; the client then loses the 415/411 it was about to read
        and reports a reset instead (seen with chunked bodies from http.client).
        """
        deadline = time.monotonic() + budget
        with contextlib.suppress(OSError):
            self.connection.settimeout(0.05)
            while time.monotonic() < deadline and self.connection.recv(65536):
                pass

    def do_POST(self) -> None:
        started = time.monotonic()
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != JSON_CONTENT_TYPE:
            self._reject(415, f"Content-Type must be {JSON_CONTENT_TYPE}, got {ctype or 'none'}")
            return
        if self.headers.get("Transfer-Encoding"):
            self._reject(411, "chunked bodies are not supported; send Content-Length")
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._reject(400, "Content-Length is not a number")
            return
        if n > MAX_BODY:
            self._reject(413, f"body is {n} bytes; the limit is {MAX_BODY}")
            return
        try:
            raw = self._read_body(n)
        except TimeoutError:
            self._reject(408, "timed out reading the request body")
            return
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
        # A GET is a convenience for the parameterless query commands, so that
        # `curl http://127.0.0.1:8765/binaries` lists the programs instead of
        # returning the help page (the help page surprised every new client).
        bare = self.path.split("?", 1)[0].rstrip("/")
        name = bare.rsplit("/", 1)[-1]
        spec = protocol.SPECS.get(name)
        # `not spec.required` still matters: GET never invents arguments, so a name
        # that needs one must fall through to the help page rather than fail.
        if spec is not None and name in GET_COMMANDS and not spec.required:
            started = time.monotonic()
            status = 200
            try:
                result = session.dispatch(spec.name, {})
                self._send(protocol.Ok(result, int(1000 * (time.monotonic() - started))).to_bytes())
            except Exception as ex:  # noqa: BLE001
                status = 500
                self._send(protocol.Err(f"{type(ex).__name__}: {ex}").to_bytes(), 500)
            finally:
                ms = int(1000 * (time.monotonic() - started))
                _log(f"cmd={spec.name} ms={ms} status={status} (GET)")
            return
        if bare in ("/health", "/ping"):
            try:
                body = json.dumps({"ok": True, "result": session.ping({})}).encode()
            except Exception as ex:  # noqa: BLE001
                body = json.dumps({"ok": False, "error": f"{type(ex).__name__}: {ex}"}).encode()
        else:
            body = _info_body()
        self._send(body)

    def do_HEAD(self) -> None:
        # `curl -I` and link checkers probe with HEAD; the inherited 501 made a
        # healthy daemon look broken. Same headers as GET /, no body.
        self._send(_info_body(), head_only=True)

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
