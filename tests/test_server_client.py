"""End-to-end over real HTTP, with a stub session so no Ghidra is needed."""

import http.client
import json
import os
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

from ghlab import session
from ghlab.client import Client, RemoteError
from ghlab.server import Handler, Server


class ClientConfigTest(unittest.TestCase):
    def test_env_sets_the_default_url_and_timeout(self):
        with mock.patch.dict(
            os.environ, {"GHLAB_URL": "http://10.0.0.5:9000/", "GHLAB_TIMEOUT": "42"}, clear=False
        ):
            c = Client()
            self.assertEqual(c.url, "http://10.0.0.5:9000/")
            self.assertEqual(c.timeout, 42.0)
            self.assertEqual(Client(timeout=7).timeout, 7.0)

    def test_defaults_when_env_is_absent(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            c = Client()
            self.assertIn("127.0.0.1", c.url)
            self.assertEqual(c.timeout, 300.0)


class StubSession:
    def __init__(self):
        self.calls = []

    def dispatch(self, cmd, params):
        self.calls.append((cmd, params))
        if cmd == "ping":
            return {"service": "stub", "binaries": ["stub.exe"]}
        if cmd == "binaries":
            return {"binaries": ["stub.exe"]}
        if cmd == "decompile":
            return {"binary": params["binary"], "results": []}
        raise KeyError(f"stub has no {cmd}")


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stub = StubSession()
        cls._real_dispatch = session.dispatch
        session.dispatch = cls.stub.dispatch  # ty: ignore[invalid-assignment]
        cls.httpd = Server(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.client = Client(f"http://127.0.0.1:{cls.port}/", timeout=10)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        session.dispatch = cls._real_dispatch  # ty: ignore[invalid-assignment]

    def test_ping(self):
        self.assertEqual(self.client.call("ping")["service"], "stub")

    def test_parameters_reach_the_handler(self):
        self.client.call("decompile", binary="stub.exe", targets=["main"])
        self.assertEqual(self.stub.calls[-1][1]["targets"], ["main"])

    def test_unknown_command_is_a_client_error(self):
        with self.assertRaises(RemoteError) as ctx:
            self.client.call("nope")
        self.assertIn("unknown cmd", str(ctx.exception))

    def test_handler_failure_is_a_remote_error_with_trace(self):
        with self.assertRaises(RemoteError) as ctx:
            self.client.call("info", binary="stub.exe")  # stub raises KeyError
        self.assertIn("KeyError", str(ctx.exception))

    def test_get_overview_lists_commands(self):
        info = self.client.info()
        self.assertTrue(info["ok"])
        self.assertIn("decompile", info["cmds"])
        self.assertEqual(info["cmds"]["decompile"]["required"], ["binary"])

    def _get(self, path: str) -> dict:
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=10) as r:
            return json.loads(r.read())

    def _raw(self, payload: bytes) -> tuple[int, bytes]:
        """Send bytes a well-behaved client would never send, and read the answer."""
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        try:
            sock.sendall(payload)
            return self._read_response(sock)
        finally:
            sock.close()

    @staticmethod
    def _read_response(sock) -> tuple[int, bytes]:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        status = int(head.split(b" ")[1])
        length = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1])
        while len(rest) < length:
            chunk = sock.recv(4096)
            if not chunk:
                break
            rest += chunk
        return status, rest[:length]

    def test_get_runs_a_command_that_takes_no_arguments(self):
        # `curl host/binaries` is the first thing a new client tries; the help page
        # that came back instead was the surprise this branch exists to remove.
        payload = self._get("/binaries")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["binaries"], ["stub.exe"])

    def test_get_of_a_command_that_needs_arguments_is_still_the_help_page(self):
        # Guessing empty params for `decompile` would answer a question nobody asked.
        payload = self._get("/decompile")
        self.assertIn("decompile", payload["cmds"])
        self.assertNotIn("result", payload)

    def test_a_heavy_parameterless_command_stays_post_only(self):
        # `campaign` takes no arguments either, but it clusters every program: a GET
        # that silently started minutes of work is exactly what the allowlist stops.
        payload = self._get("/campaign")
        self.assertIn("cmds", payload)
        self.assertNotIn("result", payload)

    def test_a_failing_get_is_logged_as_a_failure(self):
        lines: list[str] = []
        with mock.patch("ghlab.server._log", lines.append):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self._get("/overview")  # the stub raises KeyError for it
            self.assertEqual(ctx.exception.code, 500)
            lines = self._wait_for_line(lines, 1)
        self.assertIn("status=500", lines[0])

    def test_down_daemon_gives_actionable_message(self):
        dead = Client("http://127.0.0.1:9/", timeout=1)
        self.assertFalse(dead.alive())
        with self.assertRaises(RemoteError) as ctx:
            dead.call("ping")
        self.assertIn("ghlab start", str(ctx.exception))

    def _wait_for_line(self, lines: list[str], count: int, timeout: float = 2.0) -> list[str]:
        """The handler logs after it answers, so a fast client can beat the log."""
        deadline = time.monotonic() + timeout
        while len(lines) < count and time.monotonic() < deadline:
            time.sleep(0.01)
        return lines

    def test_every_request_is_logged(self):
        lines: list[str] = []
        with mock.patch("ghlab.server._log", lines.append):
            self.client.call("ping")
            with self.assertRaises(RemoteError):
                self.client.call("info", binary="stub.exe")
            lines = self._wait_for_line(lines, 2)
        self.assertEqual(len(lines), 2)
        self.assertIn("cmd=ping", lines[0])
        self.assertIn("status=200", lines[0])
        self.assertIn("cmd=info", lines[1])
        self.assertIn("status=500", lines[1])
        self.assertIn("KeyError", lines[1])

    def test_slow_requests_are_marked(self):
        lines: list[str] = []
        blocker = threading.Event()

        def slow(cmd, params):
            blocker.wait(2)
            return {"service": "stub"}

        with mock.patch("ghlab.server._log", lines.append), mock.patch("ghlab.server.SLOW_MS", 1):
            session.dispatch = slow  # ty: ignore[invalid-assignment]
            try:
                timer = threading.Timer(0.05, blocker.set)
                timer.start()
                self.client.call("ping")
                timer.join()
            finally:
                session.dispatch = self.stub.dispatch  # ty: ignore[invalid-assignment]
            # The response is written inside the try, the log line in a finally on the
            # handler thread: wait *inside* the patch, or the line lands after _log is
            # restored and is lost.
            deadline = time.time() + 5
            while not any("SLOW" in line for line in lines) and time.time() < deadline:
                time.sleep(0.01)
        self.assertTrue(any("SLOW" in ln for ln in lines), lines)

    def test_status_answers_while_a_long_call_holds_the_lock(self):
        started = threading.Event()
        release = threading.Event()

        def slow(a: dict) -> dict:
            started.set()
            release.wait(5)
            return {"binary": "x", "results": []}

        with mock.patch("ghlab.server._log", lambda _line: None):
            session.dispatch = type(self)._real_dispatch  # ty: ignore[invalid-assignment]
            original = session.HANDLERS["decompile"]
            session.HANDLERS["decompile"] = slow
            try:
                worker = threading.Thread(target=lambda: self.client.call("decompile", binary="x"))
                worker.start()
                self.assertTrue(started.wait(2))
                began = time.monotonic()
                info = self.client.info()  # GET / must not queue behind the lock
                took = time.monotonic() - began
                self.assertLess(took, 2.0)
                self.assertEqual(info["busy"]["cmd"], "decompile")
                release.set()
                worker.join(5)
            finally:
                release.set()
                session.HANDLERS["decompile"] = original
                session.dispatch = self.stub.dispatch  # ty: ignore[invalid-assignment]
        self.assertEqual(session.in_flight(), {})

    def test_ping_never_reports_itself_as_busy(self):
        info = self.client.call("ping")
        self.assertNotIn("busy", info)

    def test_status_view_reports_what_is_running(self):
        before = session.in_flight()
        self.assertEqual(before, {})
        session._INFLIGHT.update({"cmd": "scan", "started": time.monotonic(), "since": "12:00:00"})
        try:
            busy = session.in_flight()
            self.assertEqual(busy["cmd"], "scan")
            self.assertIsNotNone(busy["elapsed_s"])
            info = self.client.info()
            self.assertEqual(info["busy"]["cmd"], "scan")
            self.assertIn("uptime_s", info)
            self.assertIn("pid", info)
        finally:
            session._INFLIGHT.update({"cmd": None, "started": 0.0, "since": None})
        self.assertEqual(session.in_flight(), {})

    def test_a_text_plain_post_is_refused(self):
        # `text/plain` is a CORS "simple" request: the browser sends it without a
        # preflight, so without this check any page the user visits could drive
        # `patch`/`rename`/`note` against the daemon.
        before = len(self.stub.calls)
        body = json.dumps({"cmd": "patch", "binary": "x.exe", "addr": "0x1000", "bytes": "90"})
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/",
            data=body.encode(),
            headers={"Content-Type": "text/plain;charset=UTF-8", "Origin": "https://evil.example"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 415)
        self.assertEqual(len(self.stub.calls), before, "the rejected body must not run")

    def test_a_chunked_body_is_refused_with_an_explanation(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(
                "POST",
                "/",
                body=iter([b'{"cmd":"ping"}']),
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            payload = json.loads(resp.read())
        finally:
            conn.close()
        self.assertEqual(resp.status, 411)
        self.assertIn("Content-Length", payload["error"])

    def test_head_answers_with_the_help_page_headers_and_no_body(self):
        # `curl -I` / link checkers use HEAD; 501 from the base class made a healthy
        # daemon look dead to every one of them.
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            body = resp.read()
        finally:
            conn.close()
        self.assertEqual(resp.status, 200)
        self.assertIn("application/json", resp.getheader("Content-Type"))
        self.assertGreater(int(resp.getheader("Content-Length")), 100)
        self.assertEqual(body, b"")

    def test_an_oversized_body_is_refused_before_it_is_read(self):
        # Nothing downstream needs a 1 GB command; reading it would park a thread.
        from ghlab import server as server_mod

        with mock.patch.object(server_mod, "MAX_BODY", 16):
            status, body = self._raw(
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                b"Content-Length: 999999\r\n\r\n"
            )
        self.assertEqual(status, 413)
        self.assertIn(b"limit is 16", body)

    def test_a_stalled_body_is_dropped_after_the_read_timeout(self):
        # The response timeout is 900 s because big answers take a while to write;
        # a client that never sends its body must not inherit that patience.
        with mock.patch.dict(os.environ, {"GHLAB_READ_TIMEOUT": "0.2"}):
            status, body = self._raw(
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                b"Content-Length: 10\r\n\r\n"
            )
        self.assertEqual(status, 408)
        self.assertIn(b"timed out", body)

    def test_a_queued_call_is_not_reported_as_running(self):
        # Dispatch marks a command only once it holds the lock; a request parked
        # behind a slow call used to overwrite (then wipe) the running status.
        entered = threading.Event()
        session.dispatch = type(self)._real_dispatch  # ty: ignore[invalid-assignment]
        original = session.HANDLERS["binaries"]
        session.HANDLERS["binaries"] = lambda _p: (entered.set(), {"binaries": []})[1]
        session.LOCK.acquire()
        worker = threading.Thread(target=lambda: session.dispatch("binaries", {}))
        try:
            worker.start()
            self.assertFalse(entered.wait(0.3), "the call must still be waiting for the lock")
            self.assertEqual(session.in_flight(), {}, "a queued call is not running")
        finally:
            session.LOCK.release()
            worker.join(5)
            session.HANDLERS["binaries"] = original
            session.dispatch = self.stub.dispatch  # ty: ignore[invalid-assignment]
        self.assertEqual(session.in_flight(), {})


if __name__ == "__main__":
    unittest.main()
