"""End-to-end over real HTTP, with a stub session so no Ghidra is needed."""

import os
import threading
import time
import unittest
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

    def test_down_daemon_gives_actionable_message(self):
        dead = Client("http://127.0.0.1:9/", timeout=1)
        self.assertFalse(dead.alive())
        with self.assertRaises(RemoteError) as ctx:
            dead.call("ping")
        self.assertIn("ghlab start", str(ctx.exception))

    def test_every_request_is_logged(self):
        lines: list[str] = []
        with mock.patch("ghlab.server._log", lines.append):
            self.client.call("ping")
            with self.assertRaises(RemoteError):
                self.client.call("info", binary="stub.exe")
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
        # The response is written inside the try, the log line inside the finally: the
        # client can see its answer before the handler has logged. Wait for the line.
        deadline = time.time() + 2
        while not lines and time.time() < deadline:
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


if __name__ == "__main__":
    unittest.main()
