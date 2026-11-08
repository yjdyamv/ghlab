"""End-to-end over real HTTP, with a stub session so no Ghidra is needed."""

import os
import threading
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
        session.dispatch = cls.stub.dispatch
        cls.httpd = Server(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.client = Client(f"http://127.0.0.1:{cls.port}/", timeout=10)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        session.dispatch = cls._real_dispatch

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


if __name__ == "__main__":
    unittest.main()
