"""The two error paths an agent hits first: no daemon, and a wrong parameter."""

from __future__ import annotations

import io
import unittest
import urllib.error
from unittest import mock

from ghlab import cli
from ghlab.client import Client, RemoteError


class UnreachableTest(unittest.TestCase):
    def test_a_refused_connection_names_the_next_command(self):
        refused = urllib.error.URLError(ConnectionRefusedError(10061, "refused"))
        with (
            mock.patch.object(urllib.request, "urlopen", side_effect=refused),
            self.assertRaises(RemoteError) as caught,
        ):
            Client("http://127.0.0.1:8775/").call("ping")
        message = str(caught.exception)
        self.assertIn("nothing is listening on http://127.0.0.1:8775/", message)
        self.assertIn("ghlab start --port 8775", message)
        self.assertNotIn("10061", message)  # errno noise stays out

    def test_another_failure_is_worded_differently(self):
        broken = urllib.error.URLError(OSError("name resolution"))
        with (
            mock.patch.object(urllib.request, "urlopen", side_effect=broken),
            self.assertRaises(RemoteError) as caught,
        ):
            Client("http://box:8765/").call("ping")
        self.assertIn("cannot reach http://box:8765/", str(caught.exception))

    def test_debug_keeps_the_original_reason(self):
        refused = urllib.error.URLError(ConnectionRefusedError(10061, "refused"))
        with (
            mock.patch.object(urllib.request, "urlopen", side_effect=refused),
            mock.patch.dict("os.environ", {"GHLAB_DEBUG": "1"}),
            self.assertRaises(RemoteError) as caught,
        ):
            Client("http://127.0.0.1:8775/").call("ping")
        self.assertIn("refused", str(caught.exception))

    def test_a_timeout_says_what_to_check(self):
        with (
            mock.patch.object(urllib.request, "urlopen", side_effect=TimeoutError()),
            self.assertRaises(RemoteError) as caught,
        ):
            Client("http://127.0.0.1:8775/", timeout=7).call("decompile")
        message = str(caught.exception)
        self.assertIn("did not answer within 7s", message)
        self.assertIn("ghlab job --list", message)


class ShapeHintTest(unittest.TestCase):
    def test_a_missing_parameter_shows_the_shape(self):
        hint = cli._shape_hint("decompile", "decompile: missing ['target']")
        self.assertIn("ghlab decompile binary=...", hint)
        self.assertIn("target=...", hint)

    def test_an_unknown_parameter_shows_the_shape_too(self):
        self.assertIn(
            "ghlab scan binary=...", cli._shape_hint("scan", "scan: unknown parameter(s) [])")
        )

    def test_other_errors_get_no_hint(self):
        self.assertEqual(cli._shape_hint("scan", "no function at 0x1"), "")
        self.assertEqual(cli._shape_hint("nonsense", "missing ['x']"), "")


class ShapeHintPrintTest(unittest.TestCase):
    def test_the_hint_goes_to_stderr_after_the_error(self):
        args = cli.build_parser().parse_args(["functions", "b.exe"])
        with (
            mock.patch("ghlab.cli.Client") as client,
            mock.patch("sys.stderr", new_callable=io.StringIO) as err,
        ):
            client.return_value.call.side_effect = RemoteError("functions: missing ['binary']")
            code = cli._call(args, "functions", {"binary": "b.exe"})
        lines = err.getvalue().splitlines()
        self.assertEqual(code, 1)
        self.assertTrue(lines[0].startswith("ghlab: functions: missing"), lines)
        self.assertIn("shape: ghlab functions binary=...", lines[1])


if __name__ == "__main__":
    unittest.main()
