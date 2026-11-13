"""`ghlab start` must not spawn a daemon that cannot import the JVM bridge."""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ghlab import cli


class _Alive:
    def __init__(self, up: bool):
        self.up = up

    def alive(self) -> bool:
        return self.up


class PyghidraCheckTest(unittest.TestCase):
    def test_an_interpreter_that_imports_wins(self):
        with mock.patch.object(cli.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.assertTrue(cli._pyghidra_ok())
            self.assertIn("pyghidra", run.call_args[0][0][-1])

    def test_a_missing_module_is_reported_not_raised(self):
        with mock.patch.object(cli.subprocess, "run") as run:
            run.return_value.returncode = 1
            self.assertFalse(cli._pyghidra_ok())
        with mock.patch.object(cli.subprocess, "run", side_effect=OSError("no such exe")):
            self.assertFalse(cli._pyghidra_ok())


class LogTailTest(unittest.TestCase):
    def test_the_last_lines_come_back_indented(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ghlab.log"
            path.write_text("a\n\nb\nc\n", encoding="utf-8")
            self.assertEqual(cli._log_tail(path, 2), "  b\n  c")

    def test_a_missing_log_is_not_an_error(self):
        self.assertEqual(cli._log_tail(Path("/nope/ghlab.log")), "")


class StartRefusalTest(unittest.TestCase):
    def _args(self):
        return cli.build_parser().parse_args(["start", "--port", "8799"])

    def test_a_wrong_interpreter_is_refused_before_spawning(self):
        with (
            mock.patch.object(cli, "Client", return_value=_Alive(False)),
            mock.patch.object(cli, "_pyghidra_ok", return_value=False),
            mock.patch.object(cli.subprocess, "Popen") as spawn,
            mock.patch("sys.stderr", new_callable=io.StringIO) as err,
        ):
            self.assertEqual(cli.cmd_start(self._args()), 2)
        spawn.assert_not_called()
        self.assertIn("cannot import jpype/pyghidra", err.getvalue())

    def test_a_running_daemon_is_not_revalidated(self):
        # a healthy daemon means the check is pointless, and it costs a subprocess
        with (
            mock.patch.object(cli, "Client", return_value=_Alive(True)),
            mock.patch.object(cli, "_pyghidra_ok") as check,
            mock.patch.object(cli, "_pidfile", return_value={"pid": 1, "stamp": "abc"}),
            mock.patch.object(cli.session, "code_stamp", return_value="abc"),
            mock.patch("builtins.print"),
        ):
            self.assertEqual(cli.cmd_start(self._args()), 0)
        check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
