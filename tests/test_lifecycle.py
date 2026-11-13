"""`ghlab start` must not spawn a daemon that cannot import the JVM bridge."""

from __future__ import annotations

import io
import os
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
        self.assertIn("jpype/pyghidra", err.getvalue())
        self.assertIn("GHLAB_PYTHON", err.getvalue())

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


class HostPythonTest(unittest.TestCase):
    def test_ghlab_python_wins_over_this_interpreter(self):
        with (
            mock.patch.dict("os.environ", {"GHLAB_PYTHON": "C:/venv/python.exe"}),
            mock.patch.object(
                cli, "_pyghidra_ok", side_effect=lambda exe=None: exe == "C:/venv/python.exe"
            ),
        ):
            self.assertEqual(cli._host_python(), "C:/venv/python.exe")

    def test_the_configured_interpreter_is_the_last_resort(self):
        with (
            mock.patch.dict("os.environ", {}, clear=False),
            mock.patch.object(cli, "load_config", return_value={"python": "C:/old/python.exe"}),
            mock.patch.object(
                cli, "_pyghidra_ok", side_effect=lambda exe=None: exe == "C:/old/python.exe"
            ),
        ):
            os.environ.pop("GHLAB_PYTHON", None)
            self.assertEqual(cli._host_python(), "C:/old/python.exe")

    def test_none_of_them_working_is_not_an_exception(self):
        with (
            mock.patch.object(cli, "load_config", return_value={}),
            mock.patch.object(cli, "_pyghidra_ok", return_value=False),
        ):
            os.environ.pop("GHLAB_PYTHON", None)
            self.assertIsNone(cli._host_python())

    def test_the_daemon_is_spawned_with_the_chosen_interpreter(self):
        args = cli.build_parser().parse_args(["start", "--port", "8799", "--wait", "0"])
        with (
            mock.patch.object(cli, "Client", return_value=_Alive(False)),
            mock.patch.object(cli, "_host_python", return_value="C:/venv/python.exe"),
            mock.patch.object(cli, "_ghidra_env_ok", return_value=True),
            mock.patch.object(cli.subprocess, "Popen") as spawn,
            mock.patch.object(cli, "_rotate_log"),
            mock.patch.object(cli, "LOGDIR", Path(tempfile.gettempdir())),
            mock.patch("builtins.open", mock.mock_open()),
            mock.patch("builtins.print"),
        ):
            spawn.return_value.pid = 7
            self.assertEqual(cli.cmd_start(args), 4)  # wait deadline passes: no daemon
        self.assertEqual(spawn.call_args[0][0][0], "C:/venv/python.exe")

    def test_a_stale_daemon_is_left_alone_when_no_interpreter_can_replace_it(self):
        args = cli.build_parser().parse_args(["start", "--port", "8799"])
        with (
            mock.patch.object(cli, "Client", return_value=_Alive(True)),
            mock.patch.object(cli, "_pidfile", return_value={"pid": 501, "stamp": "old"}),
            mock.patch.object(cli.session, "code_stamp", return_value="new"),
            mock.patch.object(cli, "_host_python", return_value=None),
            mock.patch.object(cli, "_terminate") as kill,
            mock.patch("sys.stderr", new_callable=io.StringIO),
        ):
            self.assertEqual(cli.cmd_start(args), 2)
        kill.assert_not_called()


class SetupRecordsPythonTest(unittest.TestCase):
    def test_setup_remembers_the_interpreter_that_can_host_ghidra(self):
        args = cli.build_parser().parse_args(["setup"])
        cfg: dict = {}
        with (
            mock.patch.object(cli, "load_config", return_value=cfg),
            mock.patch.object(cli, "save_config", side_effect=lambda _data: Path("cfg.json")),
            mock.patch.object(cli, "_host_python", return_value="C:/venv/python.exe"),
            mock.patch.object(cli, "ghidra_dir", return_value="C:/ghidra"),
            mock.patch.object(cli, "_mcp_snippet", return_value=""),
            mock.patch("builtins.print"),
        ):
            cli.cmd_setup(args)
        self.assertEqual(cfg.get("python"), "C:/venv/python.exe")


if __name__ == "__main__":
    unittest.main()
