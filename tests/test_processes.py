"""Which python processes are ghlab's, and how to stop all of them.

A venv `python.exe` is a launcher that re-execs the real interpreter, so one daemon
appears as two processes: the shim (the pid a pidfile names) and its child (the one
holding the port and the project lock).  Killing only the pidfile pid leaves the child
behind -- that is what stray `python.exe` was, and why `ghlab stop` could report
success while the port stayed busy.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ghlab import cli


def _row(pid: int, parent: int, cmd: str) -> dict:
    return {"pid": pid, "parent": parent, "cmd": cmd}


class ProcessTableTest(unittest.TestCase):
    def test_powershell_output_is_parsed(self):
        rows = "100\t1\tC:\\v\\python.exe -m ghlab.cli serve --port 8775\njunk\n200\t100\tx\n"
        with mock.patch.object(cli.subprocess, "run") as run:
            run.return_value.stdout = rows
            with mock.patch.object(cli.os, "name", "nt"):
                table = cli._process_table()
        self.assertEqual([r["pid"] for r in table], [100, 200])
        self.assertEqual(table[0]["parent"], 1)
        self.assertIn("serve", table[0]["cmd"])

    def test_a_failing_powershell_is_not_fatal(self):
        with (
            mock.patch.object(cli.subprocess, "run", side_effect=OSError("no powershell")),
            mock.patch.object(cli.os, "name", "nt"),
        ):
            self.assertEqual(cli._process_table(), [])


class GhlabProcessesTest(unittest.TestCase):
    def test_shim_and_child_are_both_listed(self):
        table = [
            _row(10, 1, "C:\\venv\\python.exe -m ghlab.cli serve --port 8775 --project-dir X"),
            _row(11, 10, '"C:\\uv\\python.exe" -m ghlab.cli serve --port 8775 --project-dir X'),
            _row(12, 1, "python.exe -m ghlab.mcp"),
            _row(13, 1, "python.exe -m pip install x"),
        ]
        procs = cli._ghlab_processes(table)
        self.assertEqual([p["pid"] for p in procs], [10, 11, 12])
        self.assertEqual([p["role"] for p in procs], ["serve", "serve", "mcp"])
        self.assertEqual([p["port"] for p in procs], [8775, 8775, 0])

    def test_port_equals_form_is_understood(self):
        procs = cli._ghlab_processes([_row(1, 0, "python -m ghlab.cli serve --port=8766")])
        self.assertEqual(procs[0]["port"], 8766)

    def test_other_pythons_are_ignored(self):
        self.assertEqual(cli._ghlab_processes([_row(1, 0, "python -m pytest")]), [])


class TreeTest(unittest.TestCase):
    def test_descendants_are_depth_first(self):
        table = [_row(2, 1, ""), _row(3, 2, ""), _row(4, 1, "")]
        self.assertEqual(cli._descendants(1, table), [2, 4, 3])

    def test_a_cycle_does_not_hang(self):
        table = [_row(2, 3, ""), _row(3, 2, "")]
        self.assertEqual(cli._descendants(1, table), [])

    def test_kill_tree_kills_the_child_too(self):
        table = [_row(10, 1, ""), _row(11, 10, "")]
        killed: list[int] = []

        def fake_one(pid):
            killed.append(pid)
            return "killed"

        with mock.patch.object(cli, "_terminate_one", fake_one):
            how = cli._kill_tree(10, table)
        self.assertEqual(how, "killed")
        self.assertEqual(killed, [10, 11])

    def test_windows_kills_the_whole_tree_with_taskkill(self):
        with mock.patch.object(cli.subprocess, "run") as run:
            run.return_value.returncode = 0
            with mock.patch.object(cli.os, "name", "nt"):
                self.assertEqual(cli._terminate_one(11), "killed")
        self.assertEqual(run.call_args[0][0][:5], ["taskkill", "/F", "/T", "/PID", "11"])

    def test_posix_uses_a_signal_and_reports_a_gone_pid(self):
        with mock.patch.object(cli.os, "name", "posix"), mock.patch.object(cli.os, "kill") as kill:
            kill.side_effect = ProcessLookupError()
            self.assertEqual(cli._terminate_one(1), "gone")
            kill.side_effect = PermissionError()
            self.assertEqual(cli._terminate_one(1), "denied")


class StrayTest(unittest.TestCase):
    def test_a_child_of_a_recorded_shim_is_not_a_stray(self):
        procs = [
            {"pid": 10, "parent": 1, "role": "serve", "port": 1},
            {"pid": 11, "parent": 10, "role": "serve", "port": 1},
            {"pid": 20, "parent": 1, "role": "mcp", "port": 0},
        ]
        self.assertEqual([p["pid"] for p in cli._strays(procs, {10})], [20])


class StopAllTest(unittest.TestCase):
    def _project(self, name: str, pid: int, root: Path) -> Path:
        (root / name).mkdir(exist_ok=True)
        pidfile = root / name / ".ghlab.pid"
        pidfile.write_text(
            f'{{"pid": {pid}, "port": {1000 + pid}, "stamp": "x"}}', encoding="utf-8"
        )
        return pidfile

    def test_it_stops_recorded_daemons_and_strays(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pidfile = self._project("proj", 10, root)
            targets = {
                "proj": type("T", (), {"project_dir": str(root / "proj"), "url": "http://h:1/"})()
            }
            procs = cli._ghlab_processes(
                [
                    _row(10, 1, "python -m ghlab.cli serve --port 8775"),
                    _row(11, 10, "python -m ghlab.cli serve --port 8775"),
                    _row(30, 1, "python -m ghlab.mcp"),
                ]
            )
            killed: list[int] = []

            def fake_kill(pid, table=None):
                killed.append(pid)
                return "killed"

            with (
                mock.patch.object(cli, "projects", return_value=targets),
                mock.patch.object(cli, "_ghlab_processes", return_value=procs),
                mock.patch.object(cli, "_kill_tree", fake_kill),
            ):
                self.assertEqual(cli._stop_all(), 0)
            self.assertEqual(sorted(killed), [10, 11, 30])
            self.assertFalse(pidfile.exists())

    def test_nothing_to_stop_needs_no_process_table(self):
        with (
            mock.patch.object(cli, "projects", return_value={}),
            mock.patch.object(cli, "_ghlab_processes", return_value=[]),
        ):
            self.assertEqual(cli._stop_all(), 0)


class StopUsesTheDaemonsPidTest(unittest.TestCase):
    def test_the_reported_pid_wins_over_the_pidfile_shim(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / ".ghlab.pid"
            pidfile.write_text('{"pid": 500, "port": 8775}', encoding="utf-8")
            args = cli.build_parser().parse_args(["stop", "--port", "8775", "--project-dir", tmp])
            killed: list[int] = []

            def fake_kill(pid, table=None):
                killed.append(pid)
                return "killed"

            with (
                mock.patch.object(
                    cli, "_daemon_info", return_value={"service": "ghlab", "pid": 501}
                ),
                mock.patch.object(cli, "_kill_tree", fake_kill),
                mock.patch.object(cli, "Client") as client,
            ):
                client.return_value.alive.return_value = False
                self.assertEqual(cli.cmd_stop(args), 0)
            self.assertEqual(killed, [501])
            self.assertFalse(pidfile.exists())

    def test_nothing_listening_says_so_and_clears_the_pidfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / ".ghlab.pid"
            pidfile.write_text('{"pid": 500, "port": 8775}', encoding="utf-8")
            args = cli.build_parser().parse_args(["stop", "--port", "8775", "--project-dir", tmp])
            with (
                mock.patch.object(cli, "_daemon_info", return_value={}),
                mock.patch.object(cli, "_port_owner", return_value=None),
                mock.patch.object(cli, "Client") as client,
            ):
                client.return_value.alive.return_value = False
                self.assertEqual(cli.cmd_stop(args), 0)
            self.assertFalse(pidfile.exists())

    def test_all_reaches_the_sweep(self):
        args = cli.build_parser().parse_args(["stop", "--all"])
        with mock.patch.object(cli, "_stop_all", return_value=0) as sweep:
            self.assertEqual(cli.cmd_stop(args), 0)
        sweep.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
