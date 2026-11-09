"""CLI surface that does not need a daemon: version, help, script errors."""

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ghlab import cli


class CliTest(unittest.TestCase):
    def test_version_flag(self):
        out = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, redirect_stdout(out):
            cli.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("ghlab", out.getvalue())

    def test_help_lists_every_command_family(self):
        text = cli.build_parser().format_help()
        for cmd in ("digest", "find", "diff", "emulate", "campaign", "run", "mcp", "report"):
            self.assertIn(cmd, text)

    def test_missing_script_is_a_clean_error(self):
        with redirect_stderr(io.StringIO()) as err, redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["run", "no-such-script.gh"]), 2)
        self.assertIn("no-such-script.gh", err.getvalue())

    def test_bad_set_argument_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "job.gh"
            script.write_text("ping\n", encoding="utf-8")
            with redirect_stderr(io.StringIO()) as err, redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["run", str(script), "--set", "oops"]), 2)
            self.assertIn("K=V", err.getvalue())

    def test_dry_run_prints_the_plan_without_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "job.gh"
            script.write_text("# nothing to do\nping\ndigest $BIN\n", encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = cli.main(["run", str(script), "--set", "BIN=a.exe", "--dry-run"])
            self.assertEqual(code, 0)
            self.assertIn("2 step(s) planned (dry run)", out.getvalue())

    def test_failing_script_exits_non_zero_and_names_the_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "job.gh"
            script.write_text("this-command-does-not-exist\n", encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = cli.main(["run", str(script)])
            self.assertEqual(code, 1)
            self.assertIn("line 1", out.getvalue())

    def test_log_rotation_keeps_one_previous_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "ghlab.log"
            log.write_text("x" * 2048, encoding="utf-8")
            cli._rotate_log(log, limit=1024)
            self.assertFalse(log.exists())
            backup = Path(tmp) / "ghlab.log.1"
            self.assertTrue(backup.exists())
            self.assertEqual(backup.stat().st_size, 2048)
            # a fresh log is created by the daemon, so rotate again: one backup only
            log.write_text("y" * 2048, encoding="utf-8")
            cli._rotate_log(log, limit=1024)
            self.assertEqual(backup.read_text(encoding="utf-8")[0], "y")

    def test_small_log_is_left_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "ghlab.log"
            log.write_text("ok", encoding="utf-8")
            cli._rotate_log(log, limit=1024)
            self.assertTrue(log.exists())
            self.assertFalse((Path(tmp) / "ghlab.log.1").exists())


if __name__ == "__main__":
    unittest.main()
