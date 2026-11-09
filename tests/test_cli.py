"""CLI surface that does not need a daemon: version, help, script errors."""

import contextlib
import io
import json
import os
import pathlib
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

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


class SetupConfigTest(unittest.TestCase):
    """`ghlab setup` must be the only machine-specific step an agent needs."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ghlab-cfg-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = os.path.join(self.tmp, "config.json")
        self.env = mock.patch.dict(os.environ, {"GHLAB_CONFIG": self.path})
        self.env.start()
        self.addCleanup(self.env.stop)

    def run_cli(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = cli.main(list(argv))
        return code, buf.getvalue()

    def test_setup_rejects_a_fake_ghidra_folder(self):
        code, out = self.run_cli("setup", "--ghidra", self.tmp)
        self.assertEqual(code, 2)
        self.assertIn("does not look like a Ghidra install", out)

    def test_setup_writes_config_and_prints_mcp_snippets(self):
        ghidra = os.path.join(self.tmp, "ghidra")
        os.makedirs(os.path.join(ghidra, "support"))
        pathlib.Path(ghidra, "support", "analyzeHeadless").write_text("#!/bin/sh", encoding="utf-8")
        code, out = self.run_cli(
            "setup",
            "--ghidra",
            ghidra,
            "--project-dir",
            self.tmp,
            "--project-name",
            "wps",
            "--port",
            "8766",
        )
        self.assertEqual(code, 0)
        cfg = json.loads(pathlib.Path(self.path).read_text(encoding="utf-8"))
        self.assertEqual(cfg["ghidra"], ghidra)
        self.assertEqual(cfg["project_name"], "wps")
        self.assertEqual(cfg["port"], 8766)
        self.assertIn("mcpServers", out)
        self.assertIn("GHLAB_AUTOSTART", out)
        self.assertIn("ghlab.mcp", out)

    def test_doctor_reports_json_and_fails_without_a_daemon(self):
        code, out = self.run_cli(
            "doctor", "--url", "http://127.0.0.1:1/", "--json", "--project-dir", self.tmp
        )
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        names = {c["check"]: c for c in payload["checks"]}
        self.assertEqual(names["daemon"]["status"], "fail")
        self.assertEqual(names["project dir"]["status"], "ok")
        self.assertIn("versions", names)


if __name__ == "__main__":
    unittest.main()


class ConfigIsolationTest(unittest.TestCase):
    """A test that writes config must never touch the real ~/.ghlab/config.json."""

    def test_setup_writes_only_the_configured_path(self):
        real = pathlib.Path(
            os.environ.get("GHLAB_CONFIG") or (pathlib.Path.home() / ".ghlab" / "config.json")
        )
        before = real.read_text(encoding="utf-8") if real.exists() else None
        tmp = tempfile.mkdtemp(prefix="ghlab-iso-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        ghidra = pathlib.Path(tmp, "ghidra")
        (ghidra / "support").mkdir(parents=True)
        (ghidra / "support" / "analyzeHeadless").write_text("x", encoding="utf-8")
        with (
            mock.patch.dict(os.environ, {"GHLAB_CONFIG": str(pathlib.Path(tmp, "c.json"))}),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            cli.main(["setup", "--ghidra", str(ghidra), "--project-dir", tmp])
        after = real.read_text(encoding="utf-8") if real.exists() else None
        self.assertEqual(before, after, "setup escaped GHLAB_CONFIG and wrote the real config")


class McpSnippetTest(unittest.TestCase):
    """The printed snippet must keep routing working: a pinned GHLAB_URL would not."""

    def snippet(self, cfg: dict):
        return cli._mcp_snippet(cfg)

    def test_one_project_pins_the_url(self):
        text = self.snippet({"project_dir": "/p", "project_name": "one", "port": 8765})
        self.assertIn("GHLAB_URL", text)
        self.assertNotIn("GHLAB_CONFIG", text)

    def test_many_projects_pass_the_config_instead(self):
        cfg = {
            "project_dir": "/p",
            "project_name": "one",
            "port": 8765,
            "default": "one",
            "projects": {
                "one": {"url": "http://127.0.0.1:8765", "project_dir": "/p", "project_name": "one"},
                "two": {"url": "http://127.0.0.1:8766", "project_dir": "/q", "project_name": "two"},
            },
        }
        text = self.snippet(cfg)
        self.assertIn("GHLAB_CONFIG", text)
        self.assertNotIn('"GHLAB_URL"', text, "a pinned URL would disable routing")
        self.assertIn("2 project(s)", text)
