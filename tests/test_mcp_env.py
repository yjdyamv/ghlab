"""The env we write into client configs: portable shapes, one timeout, no dead paths.

Two things can go wrong here and both are silent: a value that only makes sense on the
machine that wrote it (or uses the wrong separator), and a path that pointed at a venv or
a Ghidra folder that has since been deleted.  A client that gets either just fails to
start, usually with "connection closed" and nothing else.
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest import mock

from ghlab import cli, client, mcpconfig
from ghlab.protocol import DEFAULT_TIMEOUT

CFG = {
    "ghidra": "/opt/ghidra",
    "project_dir": "/re/proj",
    "project_name": "proj",
    "host": "127.0.0.1",
    "port": 8765,
    "python": "/venv/bin/python",
}


class _NoUv(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        patcher = mock.patch.object(cli.shutil, "which", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)


class OneTimeoutTest(_NoUv):
    """Four places can cut a call off; they must agree, or the smallest one decides."""

    def test_the_client_default_is_the_shared_number(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GHLAB_TIMEOUT", None)
            self.assertEqual(client.Client().timeout, DEFAULT_TIMEOUT)

    def test_the_env_we_hand_over_matches_it(self) -> None:
        env = cli._mcp_payload(CFG)["env"]
        self.assertEqual(env["GHLAB_TIMEOUT"], str(DEFAULT_TIMEOUT))

    def test_pi_gets_the_same_budget_as_a_timeout_field(self) -> None:
        text = cli._mcp_entry("pi", cli._mcp_payload(CFG))
        body = chr(10).join(line for line in text.splitlines() if not line.startswith("//"))
        entry = json.loads(body)["mcpServers"]["ghlab"]
        self.assertEqual(entry["timeout"], DEFAULT_TIMEOUT)

    def test_goose_gets_the_same_budget_as_yaml(self) -> None:
        text = mcpconfig.render("goose", cli._mcp_payload(CFG))
        self.assertIn(f"timeout: {DEFAULT_TIMEOUT}", text)

    def test_an_old_value_from_a_config_file_still_wins(self) -> None:
        self.assertEqual(client.Client(timeout=7).timeout, 7)


class SeparatorTest(_NoUv):
    def test_pythonpath_uses_the_platform_separator(self) -> None:
        root = Path("/repo")
        with mock.patch.object(cli, "_repo_root", return_value=root):
            env = cli._mcp_payload(CFG)["env"]
        self.assertEqual(env["PYTHONPATH"], os.pathsep.join([str(root / "src")]))
        if os.pathsep == ";":
            self.assertNotIn(":", env["PYTHONPATH"])


class DeadPathTest(unittest.TestCase):
    def test_a_ghidra_folder_that_is_gone_is_reported(self) -> None:
        lines = cli._payload_warnings({"ghidra": "/nope/ghidra"})
        self.assertEqual(len(lines), 1)
        self.assertIn("ghidra", lines[0])
        self.assertIn("ghlab setup --ghidra", lines[0])

    def test_an_interpreter_that_is_gone_is_reported(self) -> None:
        lines = cli._payload_warnings({"python": "/nope/python.exe"})
        self.assertEqual(len(lines), 1)
        self.assertIn("GHLAB_PYTHON", lines[0])

    def test_paths_that_exist_are_quiet(self) -> None:
        self.assertEqual(cli._payload_warnings({}), [])
        self.assertEqual(cli._payload_warnings({"ghidra": str(Path(__file__).parent)}), [])
