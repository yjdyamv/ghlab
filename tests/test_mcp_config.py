"""The MCP config we hand to other agents: right shape, right command, no surprises.

Every client speaks the same stdio protocol but stores it differently -- ``mcpServers``,
``servers``, ``context_servers``, ``mcp.<name>.command[]``, ``[mcp_servers.*]`` in TOML,
``extensions`` in YAML.  These tests read each snippet the way that client would.
"""

from __future__ import annotations

import io
import json
import unittest
from unittest import mock

from ghlab import cli

CFG = {
    "ghidra": "/opt/ghidra",
    "project_dir": "/re/proj",
    "project_name": "proj",
    "host": "127.0.0.1",
    "port": 8765,
    "python": "/venv/bin/python",
}


def _json_part(text: str) -> dict:
    """Drop the comment header (JSONC clients allow //, json.loads does not) and parse."""
    body = "\n".join(line for line in text.splitlines() if not line.startswith("//"))
    return json.loads(body)


class _NoUv(unittest.TestCase):
    """These cases describe the entry for a machine without uv: the interpreter form."""

    def setUp(self) -> None:
        super().setUp()
        patcher = mock.patch.object(cli.shutil, "which", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)


class PayloadTest(_NoUv):
    def test_the_command_is_the_interpreter_that_can_host_ghidra(self) -> None:
        with mock.patch.object(cli, "_host_python", return_value="/venv/bin/python"):
            payload = cli._mcp_payload(CFG)
        self.assertEqual(payload["command"], "/venv/bin/python")
        self.assertEqual(payload["args"], ["-m", "ghlab.mcp"])

    def test_a_single_project_pins_the_url_and_the_project(self) -> None:
        with (
            mock.patch.object(cli, "projects", return_value={"proj": object()}),
            mock.patch.object(cli, "_host_python", return_value="/venv/bin/python"),
            mock.patch.object(cli, "default_port", return_value=8765),
        ):
            env = cli._mcp_payload(CFG)["env"]
        self.assertEqual(env["GHLAB_URL"], "http://127.0.0.1:8765")
        self.assertEqual(env["GHLAB_PROJECT_DIR"], "/re/proj")
        self.assertEqual(env["GHLAB_PROJECT_NAME"], "proj")
        self.assertNotIn("GHLAB_CONFIG", env)

    def test_several_projects_route_through_the_registry(self) -> None:
        # a pinned GHLAB_URL would hide every project but one
        with (
            mock.patch.object(cli, "projects", return_value={"a": object(), "b": object()}),
            mock.patch.object(cli, "_host_python", return_value="/venv/bin/python"),
            mock.patch.object(cli, "config_path", return_value="/home/u/.ghlab/config.json"),
        ):
            env = cli._mcp_payload(CFG)["env"]
        self.assertEqual(env["GHLAB_CONFIG"], "/home/u/.ghlab/config.json")
        self.assertNotIn("GHLAB_URL", env)


class JsonClientsTest(_NoUv):
    def test_pi_takes_mcp_servers_and_a_timeout_that_survives_a_cold_daemon(self) -> None:
        entry = _json_part(cli._mcp_entry("pi", cli._mcp_payload(CFG)))["mcpServers"]["ghlab"]
        self.assertEqual(entry["command"], "/venv/bin/python")
        # pi's default per-call timeout is 60s; the first call may wait for Ghidra
        self.assertGreaterEqual(entry["timeout"], 300)
        self.assertEqual(entry["exposure"], "deferred")
        self.assertIn("description", entry)

    def test_the_claude_family_gets_the_plain_shape(self) -> None:
        entry = _json_part(cli._mcp_entry("claude", cli._mcp_payload(CFG)))["mcpServers"]["ghlab"]
        self.assertEqual(sorted(entry), ["args", "command", "env"])

    def test_vscode_uses_servers_and_a_stdio_type(self) -> None:
        doc = _json_part(cli._mcp_entry("vscode", cli._mcp_payload(CFG)))
        self.assertNotIn("mcpServers", doc)
        self.assertEqual(doc["servers"]["ghlab"]["type"], "stdio")
        self.assertEqual(doc["servers"]["ghlab"]["command"], "/venv/bin/python")

    def test_zed_uses_context_servers(self) -> None:
        doc = _json_part(cli._mcp_entry("zed", cli._mcp_payload(CFG)))
        self.assertEqual(doc["context_servers"]["ghlab"]["args"], ["-m", "ghlab.mcp"])

    def test_opencode_wants_one_command_array_and_environment(self) -> None:
        doc = _json_part(cli._mcp_entry("opencode", cli._mcp_payload(CFG)))
        # opencode v2 nests its servers: {"mcp": {"servers": {"ghlab": ...}}}
        server = doc["mcp"]["servers"]["ghlab"]
        self.assertEqual(server["type"], "local")
        self.assertEqual(server["command"], ["/venv/bin/python", "-m", "ghlab.mcp"])
        self.assertIn("GHLAB_TIMEOUT", server["environment"])
        self.assertTrue(server["enabled"])


class TomlAndYamlClientsTest(_NoUv):
    def test_codex_gets_an_mcp_servers_table(self) -> None:
        text = cli._mcp_entry("codex", cli._mcp_payload(CFG))
        self.assertIn("[mcp_servers.ghlab]", text)
        self.assertIn('command = "/venv/bin/python"', text)
        self.assertIn('args = ["-m", "ghlab.mcp"]', text)
        self.assertIn("GHLAB_TIMEOUT", text)
        self.assertIn("GHLAB_URL", text)

    def test_goose_gets_extensions_with_cmd_and_envs(self) -> None:
        text = cli._mcp_entry("goose", cli._mcp_payload(CFG))
        self.assertIn("extensions:", text)
        self.assertIn("    type: stdio", text)
        self.assertIn('    cmd: "/venv/bin/python"', text)
        self.assertIn("envs: {", text)
        # goose calls it envs, not env, and it needs the same patience as pi
        self.assertNotIn("\n    env:", text)
        self.assertIn("    timeout: 900", text)


class SnippetTest(unittest.TestCase):
    def test_all_prints_every_client_with_its_file(self) -> None:
        text = cli._mcp_snippet(CFG, "all")
        for name in cli._MCP_CLIENTS:
            self.assertIn(f"== {name}", text)
        self.assertIn("mcp.json", text)  # pi
        self.assertIn("config.toml", text)  # codex
        self.assertIn("settings.json", text)  # zed
        self.assertIn("raise its per-call timeout", text)

    def test_one_client_prints_only_that_client(self) -> None:
        text = cli._mcp_snippet(CFG, "codex")
        self.assertIn("[mcp_servers.ghlab]", text)
        self.assertNotIn("context_servers", text)
        self.assertNotIn("== pi", text)

    def test_the_cli_accepts_a_client_name_and_rejects_a_typo(self) -> None:
        parser = cli.build_parser()
        self.assertEqual(parser.parse_args(["setup", "--print-mcp"]).print_mcp, "all")
        self.assertEqual(parser.parse_args(["setup", "--print-mcp", "zed"]).print_mcp, "zed")
        with (
            mock.patch("sys.stderr", new_callable=io.StringIO),
            self.assertRaises(SystemExit) as caught,
        ):
            parser.parse_args(["setup", "--print-mcp", "zedd"])
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
