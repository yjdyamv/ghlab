"""Putting our MCP entry into other agents' files without eating their config.

The dangerous part is not the JSON: it is that these files are the user's, they carry
comments and other servers, and they must survive us.  So every case here asserts on
what is preserved, and every merge is run twice to prove it is idempotent.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, ClassVar
from unittest import mock

from ghlab import cli, mcp, mcpconfig

PAYLOAD = {
    "command": "/venv/bin/python",
    "args": ["-m", "ghlab.mcp"],
    "env": {"GHLAB_TIMEOUT": "900"},
}


class JsonMergeTest(unittest.TestCase):
    def test_a_plain_file_keeps_its_other_keys(self) -> None:
        text = '{\n  "theme": "dark"\n}\n'
        out = mcpconfig.merge("claude", text, PAYLOAD)
        doc = json.loads(out)
        self.assertEqual(doc["theme"], "dark")
        self.assertEqual(doc["mcpServers"]["ghlab"]["command"], "/venv/bin/python")
        self.assertEqual(mcpconfig.merge("claude", out, PAYLOAD), out)

    def test_comments_and_existing_servers_survive(self) -> None:
        text = (
            "{\n"
            "  // my settings\n"
            '  "theme": "dark", /* otherwise unreadable */\n'
            '  "mcpServers": {\n'
            '    "other": {"command": "x"}\n'
            "  }\n"
            "}\n"
        )
        out = mcpconfig.merge("claude", text, PAYLOAD)
        self.assertIn("// my settings", out)
        self.assertIn("/* otherwise unreadable */", out)
        self.assertIn('"other": {"command": "x"}', out)
        self.assertTrue(mcpconfig.balanced(out))
        self.assertEqual(mcpconfig.merge("claude", out, PAYLOAD), out)

    def test_a_stale_entry_of_ours_is_replaced_not_duplicated(self) -> None:
        text = '{"mcpServers": {"ghlab": {"command": "old", "args": []}}, "a": 1}\n'
        out = mcpconfig.merge("claude", text, PAYLOAD)
        doc = json.loads(out)
        self.assertEqual(doc["mcpServers"]["ghlab"]["command"], "/venv/bin/python")
        self.assertEqual(doc["a"], 1)
        self.assertEqual(out.count('"ghlab"'), 1)

    def test_an_empty_file_gets_a_whole_document(self) -> None:
        doc = json.loads(mcpconfig.merge("pi", "", PAYLOAD))
        self.assertEqual(doc["mcpServers"]["ghlab"]["args"], ["-m", "ghlab.mcp"])

    def test_a_trailing_comma_file_still_balances(self) -> None:
        # Zed and OpenCode accept trailing commas; inserting after one must not eat it
        text = '{\n  "theme": "One Dark",\n}\n'
        out = mcpconfig.merge("zed", text, PAYLOAD)
        self.assertTrue(mcpconfig.balanced(out))
        self.assertIn('"theme": "One Dark",', out)
        self.assertIn('"context_servers"', out)
        self.assertEqual(mcpconfig.merge("zed", out, PAYLOAD), out)

    def test_an_unbalanced_file_is_left_alone(self) -> None:
        with self.assertRaises(ValueError):
            mcpconfig.merge("claude", '{"a": 1', PAYLOAD)


class TomlMergeTest(unittest.TestCase):
    def test_a_new_table_is_appended_after_the_others(self) -> None:
        text = 'model = "gpt-5"\n\n[mcp_servers.other]\ncommand = "x"\n'
        out = mcpconfig.merge("codex", text, PAYLOAD)
        self.assertIn("[mcp_servers.other]", out)
        self.assertIn("[mcp_servers.ghlab]", out)
        self.assertTrue(out.index("[mcp_servers.other]") < out.index("[mcp_servers.ghlab]"))
        self.assertEqual(mcpconfig.merge("codex", out, PAYLOAD), out)

    def test_our_old_table_and_its_subtables_are_replaced(self) -> None:
        text = (
            '[mcp_servers.ghlab]\ncommand = "old"\n\n'
            '[mcp_servers.ghlab.env]\nX = "1"\n\n'
            "[other]\na = 1\n"
        )
        out = mcpconfig.merge("codex", text, PAYLOAD)
        self.assertIn('command = "/venv/bin/python"', out)
        self.assertNotIn("old", out)
        self.assertNotIn("X =", out)  # our stale env sub-table went with it
        self.assertIn("[other]", out)
        self.assertNotIn("[mcp_servers.ghlab.env]", out)
        self.assertEqual(mcpconfig.merge("codex", out, PAYLOAD), out)


class YamlMergeTest(unittest.TestCase):
    def test_our_block_joins_the_extensions_mapping(self) -> None:
        text = "GOOSE_MODEL: claude\n\nextensions:\n  developer:\n    type: builtin\n"
        out = mcpconfig.merge("goose", text, PAYLOAD)
        self.assertIn("  developer:", out)
        self.assertIn("  ghlab:", out)
        self.assertIn('    cmd: "/venv/bin/python"', out)
        self.assertIn("    envs: {", out)
        self.assertEqual(mcpconfig.merge("goose", out, PAYLOAD), out)

    def test_our_old_block_is_replaced_and_the_next_extension_stays(self) -> None:
        text = "extensions:\n  ghlab:\n    type: stdio\n    cmd: old\n  other:\n    type: stdio\n"
        out = mcpconfig.merge("goose", text, PAYLOAD)
        self.assertNotIn("cmd: old", out)
        self.assertEqual(out.count("  ghlab:"), 1)
        self.assertIn("  other:", out)
        self.assertEqual(mcpconfig.merge("goose", out, PAYLOAD), out)

    def test_a_file_without_extensions_gets_the_key(self) -> None:
        out = mcpconfig.merge("goose", "GOOSE_MODEL: claude\n", PAYLOAD)
        self.assertIn("extensions:", out)
        self.assertIn("  ghlab:", out)
        self.assertEqual(mcpconfig.merge("goose", out, PAYLOAD), out)


class DetectTest(unittest.TestCase):
    def test_a_client_is_present_when_its_directory_is(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".codex").mkdir()
            env = {"HOME": tmp, "USERPROFILE": tmp, "APPDATA": tmp, "LOCALAPPDATA": tmp}
            with (
                mock.patch.dict(os.environ, env),
                mock.patch.object(mcpconfig.Path, "home", return_value=home),
                mock.patch.object(mcpconfig.shutil, "which", return_value=None),
            ):
                self.assertTrue(mcpconfig.present("codex"))
                self.assertFalse(mcpconfig.present("pi"))
                self.assertEqual(mcpconfig.installed(), ["codex"])

    def test_an_executable_on_path_counts_too(self) -> None:
        with mock.patch.object(mcpconfig.shutil, "which", return_value="/usr/bin/opencode"):
            self.assertTrue(mcpconfig.present("opencode"))


class InstallTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.addCleanup(self.dir.cleanup)

    def _targets(self, files: dict[str, tuple[str, str]]) -> None:
        patcher = mock.patch.object(mcpconfig, "FILES", files)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher2 = mock.patch.object(
            mcpconfig, "target", lambda client: self.root / files[client][0]
        )
        patcher2.start()
        self.addCleanup(patcher2.stop)

    def test_it_writes_keeps_a_backup_and_is_silent_the_second_time(self) -> None:
        self._targets({"claude": ("claude.json", "json")})
        path = self.root / "claude.json"
        path.write_text('{"theme": "dark"}\n', encoding="utf-8")
        first = mcpconfig.install(["claude"], PAYLOAD)
        self.assertIn("wrote", first[0])
        self.assertTrue(path.with_name("claude.json.ghlab.bak").exists())
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["theme"], "dark")
        second = mcpconfig.install(["claude"], PAYLOAD)
        self.assertIn("current", second[0])

    def test_the_backup_is_the_first_version_even_after_three_runs(self) -> None:
        self._targets({"claude": ("claude.json", "json")})
        path = self.root / "claude.json"
        path.write_text('{"theme": "dark"}\n', encoding="utf-8")
        mcpconfig.install(["claude"], PAYLOAD)
        path.write_text(path.read_text(encoding="utf-8").replace("dark", "light"), encoding="utf-8")
        mcpconfig.install(["claude"], PAYLOAD)
        backup = path.with_name("claude.json.ghlab.bak").read_text(encoding="utf-8")
        self.assertEqual(json.loads(backup)["theme"], "dark")

    def test_dry_run_writes_nothing(self) -> None:
        self._targets({"claude": ("claude.json", "json")})
        path = self.root / "claude.json"
        path.write_text("{}\n", encoding="utf-8")
        report = mcpconfig.install(["claude"], PAYLOAD, dry_run=True)
        self.assertIn("would", report[0])
        self.assertEqual(path.read_text(encoding="utf-8"), "{}\n")

    def test_a_missing_file_is_created(self) -> None:
        self._targets({"codex": ("nested/config.toml", "toml")})
        report = mcpconfig.install(["codex"], PAYLOAD)
        self.assertIn("wrote", report[0])
        text = (self.root / "nested" / "config.toml").read_text(encoding="utf-8")
        self.assertIn("[mcp_servers.ghlab]", text)

    def test_a_file_we_cannot_parse_is_reported_not_clobbered(self) -> None:
        self._targets({"claude": ("claude.json", "json")})
        path = self.root / "claude.json"
        path.write_text('{"a": 1', encoding="utf-8")
        report = mcpconfig.install(["claude"], PAYLOAD)
        self.assertIn("failed", report[0])
        self.assertEqual(path.read_text(encoding="utf-8"), '{"a": 1')


class PlaceTest(unittest.TestCase):
    def test_zed_and_vscode_follow_each_platform(self) -> None:
        cases = {
            "Windows": ("%APPDATA%/Zed/settings.json", "%APPDATA%/Code/User/mcp.json"),
            "Darwin": (
                "~/.config/zed/settings.json",
                "~/Library/Application Support/Code/User/mcp.json",
            ),
            "Linux": ("~/.config/zed/settings.json", "~/.config/Code/User/mcp.json"),
        }
        for system, (zed, vscode) in cases.items():
            with mock.patch.object(mcpconfig, "SYSTEM", system):
                self.assertEqual(mcpconfig.place("zed"), zed)
                self.assertEqual(mcpconfig.place("vscode"), vscode)

    def test_every_other_client_keeps_one_home_relative_file(self) -> None:
        for name in ("pi", "claude", "codex", "goose", "opencode", "gemini", "cursor"):
            with mock.patch.object(mcpconfig, "SYSTEM", "Linux"):
                self.assertTrue(mcpconfig.place(name).startswith("~"), name)

    def test_appdata_resolves_and_a_missing_var_falls_back_to_home(self) -> None:
        with mock.patch.dict(os.environ, {"APPDATA": "/roaming"}):
            self.assertEqual(
                mcpconfig._expand("%APPDATA%/Zed/settings.json"),
                Path("/roaming/Zed/settings.json"),
            )
        env = {k: v for k, v in os.environ.items() if k != "APPDATA"}
        with mock.patch.dict(os.environ, env, clear=True):
            got = mcpconfig._expand("%APPDATA%/Zed/settings.json")
            self.assertTrue(got.is_absolute())
            self.assertNotIn("%", str(got))


class PayloadTest(unittest.TestCase):
    def test_uv_launches_the_server_because_it_is_on_path(self) -> None:
        with (
            mock.patch.object(cli.shutil, "which", return_value="/usr/bin/uv"),
            mock.patch.object(cli, "_host_python", return_value="/venv/python"),
            mock.patch.object(cli, "_repo_root", return_value=Path("/repo")),
        ):
            payload = cli._mcp_payload({"project_name": "proj", "port": 8765})
        self.assertEqual(payload["command"], "/usr/bin/uv")
        self.assertEqual(
            payload["args"],
            ["run", "--quiet", "--no-project", "--python", ">=3.10", "python", "-m", "ghlab.mcp"],
        )
        self.assertEqual(payload["env"]["GHLAB_PYTHON"], "/venv/python")
        self.assertEqual(payload["env"]["PYTHONPATH"], str(Path("/repo") / "src"))

    def test_without_uv_the_server_runs_on_the_recorded_interpreter(self) -> None:
        with (
            mock.patch.object(cli.shutil, "which", return_value=None),
            mock.patch.object(cli, "_repo_root", return_value=None),
            mock.patch.object(cli, "_host_python", return_value=None),
        ):
            payload = cli._mcp_payload({"python": "/venv/python", "project_name": "proj"})
        self.assertEqual(payload["command"], "/venv/python")
        self.assertEqual(payload["args"], ["-m", "ghlab.mcp"])
        self.assertNotIn("PYTHONPATH", payload["env"])
        self.assertEqual(payload["env"]["GHLAB_PYTHON"], "/venv/python")

    def test_the_ghidra_folder_travels_with_the_entry(self) -> None:
        with (
            mock.patch.object(cli.shutil, "which", return_value=None),
            mock.patch.object(cli, "_repo_root", return_value=None),
            mock.patch.object(cli, "_host_python", return_value=None),
        ):
            payload = cli._mcp_payload({"ghidra": "/opt/ghidra", "python": "/venv/python"})
        self.assertEqual(payload["env"]["GHIDRA_INSTALL_DIR"], "/opt/ghidra")

    def test_several_projects_pass_the_registry_instead_of_one_url(self) -> None:
        cfg = {
            "projects": {
                "a": {"url": "http://127.0.0.1:1/"},
                "b": {"url": "http://127.0.0.1:2/"},
            },
            "default": "a",
            "python": "/venv/python",
        }
        with (
            mock.patch.object(cli.shutil, "which", return_value=None),
            mock.patch.object(cli, "_repo_root", return_value=None),
            mock.patch.object(cli, "_host_python", return_value=None),
        ):
            payload = cli._mcp_payload(cfg)
        self.assertIn("GHLAB_CONFIG", payload["env"])
        self.assertNotIn("GHLAB_URL", payload["env"])


class SetupCommandTest(unittest.TestCase):
    def test_install_all_only_touches_clients_found_here(self) -> None:
        args = mock.Mock(install_mcp="all", dry_run=False)
        with (
            mock.patch.object(mcpconfig, "installed", return_value=["pi"]),
            mock.patch.object(mcpconfig, "install", return_value=["pi        wrote     x"]) as inst,
        ):
            code = cli._install_mcp(args, {})
        self.assertEqual(code, 0)
        self.assertEqual(inst.call_args[0][0], ["pi"])

    def test_install_all_with_nothing_found_explains_what_to_do(self) -> None:
        args = mock.Mock(install_mcp="all", dry_run=False)
        with (
            mock.patch.object(mcpconfig, "installed", return_value=[]),
            mock.patch.object(mcpconfig, "install") as inst,
            mock.patch("builtins.print") as printed,
        ):
            code = cli._install_mcp(args, {})
        self.assertEqual(code, 0)
        inst.assert_not_called()
        self.assertIn("--print-mcp", " ".join(str(c) for c in printed.call_args_list))

    def test_an_explicit_client_is_written_even_if_not_detected(self) -> None:
        args = mock.Mock(install_mcp="codex", dry_run=True)
        with mock.patch.object(
            mcpconfig, "install", return_value=["codex     would     x"]
        ) as inst:
            cli._install_mcp(args, {})
        self.assertEqual(inst.call_args[0][0], ["codex"])
        self.assertTrue(inst.call_args[1]["dry_run"])


if __name__ == "__main__":
    unittest.main()


class MergeOpenCodeTest(unittest.TestCase):
    """opencode v2 keeps servers under mcp.servers; v1 had them under mcp itself."""

    VALUE: ClassVar[dict[str, Any]] = {
        "type": "local",
        "command": ["uv"],
        "environment": {"A": "1"},
    }

    def test_an_empty_file_gets_the_nested_shape(self) -> None:
        text = mcpconfig.merge_json("", ("mcp", "servers"), "ghlab", self.VALUE)
        self.assertEqual(json.loads(text)["mcp"]["servers"]["ghlab"], self.VALUE)

    def test_other_servers_and_keys_survive(self) -> None:
        before = chr(10).join(
            [
                "{",
                '  "$schema": "x",',
                '  "mcp": {"servers": {"other": {"type": "remote"}}}',
                "}",
                "",
            ]
        )
        after = mcpconfig.merge_json(before, ("mcp", "servers"), "ghlab", self.VALUE)
        self.assertIn('"$schema": "x"', after)
        self.assertIn('"other"', after)
        self.assertEqual(json.loads(after)["mcp"]["servers"]["ghlab"], self.VALUE)

    def test_running_it_twice_changes_nothing(self) -> None:
        once = mcpconfig.merge_json("", ("mcp", "servers"), "ghlab", self.VALUE)
        self.assertEqual(mcpconfig.merge_json(once, ("mcp", "servers"), "ghlab", self.VALUE), once)

    def test_a_key_that_is_not_an_object_is_replaced(self) -> None:
        after = mcpconfig.merge_json('{"mcp": "nope"}', ("mcp", "servers"), "ghlab", self.VALUE)
        self.assertEqual(json.loads(after)["mcp"]["servers"]["ghlab"], self.VALUE)


class CommandCodeTest(unittest.TestCase):
    """Command Code (npm `command-code`, CLI `cmd`) keeps servers under `mcpServers`."""

    PAYLOAD: ClassVar[dict[str, Any]] = {
        "command": "uv",
        "args": ["run", "python", "-m", "ghlab.mcp"],
        "env": {"A": "1"},
    }

    def test_the_entry_carries_a_transport(self):
        value = mcpconfig.entry("commandcode", self.PAYLOAD)
        self.assertEqual(value["transport"], "stdio")
        self.assertIs(value["enabled"], True)
        self.assertEqual(value["command"], "uv")
        self.assertEqual(value["env"], {"A": "1"})

    def test_it_lands_in_mcp_servers(self):
        text = mcpconfig.merge("commandcode", "", self.PAYLOAD)
        doc = json.loads(text)
        self.assertEqual(doc["mcpServers"]["ghlab"]["transport"], "stdio")

    def test_an_existing_file_keeps_its_other_servers(self):
        before = chr(10).join(
            [
                "{",
                '  "mcpServers": {',
                '    "other": {"command": "x"}',
                "  }",
                "}",
                "",
            ]
        )
        doc = json.loads(mcpconfig.merge("commandcode", before, self.PAYLOAD))
        self.assertEqual(sorted(doc["mcpServers"]), ["ghlab", "other"])
        self.assertEqual(doc["mcpServers"]["other"], {"command": "x"})

    def test_the_file_is_the_one_its_cli_writes(self):
        self.assertEqual(mcpconfig.place("commandcode"), "~/.commandcode/mcp.json")

    def test_it_is_found_by_its_folder_not_by_the_name_cmd(self):
        # On Windows `cmd` resolves to C:/Windows/System32/cmd.exe
        self.assertNotIn("exe:cmd", mcpconfig.SIGNALS["commandcode"])
        self.assertIn("~/.commandcode", mcpconfig.SIGNALS["commandcode"])


class TraceTest(unittest.TestCase):
    """`GHLAB_MCP_LOG` exists so a client bug report can say how far the session got."""

    def test_it_records_the_method_and_the_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.log"
            with mock.patch.dict(os.environ, {"GHLAB_MCP_LOG": str(path)}):
                mcp._trace({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, {"id": 3})
                mcp._trace(
                    {"jsonrpc": "2.0", "id": 4, "method": "nope"},
                    {"id": 4, "error": {"code": -32601, "message": "no such method"}},
                )
            lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0], "tools/list id=3 -> ok")
        self.assertIn("-32601 no such method", lines[1])

    def test_it_is_silent_without_the_variable(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            mcp._trace({"id": 1, "method": "ping"}, {"id": 1})
