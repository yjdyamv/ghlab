"""MCP facade tests: protocol shape and argument forwarding, no Ghidra involved."""

import io
import json
import unittest
from pathlib import Path

from ghlab import mcp, protocol
from ghlab.client import RemoteError


class Fake:
    """Stands in for Client: records what the tools ask the daemon for."""

    def __init__(self, result=None, error=None, routes=None):
        self.calls = []
        self.result = {"ok": True} if result is None else result
        self.error = error
        self.routes = routes or {}

    def __call__(self, cmd, **params):
        self.calls.append((cmd, params))
        if self.error is not None:
            raise self.error
        if cmd in self.routes:
            return self.routes[cmd]
        return self.result


def handle(message, call=None):
    """`mcp.handle` answers None for notifications; these tests never send one."""
    reply = mcp.handle(message, call if call is not None else Fake())
    assert reply is not None, message
    return reply


class ProtocolTest(unittest.TestCase):
    def test_initialize_announces_tools_and_resources(self):
        reply = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, Fake())
        self.assertEqual(reply["id"], 1)
        result = reply["result"]
        self.assertEqual(result["protocolVersion"], mcp.PROTOCOL_VERSION)
        self.assertIn("tools", result["capabilities"])
        self.assertIn("resources", result["capabilities"])
        self.assertEqual(result["serverInfo"]["name"], "ghlab")

    def test_notifications_get_no_response(self):
        # A notification has no id, so the daemon must not answer at all.
        self.assertIsNone(
            mcp.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, Fake())
        )
        self.assertIsNone(mcp.handle({"jsonrpc": "2.0", "method": "ping"}, Fake()))

    def test_unknown_method_is_an_error(self):
        reply = handle({"jsonrpc": "2.0", "id": 7, "method": "nope"}, Fake())
        self.assertEqual(reply["error"]["code"], -32601)

    def test_tools_are_few_and_well_formed(self):
        tools = mcp.TOOLS
        # The point of the cap is "the facade stays a short list", not a fixed number:
        # raise it only when a daemon command that answers a question is missing here.
        self.assertLessEqual(len(tools), 34, "MCP facade should stay small")
        names = [t["name"] for t in tools]
        self.assertEqual(len(names), len(set(names)))
        for tool in tools:
            self.assertTrue(tool["name"].startswith("ghlab_"), tool["name"])
            self.assertGreater(len(tool["description"]), 40, tool["name"])
            schema = tool["inputSchema"]
            self.assertEqual(schema["type"], "object")
            self.assertIn("properties", schema)
            for key in schema.get("required", []):
                self.assertIn(
                    key, schema["properties"], f"{tool['name']} requires undeclared {key}"
                )

    def test_every_tool_maps_to_a_real_daemon_command(self):
        for tool in mcp.TOOLS:
            self.assertIn(tool["name"], mcp._COMMANDS, tool["name"])
            cmd = mcp._COMMANDS[tool["name"]]
            # `projects` is answered by the router itself, not by a daemon.
            if cmd == "projects":
                continue
            self.assertIn(cmd, protocol.COMMAND_NAMES, tool["name"])
            declared = set(protocol.SPECS[cmd].required) | set(protocol.SPECS[cmd].optional)
            for key in tool["inputSchema"]["properties"]:
                self.assertIn(key, declared, f"{tool['name']}.{key} is not a {cmd} parameter")

    def test_tools_list(self):
        reply = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, Fake())
        self.assertEqual(len(reply["result"]["tools"]), len(mcp.TOOLS))


class ToolCallTest(unittest.TestCase):
    def test_digest_forwards_to_the_daemon(self):
        fake = Fake({"functions": 855})
        reply = handle(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "ghlab_digest", "arguments": {"binary": "a.exe", "top": 4}},
            },
            fake,
        )
        self.assertEqual(fake.calls, [("digest", {"binary": "a.exe", "top": 4})])
        self.assertFalse(reply["result"].get("isError"))
        self.assertEqual(json.loads(reply["result"]["content"][0]["text"]), {"functions": 855})

    def test_string_lists_become_lists(self):
        fake = Fake()
        handle(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "ghlab_find",
                    "arguments": {"binary": "a.exe", "import": "RegSetValueExW"},
                },
            },
            fake,
        )
        self.assertEqual(fake.calls[0][1]["import"], ["RegSetValueExW"])

    def test_none_arguments_are_dropped(self):
        fake = Fake()
        handle(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "ghlab_slice",
                    "arguments": {"binary": "a.exe", "to": "CreateProcessW", "from": None},
                },
            },
            fake,
        )
        self.assertNotIn("from", fake.calls[0][1])

    def test_unknown_tool_and_daemon_errors_are_flagged(self):
        reply = handle(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "nope", "arguments": {}},
            },
            Fake(),
        )
        self.assertTrue(reply["result"]["isError"])
        failing = Fake(error=RemoteError("daemon said no"))
        reply = handle(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "ghlab_digest", "arguments": {"binary": "a.exe"}},
            },
            failing,
        )
        self.assertTrue(reply["result"]["isError"])
        self.assertIn("daemon said no", reply["result"]["content"][0]["text"])


class ResourceTest(unittest.TestCase):
    def test_resources_cover_programs_and_each_binary(self):
        # the daemon returns plain names, but tolerate objects too
        for payload in (
            {"binaries": ["a.exe", "b.exe"]},
            {"binaries": [{"name": "a.exe"}, {"name": "b.exe"}]},
        ):
            reply = handle({"jsonrpc": "2.0", "id": 8, "method": "resources/list"}, Fake(payload))
            uris = [r["uri"] for r in reply["result"]["resources"]]
            self.assertIn("ghlab://programs", uris)
            self.assertIn("ghlab://program/a.exe/digest", uris)
            self.assertIn("ghlab://program/b.exe/notes", uris)

    def test_resources_survive_a_dead_daemon(self):
        reply = handle(
            {"jsonrpc": "2.0", "id": 11, "method": "resources/list"},
            Fake(error=RemoteError("down")),
        )
        uris = [r["uri"] for r in reply["result"]["resources"]]
        self.assertEqual(uris[0], "ghlab://programs")

    def test_read_program_digest(self):
        fake = Fake({"functions": 855})
        reply = handle(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "resources/read",
                "params": {"uri": "ghlab://program/a.exe/digest"},
            },
            fake,
        )
        self.assertEqual(fake.calls, [("digest", {"binary": "a.exe"})])
        self.assertIn("855", reply["result"]["content"][0]["text"])

    def test_unknown_resource_is_an_error(self):
        reply = handle(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "resources/read",
                "params": {"uri": "ghlab://nope"},
            },
            Fake(),
        )
        self.assertIn("error", reply)


class StdioTest(unittest.TestCase):
    def test_loop_answers_each_request_and_skips_notifications(self):
        lines = [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            "",  # blank line
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            "{not json",
        ]
        out = io.StringIO()
        code = mcp.serve(io.StringIO("\n".join(lines) + "\n"), out, Fake())
        self.assertEqual(code, 0)
        replies = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([r["id"] for r in replies], [1, 2, None])
        self.assertEqual(replies[2]["error"]["code"], -32700)


class PromptTest(unittest.TestCase):
    def test_prompts_list(self):
        reply = handle({"jsonrpc": "2.0", "id": 20, "method": "prompts/list"}, Fake())
        prompts = {p["name"]: p for p in reply["result"]["prompts"]}
        self.assertEqual(set(prompts), {"triage", "diff-review"})
        self.assertTrue(prompts["triage"]["arguments"][0]["required"])

    def test_triage_prompt_inlines_the_digest_so_no_second_call_is_needed(self):
        fake = Fake(routes={"digest": {"binary": "a.exe", "functions": 7, "md5": "deadbeef"}})
        reply = handle(
            {
                "jsonrpc": "2.0",
                "id": 21,
                "method": "prompts/get",
                "params": {"name": "triage", "arguments": {"binary": "a.exe"}},
            },
            fake,
        )
        text = reply["result"]["messages"][0]["content"]["text"]
        self.assertEqual(fake.calls, [("digest", {"binary": "a.exe"})])
        self.assertIn("do not call ghlab_digest again", text)
        self.assertIn("ghlab_find", text)
        self.assertLess(len(text), 20000)

    def test_diff_prompt_inlines_the_diff(self):
        fake = Fake(routes={"diff": {"a": "x", "b": "y", "summary": {"matched": 3}}})
        reply = handle(
            {
                "jsonrpc": "2.0",
                "id": 22,
                "method": "prompts/get",
                "params": {"name": "diff-review", "arguments": {"a": "x", "b": "y"}},
            },
            fake,
        )
        self.assertIn(
            "do not call ghlab_diff again", reply["result"]["messages"][0]["content"]["text"]
        )

    def test_prompt_errors_are_reported_not_crashed(self):
        for params in (
            {"name": "triage", "arguments": {}},
            {"name": "diff-review", "arguments": {"a": "x"}},
            {"name": "nope", "arguments": {}},
        ):
            reply = handle(
                {"jsonrpc": "2.0", "id": 23, "method": "prompts/get", "params": params}, Fake()
            )
            self.assertEqual(reply["error"]["code"], -32000, params)

    def test_prompt_survives_a_dead_daemon(self):
        reply = handle(
            {
                "jsonrpc": "2.0",
                "id": 24,
                "method": "prompts/get",
                "params": {"name": "triage", "arguments": {"binary": "a.exe"}},
            },
            Fake(error=RemoteError("down")),
        )
        text = reply["result"]["messages"][0]["content"]["text"]
        self.assertIn("could not answer digest", text)
        self.assertIn("ghlab_find", text)


class ProgramResourceTest(unittest.TestCase):
    def test_programs_resource_merges_info(self):
        fake = Fake(
            routes={
                "binaries": {"binaries": ["a.exe"]},
                "info": {"md5": "abc", "functions": 12, "language": "x86:LE:64:default"},
            }
        )
        reply = handle(
            {
                "jsonrpc": "2.0",
                "id": 25,
                "method": "resources/read",
                "params": {"uri": "ghlab://programs"},
            },
            fake,
        )
        programs = json.loads(reply["result"]["content"][0]["text"])["programs"]
        self.assertEqual(
            programs,
            [
                {
                    "name": "a.exe",
                    "md5": "abc",
                    "language": "x86:LE:64:default",
                    "compiler": None,
                    "functions": 12,
                }
            ],
        )

    def test_program_resources_describe_themselves(self):
        fake = Fake(
            routes={
                "binaries": {"binaries": ["a.exe"]},
                "info": {"functions": 12, "language": "x86:LE:64:default"},
            }
        )
        reply = handle({"jsonrpc": "2.0", "id": 26, "method": "resources/list"}, fake)
        described = next(
            r for r in reply["result"]["resources"] if r["uri"] == "ghlab://program/a.exe/digest"
        )
        self.assertIn("one-shot triage", described["description"])
        self.assertIn("12", described["description"])


if __name__ == "__main__":
    unittest.main()

    def test_readme_counts_match_the_code(self):
        """A README that says "15 tools" while the code has 22 is worse than no README."""
        readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"{len(mcp.TOOLS)} 个工具", readme)
