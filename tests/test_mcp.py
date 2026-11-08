"""MCP facade tests: protocol shape and argument forwarding, no Ghidra involved."""

import io
import json
import unittest

from ghlab import mcp, protocol
from ghlab.client import RemoteError


class Fake:
    """Stands in for Client: records what the tools ask the daemon for."""

    def __init__(self, result=None, error=None):
        self.calls = []
        self.result = {"ok": True} if result is None else result
        self.error = error

    def __call__(self, cmd, **params):
        self.calls.append((cmd, params))
        if self.error is not None:
            raise self.error
        return self.result


class ProtocolTest(unittest.TestCase):
    def test_initialize_announces_tools_and_resources(self):
        reply = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, Fake())
        self.assertEqual(reply["id"], 1)
        result = reply["result"]
        self.assertEqual(result["protocolVersion"], mcp.PROTOCOL_VERSION)
        self.assertIn("tools", result["capabilities"])
        self.assertIn("resources", result["capabilities"])
        self.assertEqual(result["serverInfo"]["name"], "ghlab")

    def test_notifications_get_no_response(self):
        self.assertIsNone(mcp.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, Fake()))
        self.assertIsNone(mcp.handle({"jsonrpc": "2.0", "method": "ping"}, Fake()))

    def test_unknown_method_is_an_error(self):
        reply = mcp.handle({"jsonrpc": "2.0", "id": 7, "method": "nope"}, Fake())
        self.assertEqual(reply["error"]["code"], -32601)

    def test_tools_are_few_and_well_formed(self):
        tools = mcp.TOOLS
        self.assertLessEqual(len(tools), 12, "MCP facade should stay small")
        names = [t["name"] for t in tools]
        self.assertEqual(len(names), len(set(names)))
        for tool in tools:
            self.assertTrue(tool["name"].startswith("ghlab_"), tool["name"])
            self.assertGreater(len(tool["description"]), 40, tool["name"])
            schema = tool["inputSchema"]
            self.assertEqual(schema["type"], "object")
            self.assertIn("properties", schema)
            for key in schema.get("required", []):
                self.assertIn(key, schema["properties"], f"{tool['name']} requires undeclared {key}")

    def test_every_tool_maps_to_a_real_daemon_command(self):
        for tool in mcp.TOOLS:
            cmd = mcp._COMMANDS.get(tool["name"])
            self.assertIn(cmd, protocol.COMMAND_NAMES, tool["name"])
            declared = set(protocol.SPECS[cmd].required) | set(protocol.SPECS[cmd].optional)
            for key in tool["inputSchema"]["properties"]:
                self.assertIn(key, declared, f"{tool['name']}.{key} is not a {cmd} parameter")

    def test_tools_list(self):
        reply = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, Fake())
        self.assertEqual(len(reply["result"]["tools"]), len(mcp.TOOLS))


class ToolCallTest(unittest.TestCase):
    def test_digest_forwards_to_the_daemon(self):
        fake = Fake({"functions": 855})
        reply = mcp.handle(
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
        mcp.handle(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "ghlab_find", "arguments": {"binary": "a.exe", "import": "RegSetValueExW"}},
            },
            fake,
        )
        self.assertEqual(fake.calls[0][1]["import"], ["RegSetValueExW"])

    def test_none_arguments_are_dropped(self):
        fake = Fake()
        mcp.handle(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "ghlab_slice", "arguments": {"binary": "a.exe", "to": "CreateProcessW", "from": None}},
            },
            fake,
        )
        self.assertNotIn("from", fake.calls[0][1])

    def test_unknown_tool_and_daemon_errors_are_flagged(self):
        reply = mcp.handle(
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "nope", "arguments": {}}},
            Fake(),
        )
        self.assertTrue(reply["result"]["isError"])
        failing = Fake(error=RemoteError("daemon said no"))
        reply = mcp.handle(
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
        for payload in ({"binaries": ["a.exe", "b.exe"]}, {"binaries": [{"name": "a.exe"}, {"name": "b.exe"}]}):
            reply = mcp.handle({"jsonrpc": "2.0", "id": 8, "method": "resources/list"}, Fake(payload))
            uris = [r["uri"] for r in reply["result"]["resources"]]
            self.assertIn("ghlab://programs", uris)
            self.assertIn("ghlab://program/a.exe/digest", uris)
            self.assertIn("ghlab://program/b.exe/notes", uris)

    def test_resources_survive_a_dead_daemon(self):
        reply = mcp.handle(
            {"jsonrpc": "2.0", "id": 11, "method": "resources/list"}, Fake(error=RemoteError("down"))
        )
        uris = [r["uri"] for r in reply["result"]["resources"]]
        self.assertEqual(uris[0], "ghlab://programs")

    def test_read_program_digest(self):
        fake = Fake({"functions": 855})
        reply = mcp.handle(
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
        reply = mcp.handle(
            {"jsonrpc": "2.0", "id": 10, "method": "resources/read", "params": {"uri": "ghlab://nope"}},
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


if __name__ == "__main__":
    unittest.main()
