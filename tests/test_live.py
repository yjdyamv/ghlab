"""Live tests against a running daemon: `ghlab start` first, then run these.

Unit runs (`tests/test_*.py` without a daemon) skip this module automatically.
"""

import os
import re
import unittest

from ghlab.client import Client, RemoteError

client = Client(os.environ.get("GHLAB_URL"), timeout=600)
BIN = os.environ.get("GHLAB_TEST_BIN", "notepad.exe")


def _alive():
    try:
        return client.alive() and BIN in client.call("binaries")["binaries"]
    except Exception:  # noqa: BLE001
        return False


LIVE = _alive()
reason = f"no daemon on {client.url} or {BIN} not imported"


@unittest.skipUnless(LIVE, reason)
class LiveTest(unittest.TestCase):
    def test_ping_reports_project(self):
        r = client.call("ping")
        self.assertEqual(r["service"], "ghlab")
        self.assertIn(BIN, r["loaded"])

    def test_info_has_md5_and_functions(self):
        r = client.call("info", binary=BIN)
        self.assertEqual(len(r["md5"]), 32)
        self.assertGreater(r["functions"], 100)
        self.assertTrue(r["memory_blocks"])

    def test_functions_regex_filters(self):
        r = client.call("functions", binary=BIN, match="^FUN_", limit=5)
        self.assertEqual(len(r["functions"]), 5)
        self.assertTrue(all(f["name"].startswith("FUN_") for f in r["functions"]))
        self.assertGreater(r["matched"], 5)

    def test_decompile_single_returns_code(self):
        r = client.call("decompile", binary=BIN, targets=["entry"], max_lines=20)
        item = r["results"][0]
        self.assertEqual(item["name"], "entry")
        self.assertIn("{", item["code"])
        self.assertLessEqual(item["code"].count("\n"), 22)

    def test_batch_decompile_with_server_side_grep(self):
        r = client.call(
            "decompile", binary=BIN, match="^FUN_", grep="if \\(", limit=8
        )
        self.assertTrue(r["results"], "expected at least one function with an if")
        for item in r["results"]:
            self.assertGreater(item["grep_hits"], 0)
            self.assertNotIn("code", item, "grep mode must not ship whole source")
            for hit in item["matched"]:
                self.assertRegex(hit["text"], r"if \(")

    def test_decompile_callgraph_flags(self):
        r = client.call(
            "decompile", binary=BIN, targets=["entry"], include_callees=True, include_code=False
        )
        item = r["results"][0]
        self.assertNotIn("code", item)
        self.assertTrue(item["callees"])

    def test_graph_walks_two_levels(self):
        r = client.call("graph", binary=BIN, target="entry", depth=2)
        self.assertEqual(r["root"], "entry")
        self.assertGreaterEqual(len(r["nodes"]), 2)
        self.assertTrue(all(edge["from"] for edge in r["edges"]))

    def test_strings_query(self):
        r = client.call("strings", binary=BIN, query="txt", limit=5)
        self.assertGreater(r["defined_data_scanned"], 100)
        for s in r["strings"]:
            self.assertRegex(s["value"].lower(), "txt")

    def test_bytes_matches_address(self):
        r = client.call("bytes", binary=BIN, addr="0x140001008", size=8)
        self.assertEqual(len(r["hex"]), 16)
        self.assertEqual(len(r["ascii"]), 8)

    def test_xrefs_shape(self):
        r = client.call("xrefs", binary=BIN, targets=["entry"])
        self.assertEqual(r["results"][0]["target"], "entry")
        self.assertIsInstance(r["results"][0]["xrefs"], list)

    def test_rename_roundtrip_and_comment(self):
        target = client.call("functions", binary=BIN, match="^FUN_", limit=1)["functions"][0]
        original = target["name"]
        try:
            renamed = client.call("rename", binary=BIN, target=original, new="ghlab_probe")
            self.assertEqual(renamed["renamed"], "ghlab_probe")
            hit = client.call("functions", binary=BIN, match="^ghlab_probe$", limit=1)
            self.assertEqual(hit["functions"][0]["name"], "ghlab_probe")
            self.assertTrue(
                client.call(
                    "comment", binary=BIN, target="ghlab_probe", text="ghlab live test"
                )["ok"]
            )
        finally:
            client.call("rename", binary=BIN, target="ghlab_probe", new=original)

    def test_bad_request_is_reported_without_crashing_daemon(self):
        with self.assertRaises(RemoteError) as ctx:
            client.call("decompile", binary=BIN, bogus=1)
        self.assertIn("unknown parameter", str(ctx.exception))
        self.assertTrue(client.alive(), "daemon must survive bad input")

    def test_missing_function_reports_per_target_error(self):
        r = client.call("decompile", binary=BIN, targets=["definitely_not_here"])
        self.assertIn("not found", r["results"][0]["error"])


@unittest.skipUnless(LIVE and os.environ.get("GHLAB_LIVE_IMPORT"), "set GHLAB_LIVE_IMPORT=1")
class LiveImportTest(unittest.TestCase):
    def test_import_is_idempotent(self):
        path = os.environ["GHLAB_LIVE_IMPORT"]
        first = client.call("import", path=path)
        second = client.call("import", path=path)
        self.assertTrue(first.get("imported") or first.get("already_present"))
        self.assertTrue(second.get("already_present"))


if __name__ == "__main__":
    unittest.main()
