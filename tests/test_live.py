"""Live tests against a running daemon: `ghlab start` first, then run these.

Unit runs (`tests/test_*.py` without a daemon) skip this module automatically.
"""

import json
import os
import subprocess
import sys
import tempfile
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
        r = client.call("decompile", binary=BIN, match="^FUN_", grep="if \\(", limit=8)
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
                client.call("comment", binary=BIN, target="ghlab_probe", text="ghlab live test")[
                    "ok"
                ]
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

    def test_digest_summarises_without_flooding(self):
        r = client.call("digest", binary=BIN)
        self.assertGreater(r["functions"], 100)
        self.assertEqual(len(r["md5"]), 32)
        self.assertTrue(r["entry"], "entry chain should resolve on a PE")
        self.assertGreater(r["imports"]["total"], 10)
        self.assertTrue(r["imports"]["groups"], "risk grouping should find something")
        self.assertIn("total", r["strings"])
        self.assertTrue(r["sizes"], "size buckets expected")
        # a digest must stay cheap: whole payload well under a decompiled file
        self.assertLess(len(str(r)), 40000)

    def test_find_locates_registry_writer(self):
        r = client.call("find", binary=BIN, **{"import": ["RegSetValue"], "string": ["Notepad"]})
        self.assertGreater(r["candidates"], 0)
        first = r["functions"][0]
        self.assertIn("RegSetValueExW", first["matched"]["import"])
        self.assertEqual(first["filters_matched"], 2, "default mode is all-filters")

    def test_find_requires_a_filter(self):
        with self.assertRaises(RemoteError) as ctx:
            client.call("find", binary=BIN)
        self.assertIn("at least one", str(ctx.exception))

    def test_emulate_runs_and_reports_stubs(self):
        r = client.call("emulate", binary=BIN, target="__security_check_cookie", args=[1], ms=5000)
        self.assertIn(r["stop"], ("returned", "fault", "timeout"))
        self.assertGreater(r["insns"], 0)
        self.assertIn("rax_hex", r["ret"])
        self.assertIsInstance(r["stubs"], list)
        self.assertIn("scratch", r)

    def test_emulate_seeds_strings_in_memory(self):
        r = client.call(
            "emulate", binary=BIN, target="__security_check_cookie", args=['"abc"'], ms=5000
        )
        arg = r["args"][0]
        self.assertEqual(arg["kind"], "str")
        self.assertEqual(arg["bytes"], 4, "string plus NUL is written into scratch memory")

    def test_emulate_buffer_is_read_back(self):
        r = client.call(
            "emulate", binary=BIN, target="__security_check_cookie", args=[1], buffer=32
        )
        self.assertEqual(r["buffer"]["size"], 32)
        buf = [d for d in r["dump"] if d["addr"] == r["buffer"]["addr"]]
        self.assertEqual(len(buf), 1)
        self.assertEqual(buf[0]["size"], 32)

    def test_emulate_rejects_unknown_function(self):
        with self.assertRaises(RemoteError) as ctx:
            client.call("emulate", binary=BIN, target="definitely_not_a_function")
        self.assertIn("not found", str(ctx.exception))

    def test_diff_against_self_has_no_changes(self):
        r = client.call("diff", a=BIN, b=BIN)
        self.assertEqual(r["summary"]["changed"], 0)
        self.assertEqual(r["summary"]["added"], 0)
        self.assertEqual(r["summary"]["removed"], 0)
        self.assertEqual(r["summary"]["identical"], r["summary"]["matched"])
        self.assertEqual(r["sections"]["changed"], [])

    def test_diff_reports_a_patched_function(self):
        binaries = client.call("binaries")["binaries"]
        patched = [b for b in binaries if b == "notepad_p2.exe"]
        if not patched:
            self.skipTest("notepad_p2.exe not imported")
        r = client.call("diff", a=BIN, b=patched[0])
        self.assertEqual(r["summary"]["changed"], 1)
        self.assertEqual(r["summary"]["added"], 1)
        self.assertIn(".text", r["sections"]["changed"])
        changed = r["changed"][0]
        self.assertEqual(changed["matched_by"], "signature")
        self.assertLess(changed["delta"]["insns"][1], changed["delta"]["insns"][0])

    def test_patch_roundtrip_and_expect_guard(self):
        addr = "1400019d0"
        original = client.call("bytes", binary=BIN, addr=addr, size=4)["hex"]
        try:
            r = client.call("patch", binary=BIN, addr=addr, bytes="90909090", expect=original)
            self.assertEqual(r["after"], "90909090")
            self.assertEqual(client.call("bytes", binary=BIN, addr=addr, size=4)["hex"], "90909090")
        finally:
            client.call("patch", binary=BIN, addr=addr, bytes=original, expect="90909090")
        self.assertEqual(client.call("bytes", binary=BIN, addr=addr, size=4)["hex"], original)
        with self.assertRaises(RemoteError) as ctx:
            client.call("patch", binary=BIN, addr=addr, bytes="90", expect="aabb")
        self.assertIn("expect", str(ctx.exception))

    def test_set_type_signature_and_data(self):
        # Rename a spare function, then put the name back: the point is that the
        # declaration's name wins and that the signature sticks.
        target = "FUN_140008508"
        names = client.call("functions", binary=BIN, match=f"^{target}$")["functions"]
        if not names:
            self.skipTest(f"{target} not present")
        try:
            r = client.call("set_type", binary=BIN, target=target, decl="int ghlab_probe(int a)")
            self.assertEqual(r["kind"], "signature")
            self.assertTrue(r["applied"])
            self.assertIn("ghlab_probe", r["prototype"])
        finally:
            client.call("rename", binary=BIN, target="ghlab_probe", new=target)
        data = client.call("set_type", binary=BIN, target="0x140038600", decl="char[8]")
        self.assertEqual(data["kind"], "data")
        self.assertEqual(data["size"], 8)
        self.assertTrue(data["datatype"].startswith("char"))

    def test_bookmark_roundtrip(self):
        addr = "1400019d0"
        client.call("bookmark", binary=BIN, addr=addr, category="ghlab-test", comment="unit test")
        listed = client.call("bookmark", binary=BIN, action="list")["bookmarks"]
        self.assertTrue(any(b["category"] == "ghlab-test" for b in listed))
        removed = client.call(
            "bookmark", binary=BIN, action="remove", addr=addr, category="ghlab-test"
        )
        self.assertEqual(removed["removed"], 1)

    def test_note_then_report_contains_it(self):
        text = "ghlab live test finding"
        r = client.call("note", binary=BIN, text=text, at="entry", tag="test")
        note = r["note"]
        self.assertEqual(note["function"], "entry")
        listed = client.call("notes", binary=BIN, tag="test")
        self.assertTrue(any(n["text"] == text for n in listed["notes"]))
        report = client.call("report", binary=BIN, top=3)["markdown"]
        self.assertIn("## Findings", report)
        self.assertIn(text, report)
        self.assertIn("Call-graph hubs", report)

    def test_decompile_cache_round_trip(self):
        cold = client.call("decompile", binary=BIN, target="FUN_140007e1c", refresh=True)
        warm = client.call("decompile", binary=BIN, target="FUN_140007e1c")
        self.assertFalse(cold["results"][0]["cached"])
        self.assertTrue(warm["results"][0]["cached"])
        self.assertEqual(cold["results"][0]["code"], warm["results"][0]["code"])

    def test_cross_xref_finds_strings_in_every_program(self):
        r = client.call("cross_xref", query="Autosave")
        self.assertGreaterEqual(r["searched"], 1)
        self.assertTrue(r["binaries"])
        for b in r["binaries"]:
            self.assertGreater(b["count"], 0)
            self.assertTrue(b["matches"][0]["refs"])
            self.assertTrue(b["matches"][0]["value"])

    def test_slice_reaches_entry(self):
        r = client.call("slice", binary=BIN, to="RegSetValueExW")
        self.assertTrue(r["paths"])
        self.assertTrue(any(p["reaches_entry"] for p in r["paths"]))
        self.assertIn("RegSetValueExW", r["paths"][0]["via"])
        reach = next(p for p in r["paths"] if p["reaches_entry"])
        self.assertGreater(len(reach["path"]), 1)

    def test_similar_finds_the_same_function_elsewhere(self):
        r = client.call("similar", binary=BIN, target="FUN_140021ba8")
        if not r["matches"]:
            self.skipTest("only one program in the project")
        best = r["matches"][0]
        self.assertEqual(best["name"], "FUN_140021ba8")
        self.assertGreater(best["score"], 0.9)
        self.assertTrue(best["shared_imports"] or best["shared_strings"])

    def test_campaign_clusters_the_project(self):
        r = client.call("campaign", min_score=0.5)
        self.assertGreaterEqual(r["binaries"], 1)
        self.assertFalse(r["errors"], r["errors"])
        sizes = sum(c["size"] for c in r["clusters"])
        self.assertEqual(sizes, r["binaries"])
        for c in r["clusters"]:
            self.assertEqual(c["size"], len(c["members"]))
            if c["size"] > 1:
                self.assertTrue(c["shared_imports"] or c["shared_strings"])

    def test_mcp_stdio_serves_tools_and_a_digest(self):
        lines = [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "ghlab_digest", "arguments": {"binary": BIN, "top": 2}},
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "resources/read",
                    "params": {"uri": f"ghlab://program/{BIN}/notes"},
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "prompts/get",
                    "params": {"name": "triage", "arguments": {"binary": BIN}},
                }
            ),
        ]
        payload = "".join(line + "\n" for line in lines)
        proc = subprocess.run(
            [sys.executable, "-m", "ghlab.mcp"],
            input=payload,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=180,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        replies = {
            json.loads(line)["id"]: json.loads(line)
            for line in proc.stdout.splitlines()
            if line.strip()
        }
        self.assertEqual(set(replies), {1, 2, 3, 4, 5})
        self.assertEqual(replies[1]["result"]["serverInfo"]["name"], "ghlab")
        self.assertGreaterEqual(len(replies[2]["result"]["tools"]), 8)
        digest = json.loads(replies[3]["result"]["content"][0]["text"])
        self.assertIn("functions", digest)
        self.assertIn("notes", json.loads(replies[4]["result"]["content"][0]["text"]))
        prompt = replies[5]["result"]["messages"][0]["content"]["text"]
        self.assertIn(f"Digest for {BIN}", prompt)
        self.assertIn("do not call ghlab_digest again", prompt)
        self.assertLess(len(prompt), 20000, "the triage prompt must stay cheap")

    def test_run_script_against_the_daemon(self):
        script_text = "\n".join(["# smoke", "digest $BIN --top 2", "report $BIN > report.md", ""])
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, "job.gh")
            with open(script, "w", encoding="utf-8") as fh:
                fh.write(script_text)
            proc = subprocess.run(
                [sys.executable, "-m", "ghlab.cli", "run", script, "--set", f"BIN={BIN}"],
                cwd=tmp,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=180,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("2/2 steps ok", proc.stdout)
            with open(os.path.join(tmp, "report.md"), encoding="utf-8") as fh:
                self.assertIn("Call-graph hubs", fh.read())

    def test_similar_does_not_equate_empty_stubs(self):
        r = client.call("similar", binary=BIN, target="FUN_140007e1c")
        for m in r["matches"]:
            self.assertTrue(m["shared_strings"] or m["shared_imports"] or m["score"] <= 0.3)


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
