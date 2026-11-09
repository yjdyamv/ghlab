"""End-to-end tests that must run anywhere: a 40 KB binary, a temp project.

Tier 1 (`GHLAB_LIVE=1`): everything here, on whatever small sample the OS
ships, in a project created under a temp dir.  Nothing is assumed about the
machine beyond "has Ghidra" and "has some system binary".

Tier 2 (`GHLAB_LIVE_RICH=1`) is `test_live.py`: it leans on a specific sample
(notepad.exe) to assert facts we learned from it, so it is opt-in.

Assertions here are structural on purpose: counts, keys, ordering, invariants
like "grep mode returns no code".  No magic numbers -- those live in tier 2.
"""

import unittest

from ghlab import protocol
from ghlab.client import RemoteError

try:  # `python -m unittest discover -s tests` puts tests/ on sys.path
    from liveutil import bootstrap, skip_reason
except ImportError:  # when imported as tests.test_live_smoke
    from .liveutil import bootstrap, skip_reason

import os

# Opt-in, and lazy: importing this module must not start a daemon, or the
# default `unittest discover` (which imports every module) pays for it.
ENABLED = bool(os.environ.get("GHLAB_LIVE"))
READY = None
REASON = ""
if ENABLED:
    REASON = skip_reason()
    if not REASON:
        READY = bootstrap()
        if READY is None:
            REASON = "could not start a daemon for the live tests"
else:
    REASON = "set GHLAB_LIVE=1 to run the live tests"
LIVE = READY is not None
client, BIN = READY if READY else (None, "sample.exe")


@unittest.skipUnless(LIVE, REASON)
class SmokeTest(unittest.TestCase):
    """One pass over every command a fresh user would reach for first."""

    def setUp(self) -> None:
        # skipUnless already proved the daemon exists; this narrows the type.
        assert READY is not None
        self.c = READY[0]

    def test_ping_names_the_project(self):
        r = self.c.call("ping")
        self.assertEqual(r["service"], "ghlab")
        self.assertTrue(r["project"])
        self.assertIn(BIN, r["loaded"])

    def test_overview_and_digest_describe_the_sample(self):
        over = self.c.call("overview")
        names = [row["binary"] for row in over["binaries"]]
        self.assertIn(BIN, names)
        digest = self.c.call("digest", binary=BIN)
        self.assertGreater(digest["functions"], 0)
        self.assertIn("entry", digest)
        # digest exists to be cheap: it must stay well under a page of text.
        self.assertLess(len(str(digest)), 40000)

    def test_functions_list_and_match(self):
        listing = self.c.call("functions", binary=BIN, limit=5)
        self.assertGreater(listing["matched"], 0)
        self.assertTrue(listing["functions"])
        for fn in listing["functions"]:
            self.assertTrue(fn["name"])
            self.assertTrue(fn["addr"])
        narrowed = self.c.call("functions", binary=BIN, match="^entry$")
        self.assertGreaterEqual(narrowed["matched"], 1)

    def test_decompile_code_and_signature_modes(self):
        code = self.c.call("decompile", binary=BIN, target="entry")
        self.assertTrue(code["results"])
        self.assertIn("entry", code["results"][0]["code"])
        sig = self.c.call("decompile", binary=BIN, target="entry", sig=True)
        self.assertNotIn("code", sig["results"][0])
        self.assertTrue(sig["results"][0]["prototype"])

    def test_decompile_grep_returns_lines_not_source(self):
        r = self.c.call("decompile", binary=BIN, target="entry", grep="return")
        entry = r["results"][0]
        self.assertNotIn("code", entry, "grep mode must not ship the whole source")
        self.assertGreater(entry["grep_hits"], 0)
        for hit in entry["hits"]:
            self.assertIn("text", hit)
            self.assertIn("line", hit)

    def test_strings_are_cached_and_refreshable(self):
        first = self.c.call("strings", binary=BIN, limit=5)
        self.assertTrue(first["strings"])
        again = self.c.call("strings", binary=BIN, limit=5)
        self.assertTrue(again["cached"])
        forced = self.c.call("strings", binary=BIN, limit=5, refresh=True)
        self.assertFalse(forced["cached"])

    def test_imports_group_by_risk_and_count_callers(self):
        r = self.c.call("imports", binary=BIN, limit=5)
        self.assertGreater(r["total"], 0)
        for imp in r["imports"]:
            self.assertIn("callers", imp)
            self.assertIsInstance(imp["callers"], int)
        grouped = self.c.call("imports", binary=BIN, group="file", limit=5)
        self.assertTrue(all(i["risk"] == "file" for i in grouped["imports"]))

    def test_offsets_attributes_a_field_to_its_parameter(self):
        """The whole point: +0x40 on param_2 is not the same fact as +0x40 on a local."""
        args = sorted(
            (row for row in self.c.call("functions", binary=BIN, limit=200)["functions"]),
            key=lambda row: row["size"],
            reverse=True,
        )
        target = args[0]["name"]
        r = self.c.call("offsets", binary=BIN, target=target, limit=40)
        self.assertEqual(r["function"], target)
        self.assertIsNone(r["error"])
        self.assertTrue(r["accesses"])
        for row in r["accesses"]:
            self.assertIn(row["kind"], ("param", "local"))
            self.assertTrue(row["offset"].startswith(("0x", "-0x")))

    def test_scan_accepts_several_offsets_at_once(self):
        """Several offsets at once keeps only functions that touch all of them."""
        r = self.c.call("scan", binary=BIN, offset="0x8,0x10", func="entry", writes=True, limit=5)
        self.assertIn("matched_functions", r)
        self.assertEqual(r["offset"], "0x8,0x10")
        for row in r["matched_functions"]:
            self.assertEqual(set(row["offsets"]), {"0x8", "0x10"})

    def test_scan_can_ask_for_an_ordered_window(self):
        """`--sequence` keeps offsets in order: the shape of a struct copy."""
        r = self.c.call(
            "scan", binary=BIN, offset="0x8,0x10", func="entry", sequence=True, window=16, limit=5
        )
        self.assertIn("seq ", r["pattern"])
        self.assertEqual(r["window"], 16)
        for site in r["sites"]:
            self.assertLessEqual(len(site["sequence"]), 16)

    def test_xrefs_and_scan_agree_on_a_function(self):
        xr = self.c.call("xrefs", binary=BIN, target="entry", limit=5)
        self.assertTrue(xr["results"])
        for entry in xr["results"]:
            self.assertIsInstance(entry["xrefs"], list)
            self.assertLessEqual(len(entry["xrefs"]), 5)
        scoped = self.c.call("scan", binary=BIN, offset="0x8", func="entry", limit=5)
        self.assertGreater(scoped["scanned"], 0)
        for site in scoped["sites"]:
            self.assertIn("+ 0x8]", site["text"])

    def test_index_builds_once_then_is_reused(self):
        # a pinned daemon may already hold the index, so force the build once
        first = self.c.call("index", binary=BIN, refresh=True)
        self.assertGreater(first["functions"], 0)
        second = self.c.call("index", binary=BIN)
        self.assertTrue(second["cached"])
        self.assertFalse(first["cached"])

    def test_claim_roundtrip_and_report(self):
        before = self.c.call("notes", binary=BIN)["total"]
        self.c.call(
            "note",
            binary=BIN,
            at="entry",
            tag="smoke",
            text="entry exists and is bigger than a byte",
            **{"assert": ["size>=1"]},
        )
        after = self.c.call("notes", binary=BIN)["total"]
        self.assertEqual(after, before + 1)
        verified = self.c.call("verify", binary=BIN)
        self.assertGreaterEqual(verified["passed"], 1)
        self.assertIn("claims", self.c.call("report", binary=BIN)["markdown"])

    def test_journal_records_the_note(self):
        entries = self.c.call("journal", binary=BIN, limit=5)
        self.assertTrue(entries["entries"])
        self.assertIn("op", entries["entries"][0])

    def test_graph_renders_without_external_tools(self):
        dot = self.c.call("graph", binary=BIN, target="entry", depth=1, format="dot")
        self.assertIn("digraph", dot["rendered"])
        mermaid = self.c.call("graph", binary=BIN, target="entry", depth=1, format="mermaid")
        self.assertIn("-->", mermaid["rendered"])

    def test_names_answers_even_when_empty(self):
        r = self.c.call("names", binary=BIN, limit=5)
        self.assertIn("count", r)
        self.assertEqual(r["count"], r["count"])

    def test_emulate_reports_a_stop_reason(self):
        r = self.c.call("emulate", binary=BIN, target="entry", max_insns=8)
        self.assertIn(r["stop"], {"returned", "timeout", "fault", "max-insns"})
        self.assertGreaterEqual(r["insns"], 1)

    def test_unknown_parameters_are_rejected(self):
        with self.assertRaises(RemoteError):
            self.c.call("digest", binary=BIN, nonsense=1)
        self.assertIn("digest", protocol.COMMAND_NAMES)


if __name__ == "__main__":
    unittest.main()
