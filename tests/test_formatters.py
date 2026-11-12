"""Formatters read the daemon's reply; when the shape moves, the CLI dies.

`fmt_map` iterated `item["hits"]`, which the daemon returns as a *count*, so every
real `ghlab map` call ended in `TypeError: 'int' object is not iterable` while the
unit tests were green.
"""

import unittest

from ghlab import cli, session


def row(**kw):
    base = {"addr": "140001008", "name": "FUN_140001008", "size": 123, "hits": 0}
    base.update(kw)
    return base


class MapFormatterTest(unittest.TestCase):
    def test_a_grep_hit_lists_the_matches_from_matched(self):
        text = cli.fmt_map(
            {
                "from": "all",
                "op": "decompile",
                "grep": "Autosave",
                "matched": 1,
                "scanned": 2,
                "hits": 2,
                "elapsed_ms": 3,
                "results": [
                    row(
                        hits=2,
                        matched=[
                            {"line": 12, "text": "uVar1 = GetProfileStringW(...Autosave)"},
                            {"line": 40, "text": "bVar2 = lstrlenW(autosave);"},
                        ],
                    )
                ],
            }
        )
        self.assertIn("2 hit(s)", text)
        self.assertIn("12: uVar1 = GetProfileStringW", text)
        self.assertIn("40: bVar2 = lstrlenW", text)

    def test_a_decompile_without_grep_reports_the_line_count(self):
        text = cli.fmt_map(
            {
                "from": "all",
                "op": "decompile",
                "grep": None,
                "matched": 1,
                "scanned": 1,
                "hits": 0,
                "elapsed_ms": 1,
                "results": [row(lines=71)],
            }
        )
        self.assertIn("71 line(s)", text)

    def test_an_error_row_prints_the_error_not_a_hit_list(self):
        text = cli.fmt_map(
            {
                "from": "all",
                "op": "calls",
                "grep": "x",
                "matched": 1,
                "scanned": 1,
                "hits": 0,
                "elapsed_ms": 1,
                "results": [row(error="boom")],
            }
        )
        self.assertIn("error: boom", text)

    def test_nothing_matched_says_so(self):
        text = cli.fmt_map(
            {
                "from": "all",
                "op": "decompile",
                "grep": "zzz",
                "matched": 0,
                "scanned": 5,
                "hits": 0,
                "elapsed_ms": 1,
                "results": [],
            }
        )
        self.assertIn("nothing matched", text)


class DecryptArgumentTest(unittest.TestCase):
    def test_a_binary_without_an_address_says_what_is_missing(self):
        with self.assertRaises(ValueError) as cm:
            session.cmd_decrypt({"binary": "a.exe", "len": 64})
        self.assertIn("addr=", str(cm.exception))
        self.assertIn("hex=", str(cm.exception))

    def test_neither_hex_nor_a_binary_is_a_different_message(self):
        with self.assertRaises(ValueError) as cm:
            session.cmd_decrypt({})
        self.assertIn("hex=", str(cm.exception))


class SameFileDiffTest(unittest.TestCase):
    """Two copies of one file, only one of them analysed, used to read as 455 changes."""

    def test_the_note_appears_only_for_same_md5_with_no_identical_function(self):
        note = session._same_md5_note("ab" * 16, "ab" * 16, 0, 455)
        self.assertIn("same md5", note)
        self.assertIn("analyze", note)

    def test_different_files_need_no_excuse(self):
        self.assertEqual(session._same_md5_note("ab", "cd", 0, 455), "")

    def test_real_changes_in_one_file_are_not_excused(self):
        self.assertEqual(session._same_md5_note("ab", "ab", 3, 2), "")

    def test_nothing_changed_needs_no_note(self):
        self.assertEqual(session._same_md5_note("ab", "ab", 455, 0), "")

    def test_the_formatter_prints_the_note(self):
        text = cli.fmt_diff(
            {
                "a": {"binary": "a.exe", "md5": "ab", "functions": 455},
                "b": {"binary": "b.exe", "md5": "ab", "functions": 477},
                "summary": {
                    "matched": 455,
                    "identical": 0,
                    "changed": 455,
                    "added": 22,
                    "removed": 0,
                    "by": {"address": 450},
                },
                "sections": {"changed": [], "added": [], "removed": []},
                "changed": [],
                "added": [],
                "removed": [],
                "elapsed_ms": 7,
                "note": session._same_md5_note("ab", "ab", 0, 455),
            }
        )
        self.assertIn("!! both programs have the same md5", text)


class SmallFormatterTest(unittest.TestCase):
    def test_ping_without_pid_or_uptime_still_reads_as_a_sentence(self):
        text = cli.fmt_ping(
            {"service": "ghlab", "project": "C:/p/p", "binaries": 3, "loaded": ["a.exe"]}
        )
        self.assertTrue(text.startswith("# ghlab up"))
        self.assertNotIn("pid ?", text)
        self.assertIn("3 program(s), 1 open: a.exe", text)

    def test_ping_with_the_help_page_fields(self):
        text = cli.fmt_ping(
            {
                "service": "ghlab",
                "pid": 42,
                "uptime_s": 187.0,
                "project": "C:/p/p",
                "binaries": 0,
                "loaded": [],
                "readonly": True,
            }
        )
        self.assertIn("pid 42", text)
        self.assertIn("187.0s", text)
        self.assertIn("[read-only]", text)

    def test_bytes_prints_a_hexdump_and_the_truncation_reason(self):
        text = cli.fmt_bytes(
            {
                "addr": "140000000",
                "hex": "4c8bdc4831c0",
                "ascii": "L...H1.",
                "size": 8,
                "truncated": True,
            }
        )
        self.assertIn("0000  4c 8b dc 48 31 c0", text)
        self.assertIn("|L...H1.|", text)
        self.assertIn("cut at the end of the block", text)

    def test_comment_shows_the_text_it_wrote(self):
        text = cli.fmt_comment({"addr": "1400011b4", "type": "plate", "text": "checked by hand"})
        self.assertEqual(text, "comment @ 1400011b4 (plate): checked by hand")

    def test_rename_prefers_both_names(self):
        self.assertEqual(
            cli.fmt_rename({"addr": "1400011b4", "was": "FUN_1400011b4", "renamed": "h"}),
            "renamed 1400011b4: FUN_1400011b4 -> h",
        )


if __name__ == "__main__":
    unittest.main()
