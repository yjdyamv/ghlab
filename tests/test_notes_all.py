"""`ghlab notes` without a binary reads the whole project's findings."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ghlab import cli, protocol, session


def _note(nid: int, binary: str, text: str, tag: str = "fact") -> dict:
    return {
        "id": nid,
        "binary": binary,
        "text": text,
        "tag": tag,
        "addr": "140001000",
        "function": "FUN_140001000",
        "at": "2026-11-13T00:00:00",
    }


class AllProgramsTest(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        patcher = mock.patch.object(session, "_project_dir", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _write(self, binary: str, notes: list[dict]) -> None:
        session._store_notes(binary, notes)

    def test_no_binary_reads_every_program(self):
        self._write("a.exe", [_note(1, "a.exe", "first")])
        self._write("b.exe", [_note(2, "b.exe", "second"), _note(1, "b.exe", "third")])
        out = session.cmd_notes({})
        self.assertEqual(out["total"], 3)
        self.assertEqual(out["count"], 3)
        self.assertEqual(out["programs"], 2)
        self.assertEqual([n["text"] for n in out["notes"]], ["first", "third", "second"])
        self.assertEqual({n["binary"] for n in out["notes"]}, {"a.exe", "b.exe"})

    def test_asking_for_one_program_still_works(self):
        self._write("a.exe", [_note(1, "a.exe", "first")])
        self._write("b.exe", [_note(2, "b.exe", "second")])
        out = session.cmd_notes({"binary": "a.exe"})
        self.assertEqual(out["total"], 1)
        self.assertEqual(out["programs"], 1)
        self.assertEqual(out["path"], str(session._notes_file("a.exe")))

    def test_filters_apply_across_programs(self):
        self._write("a.exe", [_note(1, "a.exe", "crypto key", tag="crypto")])
        self._write(
            "b.exe",
            [
                _note(1, "b.exe", "crypto in b", tag="crypto"),
                _note(2, "b.exe", "network", tag="network"),
            ],
        )
        out = session.cmd_notes({"tag": "crypto"})
        self.assertEqual((out["count"], out["total"]), (2, 3))
        out = session.cmd_notes({"query": "in b"})
        self.assertEqual([n["text"] for n in out["notes"]], ["crypto in b"])

    def test_an_empty_project_says_so(self):
        out = session.cmd_notes({})
        self.assertEqual(out["total"], 0)
        self.assertEqual(out["programs"], 0)
        self.assertEqual(
            cli.fmt_notes(out), f"(no notes matched; 0 stored in {self.root / '.ghlab' / 'notes'})"
        )

    def test_a_note_without_its_own_binary_is_tagged_from_the_file(self):
        path = session._notes_file("c.exe")
        path.write_text(json.dumps([{"id": 4, "text": "bare", "tag": "fact"}]), encoding="utf-8")
        out = session.cmd_notes({})
        self.assertEqual(out["notes"][0]["binary"], "c.exe")

    def test_a_broken_id_does_not_break_the_sort(self):
        path = session._notes_file("d.exe")
        path.write_text(
            json.dumps([{"id": "x", "text": "bad", "tag": "fact"}, _note(2, "d.exe", "good")]),
            encoding="utf-8",
        )
        out = session.cmd_notes({})
        self.assertEqual([n["text"] for n in out["notes"]], ["good", "bad"])


class FormatTest(unittest.TestCase):
    def test_the_program_is_named_only_when_several_are_listed(self):
        one = {
            "notes": [_note(1, "a.exe", "first")],
            "count": 1,
            "total": 1,
            "programs": 1,
            "path": "/p/.ghlab/notes",
        }
        self.assertNotIn("a.exe #1", cli.fmt_notes(one))
        two = {
            "notes": [_note(1, "a.exe", "first"), _note(2, "b.exe", "second")],
            "count": 2,
            "total": 2,
            "programs": 2,
            "path": "/p/.ghlab/notes",
        }
        text = cli.fmt_notes(two)
        self.assertIn("a.exe #1", text)
        self.assertIn("across 2 program(s)", text)


class InterfaceTest(unittest.TestCase):
    def test_the_daemon_accepts_notes_without_a_binary(self):
        protocol.validate({"cmd": "notes"})

    def test_the_cli_accepts_notes_without_a_binary(self):
        seen = {}

        def fake_call(_args, cmd, params=None):
            seen["cmd"], seen["params"] = cmd, params
            return 0

        parser = cli.build_parser()
        args = parser.parse_args(["notes", "--tag", "crypto"])
        original = cli._call
        cli._call = fake_call  # type: ignore[assignment]
        try:
            args.func(args)
        finally:
            cli._call = original  # type: ignore[assignment]
        self.assertEqual(seen["cmd"], "notes")
        self.assertIsNone(seen["params"]["binary"])


if __name__ == "__main__":
    unittest.main()
