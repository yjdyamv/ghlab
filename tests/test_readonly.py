"""GHLAB_READONLY: questions yes, changes no."""

from __future__ import annotations

import json
import os
import unittest
from unittest import mock

from ghlab import server, session


class ReadonlyTest(unittest.TestCase):
    def setUp(self):
        self.calls: list[dict] = []
        patches = mock.patch.dict(
            session.HANDLERS,
            {
                "patch": self._stub,
                "digest": self._stub,
            },
            clear=False,
        )
        patches.start()
        self.addCleanup(patches.stop)
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("GHLAB_READONLY", None)

    def _stub(self, params):
        self.calls.append(params)
        return {"changed": True}

    def test_a_change_is_refused_before_anything_runs(self):
        with (
            mock.patch.dict(os.environ, {"GHLAB_READONLY": "1"}),
            self.assertRaises(PermissionError) as ctx,
        ):
            session.dispatch("patch", {"binary": "a.exe", "bytes": "90"})
        self.assertIn("read-only", str(ctx.exception))
        self.assertEqual(self.calls, [], "the handler must not have been reached")

    def test_a_question_still_answers(self):
        with mock.patch.dict(os.environ, {"GHLAB_READONLY": "1"}):
            self.assertEqual(session.dispatch("digest", {}), {"changed": True})
        self.assertEqual(len(self.calls), 1)

    def test_off_by_default_and_falsy_spellings(self):
        self.assertFalse(session.readonly())
        for value in ("", "0", "no", "false", " FALSE "):
            with self.subTest(value=value), mock.patch.dict(os.environ, {"GHLAB_READONLY": value}):
                self.assertFalse(session.readonly())

    def test_changes_run_when_the_switch_is_off(self):
        self.assertEqual(session.dispatch("patch", {"binary": "a.exe"}), {"changed": True})
        self.assertEqual(len(self.calls), 1)

    def test_the_switch_is_read_per_call(self):
        session.dispatch("patch", {"binary": "a.exe"})
        with (
            mock.patch.dict(os.environ, {"GHLAB_READONLY": "1"}),
            self.assertRaises(PermissionError),
        ):
            session.dispatch("patch", {"binary": "a.exe"})
        self.assertEqual(len(self.calls), 1)

    def test_notes_are_left_alone(self):
        with (
            mock.patch.dict(os.environ, {"GHLAB_READONLY": "1"}),
            mock.patch.object(session.config, "atomic_write_text") as written,
        ):
            session._store_notes("a.exe", [{"id": 1}])
        written.assert_not_called()

    def test_note_refuses_instead_of_dropping_the_finding(self):
        # found on a real run: `note` "succeeded" under GHLAB_READONLY and the finding
        # was never stored, because _store_notes returns early
        with (
            mock.patch.dict(os.environ, {"GHLAB_READONLY": "1"}),
            self.assertRaises(PermissionError) as ctx,
        ):
            session.cmd_note({"binary": "a.exe", "text": "main calls sprintf"})
        self.assertIn("read-only", str(ctx.exception))
        self.assertIn("note", str(ctx.exception))

    def test_the_daemon_page_advertises_it(self):
        with mock.patch.dict(os.environ, {"GHLAB_READONLY": "1"}):
            body = json.loads(server._info_body())
        self.assertTrue(body["readonly"])

    def test_the_daemon_page_says_nothing_when_writable(self):
        self.assertFalse(json.loads(server._info_body())["readonly"])

    def test_the_help_page_says_which_project_it_serves(self):
        # `ghlab projects` compares this with the config, so a --url override shows
        # the directory the daemon really has open instead of the config path
        body = json.loads(server._info_body())
        self.assertIn("project", body)
        self.assertEqual(body["project"], session.project_location())


if __name__ == "__main__":
    unittest.main()
