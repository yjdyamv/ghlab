"""Error messages that say what is wrong with an argument, not which line broke.

`limit=all` used to reach `int()` and come back as `invalid literal for int() with base
10: 'all'`; `binary=C:\\re\\notepad.exe` used to be "not found".  Both cost the same
minute every time: the caller has to guess what the daemon wanted.
"""

from __future__ import annotations

import unittest
from unittest import mock

from ghlab import protocol, session


class NumTest(unittest.TestCase):
    def test_a_digit_string_is_accepted(self):
        self.assertEqual(session._num({"limit": "12"}, "limit", 5), 12)

    def test_the_default_is_used_when_absent(self):
        self.assertEqual(session._num({}, "limit", 5), 5)

    def test_a_word_names_the_argument(self):
        with self.assertRaises(ValueError) as ctx:
            session._num({"limit": "all"}, "limit", 5)
        self.assertEqual(str(ctx.exception), "limit must be a number, got 'all'")

    def test_a_boolean_is_refused_rather_than_becoming_one(self):
        with self.assertRaises(ValueError) as ctx:
            session._num({"limit": True}, "limit", 5)
        self.assertIn("got True", str(ctx.exception))

    def test_a_minimum_is_enforced(self):
        with self.assertRaises(ValueError) as ctx:
            session._num({"window": 0}, "window", 32, minimum=1)
        self.assertEqual(str(ctx.exception), "window must be >= 1, got 0")


class BinaryHintTest(unittest.TestCase):
    def test_an_empty_project_says_how_to_fill_it(self):
        self.assertIn("ghlab import", session._binary_hint("a.exe", []))

    def test_a_path_says_programs_are_named_by_file_name(self):
        hint = session._binary_hint("C:\\re\\samples\\notepad.exe", ["notepad.exe", "x.exe"])
        self.assertIn("looks like a path", hint)
        self.assertIn("2 available", hint)

    def test_a_typo_is_guessed(self):
        self.assertEqual(
            session._binary_hint("notpad.exe", ["notepad.exe", "cmd.exe"]),
            "did you mean notepad.exe?",
        )

    def test_a_far_off_name_lists_what_is_there(self):
        names = [f"sample{i}.exe" for i in range(20)]
        hint = session._binary_hint("zzz.exe", names)
        self.assertIn("project has sample0.exe", hint)
        self.assertIn("...", hint)  # 12 shown, the rest elided

    def test_entry_separates_not_found_from_ambiguous(self):
        with mock.patch.object(session, "binary_names", return_value=["a.exe", "b.exe"]):
            with self.assertRaises(KeyError) as ctx:
                session._entry("zzz.exe")
            self.assertIn("not found: ", str(ctx.exception))
            self.assertIn("did you mean", str(ctx.exception))

            with self.assertRaises(KeyError) as ctx:
                session._entry(".exe")
            self.assertIn("matches 2 programs", str(ctx.exception))
            self.assertIn("name one exactly", str(ctx.exception))


class ProtocolSuggestionTest(unittest.TestCase):
    def test_a_typo_in_a_command_is_guessed(self):
        with self.assertRaises(protocol.ProtocolError) as ctx:
            protocol.validate({"cmd": "decompil", "binary": "a.exe"})
        self.assertIn("did you mean decompile?", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
