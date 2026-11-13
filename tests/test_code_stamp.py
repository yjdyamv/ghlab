"""The stamp says which code the *process* is running, not which code is on disk."""

from __future__ import annotations

import unittest
from unittest import mock

from ghlab import session


class CodeStampTest(unittest.TestCase):
    def test_it_is_computed_once(self):
        # a daemon that recomputed per call would always look current
        session.code_stamp(refresh=True)
        with mock.patch.object(session.hashlib, "md5", wraps=session.hashlib.md5) as md5:
            first = session.code_stamp()
            calls = md5.call_count
            self.assertEqual(session.code_stamp(), first)
            self.assertEqual(md5.call_count, calls)
            session.code_stamp(refresh=True)
            self.assertEqual(md5.call_count, calls + 1)

    def test_it_is_twelve_hex_characters(self):
        stamp = session.code_stamp(refresh=True)
        self.assertEqual(len(stamp), 12)
        self.assertTrue(all(c in "0123456789abcdef" for c in stamp))


if __name__ == "__main__":
    unittest.main()
