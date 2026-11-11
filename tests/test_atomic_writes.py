"""State files are replaced, never truncated in place.

Notes, the decompile cache and the setup file are all read back as if complete; a
half-written file reads as "no findings" (or as a cache hit) instead of an error.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ghlab import config, session


class AtomicWriteTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_writes_content_and_leaves_no_temp_file(self):
        path = self.dir / "sub" / "notes.json"
        config.atomic_write_text(path, '{"a": 1}\n')
        self.assertEqual(path.read_text(encoding="utf-8"), '{"a": 1}\n')
        self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ["notes.json"])

    def test_a_failed_replace_keeps_the_old_file(self):
        path = self.dir / "notes.json"
        path.write_text("old\n", encoding="utf-8")
        with (
            mock.patch("ghlab.config.os.replace", side_effect=OSError("disk full")),
            self.assertRaises(OSError),
        ):
            config.atomic_write_text(path, "new\n")
        self.assertEqual(path.read_text(encoding="utf-8"), "old\n")
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["notes.json"])

    def test_notes_go_through_the_atomic_writer(self):
        with mock.patch.object(session, "_notes_dir", lambda: self.dir):
            session._store_notes("a.exe", [{"id": 1, "text": "hi"}])
        path = self.dir / "a.exe.json"
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))[0]["text"], "hi")
        self.assertEqual(list(self.dir.glob("*.tmp")), [])

    def test_an_empty_cache_entry_is_not_written(self):
        with mock.patch.object(session, "_cache_dir", lambda: self.dir):
            session._cache_write("deadbeef", "")
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_save_config_round_trips(self):
        cfg = self.dir / "config.json"
        with mock.patch.dict(os.environ, {"GHLAB_CONFIG": str(cfg)}):
            config.save_config({"ghidra": "/opt/ghidra"})
            self.assertEqual(config.load_config()["ghidra"], "/opt/ghidra")
        self.assertEqual(list(self.dir.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
