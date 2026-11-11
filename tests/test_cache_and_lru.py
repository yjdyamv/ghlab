"""The two caches that outlive a request: decompiled source on disk, programs in memory."""

import os
import pathlib
import tempfile
import unittest
from unittest import mock

from ghlab import session


class FakeProgram:
    def __init__(self, md5: str = "md5-a"):
        self.md5 = md5
        self.released_with = None

    def getExecutableMD5(self):
        return self.md5

    def release(self, proj):
        self.released_with = proj


class FakeDecomp:
    def __init__(self):
        self.disposed = False

    def dispose(self):
        self.disposed = True


class CacheBucketTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(session, "_project_dir", pathlib.Path(self.tmp.name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_entries_live_in_a_bucket_named_after_the_program(self):
        path = session._cache_bucket("abc123") / "key.c"
        session._cache_write(path, "int f(void) { return 0; }\n")
        self.assertEqual(session._cache_read(path), "int f(void) { return 0; }\n")
        self.assertEqual(path.parts[-3:-1], ("cache", "abc123"))

    def test_purge_drops_one_program_and_leaves_the_others(self):
        keep = session._cache_bucket("other") / "k.c"
        drop = session._cache_bucket("md5-a") / "k.c"
        session._cache_write(keep, "int g(void) { return 1; }\n")
        session._cache_write(drop, "int f(void) { return 0; }\n")
        self.assertEqual(session._cache_purge({"program": FakeProgram("md5-a")}), 1)
        self.assertIsNone(session._cache_read(drop))
        self.assertEqual(session._cache_read(keep), "int g(void) { return 1; }\n")

    def test_purge_of_a_program_that_was_never_read_is_a_no_op(self):
        self.assertEqual(session._cache_purge({"program": FakeProgram("nope")}), 0)

    def test_a_save_that_changes_code_drops_that_programs_cache(self):
        # The key is md5 + prototype + comments, so patched bytes keep hitting the
        # old entry: the write has to say so, not hope someone passes --refresh.
        path = session._cache_bucket("md5-a") / "k.c"
        session._cache_write(path, "int f(void) { return 0; }\n")
        entry = {"program": FakeProgram("md5-a")}
        with mock.patch.object(session, "project") as proj:
            session._save(entry["program"], "ghlab patch", entry)
        proj.return_value.save.assert_called_once()
        self.assertIsNone(session._cache_read(path))

    def test_a_save_without_an_entry_keeps_the_cache(self):
        path = session._cache_bucket("md5-a") / "k.c"
        session._cache_write(path, "int f(void) { return 0; }\n")
        with mock.patch.object(session, "project"):
            session._save(FakeProgram("md5-a"), "ghlab rename")
        self.assertEqual(session._cache_read(path), "int f(void) { return 0; }\n")


class LruTest(unittest.TestCase):
    def setUp(self):
        session._programs.clear()
        session._FP_CACHE.clear()
        self.addCleanup(session._programs.clear)
        self.addCleanup(session._FP_CACHE.clear)

    def _add(self, name: str, used: float) -> dict:
        entry = {
            "binary": name,
            "proj": "proj",
            "program": FakeProgram(),
            "decomp": FakeDecomp(),
            "used": used,
        }
        session._programs[name] = entry
        return entry

    def test_the_least_recently_used_program_is_closed(self):
        # Every open program holds its symbol index and decompiler for the life of
        # the daemon, so a session that touched ten binaries holds ten.
        a = self._add("a.exe", 1.0)
        self._add("b.exe", 2.0)
        self._add("c.exe", 3.0)
        session._FP_CACHE[("a.exe", "m", 0)] = {"rows": 1}
        session._FP_CACHE[("c.exe", "m", 0)] = {"rows": 1}
        with mock.patch.dict(os.environ, {"GHLAB_MAX_OPEN_PROGRAMS": "2"}):
            session._evict_lru(keep="c.exe")
        self.assertEqual(sorted(session._programs), ["b.exe", "c.exe"])
        self.assertEqual(a["program"].released_with, "proj")
        self.assertTrue(a["decomp"].disposed)
        self.assertEqual(list(session._FP_CACHE), [("c.exe", "m", 0)])

    def test_the_program_being_asked_for_is_never_evicted(self):
        self._add("a.exe", 1.0)
        self._add("b.exe", 2.0)
        z = self._add("z.exe", 0.5)  # oldest, but it is the one being opened
        with mock.patch.dict(os.environ, {"GHLAB_MAX_OPEN_PROGRAMS": "1"}):
            session._evict_lru(keep="z.exe")
        self.assertEqual(sorted(session._programs), ["z.exe"])
        self.assertIs(session._programs["z.exe"], z)

    def test_a_nonsense_cap_still_keeps_one_program(self):
        self._add("a.exe", 1.0)
        self._add("b.exe", 2.0)
        with mock.patch.dict(os.environ, {"GHLAB_MAX_OPEN_PROGRAMS": "0"}):
            session._evict_lru(keep="b.exe")
        self.assertEqual(sorted(session._programs), ["b.exe"])

    def test_a_released_program_that_refuses_to_close_does_not_stop_eviction(self):
        class Stubborn(FakeProgram):
            def release(self, proj):
                raise RuntimeError("already closed")

        self._add("a.exe", 1.0)
        session._programs["a.exe"]["program"] = Stubborn()
        self._add("b.exe", 2.0)
        with mock.patch.dict(os.environ, {"GHLAB_MAX_OPEN_PROGRAMS": "1"}):
            session._evict_lru(keep="b.exe")
        self.assertEqual(sorted(session._programs), ["b.exe"])


if __name__ == "__main__":
    unittest.main()
