"""The two caches that outlive a request: decompiled source on disk, programs in memory."""

import os
import pathlib
import tempfile
import unittest
from unittest import mock

from ghlab import session


class FakeDomainFile:
    def __init__(self):
        self.saves = 0

    def save(self, monitor=None):
        self.saves += 1


class FakeProgram:
    def __init__(self, md5: str = "md5-a"):
        self.md5 = md5
        self.released_with = None
        self.domain = FakeDomainFile()

    def getExecutableMD5(self):
        return self.md5

    def release(self, proj):
        self.released_with = proj

    def getCurrentTransactionInfo(self):
        return None

    def getDomainFile(self):
        return self.domain

    def getFunctionManager(self):
        return mock.MagicMock()


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
        program = FakeProgram("md5-a")
        entry = {"program": program}
        session._save(program, "ghlab patch", entry)
        self.assertEqual(program.domain.saves, 1)
        self.assertIsNone(session._cache_read(path))

    def test_a_save_without_an_entry_keeps_the_cache(self):
        path = session._cache_bucket("md5-a") / "k.c"
        session._cache_write(path, "int f(void) { return 0; }\n")
        session._save(FakeProgram("md5-a"), "ghlab rename")
        self.assertEqual(session._cache_read(path), "int f(void) { return 0; }\n")


class DecompileCacheRoundTripTest(unittest.TestCase):
    """`refresh` recomputes; it must still *store* what it computed.

    A refreshed call that skipped the write left the next call decompiling again, so
    "refresh once, then read the cache" never warmed anything (found on a live run:
    the second call reported cached=False).
    """

    class Decomp:
        def __init__(self, code: str):
            self.code = code
            self.calls = 0
            self.disposed = False

        def dispose(self):
            self.disposed = True

        def decompileFunction(self, fn, timeout, monitor):
            self.calls += 1
            code = self.code

            class Result:
                def decompileCompleted(self):
                    return True

                def getErrorMessage(self):
                    return ""

                def getDecompiledFunction(self):
                    inner = type("F", (), {"getC": lambda _self: code})
                    return inner()

            return Result()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(session, "_project_dir", pathlib.Path(self.tmp.name))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.program = FakeProgram()
        self.decomp = self.Decomp("int f(void) { return 1; }")
        entry = {"binary": "a.exe", "program": self.program, "decomp": self.decomp}
        for name, value in (
            ("_entry", lambda *_args: entry),
            ("_function", lambda *_args: mock.MagicMock()),
            ("brief", lambda *_args: {"name": "f", "addr": "140001000"}),
            ("_decomp_cache_key", lambda *_args: "key1"),
        ):
            p = mock.patch.object(session, name, value)
            p.start()
            self.addCleanup(p.stop)

    def _call(self, **extra):
        return session.cmd_decompile({"binary": "a.exe", "target": "140001000", **extra})

    def test_refresh_still_writes_the_cache(self):
        cold = self._call(refresh=True)
        self.assertEqual(cold["results"][0]["cached"], False)
        self.assertEqual(self.decomp.calls, 1)
        bucket = session._cache_bucket(self.program.getExecutableMD5())
        self.assertEqual(len(list(bucket.glob("*.c"))), 1)

    def test_the_call_after_a_refresh_is_cached(self):
        self._call(refresh=True)
        warm = self._call()
        self.assertEqual(warm["results"][0]["cached"], True)
        self.assertEqual(self.decomp.calls, 1)
        self.assertEqual(warm["results"][0]["code"], "int f(void) { return 1; }")


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
