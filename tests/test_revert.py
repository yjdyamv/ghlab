"""`patch` keeps the bytes it overwrote, and `revert` puts them back.

No Ghidra here: the program is fake, `_write_bytes` is captured instead of run, and
each test gets its own project directory so the patch stack starts empty.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ghlab import session


class FakeAddr:
    def __init__(self, value: int):
        self.value = value

    def add(self, delta: int) -> "FakeAddr":
        return FakeAddr(self.value + delta)

    def __str__(self) -> str:
        return f"0x{self.value:x}"


class FakeMemory:
    def __init__(self, data: bytes):
        self.data = bytearray(data)

    def getByte(self, addr) -> int:
        off = addr.value - 0x1000
        return self.data[off] if 0 <= off < len(self.data) else 0

    def getBlock(self, addr):
        return None


class FakeProgram:
    def __init__(self, data: bytes):
        self.mem = FakeMemory(data)

    def getMemory(self) -> FakeMemory:
        return self.mem


class RevertTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="ghlab-revert-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, ignore_errors=True))
        patcher = mock.patch.object(session, "_project_dir", str(self.dir))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.program = FakeProgram(b"\x48\x8b\x05\x00")
        self.written: list[tuple[int, bytes]] = []
        self.addCleanup(mock.patch.stopall)

    def revert(self, payload: dict) -> dict:
        with (
            mock.patch.object(session, "_entry", lambda _n: {"program": self.program}),
            mock.patch.object(session, "_addr", lambda _e, text: FakeAddr(int(text, 0))),
            mock.patch.object(session, "_save", lambda _p, _m, _e=None: "project.save"),
            mock.patch.object(
                session,
                "_write_bytes",
                lambda _p, addr, data, **_kw: self.written.append((addr.value, data)),
            ),
        ):
            return session.cmd_revert({"binary": "a.exe", **payload})

    def record(self, addr: str, before: str, after: str, binary: str = "a.exe") -> None:
        session._record_patch(
            binary, FakeAddr(int(addr, 0)), bytes.fromhex(before), bytes.fromhex(after)
        )

    def test_a_recorded_patch_is_written_to_the_project(self):
        rec = session._record_patch("a.exe", FakeAddr(0x1000), b"\x48\x8b", b"\x90\x90")
        path = Path(rec["file"])
        self.assertTrue(path.exists())
        self.assertEqual(path.parent, self.dir / ".ghlab" / "patches")
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["before"], "488b")

    def test_revert_restores_the_latest_patch_at_that_address(self):
        self.record("0x1000", "488b0500", "90909000")
        self.program.mem.data[:] = b"\x90\x90\x90\x00"
        out = self.revert({"addr": "0x1000"})
        self.assertEqual(self.written, [(0x1000, b"\x48\x8b\x05\x00")])
        self.assertEqual(out["reverted"][0]["was"], "90909000")
        self.assertEqual(out["remaining"], 0)

    def test_a_second_revert_unwinds_the_earlier_patch(self):
        self.record("0x1000", "488b0500", "90909000")
        self.record("0x1000", "90909000", "cccccccc")
        self.program.mem.data[:] = b"\xcc\xcc\xcc\xcc"
        self.revert({"addr": "0x1000"})
        self.program.mem.data[:] = b"\x90\x90\x90\x00"
        out = self.revert({"addr": "0x1000"})
        self.assertEqual([w[1] for w in self.written], [b"\x90\x90\x90\x00", b"\x48\x8b\x05\x00"])
        self.assertEqual(out["remaining"], 0)

    def test_all_unwinds_newest_first(self):
        self.record("0x1000", "488b0500", "90909000")
        self.record("0x1004", "0000", "cccc")
        self.program.mem.data[:] = b"\x90\x90\x90\x00\xcc\xcc"
        out = self.revert({"all": True})
        self.assertEqual([w[0] for w in self.written], [0x1004, 0x1000])
        self.assertEqual(len(out["reverted"]), 2)

    def test_bytes_changed_since_the_patch_are_refused(self):
        self.record("0x1000", "488b0500", "90909000")
        self.program.mem.data[:] = b"\x11\x22\x33\x44"
        with self.assertRaises(ValueError) as ctx:
            self.revert({"addr": "0x1000"})
        self.assertIn("changed since the patch", str(ctx.exception))
        self.assertEqual(self.written, [])

    def test_force_overwrites_anyway(self):
        self.record("0x1000", "488b0500", "90909000")
        self.program.mem.data[:] = b"\x11\x22\x33\x44"
        self.revert({"addr": "0x1000", "force": True})
        self.assertEqual(self.written, [(0x1000, b"\x48\x8b\x05\x00")])

    def test_another_binarys_records_are_invisible(self):
        self.record("0x1000", "488b0500", "90909000", binary="other.exe")
        with self.assertRaises(ValueError) as ctx:
            self.revert({"addr": "0x1000"})
        self.assertIn("no recorded patch", str(ctx.exception))

    def test_neither_addr_nor_all_is_an_error(self):
        with self.assertRaises(ValueError) as ctx:
            self.revert({})
        self.assertIn("addr=<address> or all=yes", str(ctx.exception))

    def test_a_huge_patch_is_recorded_without_its_bytes(self):
        big = bytes(session.MAX_RECORDED_PATCH + 1)
        rec = session._record_patch("a.exe", FakeAddr(0x1000), big, big)
        self.assertFalse(rec["reversible"])
        with self.assertRaises(ValueError) as ctx:
            self.revert({"addr": "0x1000"})
        self.assertIn("cannot be reverted", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
