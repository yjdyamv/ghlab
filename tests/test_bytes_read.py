"""`bytes` reads a region in one call, clamps to the block, and caps the answer.

No Ghidra here: `_read_region` is driven through a fake memory object and the one
jpype touchpoint (`_zero_bytes`) is swapped for a bytearray.
"""

import unittest
from pathlib import Path
from unittest import mock

from ghlab import session


class FakeAddr:
    def __init__(self, value: int):
        self.value = value

    def subtract(self, other: "FakeAddr") -> int:
        return self.value - other.value

    def __str__(self) -> str:
        return f"0x{self.value:x}"


class FakeBlock:
    def __init__(self, start: int, end: int, initialized: bool = True):
        self.start, self.end, self.initialized = start, end, initialized

    def getEnd(self) -> FakeAddr:
        return FakeAddr(self.end)

    def isInitialized(self) -> bool:
        return self.initialized


class FakeMemory:
    """The slice of Ghidra's `Memory` that `_read_region` touches."""

    def __init__(self, start: int, data: bytes, initialized: bool = True):
        self.start = start
        self.data = data
        self.block = FakeBlock(start, start + len(data) - 1, initialized)

    def getBlock(self, addr: FakeAddr):
        return self.block if self.start <= addr.value <= self.block.end else None

    def getBytes(self, addr: FakeAddr, buf) -> int:
        chunk = self.data[addr.value - self.start :]
        n = min(len(buf), len(chunk))
        for i in range(n):
            buf[i] = chunk[i]
        return n


class FakeProgram:
    def __init__(self, mem: FakeMemory):
        self.mem = mem

    def getMemory(self) -> FakeMemory:
        return self.mem


class ReadRegionTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(session, "_zero_bytes", bytearray)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_reads_the_requested_bytes(self):
        mem = FakeMemory(0x1000, b"\x48\x8b\x05\x90")
        data, truncated = session._read_region(mem, FakeAddr(0x1000), 4)
        self.assertEqual(data, b"\x48\x8b\x05\x90")
        self.assertFalse(truncated)

    def test_stops_at_the_end_of_the_block(self):
        mem = FakeMemory(0x1000, b"\x90" * 4)
        data, truncated = session._read_region(mem, FakeAddr(0x1000), 16)
        self.assertEqual(len(data), 4)
        self.assertTrue(truncated)

    def test_mid_block_start_only_gets_the_tail(self):
        mem = FakeMemory(0x1000, b"\x90" * 16)
        data, truncated = session._read_region(mem, FakeAddr(0x1008), 16)
        self.assertEqual(len(data), 8)
        self.assertTrue(truncated)

    def test_refuses_an_uninitialized_block(self):
        mem = FakeMemory(0x1000, b"\x90", initialized=False)
        with self.assertRaises(ValueError):
            session._read_region(mem, FakeAddr(0x1000), 8)

    def test_refuses_an_address_outside_the_blocks(self):
        mem = FakeMemory(0x1000, b"\x90")
        with self.assertRaises(ValueError):
            session._read_region(mem, FakeAddr(0x9000), 1)


class BytesCommandTest(unittest.TestCase):
    def run_cmd(self, mem: FakeMemory, size: int) -> dict:
        program = FakeProgram(mem)
        with (
            mock.patch.object(session, "_zero_bytes", bytearray),
            mock.patch.object(session, "_entry", lambda _name: {"program": program}),
            mock.patch.object(session, "_addr", lambda _entry, _text: FakeAddr(0x1000)),
        ):
            return session.cmd_bytes({"binary": "x.exe", "addr": "0x1000", "size": size})

    def test_a_short_read_is_reported_with_its_size(self):
        out = self.run_cmd(FakeMemory(0x1000, b"AB"), 8)
        self.assertEqual(out["hex"], "4142")
        self.assertEqual(out["ascii"], "AB")
        self.assertEqual(out["size"], 2)
        self.assertTrue(out["truncated"])

    def test_a_request_beyond_the_cap_is_capped_and_flagged(self):
        mem = FakeMemory(0x1000, b"\x90" * (session.MAX_BYTES + 1000))
        out = self.run_cmd(mem, session.MAX_BYTES + 1000)
        self.assertEqual(out["size"], session.MAX_BYTES)
        self.assertEqual(len(out["hex"]), session.MAX_BYTES * 2)
        self.assertTrue(out["truncated"])

    def test_zero_size_is_rejected(self):
        with self.assertRaises(ValueError):
            self.run_cmd(FakeMemory(0x1000, b"\x90"), 0)

    def test_the_sink_allocator_does_not_shadow_the_bytes_helper(self):
        # Two module-level `_byte_array` definitions: the later one wins, so a sink
        # allocator with the same name turned every real `bytes` call into a
        # TypeError (len() of an int) that the mocked tests above could not see.
        src = Path(session.__file__).read_text(encoding="utf-8")
        self.assertEqual(src.count("def _byte_array("), 1)
        self.assertEqual(src.count("def _zero_bytes("), 1)


if __name__ == "__main__":
    unittest.main()
