"""`scan --hex` walks memory with a byte mask and reports where the pattern lives.

No Ghidra here: the pattern/limit/clamping logic runs against fake memory blocks,
and the two jpype touchpoints are swapped for plain Python objects.
"""

import unittest
from unittest import mock

from ghlab import session


class FakeAddr:
    def __init__(self, value: int):
        self.value = value

    def compareTo(self, other) -> int:
        return (self.value > other.value) - (self.value < other.value)

    def add(self, delta: int) -> "FakeAddr":
        return FakeAddr(self.value + delta)

    def subtract(self, other) -> int:
        return self.value - other.value

    def __str__(self) -> str:
        return f"0x{self.value:x}"


class FakeBlock:
    def __init__(self, name: str, start: int, data: bytes, initialized: bool = True):
        self.name = name
        self.start = start
        self.data = data
        self.initialized = initialized

    def getName(self) -> str:
        return self.name

    def getStart(self) -> FakeAddr:
        return FakeAddr(self.start)

    def getEnd(self) -> FakeAddr:
        return FakeAddr(self.start + len(self.data) - 1)

    def isInitialized(self) -> bool:
        return self.initialized


class FakeMemory:
    def __init__(self, *blocks: FakeBlock):
        self.blocks = list(blocks)

    def getBlocks(self) -> list:
        return self.blocks

    def getBlock(self, addr):
        for block in self.blocks:
            if block.start <= addr.value <= block.start + len(block.data) - 1:
                return block
        return None

    def getBytes(self, addr, buf) -> int:
        block = self.getBlock(addr)
        if block is None:
            return 0
        off = addr.value - block.start
        data = block.data[off : off + len(buf)]
        for i, value in enumerate(data):
            buf[i] = value
        return len(data)

    def findBytes(self, addr, needles, mask, forward, monitor):
        block = self.getBlock(addr)
        if block is None:
            return None
        needles, mask = bytes(needles), bytes(mask)
        width = len(needles)
        for i in range(addr.value - block.start, len(block.data) - width + 1):
            if all((block.data[i + j] & mask[j]) == (needles[j] & mask[j]) for j in range(width)):
                return FakeAddr(block.start + i)
        return None


class FakeFunction:
    def __init__(self, name: str):
        self.name = name

    def getName(self) -> str:
        return self.name


class FakeFunctionManager:
    def __init__(self, owner: "FakeProgram"):
        self.owner = owner

    def getFunctionContaining(self, addr):
        return self.owner.functions.get(addr.value)


class FakeProgram:
    def __init__(self, mem: FakeMemory, functions: dict | None = None):
        self.mem = mem
        self.functions = functions or {}

    def getMemory(self) -> FakeMemory:
        return self.mem

    def getFunctionManager(self) -> FakeFunctionManager:
        return FakeFunctionManager(self)


class PatternParseTest(unittest.TestCase):
    def test_spaces_and_commas_are_ignored(self):
        self.assertEqual(
            session._parse_hex_pattern("48 8B,05"),
            (b"\x48\x8b\x05", b"\xff\xff\xff"),
        )

    def test_wildcards_become_zero_masks(self):
        self.assertEqual(
            session._parse_hex_pattern("48??05"),
            (b"\x48\x00\x05", b"\xff\x00\xff"),
        )

    def test_an_odd_number_of_digits_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            session._parse_hex_pattern("488")
        self.assertIn("odd number", str(ctx.exception))

    def test_a_half_byte_wildcard_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            session._parse_hex_pattern("4?")
        self.assertIn("whole-byte", str(ctx.exception))

    def test_an_all_wildcard_pattern_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            session._parse_hex_pattern("?? ??")
        self.assertIn("no fixed byte", str(ctx.exception))

    def test_an_empty_pattern_is_rejected(self):
        with self.assertRaises(ValueError):
            session._parse_hex_pattern("   ")


class ScanBytesTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(session, "_byte_array", bytes)
        patcher.start()
        self.addCleanup(patcher.stop)
        sink = mock.patch.object(session, "_zero_bytes", bytearray)
        sink.start()
        self.addCleanup(sink.stop)

    def scan(self, mem: FakeMemory, hex_spec: str, limit: int = 10, **kwargs):
        program = FakeProgram(mem, kwargs.pop("functions", None))
        return session._scan_bytes(
            "x.exe",
            program,
            hex_spec,
            kwargs.pop("start", None),
            kwargs.pop("end", None),
            limit,
            0.0,
        )

    def test_every_occurrence_is_reported(self):
        mem = FakeMemory(FakeBlock(".text", 0x1000, b"\x90\x48\x8b\x00\x05\x90\x48\x8b\x11\x05"))
        out = self.scan(mem, "48 8B ?? 05")
        self.assertEqual([m["addr"] for m in out["matches"]], ["0x1001", "0x1006"])
        self.assertEqual(out["matches"][0]["bytes"], "488b0005")
        self.assertEqual(out["matches"][1]["pattern"], "488b??05")
        self.assertFalse(out["truncated"])

    def test_the_limit_stops_the_sweep(self):
        mem = FakeMemory(FakeBlock(".text", 0x1000, b"\x90" * 10))
        out = self.scan(mem, "90", limit=3)
        self.assertEqual(len(out["matches"]), 3)
        self.assertTrue(out["truncated"])

    def test_uninitialized_blocks_are_skipped(self):
        mem = FakeMemory(
            FakeBlock(".bss", 0x2000, b"\x48\x8b\x05", initialized=False),
            FakeBlock(".text", 0x1000, b"\x48\x8b\x05"),
        )
        out = self.scan(mem, "488B05")
        self.assertEqual([m["addr"] for m in out["matches"]], ["0x1000"])
        self.assertEqual(out["blocks_scanned"], 1)

    def test_a_range_clips_the_sweep(self):
        mem = FakeMemory(FakeBlock(".text", 0x1000, b"\x90\x48\x8b\x05\x00\x48\x8b\x05"))
        out = self.scan(mem, "488B05", start=FakeAddr(0x1002), end=FakeAddr(0x1006))
        self.assertEqual([m["addr"] for m in out["matches"]], ["0x1005"])

    def test_matches_name_their_block_and_function(self):
        mem = FakeMemory(FakeBlock(".text", 0x1000, b"\x48\x8b\x05"))
        out = self.scan(mem, "488B05", functions={0x1000: FakeFunction("decrypt_string")})
        self.assertEqual(out["matches"][0]["block"], ".text")
        self.assertEqual(out["matches"][0]["function"], "decrypt_string")

    def test_a_pattern_that_is_absent_returns_no_matches(self):
        out = self.scan(FakeMemory(FakeBlock(".text", 0x1000, b"\x90\x90")), "DEADBEEF")
        self.assertEqual(out["matches"], [])
        self.assertFalse(out["truncated"])


class CmdScanTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(session, "_byte_array", bytes)
        patcher.start()
        self.addCleanup(patcher.stop)
        sink = mock.patch.object(session, "_zero_bytes", bytearray)
        sink.start()
        self.addCleanup(sink.stop)

    def run_cmd(self, payload: dict, program: FakeProgram) -> dict:
        with mock.patch.object(session, "_entry", lambda _name: {"program": program}):
            return session.cmd_scan(payload)

    def test_hex_dispatches_to_the_byte_search(self):
        program = FakeProgram(FakeMemory(FakeBlock(".text", 0x1000, b"\x48\x8b\x05")))
        out = self.run_cmd({"binary": "x.exe", "hex": "48 8B 05"}, program)
        self.assertEqual(len(out["matches"]), 1)
        self.assertEqual(out["hex"], "48 8B 05")

    def test_neither_offset_nor_hex_is_an_error(self):
        program = FakeProgram(FakeMemory(FakeBlock(".text", 0x1000, b"\x90")))
        with self.assertRaises(ValueError) as ctx:
            self.run_cmd({"binary": "x.exe"}, program)
        self.assertIn("offset=<n>", str(ctx.exception))

    def test_a_bad_pattern_is_rejected_before_touching_memory(self):
        program = FakeProgram(FakeMemory(FakeBlock(".text", 0x1000, b"\x90")))
        with self.assertRaises(ValueError):
            self.run_cmd({"binary": "x.exe", "hex": "488"}, program)

    def test_an_unknown_function_name_is_a_key_error(self):
        program = FakeProgram(FakeMemory(FakeBlock(".text", 0x1000, b"\x48\x8b\x05")))
        with (
            mock.patch.object(session, "_entry", lambda _name: {"program": program}),
            mock.patch.object(session, "_function", lambda _e, _name: None),
            mock.patch.object(session, "_function_suggestions", lambda *_args, **_kw: ""),
            self.assertRaises(KeyError) as ctx,
        ):
            session.cmd_scan({"binary": "x.exe", "hex": "488B05", "func": "nope"})
        self.assertIn("no function", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
