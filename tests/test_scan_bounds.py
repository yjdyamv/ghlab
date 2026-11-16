"""A `--range` that misses every memory block must fail loudly, not scan nothing.

`ghlab scan wpscore.dll 0x44 --range 0x18129000-0x18130000` answered
"0 instruction(s) scanned" -- confidently, and wrongly: the image is based at
0x180000000, so `0x18129000` is one hex digit short of the page code at
0x181292ce0 and lies outside every block. Ghidra's `getInstructionAfter` then
degrades to the program's first instruction, the sweep walks unrelated code and
finds nothing in the requested range.
"""

from __future__ import annotations

import unittest

from ghlab import session


class _FakeAddress:
    def __init__(self, value: int):
        self.value = value

    def getOffset(self) -> int:
        return self.value

    def __str__(self) -> str:
        return f"{self.value:x}"


class _FakeBlock:
    def __init__(self, name: str, start: int, end: int):
        self._name = name
        self._start = start
        self._end = end

    def getName(self) -> str:
        return self._name

    def getStart(self) -> _FakeAddress:
        return _FakeAddress(self._start)

    def getEnd(self) -> _FakeAddress:
        return _FakeAddress(self._end)


class _FakeMemory:
    def __init__(self, blocks):
        self._blocks = blocks

    def getBlocks(self):
        return list(self._blocks)

    def getBlock(self, addr):
        value = addr.getOffset()
        for block in self._blocks:
            if block.getStart().getOffset() <= value <= block.getEnd().getOffset():
                return block
        return None


class _FakeProgram:
    def __init__(self, blocks):
        self._memory = _FakeMemory(blocks)

    def getMemory(self):
        return self._memory


IMAGE = _FakeProgram([_FakeBlock(".text", 0x180001000, 0x1818C7FFF)])


class CheckInMemoryTest(unittest.TestCase):
    def test_address_inside_a_block_passes(self):
        session._check_in_memory(IMAGE, _FakeAddress(0x181292CE0), "range start")

    def test_address_outside_every_block_is_an_error(self):
        with self.assertRaises(ValueError) as caught:
            session._check_in_memory(IMAGE, _FakeAddress(0x18129000), "range start")
        message = str(caught.exception)
        self.assertIn("not inside any memory block", message)
        # The block table is what tells the caller the address wants a digit.
        self.assertIn(".text 180001000-1818c7fff", message)
        self.assertIn("range start", message)


if __name__ == "__main__":
    unittest.main()
