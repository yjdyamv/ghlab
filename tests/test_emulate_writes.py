"""`emulate` write tracking: the scratch block must not be invisible.

Two defects hid every write a function made:

* `_snapshot_writable` capped a block at 1 MB, and wpscore.dll `.data` is 0x169000 —
  so the only writable block in the binary was skipped and every run reported
  `writes 0 byte(s)`;
* the diff skip list was the *whole* scratch block, so even a snapshotted block would
  have had its writes filtered out.
"""

import unittest

from ghlab import session


class Block:
    def __init__(self, start, size, *, write=True, init=True, exec_=False, name=".data"):
        self._start, self._size, self._name = start, size, name
        self._write, self._init, self._exec = write, init, exec_

    def isWrite(self):
        return self._write

    def isInitialized(self):
        return self._init

    def isExecute(self):
        return self._exec

    def getSize(self):
        return self._size

    def getName(self):
        return self._name

    def getStart(self):
        return Addr(self._start)


class Addr:
    def __init__(self, offset):
        self._offset = offset

    def getOffset(self):
        return self._offset


class Memory:
    def __init__(self, blocks):
        self._blocks = blocks

    def getBlocks(self):
        return list(self._blocks)


class Program:
    def __init__(self, blocks):
        self._memory = Memory(blocks)

    def getMemory(self):
        return self._memory

    def getAddressFactory(self):
        return self

    def getDefaultAddressSpace(self):
        return self

    def getAddress(self, offset):
        return Addr(0)


class Emu:
    """Reads zeroes; the snapshot only needs to be able to read the block."""

    def __init__(self, program):
        self._program = program

    def getProgram(self):
        return self._program

    def readMemory(self, addr, size):
        return b"\x00" * size


class SnapshotTest(unittest.TestCase):
    def snapshot(self, *blocks):
        program = Program(blocks)
        return program, session._snapshot_writable(program, Emu(program))

    def test_a_big_data_block_is_snapshotted(self):
        # 0x169000 is wpscore.dll's .data: bigger than the old 1 MB cap
        _, snap = self.snapshot(Block(0x181ED2000, 0x169000))
        self.assertEqual(len(snap), 1)
        self.assertEqual(snap[0][0], 0x181ED2000)
        self.assertEqual(len(snap[0][1]), 0x169000)

    def test_code_and_read_only_blocks_are_skipped(self):
        _, snap = self.snapshot(
            Block(0x180001000, 0x1000, exec_=True, name=".text"),
            Block(0x1818C8000, 0x1000, write=False, name=".rdata"),
            Block(0x181ED2000, 0x2000, init=False, name="bss-ish"),
        )
        self.assertEqual(snap, [])

    def test_the_budget_stops_runaway_snapshots(self):
        blocks = [Block(0x181ED2000 + i * 0x1000000, 0x1000000) for i in range(40)]
        _, snap = self.snapshot(*blocks)
        self.assertLessEqual(sum(len(data) for _, data in snap), 32 << 20)
        self.assertTrue(snap)


class SkipRangeTest(unittest.TestCase):
    """The skip list passed to `_diff_runs` is what decides visibility."""

    def diff(self, skip, old, new):
        baseline = [(0x1000, bytes(old))]
        return session._diff_runs(FakeEmu(new), baseline, skip)

    def test_a_write_outside_the_skip_list_is_reported(self):
        skip = [(0x1000, 0x1004)]
        runs = self.diff(skip, b"\x00" * 16, b"\x00" * 8 + b"\xab" * 4 + b"\x00" * 4)
        self.assertEqual(runs, [(0x1008, b"\xab\xab\xab\xab")])

    def test_a_write_inside_the_skip_list_is_filtered(self):
        skip = [(0x1000, 0x1010)]
        self.assertEqual(self.diff(skip, b"\x00" * 16, b"\xff" * 16), [])


class FakeEmu:
    def __init__(self, data):
        self._data = data

    def getProgram(self):
        return Program([])

    def readMemory(self, addr, size):
        return self._data[:size]


if __name__ == "__main__":
    unittest.main()
