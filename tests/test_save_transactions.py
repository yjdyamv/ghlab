"""Saving a program, and the transaction stack Ghidra keeps behind it.

`GhidraProject.openProgram` starts a transaction named "Batch Processing" and records
its id; `GhidraProject.save` ends that id, saves, and only then records a fresh one.
A single failed save therefore leaves the record pointing at a finished transaction,
after which every save on that program fails ("Attempted to end Transaction more than
once", then "Unable to lock due to active transaction") until the daemon restarts --
a real run showed a program wedged for the life of the process.

`_entry` now opens through `DomainFile.getDomainObject`, so no such transaction
exists in the first place, and `_save` has exactly one way in: end what we left on
the stack, save the domain file.  If that still fails twice, the program is dropped
from the cache so the next request reopens it from disk.
"""

import unittest
from unittest import mock

from ghlab import session


class FakeTransaction:
    def __init__(self, tid: int, description: str):
        self._id = tid
        self._description = description

    def getID(self):
        return self._id

    def getDescription(self):
        return self._description


class FakeDomainFile:
    def __init__(self, fail_times: int = 0):
        self.saves = 0
        self.fail_times = fail_times

    def save(self, monitor=None):
        self.saves += 1
        if self.saves <= self.fail_times:
            raise OSError("Unable to lock due to active transaction")


class FakeProgram:
    """Just enough Program for the transaction and save paths."""

    def __init__(self, transactions=(), fail_times: int = 0, stale: FakeTransaction | None = None):
        self.stack = list(transactions)
        self.stale = stale
        self.ended: list[int] = []
        self.domain = FakeDomainFile(fail_times)
        self.program_saves = 0

    def getCurrentTransactionInfo(self):
        if self.stack:
            return self.stack[-1]
        return self.stale

    def endTransaction(self, tid: int, commit: bool = True):
        if not self.stack or int(self.stack[-1].getID()) != int(tid):
            # what Ghidra says when the id is already finished or not on top
            raise RuntimeError(f"Attempted to end Transaction more than once: {tid}")
        self.ended.append(int(tid))
        self.stack.pop()
        return True

    def getDomainFile(self):
        return self.domain

    def save(self, message, monitor=None):
        self.program_saves += 1
        raise OSError("Unable to lock due to active transaction")


class EndOpenTransactionsTest(unittest.TestCase):
    def test_a_live_transaction_is_ended(self):
        program = FakeProgram([FakeTransaction(78, "Batch Processing")])
        self.assertEqual(session._end_open_transactions(program), 1)
        self.assertEqual(program.ended, [78])

    def test_nothing_open_is_a_no_op(self):
        self.assertEqual(session._end_open_transactions(FakeProgram()), 0)

    def test_a_stale_handle_stops_the_loop(self):
        stale = FakeTransaction(78, "Batch Processing")
        program = FakeProgram(stale=stale)
        self.assertEqual(session._end_open_transactions(program), 0)

    def test_nested_leftovers_are_all_ended(self):
        program = FakeProgram([FakeTransaction(1, "a"), FakeTransaction(2, "b")])
        self.assertEqual(session._end_open_transactions(program), 2)
        self.assertEqual(program.ended, [2, 1])

    def test_the_door_is_closed_after_a_few(self):
        # a program that keeps reporting a *live* transaction must not spin forever
        class Endless(FakeProgram):
            def endTransaction(self, tid, commit=True):
                self.ended.append(int(tid))
                return True

        program = Endless([FakeTransaction(1, "a")])
        self.assertEqual(session._end_open_transactions(program), 4)


class SaveTest(unittest.TestCase):
    def _no_project(self):
        # nothing in this path may reach GhidraProject: its bookkeeping is the bug
        proj = mock.MagicMock()
        proj.save.side_effect = AssertionError("GhidraProject.save must not be used")
        patcher = mock.patch.object(session, "project", return_value=proj)
        patcher.start()
        self.addCleanup(patcher.stop)
        return proj

    def test_the_domain_file_is_the_only_way_in(self):
        proj = self._no_project()
        program = FakeProgram([FakeTransaction(2, "Batch Processing")])
        self.assertEqual(session._save(program, "ghlab rename"), "domain.save(monitor)")
        self.assertEqual(program.domain.saves, 1)
        self.assertEqual(program.ended, [2])
        self.assertEqual(proj.save.call_count, 0)

    def test_a_transient_lock_is_retried(self):
        self._no_project()
        program = FakeProgram(fail_times=1)
        with mock.patch.object(session.time, "sleep", lambda *_: None):
            self.assertEqual(session._save(program, "ghlab rename"), "domain.save(monitor)")
        self.assertEqual(program.domain.saves, 2)

    def test_a_permanent_failure_names_the_transaction(self):
        self._no_project()
        program = FakeProgram(fail_times=99, stale=FakeTransaction(78, "Batch Processing"))
        with (
            mock.patch.object(session.time, "sleep", lambda *_: None),
            self.assertRaises(RuntimeError) as ctx,
        ):
            session._save(program, "ghlab patch")
        self.assertIn("cannot save program for 'ghlab patch'", str(ctx.exception))
        self.assertIn("id=78 Batch Processing", str(ctx.exception))
        self.assertEqual(program.domain.saves, 2)

    def test_a_program_that_cannot_be_saved_leaves_the_cache(self):
        # the stale bookkeeping lives in Ghidra's private map, so "reopen from disk"
        # is the only repair: the next command must not inherit the wedged object
        self._no_project()
        program = FakeProgram(fail_times=99)
        released: list[object] = []
        consumer = object()
        session._programs["wedged.bin"] = {
            "binary": "wedged.bin",
            "program": program,
            "consumer": consumer,
            "proj": consumer,
            "decomp": mock.MagicMock(),
            "used": 0.0,
        }
        self.addCleanup(session._programs.pop, "wedged.bin", None)
        with (
            mock.patch.object(session.time, "sleep", lambda *_: None),
            self.assertRaises(RuntimeError),
        ):
            session._save(program, "ghlab rename")
        self.assertNotIn("wedged.bin", session._programs)
        program.release = lambda target: released.append(target)  # type: ignore[method-assign]
        self.assertFalse(session._forget_program(program))
        self.assertEqual(released, [])

    def test_forgetting_a_program_releases_it(self):
        program = FakeProgram()
        released: list[object] = []
        program.release = lambda target: released.append(target)  # type: ignore[method-assign]
        consumer = object()
        session._programs["gone.bin"] = {
            "binary": "gone.bin",
            "program": program,
            "consumer": consumer,
            "proj": consumer,
            "decomp": mock.MagicMock(),
            "used": 0.0,
        }
        self.addCleanup(session._programs.pop, "gone.bin", None)
        self.assertTrue(session._forget_program(program))
        self.assertNotIn("gone.bin", session._programs)
        self.assertEqual(released, [consumer])

    def test_a_program_that_is_not_cached_is_just_reported(self):
        self.assertFalse(session._forget_program(object()))


if __name__ == "__main__":
    unittest.main()
