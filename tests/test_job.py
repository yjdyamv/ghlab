"""`job` / `cancel`: a long command queued in the background, and a way to stop it.

The point of the feature is that the *caller* does not block; everything else here
checks the two things that make that safe -- the job goes through the same dispatch
path as any request (so locking, journal, in_flight, read-only all still apply),
and a cancel cannot wedge the daemon.
"""

from __future__ import annotations

import threading
import time
import unittest
from unittest import mock

from ghlab import cli, protocol, session


class BlockingMonitor:
    """Stands in for ConsoleTaskMonitor: the flag the daemon actually flips."""

    def __init__(self) -> None:
        self.cancelled = False
        self.resets = 0

    def isCancelled(self) -> bool:
        return self.cancelled

    def setCanceled(self, value: bool) -> None:
        self.cancelled = bool(value)
        if not value:
            self.resets += 1


class JobTestBase(unittest.TestCase):
    def setUp(self) -> None:
        session.JOBS.clear()
        self.addCleanup(session.JOBS.clear)
        self.addCleanup(session.HANDLERS.pop, "testy", None)
        self.monitor = BlockingMonitor()
        patcher = mock.patch.object(session, "MONITOR", self.monitor)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.seen: list[dict] = []

    def handle(self, fn) -> None:
        session.HANDLERS["testy"] = fn
        self.addCleanup(session.HANDLERS.pop, "testy", None)

    def spec_testy(self, *params: str) -> None:
        """Register a protocol entry so `job run=testy` validates."""
        session.HANDLERS.setdefault("testy", lambda a: self.seen.append(a) or {"ok": True})
        spec = protocol.Spec("testy", (), params or ("binary",))
        patcher = mock.patch.dict(protocol.SPECS, {"testy": spec})
        patcher.start()
        self.addCleanup(patcher.stop)


class ArgsTest(unittest.TestCase):
    def test_pairs_split_on_semicolon_not_comma(self):
        got = session._job_args("targets=a,b;types=0x18=float,0x20=void *")
        self.assertEqual(got, {"targets": "a,b", "types": "0x18=float,0x20=void *"})

    def test_blank_items_are_ignored(self):
        self.assertEqual(session._job_args(" ; binary=x ; "), {"binary": "x"})

    def test_a_pair_without_equals_names_the_item(self):
        with self.assertRaises(ValueError) as ctx:
            session._job_args("binary")
        self.assertIn("key=value", str(ctx.exception))

    def test_empty_args_are_empty(self):
        self.assertEqual(session._job_args(None), {})
        self.assertEqual(session._job_args(""), {})


class JobLifecycleTest(JobTestBase):
    def test_a_job_returns_before_the_work_is_done_and_then_holds_the_result(self):
        gate = threading.Event()
        self.spec_testy()
        self.handle(lambda _a: (gate.wait(5), {"slow": True})[1])
        started = time.monotonic()
        out = session.cmd_job({"run": "testy"})
        self.assertLess(time.monotonic() - started, 1.0, "job must not block the caller")
        self.assertEqual(out["state"] in ("queued", "running"), True)
        gate.set()
        deadline = time.monotonic() + 5
        while session.JOBS[out["job"]]["state"] in ("queued", "running"):
            self.assertLess(time.monotonic(), deadline, "job never finished")
            time.sleep(0.01)
        report = session.cmd_job({"list": True})
        done = next(j for j in report["jobs"] if j["job"] == out["job"])
        self.assertEqual(done["state"], "done")
        self.assertNotIn("result", done, "the queue view stays small")
        one = session.cmd_job({"id": out["job"]})["jobs"][0]
        self.assertEqual(one["result"], {"slow": True})

    def test_wait_returns_the_result_inline(self):
        self.spec_testy()
        self.handle(lambda _a: {"inline": True})
        out = session.cmd_job({"run": "testy", "wait": True})
        self.assertEqual(out["state"], "done")
        self.assertEqual(out["result"], {"inline": True})

    def test_binary_and_args_both_reach_the_handler(self):
        self.spec_testy("binary", "targets")
        out = session.cmd_job(
            {"run": "testy", "binary": "fw.bin", "args": "targets=main", "wait": True}
        )
        self.assertEqual(
            session.JOBS[out["job"]]["params"], {"targets": "main", "binary": "fw.bin"}
        )

    def test_a_typo_fails_the_call_not_a_job(self):
        self.spec_testy()
        with self.assertRaises(protocol.ProtocolError):
            session.cmd_job({"run": "testy", "args": "bogus=1"})
        self.assertEqual(session.JOBS, {}, "a rejected job must not be queued")

    def test_an_unknown_command_is_rejected(self):
        with self.assertRaises(protocol.ProtocolError):
            session.cmd_job({"run": "no-such-command"})

    def test_no_run_says_what_to_pass(self):
        with self.assertRaises(ValueError) as ctx:
            session.cmd_job({})
        self.assertIn("run=", str(ctx.exception))

    def test_a_failing_handler_becomes_a_failed_job_not_a_dead_thread(self):
        self.spec_testy()

        def boom(_a):
            raise RuntimeError("analysis blew up")

        self.handle(boom)
        out = session.cmd_job({"run": "testy", "wait": True})
        self.assertEqual(out["state"], "failed")
        self.assertIn("analysis blew up", out["error"])

    def test_readonly_still_applies_to_a_job(self):
        gate = threading.Event()
        self.spec_testy()
        self.handle(lambda _a: gate.wait(5))
        # `testy` is not on the mutating list, so claim one that is.
        with (
            mock.patch.object(session, "readonly", return_value=True),
            mock.patch.object(session, "_mutates", return_value=True),
        ):
            out = session.cmd_job({"run": "testy"})
            gate.set()
            deadline = time.monotonic() + 5
            while session.JOBS[out["job"]]["state"] in ("queued", "running"):
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
        job = session.JOBS[out["job"]]
        self.assertEqual(job["state"], "failed")
        self.assertIn("read-only", job["error"])

    def test_unknown_job_id_is_named(self):
        with self.assertRaises(KeyError) as ctx:
            session.cmd_job({"id": "j99"})
        self.assertIn("j99", str(ctx.exception))

    def test_the_queue_view_is_empty_and_says_nothing_extra(self):
        self.assertEqual(session.cmd_job({"list": True}), {"jobs": [], "running": 0})


class CancelTest(JobTestBase):
    def test_cancel_flips_the_shared_monitor(self):
        self.spec_testy()
        gate = threading.Event()
        self.handle(lambda _a: gate.wait(5))
        out = session.cmd_job({"run": "testy"})
        time.sleep(0.05)
        reply = session.cmd_cancel({"id": out["job"]})
        self.assertEqual(reply["cancel_requested"], [out["job"]])
        self.assertTrue(self.monitor.cancelled)
        self.assertIn("between steps", reply["note"])
        gate.set()

    def test_a_cancelled_job_is_reported_cancelled_even_if_the_handler_returns(self):
        gate = threading.Event()
        self.spec_testy()
        self.handle(lambda _a: (gate.wait(5), {"finished": True})[1])
        out = session.cmd_job({"run": "testy"})
        time.sleep(0.05)
        session.cmd_cancel({"id": out["job"]})
        gate.set()
        deadline = time.monotonic() + 5
        while session.JOBS[out["job"]]["state"] in ("queued", "running"):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        self.assertEqual(session.JOBS[out["job"]]["state"], "cancelled")

    def test_the_monitor_is_cleared_afterwards_so_the_next_command_runs(self):
        self.spec_testy()
        self.handle(lambda _a: {"ok": True})
        session.cmd_job({"run": "testy", "wait": True})
        self.assertFalse(self.monitor.cancelled, "a stale flag would abort the next command")
        self.assertGreaterEqual(self.monitor.resets, 1)

    def test_cancelling_a_queued_job_never_runs_it(self):
        self.spec_testy()
        ran: list[int] = []

        def slow(_a):
            ran.append(1)
            return {"ran": True}

        session.HANDLERS["testy"] = slow
        # A held lock stands in for a decompile already running: the job queues on it,
        # gets cancelled while queued, and must not run when the lock is released.
        held = threading.RLock()
        held.acquire()
        with mock.patch.object(session, "LOCK", held):
            out = session.cmd_job({"run": "testy"})
            reply = session.cmd_cancel({"id": out["job"]})
            self.assertEqual(reply["cancel_requested"], [out["job"]])
            held.release()
        deadline = time.monotonic() + 5
        while session.JOBS[out["job"]]["state"] in ("queued", "running"):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        self.assertEqual(ran, [], "a job cancelled while queued must not run")
        self.assertEqual(session.JOBS[out["job"]]["state"], "cancelled")

    def test_cancel_all_stops_only_active_jobs(self):
        self.spec_testy()
        self.handle(lambda _a: {"ok": True})
        done = session.cmd_job({"run": "testy", "wait": True})
        reply = session.cmd_cancel({"all": True})
        self.assertEqual(reply["cancel_requested"], [])
        self.assertEqual(session.JOBS[done["job"]]["state"], "done")

    def test_cancel_needs_an_id_or_all(self):
        with self.assertRaises(ValueError) as ctx:
            session.cmd_cancel({})
        self.assertIn("all=yes", str(ctx.exception))

    def test_cancel_of_an_unknown_job_is_named(self):
        with self.assertRaises(KeyError) as ctx:
            session.cmd_cancel({"id": "j404"})
        self.assertIn("j404", str(ctx.exception))


class UnlockedTest(JobTestBase):
    def test_job_and_cancel_do_not_wait_for_the_ghidra_lock(self):
        self.spec_testy()
        self.handle(lambda _a: {"ok": True})
        lock = threading.Lock()
        lock.acquire()
        with mock.patch.object(session, "LOCK", lock):

            def later():
                time.sleep(0.3)
                lock.release()

            threading.Thread(target=later, daemon=True).start()
            started = time.monotonic()
            out = session.cmd_job({"list": True})
            session.cmd_cancel({"all": True})
            self.assertLess(time.monotonic() - started, 0.25, "these must not queue on LOCK")
        self.assertEqual(out["jobs"], [])

    def test_ping_and_the_queue_are_the_unlocked_ones(self):
        self.assertEqual(set(session._UNLOCKED), {"ping", "job", "cancel"})

    def test_a_job_goes_through_dispatch_so_it_shows_as_in_flight(self):
        gate = threading.Event()
        self.spec_testy()
        self.handle(lambda _a: (gate.wait(5), {"ok": True})[1])
        out = session.cmd_job({"run": "testy"})
        deadline = time.monotonic() + 5
        while not session.in_flight():
            self.assertLess(time.monotonic(), deadline, "job never showed up as in flight")
            time.sleep(0.01)
        self.assertEqual(session.in_flight()["cmd"], "testy")
        gate.set()
        deadline = time.monotonic() + 5
        while session.in_flight():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        self.assertEqual(session.JOBS[out["job"]]["state"], "done")


class TrimTest(JobTestBase):
    def test_old_jobs_are_forgotten(self):
        self.spec_testy()
        self.handle(lambda _a: {"ok": True})
        with mock.patch.object(session, "MAX_JOBS_KEPT", 2):
            for _ in range(4):
                session.cmd_job({"run": "testy", "wait": True})
        self.assertLessEqual(len(session.JOBS), 2, f"kept {len(session.JOBS)}")
        self.assertEqual(session.cmd_job({"list": True})["running"], 0)


class ProtocolAndCliTest(unittest.TestCase):
    def test_job_and_cancel_take_optional_parameters(self):
        spec, params = protocol.validate({"cmd": "job", "run": "scan", "binary": "fw.bin"})
        self.assertEqual(spec.name, "job")
        self.assertEqual(params["run"], "scan")

    def test_job_alone_is_valid_so_list_can_be_asked(self):
        spec, _ = protocol.validate({"cmd": "job"})
        self.assertEqual(spec.name, "job")

    def test_a_typo_in_the_job_call_is_rejected(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "job", "command": "scan"})

    def test_cli_job_forwards_run_binary_and_args(self):
        args = cli.build_parser().parse_args(["job", "decompile", "fw.bin", "-a", "targets=main"])
        self.assertEqual(
            (args.run, args.binary, args.args), ("decompile", "fw.bin", "targets=main")
        )

    def test_cli_cancel_all(self):
        args = cli.build_parser().parse_args(["cancel", "--all"])
        self.assertTrue(args.all)

    def test_queue_format_lists_state_and_elapsed(self):
        text = cli.fmt_job(
            {
                "jobs": [{"job": "j2", "cmd": "scan", "state": "running", "elapsed_ms": 4200}],
                "running": 1,
            }
        )
        self.assertIn("j2", text)
        self.assertIn("running", text)
        self.assertIn("4.2s", text)
        self.assertIn("ghlab cancel", text)

    def test_cancel_format_says_nothing_to_stop(self):
        self.assertIn("nothing to stop", cli.fmt_cancel({"cancel_requested": []}))


if __name__ == "__main__":
    unittest.main()
