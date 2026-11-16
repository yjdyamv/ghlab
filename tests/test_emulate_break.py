"""`emulate --break`: stop mid-run and read the registers.

The probe workflow this exists for: run a function, stop *before* the interesting
instruction, and read the pointers it just computed (a vtable, a field, an argument).
Before this, `emulate` could only run entry→return, so any intermediate value was
invisible unless the function happened to write it somewhere diffable.
"""

import unittest
from unittest import mock

from ghlab import cli, session


def report(**kw):
    base = {
        "function": "FUN_180f1bdb0",
        "entry": "180f1bdb0",
        "prototype": "undefined FUN_180f1bdb0()",
        "arch": "x86:LE:64:default",
        "args": [],
        "stop": "returned",
        "insns": 12,
        "stubs": [],
        "skips": [],
        "ret": {"rax": 1, "rax_hex": "0x1", "rax_i32": 1},
        "writes": {"tracked": 0, "ranges": []},
        "dump": [],
        "buffer": None,
        "seeded": [],
        "fault": None,
        "scratch": {"block": ".data", "base": "181ed2000", "sp": "181ed2e00"},
        "elapsed_ms": 3,
        "regs": {},
    }
    base.update(kw)
    return base


class BreakFormatterTest(unittest.TestCase):
    def test_a_breakpoint_reports_registers_instead_of_a_return(self):
        text = cli.fmt_emulate(
            report(
                stop="breakpoint",
                regs={"RAX": "0x181ad2508", "RCX": "0x20", "RIP": "0x18108ef6e"},
            )
        )
        self.assertIn("stop=breakpoint", text)
        self.assertIn("RAX=0x181ad2508", text)
        self.assertIn("RIP=0x18108ef6e", text)
        self.assertNotIn("return", text)

    def test_registers_wrap_across_lines(self):
        regs = {f"R{i}": hex(i) for i in range(13)}
        text = cli.fmt_emulate(report(stop="breakpoint", regs=regs))
        self.assertEqual(sum(1 for line in text.splitlines() if "=" in line and "R1" in line), 3)
        for value in regs.values():
            self.assertIn(value, text)

    def test_a_normal_return_still_prints_rax(self):
        text = cli.fmt_emulate(report())
        self.assertIn("return    0x1 (1)", text)
        self.assertNotIn("regs", text)

    def test_a_returned_run_never_prints_registers_even_if_present(self):
        # the field is always populated now; printing it on every run would bury the answer
        text = cli.fmt_emulate(report(regs={"RAX": "0x1"}))
        self.assertNotIn("RAX=0x1", text)


class BreakSpecTest(unittest.TestCase):
    def test_hex_and_bare_hex_both_parse(self):
        self.assertEqual(
            session._emu_breaks(None, ["0x18108ef6e", "18108EF6E"]),
            {0x18108EF6E},
        )

    def test_no_specs_means_no_breakpoints(self):
        self.assertEqual(session._emu_breaks(None, []), set())
        self.assertEqual(session._emu_breaks(None, None), set())

    def test_an_unknown_symbol_says_so(self):
        with (
            mock.patch.object(session, "_symbol_addr", return_value=None),
            mock.patch.object(session, "_suggest_symbols", return_value=[]),
            self.assertRaises(KeyError) as ctx,
        ):
            session._emu_breaks(None, ["not_a_function"])
        self.assertIn("not a hex address or known symbol", str(ctx.exception))

    def test_a_symbol_is_resolved_through_the_symbol_table(self):
        with mock.patch.object(session, "_symbol_addr", return_value=0x180F1BDB0):
            self.assertEqual(session._emu_breaks(None, ["FUN_180f1bdb0"]), {0x180F1BDB0})

    def test_register_list_covers_what_the_caller_passes(self):
        for name in ("RCX", "RDX", "R8", "R9", "RAX", "RIP"):
            self.assertIn(name, session._EMU_REGS)


if __name__ == "__main__":
    unittest.main()
