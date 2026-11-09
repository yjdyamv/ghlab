"""Unit tests for the displacement-search filters (no daemon needed)."""

from __future__ import annotations

import unittest

from ghlab.session import (
    _displacements,
    _imm_of,
    _imm_spec,
    _is_dest_operand,
    _split_operands,
)


class SplitOperandsTest(unittest.TestCase):
    def test_splits_on_commas_outside_brackets(self) -> None:
        self.assertEqual(
            _split_operands("MOV dword ptr [RAX + 0x44],R15D"),
            ["MOV dword ptr [RAX + 0x44]", "R15D"],
        )

    def test_keeps_commas_inside_a_scale_spec(self) -> None:
        parts = _split_operands("MOV RCX,qword ptr [RAX + RDX*0x8]")
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[1].strip(), "qword ptr [RAX + RDX*0x8]")

    def test_single_operand(self) -> None:
        self.assertEqual(_split_operands("RET"), ["RET"])


class ImmOfTest(unittest.TestCase):
    def test_trailing_immediate(self) -> None:
        self.assertEqual(_imm_of("MOV dword ptr [RSP + 0x28],0x1"), 1)
        self.assertEqual(_imm_of("CMP dword ptr [RAX + 0x44],0x4"), 4)

    def test_negative_immediate(self) -> None:
        self.assertEqual(_imm_of("MOV byte ptr [RAX],-1"), -1)

    def test_register_source_is_not_an_immediate(self) -> None:
        self.assertIsNone(_imm_of("MOV dword ptr [RAX + 0x44],R15D"))

    def test_memory_source_is_not_an_immediate(self) -> None:
        self.assertIsNone(_imm_of("MOV EAX,dword ptr [RIP + 0x1234]"))
        self.assertIsNone(_imm_of("MOVSS XMM1,dword ptr [RAX + 0x54]"))


class ImmSpecTest(unittest.TestCase):
    def test_exact_values(self) -> None:
        self.assertTrue(_imm_spec("4")(4))
        self.assertTrue(_imm_spec("0x4")(4))
        self.assertFalse(_imm_spec("4")(5))

    def test_range(self) -> None:
        within = _imm_spec("0..5")
        self.assertTrue(within(0))
        self.assertTrue(within(5))
        self.assertFalse(within(6))

    def test_bad_range_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _imm_spec("5..0")


class DestOperandTest(unittest.TestCase):
    def test_store_puts_the_offset_first(self) -> None:
        self.assertTrue(_is_dest_operand("MOV dword ptr [RAX + 0x44],R15D", 0x44))

    def test_load_puts_the_offset_second(self) -> None:
        self.assertFalse(_is_dest_operand("MOV R15D,dword ptr [RAX + 0x44]", 0x44))

    def test_a_different_offset_does_not_count(self) -> None:
        self.assertFalse(_is_dest_operand("MOV dword ptr [RAX + 0x48],R15D", 0x44))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class DestinationOperandTest(unittest.TestCase):
    """`--writes` must not mistake an indirect call for a store.

    Regression: every `CALL qword ptr [RAX+0xNN]` counted as a write, which
    inflated a "who writes +0x40" sweep to 263 hits -- mostly virtual calls.
    """

    def test_indirect_call_is_a_read(self):
        self.assertFalse(_is_dest_operand("CALL qword ptr [RAX + 0x40]", 0x40))
        self.assertFalse(_is_dest_operand("JMP qword ptr [R8 + 0x40]", 0x40))

    def test_compare_and_push_are_reads(self):
        for text in ("CMP dword ptr [R12 + 0x40],0x2", "TEST byte ptr [RAX + 0x40],0x4"):
            self.assertFalse(_is_dest_operand(text, 0x40))

    def test_real_stores_still_count(self):
        for text in (
            "MOV dword ptr [RAX + 0x40],0x2",
            "MOVSS dword ptr [RCX + 0x40],XMM1",
            "AND dword ptr [RDI + 0x40],0xfffffffb",
        ):
            self.assertTrue(_is_dest_operand(text, 0x40), text)

    def test_address_computation_is_not_a_store(self):
        self.assertFalse(_is_dest_operand("LEA RAX,[RCX + 0x40]", 0x40))


class DisplacementTest(unittest.TestCase):
    """A query for +0x40 must not match -0x40.

    Regression: the fence was a string regex, so `[RCX + R13*0x1 + -0x40]`
    read as "writes +0x40" and a funnel over 2007 functions returned 12
    phantom writers instead of zero.
    """

    def test_sign_is_part_of_the_value(self):
        self.assertNotIn(0x40, _displacements("MOV dword ptr [RCX + R13*0x1 + -0x40],EDI"))
        self.assertIn(0x40, _displacements("MOV dword ptr [RAX + 0x40],0x2"))

    def test_index_scale_is_not_a_displacement(self):
        self.assertEqual(_displacements("MOV RBX,qword ptr [RAX + RDX*0x8]"), set())
        self.assertEqual(_displacements("MOV RBX,qword ptr [RAX + RDX*0x8 + 0x40]"), {0x40})

    def test_decimal_and_hex_forms_agree(self):
        self.assertEqual(_displacements("MOV [RAX + 64],ECX"), {64})
        self.assertEqual(_displacements("MOV [RAX + 0x40],ECX"), {64})

    def test_two_operands_are_merged(self):
        self.assertEqual(_displacements("MOV [RAX + 0x10],[RCX + 0x20]"), {0x10, 0x20})
