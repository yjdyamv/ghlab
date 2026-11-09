"""Unit tests for the displacement-search filters (no daemon needed)."""

from __future__ import annotations

import unittest

from ghlab.session import _imm_of, _imm_spec, _is_dest_operand, _split_operands


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
