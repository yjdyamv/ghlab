"""`struct`: the inference half, which is pure Python and therefore testable.

The Ghidra half (`cmd_struct` reading p-code, `_install_struct` building a
`StructureDataType`) is exercised by the live suite; what can go wrong silently is
the layout arithmetic and the width vote, so that lives here.
"""

import unittest

from ghlab.session import _align, _infer_struct, _parse_overrides


def row(offset, base="__param", size=4, op="load"):
    return {"offset": offset, "base": base, "size": size, "op": op, "kind": "param"}


class OverridesTest(unittest.TestCase):
    def test_a_single_override(self):
        self.assertEqual(_parse_overrides("0x18=float"), {0x18: "float"})

    def test_several_and_pointer_types(self):
        self.assertEqual(
            _parse_overrides("0x18=float, 0x20=void *"), {0x18: "float", 0x20: "void *"}
        )

    def test_empty_is_empty(self):
        self.assertEqual(_parse_overrides(None), {})
        self.assertEqual(_parse_overrides(""), {})

    def test_junk_names_the_offender(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_overrides("0x18")
        self.assertIn("'0x18'", str(ctx.exception))
        self.assertIn("OFFSET=TYPE", str(ctx.exception))


class AlignTest(unittest.TestCase):
    def test_rounds_up(self):
        self.assertEqual(_align(0, 8), 0)
        self.assertEqual(_align(1, 8), 8)
        self.assertEqual(_align(0x19, 8), 0x20)


class InferTest(unittest.TestCase):
    def test_widths_become_types(self):
        rows = [row("0x0", size=1), row("0x4", size=2), row("0x8", size=4), row("0x10", size=8)]
        spec = _infer_struct(rows, "Foo", "__param")
        self.assertEqual([f["type"] for f in spec["fields"]], ["byte", "ushort", "int", "longlong"])
        self.assertEqual(spec["size"], 0x18)

    def test_the_majority_width_wins(self):
        rows = [row("0x8", size=4), row("0x8", size=4), row("0x8", size=1)]
        spec = _infer_struct(rows, "Foo", "__param")
        self.assertEqual(spec["fields"][0]["type"], "int")
        self.assertEqual(spec["fields"][0]["widths"], {1: 1, 4: 2})

    def test_gaps_are_materialised_so_offsets_survive(self):
        spec = _infer_struct([row("0x10"), row("0x10", size=8, op="store")], "Foo", "__param")
        text = spec["decl"]
        self.assertIn("byte gap_0x0[0x10];", text)
        self.assertIn("int          field_0x10;  // 1 load(s), 1 store(s)", text)
        self.assertIn("byte gap_0x14[0x4];", text)
        self.assertEqual(spec["size"], 0x18)

    def test_an_override_beats_the_width(self):
        spec = _infer_struct([row("0x8")], "Foo", "__param", {0x8: "float"})
        self.assertEqual(spec["fields"][0]["type"], "float")

    def test_a_negative_offset_is_not_a_field(self):
        spec = _infer_struct([row("-0x8"), row("0x0")], "Foo", "__param")
        self.assertEqual([f["offset"] for f in spec["fields"]], [0])
        self.assertEqual(spec["confidence"], "single-field")

    def test_another_base_is_ignored(self):
        spec = _infer_struct([row("0x0", base="__other")], "Foo", "__param")
        self.assertEqual(spec["fields"], [])
        self.assertEqual(spec["confidence"], "none")
        self.assertIn("no field access", spec["decl"])

    def test_an_unknown_width_becomes_a_byte_array(self):
        spec = _infer_struct([row("0x0", size=16)], "Foo", "__param")
        self.assertEqual(spec["fields"][0]["type"], "byte[16]")

    def test_the_decl_is_parseable_shape(self):
        spec = _infer_struct([row("0x0"), row("0x4")], "Ctx", "__param")
        lines = spec["decl"].split("\n")
        self.assertEqual(lines[0], "struct Ctx {")
        self.assertEqual(lines[-1], "};")
        self.assertEqual(spec["confidence"], "measured")
        self.assertEqual(spec["name"], "Ctx")
        self.assertEqual(spec["base"], "__param")


if __name__ == "__main__":
    unittest.main()
