"""`struct`: the inference half, which is pure Python and therefore testable.

The Ghidra half (`cmd_struct` reading p-code, `_install_struct` building a
`StructureDataType`) is exercised by the live suite; what can go wrong silently is
the layout arithmetic and the width vote, so that lives here.
"""

import sys
import types
import unittest
from unittest import mock

from ghlab import session
from ghlab.session import _align, _infer_struct, _install_struct, _parse_overrides


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


class InstallStructTest(unittest.TestCase):
    """`_install_struct` cannot run without a JVM, but its *call shape* can be checked.

    On the first real `struct --create` run jpype found no overload, because
    `StructureDataType.add` takes (DataType, int offset, name, comment) and the call
    passed the offset first.  A fake `ghidra.program.model.data` pins the order.
    """

    def _modules(self, seen):
        class Structure:
            def __init__(self, name, size, manager):
                self.name = name
                self.size = size
                self.added = []

            def add(self, *args):
                self.added.append(args)
                seen["struct"] = self

            def getPathName(self):
                return f"/{self.name}"

        data = types.ModuleType("ghidra.program.model.data")
        data.StructureDataType = Structure
        data.PointerDataType = type("PointerDataType", (), {})
        for java in ("IntegerDataType", "LongLongDataType", "WordDataType"):
            setattr(data, java, type(java, (), {}))
        data.DataTypeConflictHandler = type("H", (), {"REPLACE_HANDLER": "replace"})
        data.__all__ = []
        chain = {}
        for name in ("ghidra", "ghidra.program", "ghidra.program.model"):
            chain[name] = types.ModuleType(name)
            chain[name].__path__ = []
        chain["ghidra.program.model.data"] = data
        chain["ghidra.program"].model = chain["ghidra.program.model"]
        chain["ghidra.program.model"].data = data
        chain["ghidra"].program = chain["ghidra.program"]
        return chain

    def test_the_field_is_added_type_first(self):
        seen = {}

        class Manager:
            def addDataType(self, struct, handler):
                seen["handler"] = handler
                seen["size"] = struct.size

        class Program:
            def getDataTypeManager(self):
                return Manager()

        spec = {
            "name": "Foo",
            "size": 16,
            "fields": [
                {"offset": 0, "name": "field_0x0", "type": "longlong", "loads": 1, "stores": 0},
                {"offset": 8, "name": "field_0x8", "type": "void *", "loads": 2, "stores": 1},
            ],
        }
        with mock.patch.dict(sys.modules, self._modules(seen)):
            path = _install_struct(Program(), spec)
        self.assertEqual(path, "/Foo")
        self.assertEqual(seen["handler"], "replace")
        struct = seen["struct"]
        self.assertEqual([call[1] for call in struct.added], [0, 8])
        self.assertEqual(struct.added[0][0].__class__.__name__, "LongLongDataType")
        self.assertEqual(struct.added[1][0].__class__.__name__, "PointerDataType")
        self.assertEqual(struct.added[0][2], "field_0x0")
        self.assertIn("1 load(s)", struct.added[0][3])


class StructCreateOrderTest(unittest.TestCase):
    """`struct --create` must save *after* the transaction: Ghidra answers a save
    inside an open transaction with "Unable to lock due to active transaction".

    The first real run got exactly that from all three save paths, so the order is
    pinned here with fakes instead of a JVM.
    """

    def test_the_save_happens_after_the_transaction_closes(self):
        events = []

        class Decomp:
            def decompileFunction(self, fn, timeout, monitor):
                class Res:
                    def decompileCompleted(self):
                        return True

                    def getHighFunction(self):
                        return object()

                return Res()

        entry = {"program": object(), "decomp": Decomp()}

        class Fn:
            def getName(self):
                return "FUN_1"

            def getPrototypeString(self, _a, _b):
                return "undefined FUN_1(void)"

        rows = [row(0x0, base="param_1", size=8), row(0x8, base="param_1", size=8)]

        import contextlib as _ctx

        @_ctx.contextmanager
        def fake_edit(_program, _reason="ghlab"):
            events.append("begin")
            try:
                yield
            finally:
                events.append("end")

        def fake_install(_program, spec):
            events.append("install")
            self.assertEqual(spec["name"], "Foo_t")
            return "/Foo_t"

        def fake_save(_program, _message, entry=None):
            events.append("save")
            self.assertIn("end", events, "save ran inside the transaction")
            return "domain.save(monitor)"

        with (
            mock.patch.object(session, "_entry", return_value=entry),
            mock.patch.object(session, "_function", return_value=Fn()),
            mock.patch.object(session, "_param_accesses", return_value=rows),
            mock.patch.object(session, "_edit", fake_edit),
            mock.patch.object(session, "_install_struct", fake_install),
            mock.patch.object(session, "_save", fake_save),
            mock.patch.object(
                session,
                "_infer_struct",
                return_value={
                    "name": "Foo_t",
                    "base": "param_1",
                    "size": 16,
                    "fields": [{"offset": 0}],
                    "decl": "",
                    "confidence": "measured",
                },
            ),
        ):
            out = session.cmd_struct(
                {"binary": "a.exe", "target": "FUN_1", "base": "param_1", "create": True}
            )
        self.assertEqual(events, ["begin", "install", "end", "save"])
        self.assertEqual(out["created"], "/Foo_t")
        self.assertEqual(out["saved_via"], "domain.save(monitor)")


if __name__ == "__main__":
    unittest.main()
