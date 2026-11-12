"""`import` options: the parts that can be checked without a JVM.

The loader plumbing (`_load_spec_rows`, `_auto_import`) needs a live Ghidra; what
is worth pinning down here is that a bad `--language` fails at the CLI with the
shape it expected, that `_auto_import` refuses to guess an overload it has not
seen, and that `fmt_import` reads all four result shapes.
"""

import sys
import types
import unittest
from unittest import mock

from ghlab import cli, protocol, session


class LanguageIdTest(unittest.TestCase):
    def test_a_full_id_passes_through(self):
        self.assertEqual(session._language_id("x86:LE:64:default"), "x86:LE:64:default")

    def test_whitespace_is_trimmed(self):
        self.assertEqual(session._language_id(" x86:LE:32:default "), "x86:LE:32:default")

    def test_a_shortcut_names_the_expected_shape(self):
        # `--language x86_64` is the mistake people actually make; the error has to
        # say what a LanguageID looks like or the next attempt is a guess too.
        for wrong in ("x86_64", "x86:LE:64", "x86::64:default", ""):
            with self.assertRaises(ValueError) as ctx:
                session._language_id(wrong)
            self.assertIn("processor:endian:size:variant", str(ctx.exception))
            self.assertIn("--show-loaders", str(ctx.exception))


class AutoImportTest(unittest.TestCase):
    class Method:
        def __init__(self, count, calls, accept):
            self.count = count
            self.calls = calls
            self.accept = accept

        def getName(self):
            return "importByLookingForLcs"

        def getParameterCount(self):
            return self.count

        def invoke(self, _target, args):
            self.calls.append((self.count, list(args)))
            if self.count not in self.accept:
                raise TypeError(f"{self.count} args does not fit")
            return "program"

    class Klass:
        def __init__(self, methods):
            self.methods = methods

        def getMethods(self):
            return self.methods

    @staticmethod
    def _modules(fake_class):
        """A `ghidra`/`java` package tree with just the names _auto_import imports."""
        util = types.ModuleType("ghidra.program.util")
        util.LanguageCompilerSpecPair = mock.MagicMock(return_value="pair")
        program = types.ModuleType("ghidra.program")
        program.util = util
        ghidra = types.ModuleType("ghidra")
        ghidra.program = program
        ghidra.importer = types.ModuleType("ghidra.importer")
        io = types.ModuleType("java.io")
        io.File = mock.MagicMock(return_value="FILE")
        java = types.ModuleType("java")
        java.io = io
        jpype = mock.MagicMock()
        jpype.JClass.return_value = fake_class
        return {
            "jpype": jpype,
            "ghidra": ghidra,
            "ghidra.program": program,
            "ghidra.program.util": util,
            "java": java,
            "java.io": io,
        }

    def _run(self, counts: list[int], accept: set[int]):
        calls: list[tuple[int, list]] = []
        methods = [self.Method(count, calls, accept) for count in counts]
        fake = mock.MagicMock()
        fake.class_ = self.Klass(methods)
        with (
            mock.patch.dict(sys.modules, self._modules(fake)),
            mock.patch.object(session, "project", lambda: "PROJ"),
            mock.patch.object(session, "MONITOR", "MON"),
        ):
            out = session._auto_import(session.Path("fw.bin"), "fw.bin", "x86:LE:32:default", "gcc")
        return out, calls

    def test_the_seven_argument_overload_gets_a_consumer_slot(self):
        out, calls = self._run([7], accept={7})
        self.assertEqual(out, "program")
        count, args = calls[0]
        self.assertEqual(count, 7)
        self.assertEqual(args[0], "FILE")
        self.assertEqual(args[1], "PROJ")
        self.assertEqual(args[2], "/")
        self.assertEqual(args[3], "fw.bin")
        self.assertEqual(args[4], "pair")
        self.assertIsNone(args[5])  # the ProgramConsumer slot
        self.assertEqual(args[6], "MON")

    def test_the_six_argument_overload_drops_the_consumer(self):
        out, calls = self._run([6], accept={6})
        self.assertEqual(out, "program")
        self.assertEqual(len(calls[0][1]), 6)
        self.assertEqual(calls[0][1][-1], "MON")

    def test_a_wrong_arity_is_skipped_not_fatal(self):
        out, calls = self._run([8, 7], accept={7})
        self.assertEqual(out, "program")
        self.assertEqual([count for count, _ in calls], [8, 7])

    def test_no_matching_overload_names_what_it_saw(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._run([3], accept=set())
        self.assertIn("3 args", str(ctx.exception))
        self.assertIn("failed", str(ctx.exception))

    def test_a_ghidra_without_the_entry_point_says_so(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._run([], accept=set())
        self.assertIn("no AutoImporter", str(ctx.exception))


class ImportFormatTest(unittest.TestCase):
    def test_load_specs_are_listed(self):
        text = cli.fmt_import(
            {
                "path": "fw.bin",
                "load_specs": [
                    {"loader": "BinaryLoader", "language": "x86:LE:32:default", "cspec": "gcc"}
                ],
            }
        )
        self.assertIn("fw.bin", text)
        self.assertIn("BinaryLoader", text)
        self.assertIn("x86:LE:32:default", text)

    def test_an_unrecognised_file_says_so(self):
        self.assertIn("no loader", cli.fmt_import({"path": "x.bin", "load_specs": []}))

    def test_a_long_load_spec_list_is_truncated(self):
        # a plain PE matches 274 specs, most of them the binary loader's fallbacks
        rows = [
            {"loader": "BinaryLoader", "language": f"x86:LE:32:{n}", "cspec": "gcc"}
            for n in range(274)
        ]
        text = cli.fmt_import({"path": "notepad.exe", "load_specs": rows})
        self.assertIn("274 load spec(s)", text)
        self.assertIn("... 266 more", text)
        self.assertEqual(len([ln for ln in text.split(chr(10)) if "BinaryLoader" in ln]), 8)

    def test_fid_list_names_the_folder_ghidra_searchs(self):
        text = cli.fmt_fid({"libraries": [], "count": 0, "folder": r"C:\gs\FunctionID"})
        self.assertIn(r"searched: C:\gs\FunctionID", text)
        self.assertIn("drop a .fidb", text)

    def test_a_new_import_reports_language_and_base(self):
        text = cli.fmt_import(
            {
                "binary": "fw.bin",
                "imported": True,
                "analyzed": True,
                "image_base": "0x8000000",
                "language": "x86:LE:32:default",
                "cspec": "gcc",
            }
        )
        self.assertIn("x86:LE:32:default:gcc", text)
        self.assertIn("base 0x8000000", text)
        self.assertIn("analyzed", text)

    def test_unanalyzed_import_points_at_analyze(self):
        text = cli.fmt_import(
            {"binary": "big.exe", "imported": True, "analyzed": False, "image_base": "0x400000"}
        )
        self.assertIn("ghlab analyze", text)

    def test_an_existing_program_points_at_overwrite(self):
        text = cli.fmt_import({"binary": "a.exe", "already_present": True})
        self.assertIn("already in the project", text)
        self.assertIn("--overwrite", text)


class ImportProtocolTest(unittest.TestCase):
    def test_the_new_options_are_allowed(self):
        spec, params = protocol.validate(
            {
                "cmd": "import",
                "path": "fw.bin",
                "base": "0x8000000",
                "language": "x86:LE:32:default",
                "cspec": "gcc",
                "name": "fw",
                "overwrite": True,
                "show_loaders": False,
            }
        )
        self.assertEqual(spec.name, "import")
        self.assertEqual(params["base"], "0x8000000")
        self.assertEqual(params["name"], "fw")

    def test_a_typo_is_still_rejected(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "import", "path": "fw.bin", "bas": "0x1000"})

    def test_the_cli_forwards_them(self):
        args = cli.build_parser().parse_args(
            ["import", "fw.bin", "--base", "0x8000000", "--language", "x86:LE:32:default"]
        )
        self.assertEqual(args.base, "0x8000000")
        self.assertEqual(args.language, "x86:LE:32:default")
        self.assertFalse(args.no_analyze)


if __name__ == "__main__":
    unittest.main()
