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
    """The call shape `import --language` is pinned to on a real JVM.

    Every reasonable guess failed there: the class is
    `ghidra.program.model.lang.LanguageCompilerSpecPair`, not
    `ghidra.program.util`; and the importer takes eight arguments with a `Language`
    in the fourth slot, so the six-argument call that looks natural fails with
    "wrong number of arguments: 6 expected: 8".
    """

    @staticmethod
    def _modules(importer: mock.MagicMock) -> dict[str, types.ModuleType]:
        """A `ghidra`/`java` package tree with just the names _auto_import imports."""
        importer_module = types.ModuleType("ghidra.app.util.importer")
        importer_module.AutoImporter = importer
        importer_module.MessageLog = mock.MagicMock(return_value="LOG")
        util = types.ModuleType("ghidra.app.util")
        util.importer = importer_module
        app = types.ModuleType("ghidra.app")
        app.util = util
        lang = types.ModuleType("ghidra.program.model.lang")
        pair = mock.MagicMock()
        pair.return_value.getLanguage.return_value = "LANG"
        pair.return_value.getCompilerSpec.return_value = "CSPEC"
        lang.LanguageCompilerSpecPair = pair
        model = types.ModuleType("ghidra.program.model")
        model.lang = lang
        program = types.ModuleType("ghidra.program")
        program.model = model
        ghidra = types.ModuleType("ghidra")
        ghidra.app = app
        ghidra.program = program
        io = types.ModuleType("java.io")
        io.File = mock.MagicMock(return_value="FILE")
        java = types.ModuleType("java")
        java.io = io
        return {
            "ghidra": ghidra,
            "ghidra.app": app,
            "ghidra.app.util": util,
            "ghidra.app.util.importer": importer_module,
            "ghidra.program": program,
            "ghidra.program.model": model,
            "ghidra.program.model.lang": lang,
            "java": java,
            "java.io": io,
        }

    def _run(self, results=None, raise_: Exception | None = None):
        importer = mock.MagicMock()
        if raise_ is not None:
            importer.importByLookingForLcs.side_effect = raise_
        else:
            results = results if results is not None else mock.MagicMock()
            results.getPrimaryDomainObject.return_value = "PROGRAM"
            importer.importByLookingForLcs.return_value = results

        def _proj():
            wrapper = mock.MagicMock()
            wrapper.getProject.return_value = "PROJ"
            return wrapper

        with (
            mock.patch.dict(sys.modules, self._modules(importer)),
            mock.patch.object(session, "project", lambda: _proj()),
            mock.patch.object(session, "MONITOR", "MON"),
        ):
            out = session._auto_import(session.Path("fw.bin"), "x86:LE:32:default", "gcc")
        return out, importer

    def test_the_eight_arguments_ghidra_actually_takes(self):
        _, importer = self._run()
        args = importer.importByLookingForLcs.call_args.args
        self.assertEqual(args, ("FILE", "PROJ", "/", "LANG", "CSPEC", None, "LOG", "MON"))

    def test_the_program_comes_back_not_the_load_results(self):
        out, _ = self._run()
        self.assertEqual(out, "PROGRAM")

    def test_a_java_failure_names_the_language_and_the_cause(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._run(raise_=RuntimeError("wrong number of arguments: 6 expected: 8"))
        text = str(ctx.exception)
        self.assertIn("x86:LE:32:default:gcc", text)
        self.assertIn("wrong number of arguments", text)
        self.assertIn("RuntimeError", text)


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
