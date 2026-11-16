"""Unit tests for the claim grammar behind `ghlab note -a` / `ghlab verify`.

These run without the daemon and without Ghidra: everything under test here is
pure Python, which is why the parse/compare helpers live outside the JVM section.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from ghlab import session


class ClaimParsingTest(unittest.TestCase):
    def test_equals(self):
        spec = session._parse_claim("const=0x41")
        self.assertEqual((spec["kind"], spec["op"], spec["value"]), ("const", "=", "0x41"))

    def test_comparisons(self):
        for raw, op, value in (
            ("size>=200", ">=", "200"),
            ("size<=16", "<=", "16"),
            ("size>7", ">", "7"),
            ("size<7", "<", "7"),
        ):
            spec = session._parse_claim(raw)
            self.assertEqual((spec["kind"], spec["op"], spec["value"]), ("size", op, value))

    def test_kind_is_case_insensitive(self):
        self.assertEqual(session._parse_claim("CONST=1")["kind"], "const")

    def test_rejects_garbage(self):
        for raw in ("", "const", "   "):
            with self.assertRaises(ValueError):
                session._parse_claim(raw)

    def test_claim_int_accepts_hex_and_decimal(self):
        self.assertEqual(session._claim_int("0x10"), 16)
        self.assertEqual(session._claim_int(" 16 "), 16)


class CompareTest(unittest.TestCase):
    def test_all_operators(self):
        self.assertTrue(session._compare(5, "=", 5))
        self.assertFalse(session._compare(5, "=", 6))
        self.assertTrue(session._compare(5, ">=", 5))
        self.assertTrue(session._compare(5, "<=", 5))
        self.assertTrue(session._compare(6, ">", 5))
        self.assertTrue(session._compare(4, "<", 5))


class ConstViewsTest(unittest.TestCase):
    def test_high_bit_constant_matches_negative_scalar(self):
        # Ghidra hands back (HKEY)0xffffffff80000001 as a negative long.
        self.assertIn(0xFFFFFFFF80000001, session._const_views(-0x7FFFFFFF))

    def test_plain_constant_stays_itself(self):
        views = session._const_views(4)
        self.assertIn(4, views)

    def test_32_bit_view(self):
        self.assertIn(0x80000001, session._const_views(-0x7FFFFFFF))


class HexAddrTest(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(session._hex_addr("0x1400019d0"), 0x1400019D0)
        self.assertEqual(session._hex_addr("1400019d0"), 0x1400019D0)

    def test_not_addresses(self):
        for text in ("entry", "FUN_1400019d0", "dead", ""):
            self.assertIsNone(session._hex_addr(text), text)


class TypeMapTest(unittest.TestCase):
    def _write(self, name, text):
        path = os.path.join(tempfile.gettempdir(), name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_text_map_classifies_signatures_and_data(self):
        text = chr(10).join(["# comment", "FUN_1 = int f(char *s)", "0x140038600 = char[16]", ""])
        path = self._write("map1.txt", text)
        items = session._load_type_map(path)
        self.assertEqual([i["kind"] for i in items], ["signatures", "data"])

    def test_json_map_accepts_groups_and_flat_objects(self):
        path = self._write(
            "map2.json", json.dumps({"signatures": {"a": "int a(void)"}, "b": "DWORD"})
        )
        items = session._load_type_map(path)
        self.assertEqual({i["target"] for i in items}, {"a", "b"})

    def test_bad_line_reports_lineno(self):
        path = self._write("map3.txt", "nonsense line" + chr(10))
        with self.assertRaises(ValueError) as ctx:
            session._load_type_map(path)
        self.assertIn(":1:", str(ctx.exception))

    def test_empty_map_is_an_error(self):
        path = self._write("map4.txt", "# only comments" + chr(10))
        with self.assertRaises(ValueError):
            session._load_type_map(path)

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            session._load_type_map("no-such-map.txt")


class StatusTest(unittest.TestCase):
    def test_pass_fail_unknown(self):
        self.assertEqual(session._claims_status([{"ok": True}]), "pass")
        self.assertEqual(session._claims_status([{"ok": True}, {"ok": False}]), "fail")
        self.assertEqual(session._claims_status([{"ok": None}]), "unknown")
        self.assertEqual(session._claims_status([{"ok": True}, {"ok": None}]), "unknown")


class NoteClaimKindTest(unittest.TestCase):
    def test_an_uncheckable_claim_is_refused_before_anything_is_written(self):
        # `--assert "size(0x140001008)=123"` used to be stored as an "unknown" claim,
        # which then showed up in every verify/audit forever
        with (
            mock.patch.object(session, "_entry", side_effect=AssertionError("opened")),
            self.assertRaises(ValueError) as cm,
        ):
            session.cmd_note(
                {
                    "binary": "a.exe",
                    "text": "x",
                    "at": "140001008",
                    "assert": "size(140001008)=123",
                }
            )
        self.assertIn("unknown kind", str(cm.exception))
        self.assertIn("size", str(cm.exception))


if __name__ == "__main__":
    unittest.main()


class DecryptTest(unittest.TestCase):
    def test_single_byte_xor_is_recovered(self):
        plain = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        blob = bytes(b ^ 0x5A for b in plain)
        found = session._decrypt_candidates(blob, ["xor"], 0.85)
        self.assertTrue(found)
        top = found[0]
        self.assertEqual(top["cipher"], "xor")
        self.assertEqual(top["key"], hex(0x5A))
        self.assertEqual(top["text"], plain.decode())

    def test_add_and_sub_constants_are_recovered(self):
        plain = b"cmd.exe /c whoami"
        blob = bytes((b + 7) & 0xFF for b in plain)
        found = session._decrypt_candidates(blob, ["add"], 0.85)
        self.assertTrue(any(c["cipher"] == "sub" and c["text"] == plain.decode() for c in found))

    def test_plain_text_is_its_own_xor_zero_candidate(self):
        found = session._decrypt_candidates(b"plain text", ["xor"], 0.85)
        self.assertTrue(any(c["key"] == "0x0" and c["text"] == "plain text" for c in found))

    def test_noise_is_filtered_out(self):
        blob = bytes([0x00, 0xFF] * 8)
        self.assertEqual(session._decrypt_candidates(blob, ["xor"], 0.99), [])

    def test_base64_candidate_is_decoded(self):
        found = session._decrypt_candidates(b"aGVsbG8sIHdvcmxk", ["base64"], 0.85)
        self.assertTrue(any(c["cipher"] == "base64" and "hello, world" in c["text"] for c in found))


class Int32Test(unittest.TestCase):
    """`emulate` reports both the raw RAX and its int32 reading."""

    def test_negative_values_survive_the_wrap(self):
        from ghlab.session import _int32

        self.assertEqual(_int32(0xFFFFFEFC), -260)
        self.assertEqual(_int32(0xFFFFFFFF), -1)
        self.assertEqual(_int32(0x7FFFFFFF), 2147483647)
        self.assertEqual(_int32(1000), 1000)

    def test_high_bits_do_not_leak_into_the_reading(self):
        from ghlab.session import _int32

        # RAX often carries garbage in the upper half; only the low 32 bits matter.
        self.assertEqual(_int32(0xDEADBEEF00000001), 1)
        self.assertEqual(_int32(0x11111111FFFFFEFC), -260)


class StubSpecTest(unittest.TestCase):
    """`emulate --stub` specs: plain returns and argument-dependent returns."""

    def test_plain_and_conditional_specs(self):
        from ghlab.session import _parse_stub_spec

        self.assertEqual(_parse_stub_spec("0x180f5b0a0=0"), ("0x180f5b0a0", None, None, 0))
        target, arg, value, ret = _parse_stub_spec("FUN_1800058c0[arg2=0xe000000b]=120")
        self.assertEqual((target, arg, value, ret), ("FUN_1800058c0", 2, 0xE000000B, 120))

    def test_negative_returns_are_kept_signed(self):
        from ghlab.session import _parse_stub_spec

        self.assertEqual(_parse_stub_spec("FUN_x[arg1=5]=-100")[3], -100)

    def test_bad_specs_are_rejected(self):
        from ghlab.session import _parse_stub_spec

        for bad in ("nope", "FUN_x=", "FUN_x[arg9=1]=2", "=1"):
            with self.subTest(spec=bad), self.assertRaises(ValueError):
                _parse_stub_spec(bad)

    def test_signed_64_wrapping_for_register_writes(self):
        from ghlab.session import _s64

        self.assertEqual(_s64(-100), -100)
        self.assertEqual(_s64(0xFFFF_FFFF_FFFF_FF9C), -100)
        self.assertEqual(_s64(1), 1)


class NoteTextTest(unittest.TestCase):
    """`note` without text, and `note delete=True`, both used to be dead ends."""

    def _call(self, params, notes=None):
        with mock.patch.object(session, "_load_notes", lambda _b: notes if notes else []):
            return session.cmd_note(params)

    def test_delete_without_an_id_says_what_is_missing(self):
        with self.assertRaises(ValueError) as ctx:
            self._call({"binary": "x.exe", "delete": True})
        self.assertIn("delete=<id>", str(ctx.exception))

    def test_neither_text_nor_delete_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            self._call({"binary": "x.exe"})
        self.assertIn("needs text", str(ctx.exception))

    def test_text_is_optional_in_the_spec_so_delete_can_stand_alone(self):
        from ghlab import protocol

        spec = protocol.SPECS["note"]
        self.assertEqual(spec.required, ("binary",))
        self.assertIn("text", spec.optional)


class NotEqualsTest(unittest.TestCase):
    def test_parse_not_equals(self):
        spec = session._parse_claim("decomp!=0x20100")
        self.assertEqual((spec["kind"], spec["op"], spec["value"]), ("decomp", "!=", "0x20100"))

    def test_compare_not_equals(self):
        self.assertTrue(session._compare(5, "!=", 6))
        self.assertFalse(session._compare(5, "!=", 5))

    def test_decomp_is_a_known_kind(self):
        self.assertIn("decomp", session._CLAIM_KINDS)


class DecompClaimTest(unittest.TestCase):
    """`decomp=` judges the note against decompiled C, not instruction immediates."""

    def _entry(self, code):
        res = mock.Mock()
        res.decompileCompleted.return_value = True
        res.getDecompiledFunction.return_value.getC.return_value = code
        return {"decomp": mock.Mock(decompileFunction=mock.Mock(return_value=res))}

    def test_regex_hit(self):
        entry = self._entry("if (iVar8 == 0x20100) {")
        ok, detail = session._claim_decomp(
            entry, object(), session._parse_claim("decomp=0x2010[0]")
        )
        self.assertTrue(ok)
        self.assertIn("1 line(s)", detail)

    def test_miss_reports_scanned_lines(self):
        entry = self._entry("int x = 0;\nint y = 1;")
        ok, detail = session._claim_decomp(entry, object(), session._parse_claim("decomp=0xdead"))
        self.assertFalse(ok)
        self.assertIn("2 line(s) scanned", detail)

    def test_not_equals_passes_only_when_absent(self):
        entry = self._entry("kind = 0x30010;")
        ok, _ = session._claim_decomp(entry, object(), session._parse_claim("decomp!=0xdead"))
        self.assertTrue(ok)
        ok, detail = session._claim_decomp(entry, object(), session._parse_claim("decomp!=0x30010"))
        self.assertFalse(ok)
        self.assertIn("still present", detail)

    def test_unfinished_decompile_is_unjudged(self):
        res = mock.Mock()
        res.decompileCompleted.return_value = False
        entry = {"decomp": mock.Mock(decompileFunction=mock.Mock(return_value=res))}
        ok, detail = session._claim_decomp(entry, object(), session._parse_claim("decomp=x"))
        self.assertIsNone(ok)
        self.assertIn("decompile failed", detail)

    def test_bad_regex_is_a_value_error(self):
        with self.assertRaises(ValueError):
            session._claim_decomp(
                self._entry(""),
                object(),
                session._parse_claim("decomp=("),  # unbalanced
            )
