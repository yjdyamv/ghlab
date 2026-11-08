import json
import unittest

from ghlab import protocol


class ValidateTest(unittest.TestCase):
    def test_unknown_command_lists_known(self):
        with self.assertRaises(protocol.ProtocolError) as ctx:
            protocol.validate({"cmd": "nope"})
        self.assertIn("unknown cmd", str(ctx.exception))
        self.assertIn("decompile", str(ctx.exception))

    def test_missing_required(self):
        with self.assertRaises(protocol.ProtocolError) as ctx:
            protocol.validate({"cmd": "info"})
        self.assertIn("missing", str(ctx.exception))
        self.assertIn("binary", str(ctx.exception))

    def test_unknown_parameter_is_rejected(self):
        with self.assertRaises(protocol.ProtocolError) as ctx:
            protocol.validate({"cmd": "info", "binary": "a.exe", "bogus": 1})
        self.assertIn("unknown parameter", str(ctx.exception))

    def test_valid_request_passes_params_through(self):
        spec, params = protocol.validate(
            {"cmd": "decompile", "binary": "a.exe", "match": "FUN_.*", "grep": "memcpy"}
        )
        self.assertEqual(spec.name, "decompile")
        self.assertEqual(params, {"binary": "a.exe", "match": "FUN_.*", "grep": "memcpy"})

    def test_command_list_is_documented(self):
        overview = {
            name: {"required": s.required, "optional": s.optional}
            for name, s in protocol.SPECS.items()
        }
        self.assertIn("decompile", overview)
        self.assertIn("binary", overview["decompile"]["required"])


class EnvelopeTest(unittest.TestCase):
    def test_ok_roundtrip(self):
        payload = json.loads(protocol.Ok({"a": 1}, ms=7).to_bytes())
        self.assertEqual(payload, {"ok": True, "ms": 7, "result": {"a": 1}})

    def test_err_roundtrip(self):
        payload = json.loads(protocol.Err("boom", trace="tb").to_bytes())
        self.assertEqual(payload, {"ok": False, "error": "boom", "trace": "tb"})

    def test_non_ascii_survives(self):
        payload = json.loads(protocol.Ok({"text": "你好"}).to_bytes())
        self.assertEqual(payload["result"]["text"], "你好")

    def test_digest_and_find_are_declared(self):
        self.assertIn("digest", protocol.COMMAND_NAMES)
        self.assertIn("find", protocol.COMMAND_NAMES)

    def test_write_commands_are_declared(self):
        for name in ("patch", "set_type", "bookmark", "note", "notes", "report"):
            self.assertIn(name, protocol.COMMAND_NAMES)

    def test_patch_requires_address(self):
        with self.assertRaises(protocol.ProtocolError) as ctx:
            protocol.validate({"cmd": "patch", "binary": "x"})
        self.assertIn("addr", str(ctx.exception))

    def test_set_type_requires_declaration(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "set_type", "binary": "x", "target": "entry"})

    def test_notes_reject_unknown_parameter(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "notes", "binary": "x", "tagz": "y"})
        spec, params = protocol.validate({"cmd": "digest", "binary": "a.exe", "top": 3})
        self.assertEqual(params["top"], 3)
        spec, params = protocol.validate(
            {"cmd": "find", "binary": "a.exe", "import": ["VirtualAlloc"], "any": True}
        )
        self.assertEqual(params["import"], ["VirtualAlloc"])
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "find", "binary": "a.exe", "name": "x"})


if __name__ == "__main__":
    unittest.main()
