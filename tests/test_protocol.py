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

    def test_scan_needs_an_offset_and_rejects_junk(self):
        spec, params = protocol.validate({"cmd": "scan", "binary": "a.exe", "offset": "0x54"})
        self.assertEqual(spec.name, "scan")
        self.assertEqual(params, {"binary": "a.exe", "offset": "0x54"})
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "scan", "binary": "a.exe"})
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "scan", "binary": "a.exe", "offset": "0x54", "nope": 1})


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
        for name in ("patch", "set_type", "bookmark", "note", "notes", "verify", "report"):
            self.assertIn(name, protocol.COMMAND_NAMES)

    def test_pdb_requires_a_file(self):
        with self.assertRaises(protocol.ProtocolError) as ctx:
            protocol.validate({"cmd": "pdb", "binary": "x"})
        self.assertIn("file", str(ctx.exception))
        _spec, params = protocol.validate({"cmd": "pdb", "binary": "x", "file": "a.pdb"})
        self.assertEqual(params["file"], "a.pdb")

    def test_index_takes_an_optional_refresh(self):
        _spec, params = protocol.validate({"cmd": "index", "binary": "x"})
        self.assertEqual(params, {"binary": "x"})
        _spec, params = protocol.validate({"cmd": "index", "binary": "x", "refresh": True})
        self.assertTrue(params["refresh"])

    def test_types_requires_a_map_file(self):
        with self.assertRaises(protocol.ProtocolError) as ctx:
            protocol.validate({"cmd": "types", "binary": "x"})
        self.assertIn("from", str(ctx.exception))
        _spec, params = protocol.validate(
            {"cmd": "types", "binary": "x", "from": "m.txt", "dry_run": True}
        )
        self.assertTrue(params["dry_run"])

    def test_map_is_declared_and_validated(self):
        _spec, params = protocol.validate(
            {"cmd": "map", "binary": "x", "from": "import:RegSetValueExW", "op": "decompile"}
        )
        self.assertEqual(params["op"], "decompile")
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "map", "binary": "x", "selector": "all"})

    def test_decrypt_needs_hex_or_a_binary(self):
        _spec, params = protocol.validate({"cmd": "decrypt", "hex": "48 65 6c 6c 6f"})
        self.assertEqual(params["hex"], "48 65 6c 6c 6f")
        _spec, params = protocol.validate({"cmd": "decrypt", "binary": "x", "addr": "0x14000"})
        self.assertEqual(params["binary"], "x")
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "decrypt", "cipher": "xor"})

    def test_emulate_accepts_seeds(self):
        _spec, params = protocol.validate(
            {"cmd": "emulate", "binary": "x", "target": "f", "seed": ["0x140000000=4142"]}
        )
        self.assertEqual(params["seed"], ["0x140000000=4142"])

    def test_emulate_accepts_call_stubs(self):
        _spec, params = protocol.validate(
            {
                "cmd": "emulate",
                "binary": "x",
                "target": "f",
                "stub": ["FUN_1800058c0[arg2=0xe000000b]=120"],
            }
        )
        self.assertEqual(params["stub"], ["FUN_1800058c0[arg2=0xe000000b]=120"])

    def test_note_accepts_claims_and_verify_takes_ids(self):
        _spec, params = protocol.validate(
            {"cmd": "note", "binary": "x", "text": "t", "at": "entry", "assert": ["const=1"]}
        )
        self.assertEqual(params["assert"], ["const=1"])
        _spec, params = protocol.validate({"cmd": "verify", "binary": "x", "id": [1, 2]})
        self.assertEqual(params["id"], [1, 2])
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "verify", "binary": "x", "claim": "x"})

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
        _spec, params = protocol.validate({"cmd": "digest", "binary": "a.exe", "top": 3})
        self.assertEqual(params["top"], 3)
        _spec, params = protocol.validate(
            {"cmd": "find", "binary": "a.exe", "import": ["VirtualAlloc"], "any": True}
        )
        self.assertEqual(params["import"], ["VirtualAlloc"])
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "find", "binary": "a.exe", "name": "x"})

    def test_cross_binary_commands_validate(self):
        for cmd, params in (
            ("cross_xref", {"query": "example.com"}),
            ("slice", {"binary": "a.exe", "to": "CreateProcessW"}),
            ("similar", {"binary": "a.exe", "target": "entry"}),
        ):
            spec, got = protocol.validate({"cmd": cmd, **params})
            self.assertEqual(spec.name, cmd)
            self.assertEqual(got, params)
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "cross_xref"})
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "slice", "binary": "a.exe"})
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "decompile", "binary": "a.exe", "cached": True})

    def test_campaign_takes_only_optional_filters(self):
        spec, params = protocol.validate({"cmd": "campaign"})
        self.assertEqual(spec.required, ())
        self.assertEqual(params, {})
        spec, params = protocol.validate({"cmd": "campaign", "min_score": 0.6, "limit": 3})
        self.assertEqual(params, {"min_score": 0.6, "limit": 3})
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "campaign", "threshold": 0.6})

    def test_imports_is_declared_and_validated(self):
        spec = protocol.SPECS["imports"]
        self.assertEqual(spec.required, ("binary",))
        self.assertIn("group", spec.optional)
        self.assertIn("refs", protocol.SPECS["strings"].optional)
        protocol.validate({"cmd": "imports", "binary": "x", "group": "registry"})
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate({"cmd": "imports"})


if __name__ == "__main__":
    unittest.main()
