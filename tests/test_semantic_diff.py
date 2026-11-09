"""Unit tests for the semantic half of `ghlab diff --semantic`.

`_semantic_delta` is pure set arithmetic, so these run without a daemon: they pin
down the contract the CLI and the MCP tool rely on — counts stay truthful even
when the printed lists are capped.
"""

import unittest

from ghlab import session


def profile(imports=None, strings=None, consts=None):
    """Build a `_semantic_profile`-shaped dict without touching Ghidra."""
    return {
        "imports": dict(imports or {}),
        "strings": set(strings or ()),
        "consts": set(consts or ()),
    }


class SemanticDeltaTest(unittest.TestCase):
    def test_identical_profiles_are_empty(self):
        left = profile({"RegSetValueExW": "registry"}, ["Software\\X"], [0x41])
        delta = session._semantic_delta(
            left, profile({"RegSetValueExW": "registry"}, ["Software\\X"], [0x41])
        )
        self.assertEqual(delta["imports"]["counts"], {"added": 0, "removed": 0})
        self.assertEqual(delta["strings"]["counts"], {"added": 0, "removed": 0})
        self.assertEqual(delta["constants"]["counts"], {"added": 0, "removed": 0})
        self.assertFalse(delta["truncated"])

    def test_new_api_is_reported_with_its_risk_group(self):
        left = profile({"RegOpenKeyExW": "registry"})
        right = profile(
            {"RegOpenKeyExW": "registry", "CreateRemoteThread": "inject", "Unknown": None}
        )
        delta = session._semantic_delta(left, right)
        self.assertEqual(delta["imports"]["added"], ["CreateRemoteThread", "Unknown"])
        self.assertEqual(delta["imports"]["counts"]["added"], 2)
        self.assertEqual(delta["imports"]["by_risk"]["inject"], {"added": 1, "removed": 0})
        self.assertEqual(delta["imports"]["by_risk"]["other"], {"added": 1, "removed": 0})

    def test_removed_api_keeps_the_group_it_had(self):
        left = profile({"WinExec": "exec"})
        delta = session._semantic_delta(left, profile())
        self.assertEqual(delta["imports"]["removed"], ["WinExec"])
        self.assertEqual(delta["imports"]["by_risk"]["exec"], {"added": 0, "removed": 1})

    def test_strings_are_compared_by_value_not_by_address(self):
        left = profile(strings=["http://a.example/", "same"])
        right = profile(strings=["http://a.example/", "same", "http://b.example/"])
        delta = session._semantic_delta(left, right)
        self.assertEqual(delta["strings"]["added"], ["http://b.example/"])
        self.assertEqual(delta["strings"]["removed"], [])

    def test_constants_are_hex_and_sorted(self):
        delta = session._semantic_delta(profile(consts=[1]), profile(consts=[1, 0xDEADBEEF]))
        self.assertEqual(delta["constants"]["added"], ["0xdeadbeef"])
        self.assertEqual(delta["constants"]["removed"], [])

    def test_lists_are_capped_but_counts_are_not(self):
        left = profile()
        right = profile(strings=[f"s{i:03d}" for i in range(200)])
        delta = session._semantic_delta(left, right, limit=40)
        self.assertEqual(len(delta["strings"]["added"]), 40)
        self.assertEqual(delta["strings"]["counts"]["added"], 200)
        self.assertTrue(delta["truncated"])

    def test_cap_is_not_flagged_when_nothing_was_dropped(self):
        delta = session._semantic_delta(
            profile(), profile(strings=[f"s{i}" for i in range(40)]), limit=40
        )
        self.assertEqual(len(delta["strings"]["added"]), 40)
        self.assertFalse(delta["truncated"])


class DeltaHexTest(unittest.TestCase):
    """`_delta` used to call hex() on values diff_set had already stringified."""

    def row(self, consts, strings=(), imports=()):
        return {
            "size": 10,
            "insns": 3,
            "blocks": 1,
            "calls": 0,
            "strings": set(strings),
            "imports": set(imports),
            "consts": set(consts),
        }

    def test_constants_are_hex_even_though_diff_set_stringifies(self):
        delta = session._delta(self.row({0x41}), self.row({0x42}), limit=5)
        self.assertEqual(delta["consts_added"], ["0x42"])
        self.assertEqual(delta["consts_removed"], ["0x41"])

    def test_cached_string_constants_still_format(self):
        self.assertEqual(session._hex_const("65"), "0x41")
        self.assertEqual(session._hex_const(65), "0x41")
        self.assertEqual(session._hex_const("0x41"), "0x41")
        self.assertEqual(session._hex_const("nonsense"), "nonsense")

    def test_strings_and_imports_stay_text(self):
        delta = session._delta(
            self.row(set(), strings=["old"], imports=["LoadIconW"]),
            self.row(set(), strings=["new"], imports=["LoadImageW"]),
            limit=5,
        )
        self.assertEqual(delta["strings_added"], ["new"])
        self.assertEqual(delta["imports_removed"], ["LoadIconW"])


if __name__ == "__main__":
    unittest.main()
