"""Router: one MCP endpoint, several daemons.

Everything here runs without sockets: the router only needs an object with
`alive()` and `call()`, which is exactly what a fake daemon is.
"""

import os
import pathlib
import shutil
import tempfile
import unittest
from typing import Any
from unittest import mock

from ghlab import config, router


class FakeClient:
    def __init__(self, url: str, binaries: list[str], up: bool = True):
        self.url = url
        self.binaries = binaries
        self.up = up
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def alive(self) -> bool:
        if not self.up:
            raise OSError("connection refused")
        return True

    def call(self, cmd: str, **params: Any) -> Any:
        if not self.up:
            raise OSError("connection refused")
        self.calls.append((cmd, params))
        if cmd == "binaries":
            return {"binaries": list(self.binaries)}
        if cmd == "overview":
            return {"binaries": [{"binary": b, "functions": 1} for b in self.binaries]}
        return {"binary": params.get("binary"), "cmd": cmd}


def target(name: str, port: int, binaries: list[str] | None = None, up: bool = True):
    return config.Target(
        name=name,
        url=f"http://127.0.0.1:{port}",
        project_dir=f"/proj/{name}",
        project_name=name,
    )


class RouterTest(unittest.TestCase):
    def make(self, **kw):
        targets = {
            "ghlab": target("ghlab", 8765, ["notepad.exe"]),
            "wps": target("wps", 8766, ["wpscore.dll", "kso.dll"]),
        }
        clients: dict[str, router.ClientLike] = {
            "ghlab": FakeClient(targets["ghlab"].url, ["notepad.exe"]),
            "wps": FakeClient(targets["wps"].url, ["wpscore.dll", "kso.dll"]),
        }
        return router.Router(targets=targets, default="ghlab", clients=clients, **kw), clients

    def test_a_binary_picks_its_own_daemon(self):
        r, clients = self.make()
        r.call("decompile", binary="wpscore.dll", target="entry")
        self.assertEqual(len(clients["wps"].calls), 2)  # binaries (owner lookup) + decompile
        self.assertEqual(clients["wps"].calls[-1][0], "decompile")
        self.assertEqual([c[0] for c in clients["ghlab"].calls], ["binaries"])

    def test_binary_lookup_is_cached_for_the_ttl(self):
        r, clients = self.make()
        r.call("decompile", binary="wpscore.dll")
        r.call("decompile", binary="kso.dll")
        self.assertEqual(
            [c[0] for c in clients["wps"].calls], ["binaries", "decompile", "decompile"]
        )

    def test_project_argument_wins_and_is_not_forwarded(self):
        r, clients = self.make()
        payload = r.call("decompile", binary="wpscore.dll", project="ghlab")
        self.assertEqual(payload["cmd"], "decompile")
        self.assertNotIn("project", clients["ghlab"].calls[-1][1])

    def test_unknown_binary_names_the_projects_and_what_they_hold(self):
        r, _ = self.make()
        with self.assertRaises(router.RouteError) as cm:
            r.call("decompile", binary="nope.exe")
        message = str(cm.exception)
        self.assertIn("nope.exe", message)
        self.assertIn("wpscore.dll", message)
        self.assertIn("notepad.exe", message)

    def test_ambiguous_binary_asks_for_the_project(self):
        targets = {
            "a": target("a", 8001, ["same.exe"]),
            "b": target("b", 8002, ["same.exe"]),
        }
        clients: dict[str, router.ClientLike] = {
            n: FakeClient(t.url, ["same.exe"]) for n, t in targets.items()
        }
        r = router.Router(targets=targets, default="a", clients=clients)
        with self.assertRaises(router.RouteError) as cm:
            r.call("decompile", binary="same.exe")
        self.assertIn("project=", str(cm.exception))

    def test_focus_binary_is_resolved_through_the_router(self):
        targets = {"wps": target("wps", 8766, ["wpscore.dll"])}
        clients: dict[str, router.ClientLike] = {
            "wps": FakeClient(targets["wps"].url, ["wpscore.dll"])
        }
        r = router.Router(targets=targets, default="wps", clients=clients)
        with mock.patch.object(config, "read_focus", return_value="wpscore.dll"):
            r.call("digest", binary="-")
        self.assertEqual(clients["wps"].calls[-1][1]["binary"], "-")

    def test_diff_needs_both_binaries_in_one_project(self):
        r, _ = self.make()
        with self.assertRaises(router.RouteError) as cm:
            r.call("diff", a="notepad.exe", b="wpscore.dll")
        self.assertIn("one project", str(cm.exception))
        r.call("diff", a="wpscore.dll", b="kso.dll")
        self.assertEqual(r.owners("kso.dll"), ["wps"])

    def test_overview_is_aggregated_from_its_binaries_key(self):
        r, _ = self.make()
        payload = r.call("overview")
        self.assertEqual(
            [row["binary"] for row in payload["overview"]],
            ["notepad.exe", "wpscore.dll", "kso.dll"],
        )
        self.assertEqual({row["project"] for row in payload["overview"]}, {"ghlab", "wps"})

    def test_commands_without_a_binary_go_to_the_default_project(self):
        r, clients = self.make()
        r.call("journal", limit=5)
        self.assertEqual(clients["ghlab"].calls[-1][0], "journal")

    def test_binaries_are_aggregated_and_dead_projects_are_reported(self):
        targets = {
            "ghlab": target("ghlab", 8765, ["notepad.exe"]),
            "wps": target("wps", 8766, ["wpscore.dll"]),
        }
        clients: dict[str, router.ClientLike] = {
            "ghlab": FakeClient(targets["ghlab"].url, ["notepad.exe"]),
            "wps": FakeClient(targets["wps"].url, ["wpscore.dll"], up=False),
        }
        r = router.Router(targets=targets, default="ghlab", clients=clients)
        payload = r.call("binaries")
        self.assertEqual([row["binary"] for row in payload["binaries"]], ["notepad.exe"])
        self.assertEqual(payload["binaries"][0]["project"], "ghlab")
        states = {row["project"]: row["alive"] for row in payload["projects"]}
        self.assertEqual(states, {"ghlab": True, "wps": False})

    def test_autostart_starts_only_the_project_that_owns_the_binary(self):
        targets = {"wps": target("wps", 8766, ["wpscore.dll"])}
        fake = FakeClient(targets["wps"].url, ["wpscore.dll"], up=False)
        clients: dict[str, router.ClientLike] = {"wps": fake}
        started: list[str] = []

        def start(t):
            started.append(t.name)
            fake.up = True
            return True

        r = router.Router(
            targets=targets, default="wps", clients=clients, start=start, autostart=True
        )
        r.call("decompile", binary="wpscore.dll")
        self.assertEqual(started, ["wps"])
        self.assertEqual(clients["wps"].calls[-1][0], "decompile")

    def test_autostart_does_not_loop_when_the_start_fails(self):
        targets = {"wps": target("wps", 8766, ["wpscore.dll"])}
        clients: dict[str, router.ClientLike] = {
            "wps": FakeClient(targets["wps"].url, [], up=False)
        }
        calls: list[int] = []

        def start(_t):
            calls.append(1)
            return False

        r = router.Router(
            targets=targets, default="wps", clients=clients, start=start, autostart=True
        )
        with self.assertRaises(router.RouteError):
            r.call("decompile", binary="wpscore.dll")
        self.assertEqual(calls, [1], "a failed start must be attempted once, not in a loop")

    def test_describe_lists_projects_default_and_binaries(self):
        r, _ = self.make()
        payload = r.describe()
        self.assertEqual(payload["default"], "ghlab")
        self.assertEqual(payload["count"], 2)
        rows = {row["project"]: row for row in payload["projects"]}
        self.assertTrue(rows["ghlab"]["default"])
        self.assertEqual(rows["wps"]["binaries"], ["wpscore.dll", "kso.dll"])

    def test_unknown_project_argument_is_a_clear_error(self):
        r, _ = self.make()
        with self.assertRaises(router.RouteError) as cm:
            r.call("digest", binary="x", project="nope")
        self.assertIn("configured", str(cm.exception))


class ConfigProjectsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ghlab-cfg-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = pathlib.Path(self.tmp, "config.json")
        patcher = mock.patch.dict(os.environ, {"GHLAB_CONFIG": str(self.path)}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("GHLAB_URL", None)

    def test_legacy_single_project_config_still_works(self):
        self.path.write_text(
            '{"ghidra": "g", "project_dir": "/p", "project_name": "wps", "port": 9000}',
            encoding="utf-8",
        )
        known = config.projects()
        self.assertEqual(list(known), ["wps"])
        self.assertEqual(known["wps"].url, "http://127.0.0.1:9000")
        self.assertEqual(config.default_project(), "wps")

    def test_registering_a_second_project_keeps_the_first(self):
        self.path.write_text(
            '{"project_dir": "/proj/one", "project_name": "one", "port": 8765}',
            encoding="utf-8",
        )
        config.register_project(
            "two", url="http://127.0.0.1:8766", project_dir="/x", project_name="two"
        )
        known = config.projects()
        self.assertEqual(sorted(known), ["one", "two"])
        self.assertEqual(config.default_project(), "one")

    def test_make_default_switches_the_legacy_keys_too(self):
        config.register_project(
            "a", url="http://127.0.0.1:8001", project_dir="/a", project_name="a"
        )
        config.register_project(
            "b", url="http://127.0.0.1:8002", project_dir="/b", project_name="b", make_default=True
        )
        cfg = config.load_config()
        self.assertEqual(cfg["default"], "b")
        self.assertEqual(cfg["project_dir"], "/b")
        self.assertEqual(cfg["port"], 8002)

    def test_remove_project_moves_the_default(self):
        config.register_project(
            "a", url="http://127.0.0.1:8001", project_dir="/a", project_name="a"
        )
        config.register_project(
            "b", url="http://127.0.0.1:8002", project_dir="/b", project_name="b"
        )
        self.assertTrue(config.remove_project("a"))
        self.assertEqual(config.default_project(), "b")
        self.assertFalse(config.remove_project("a"))


if __name__ == "__main__":
    unittest.main()
