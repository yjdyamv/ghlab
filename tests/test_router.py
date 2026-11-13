"""Router: one MCP endpoint, several daemons.

Everything here runs without sockets: the router only needs an object with
`alive()` and `call()`, which is exactly what a fake daemon is.
"""

import os
import pathlib
import shutil
import tempfile
import time
import unittest
from typing import Any
from unittest import mock

from ghlab import config, router


class FakeClient:
    def __init__(self, url: str, binaries: list[str], up: bool = True, project: str = ""):
        self.url = url
        self.binaries = binaries
        self.up = up
        self.project = project
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def info(self) -> dict[str, Any]:
        if not self.up:
            raise OSError("connection refused")
        return {"project": self.project} if self.project else {}

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


class LazyClient(FakeClient):
    """A daemon that only answers once its process exists."""

    def alive(self) -> bool:
        return self.up

    def call(self, cmd: str, **params: Any) -> Any:
        if not self.up:
            raise OSError("connection refused")
        return super().call(cmd, **params)


class AutostartTest(unittest.TestCase):
    def make(self, owners: dict[str, list[str]]):
        targets = {name: target(name, 8100 + i) for i, name in enumerate(owners)}
        clients = {n: LazyClient(t.url, owners[n], up=False) for n, t in targets.items()}
        started: list[str] = []

        def start(t):
            started.append(t.name)
            clients[t.name].up = True
            return True

        r = router.Router(
            targets=targets, default="a", clients=clients, start=start, autostart=True
        )
        return r, started

    def test_it_starts_the_default_first_and_stops_there(self):
        r, started = self.make({"a": ["x.exe"], "b": [], "c": []})
        r.call("decompile", binary="x.exe")
        self.assertEqual(started, ["a"])

    def test_it_walks_to_the_owner_one_daemon_at_a_time(self):
        r, started = self.make({"a": [], "b": [], "c": ["x.exe"]})
        r.call("decompile", binary="x.exe")
        self.assertEqual(started, ["a", "b", "c"])

    def test_when_nobody_owns_it_the_error_still_names_the_projects(self):
        r, started = self.make({"a": [], "b": []})
        with self.assertRaises(router.RouteError) as cm:
            r.call("decompile", binary="nope.exe")
        self.assertEqual(started, ["a", "b"])
        self.assertIn("nope.exe", str(cm.exception))

    def test_autostart_off_means_no_daemon_is_started(self):
        targets = {"a": target("a", 8100)}
        started: list[str] = []
        r = router.Router(
            targets=targets,
            default="a",
            clients={"a": LazyClient(targets["a"].url, [], up=False)},
            start=lambda t: started.append(t.name) or True,
            autostart=False,
        )
        with self.assertRaises(router.RouteError):
            r.call("decompile", binary="x.exe")
        self.assertEqual(started, [])


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

    def test_a_daemon_that_says_it_is_down_is_down(self):
        # Client.alive() reports False instead of raising; the router used to ignore the
        # answer and call every configured project alive, which made autostart a no-op.
        class Refusing(FakeClient):
            def alive(self) -> bool:
                return False

        targets = {"ghlab": target("ghlab", 8765, ["notepad.exe"])}
        r = router.Router(
            targets=targets,
            default="ghlab",
            clients={"ghlab": Refusing(targets["ghlab"].url, ["notepad.exe"])},
        )
        self.assertFalse(r.alive("ghlab"))

    def test_a_daemon_that_raises_on_the_probe_is_down(self):
        targets = {"ghlab": target("ghlab", 8765, ["notepad.exe"])}
        r = router.Router(
            targets=targets,
            default="ghlab",
            clients={"ghlab": FakeClient(targets["ghlab"].url, [], up=False)},
        )
        self.assertFalse(r.alive("ghlab"))

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

    def test_unique_substring_reaches_the_owner_like_the_daemon_would(self):
        r, clients = self.make()
        r.call("decompile", binary="notepad")
        self.assertEqual(clients["ghlab"].calls[-1][1]["binary"], "notepad")

    def test_substring_that_hits_two_programs_asks_for_the_exact_name(self):
        targets = {"a": target("a", 8001, ["libmwservices.dll", "libmwservices_api.dll"])}
        clients: dict[str, router.ClientLike] = {
            "a": FakeClient(targets["a"].url, ["libmwservices.dll", "libmwservices_api.dll"])
        }
        r = router.Router(targets=targets, default="a", clients=clients)
        with self.assertRaises(router.RouteError) as cm:
            r.call("decompile", binary="libmw")
        self.assertIn("libmwservices.dll", str(cm.exception))
        r.call("decompile", binary="libmwservices.dll")

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

    def test_aggregation_says_nothing_is_running_instead_of_returning_nothing(self):
        # `{"overview": []}` reads as "the project holds no programs"; with every
        # daemon down the honest answer is "nothing is running, start one".
        targets = {
            "ghlab": target("ghlab", 8765, ["notepad.exe"]),
            "wps": target("wps", 8766, ["wpscore.dll"]),
        }
        clients: dict[str, router.ClientLike] = {
            "ghlab": FakeClient(targets["ghlab"].url, ["notepad.exe"], up=False),
            "wps": FakeClient(targets["wps"].url, ["wpscore.dll"], up=False),
        }
        r = router.Router(targets=targets, default="ghlab", clients=clients)
        with self.assertRaises(router.RouteError) as cm:
            r.call("overview")
        self.assertIn("no daemon is running", str(cm.exception))
        self.assertIn("ghlab start", str(cm.exception))

    def test_an_aggregate_starts_the_default_and_answers(self):
        # An agent's first call is usually `overview`; with nothing running it must
        # start one daemon and answer, not hand back a dead end it cannot act on.
        targets = {
            "ghlab": target("ghlab", 8765, ["notepad.exe"]),
            "wps": target("wps", 8766, ["wpscore.dll"]),
        }
        clients: dict[str, router.ClientLike] = {
            "ghlab": FakeClient(targets["ghlab"].url, ["notepad.exe"], up=False),
            "wps": FakeClient(targets["wps"].url, ["wpscore.dll"], up=False),
        }
        started: list[str] = []

        def start(t):
            started.append(t.name)
            clients["ghlab"] = FakeClient(targets["ghlab"].url, ["notepad.exe"])
            return True

        r = router.Router(
            targets=targets, default="ghlab", clients=clients, start=start, autostart=True
        )
        payload = r.call("overview")
        self.assertEqual(started, ["ghlab"])
        self.assertEqual([row["binary"] for row in payload["overview"]], ["notepad.exe"])

    def test_a_running_but_empty_project_still_answers_with_an_empty_list(self):
        targets = {"ghlab": target("ghlab", 8765, [])}
        clients: dict[str, router.ClientLike] = {"ghlab": FakeClient(targets["ghlab"].url, [])}
        r = router.Router(targets=targets, default="ghlab", clients=clients)
        self.assertEqual(r.call("overview")["overview"], [])

    def test_aggregation_reports_how_long_it_took(self):
        # `elapsed_ms` used to be a hardcoded 0, which made "why is `binaries` slow
        # with five projects?" unanswerable from the tool's own output.
        targets = {
            "ghlab": target("ghlab", 8765, ["notepad.exe"]),
            "wps": target("wps", 8766, ["wpscore.dll"]),
        }

        class SlowClient(FakeClient):
            def call(self, cmd, **params):
                time.sleep(0.02)
                return super().call(cmd, **params)

        clients: dict[str, router.ClientLike] = {
            "ghlab": SlowClient(targets["ghlab"].url, ["notepad.exe"]),
            "wps": SlowClient(targets["wps"].url, ["wpscore.dll"]),
        }
        payload = router.Router(targets=targets, default="ghlab", clients=clients).call("binaries")
        self.assertGreaterEqual(payload["elapsed_ms"], 30)

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


class DiscoverTest(unittest.TestCase):
    """Finding projects Ghidra (or a human) already created, without hand-typed paths."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="ghlab-disc-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def project(self, name: str, *, rep: bool = True, sub: str = "") -> pathlib.Path:
        d = self.root / sub / name if sub else self.root / name
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{name}.gpr").write_text("", encoding="utf-8")
        if rep:
            (d / f"{name}.rep").mkdir()
        return d

    def test_finds_a_project_only_when_gpr_and_rep_are_both_there(self):
        good = self.project("good")
        self.project("stray", rep=False)
        found = config.discover_projects([self.root], known={}, base_port=8700)
        self.assertEqual([t.name for t in found], ["good"])
        self.assertEqual(found[0].project_dir, str(good))
        self.assertEqual(found[0].project_name, "good")

    def test_nested_projects_are_found(self):
        self.project("deep", sub="a/b/c")
        found = config.discover_projects([self.root], known={}, base_port=8700)
        self.assertEqual([t.name for t in found], ["deep"])

    def test_already_registered_directories_and_names_are_skipped(self):
        d = self.project("known")
        self.project("samename")
        known = {
            "renamed": config.Target(
                name="renamed",
                url="http://127.0.0.1:8700",
                project_dir=str(d),
                project_name="known",
            ),
            "samename": config.Target(
                name="samename",
                url="http://127.0.0.1:8701",
                project_dir="/elsewhere",
                project_name="samename",
            ),
        }
        self.assertEqual(config.discover_projects([self.root], known=known, base_port=8700), [])

    def test_ports_skip_registered_and_busy_ones(self):
        self.project("a")
        self.project("b")
        known = {
            "other": config.Target(
                name="other", url="http://127.0.0.1:8701", project_dir="/x", project_name="other"
            )
        }
        with mock.patch.object(config, "port_free", side_effect=lambda port, *_: port != 8702):
            found = config.discover_projects([self.root], known=known, base_port=8701)
        self.assertEqual([t.url.rsplit(":", 1)[-1] for t in found], ["8703", "8704"])

    def test_limit_stops_the_scan(self):
        for name in ("a", "b", "c"):
            self.project(name)
        found = config.discover_projects([self.root], known={}, base_port=8700, limit=2)
        self.assertEqual(len(found), 2)

    def test_missing_root_is_not_an_error(self):
        self.assertEqual(config.discover_projects([self.root / "nope"], known={}), [])

    def test_projects_shows_the_directory_the_daemon_has_open(self):
        # a --url override (or a moved project) makes the config path a lie while the
        # daemon's own answer stays true; the row used to print the config path beside
        # the daemon's binary count
        targets = {"ghlab": target("ghlab", 8765, ["notepad.exe"])}
        clients: dict[str, router.ClientLike] = {
            "ghlab": FakeClient(
                targets["ghlab"].url, ["notepad.exe"], project="C:/tmp/jvmcheck/jvmcheck"
            )
        }
        r = router.Router(targets=targets, default="ghlab", clients=clients)
        row = r.describe()["projects"][0]
        self.assertEqual(row["project_dir"], "C:/tmp/jvmcheck/jvmcheck")
        self.assertEqual(row["configured_project_dir"], "/proj/ghlab")

    def test_projects_keeps_the_config_path_when_the_daemon_agrees(self):
        targets = {"ghlab": target("ghlab", 8765, ["notepad.exe"])}
        clients: dict[str, router.ClientLike] = {
            "ghlab": FakeClient(targets["ghlab"].url, ["notepad.exe"], project="/proj/ghlab")
        }
        r = router.Router(targets=targets, default="ghlab", clients=clients)
        row = r.describe()["projects"][0]
        self.assertEqual(row["project_dir"], "/proj/ghlab")
        self.assertNotIn("configured_project_dir", row)


if __name__ == "__main__":
    unittest.main()
