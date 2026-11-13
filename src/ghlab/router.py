"""One MCP endpoint, many daemons.

An agent should not need one MCP entry per Ghidra project. The router looks at the
arguments a tool already takes -- ``binary``, or the ``a``/``b`` pair of ``diff`` --
and asks each daemon which binaries it owns, then forwards the call to the owner.

Resolution order:

1. ``project=<name>`` in the arguments (explicit wins, and is stripped before the call).
2. The binary named by ``binary`` / ``a`` / ``b`` (``-`` means the focus binary).
3. If nothing names a binary: the default project; ``binaries`` and ``overview``
   are aggregated across every daemon that answers, because that is the question
   "what do I have?" rather than "tell me about this project".
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable
from typing import Any, Protocol

from . import config
from .client import Client, RemoteError


class ClientLike(Protocol):
    """What the router needs from a daemon handle (Client in production, a fake in tests)."""

    def alive(self) -> bool: ...

    def call(self, cmd: str, **params: Any) -> Any: ...

    def info(self) -> dict[str, Any]: ...


AGGREGATE = ("binaries", "overview")
DIFF_PAIR = ("a", "b")


class RouteError(RuntimeError):
    """The call cannot be sent as asked; the message says what to do about it."""


class Router:
    def __init__(
        self,
        targets: dict[str, config.Target] | None = None,
        default: str | None = None,
        *,
        clients: dict[str, ClientLike] | None = None,
        start: Callable[[config.Target], bool] | None = None,
        autostart: bool = False,
        ttl: float = 15.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.targets = targets if targets is not None else config.projects()
        if not self.targets:
            raise RouteError("no Ghidra project configured; run `ghlab setup --ghidra DIR`")
        self.default = default if default in self.targets else next(iter(self.targets))
        self._clients = clients or {}
        self._start = start
        self.autostart = autostart
        self.ttl = ttl
        self._clock = clock
        self._cache: dict[str, tuple[float, list[str]]] = {}

    # ---- targets -----------------------------------------------------------
    def client(self, name: str) -> ClientLike:
        target = self.targets[name]
        client = self._clients.get(name)
        if client is None:
            client = self._clients[name] = Client(url=target.url)
        return client

    def target(self, name: str) -> config.Target:
        try:
            return self.targets[name]
        except KeyError:
            known = ", ".join(self.targets)
            raise RouteError(f"unknown project {name!r}; configured: {known}") from None

    def _match(self, wanted: str) -> str:
        """Accept a project name, its project_name, its URL or a unique prefix."""
        if wanted in self.targets:
            return wanted
        for name, target in self.targets.items():
            if wanted in (target.url, target.project_name, target.project_dir):
                return name
        hits = [n for n in self.targets if n.startswith(wanted)]
        if len(hits) == 1:
            return hits[0]
        known = ", ".join(self.targets)
        raise RouteError(f"unknown project {wanted!r}; configured: {known}")

    def alive(self, name: str) -> bool:
        try:
            return self.client(name).alive()
        except (RemoteError, OSError):
            return False

    def binaries(self, name: str, *, refresh: bool = False) -> list[str]:
        cached = self._cache.get(name)
        if cached is not None and not refresh and self._clock() - cached[0] < self.ttl:
            return cached[1]
        try:
            payload = self.client(name).call("binaries")
        except (RemoteError, OSError):
            return []
        names = [str(b) for b in payload.get("binaries") or []]
        self._cache[name] = (self._clock(), names)
        return names

    def _hits(self, binary: str) -> list[tuple[str, str]]:
        """(project, real name) pairs naming this binary; exact names beat substrings.

        The daemons accept a unique substring, so the router has to resolve one the
        same way or a call that the owner would happily serve dies in routing.
        """
        exact: list[tuple[str, str]] = []
        loose: list[tuple[str, str]] = []
        needle = binary.lower()
        for name in self.targets:
            for known in self.binaries(name):
                if known == binary:
                    exact.append((name, known))
                elif needle in known.lower():
                    loose.append((name, known))
        return exact or loose

    def owners(self, binary: str) -> list[str]:
        seen: list[str] = []
        for name, _ in self._hits(binary):
            if name not in seen:
                seen.append(name)
        return seen

    def _owner_for(self, binary: str) -> str:
        if binary == "-":
            binary = config.read_focus()
            if not binary:
                raise RouteError("no focus binary; run `ghlab use <binary>` or name one explicitly")
        hits = self._hits(binary)
        owners = self.owners(binary)
        if not hits:
            seen = "; ".join(
                f"{name}: {', '.join(self.binaries(name, refresh=True)[:6]) or '(down)'}"
                for name in self.targets
            )
            raise RouteError(f"binary {binary!r} is in no configured project ({seen})")
        if len(hits) == 1:
            return hits[0][0]
        if len(owners) > 1:
            raise RouteError(
                f"binary {binary!r} is in several projects ({', '.join(owners)}); "
                f"add project=<one of them>"
            )
        names = ", ".join(known for _, known in hits)
        raise RouteError(
            f"binary {binary!r} matches several programs in {owners[0]} ({names}); name one exactly"
        )

    # ---- routing -----------------------------------------------------------
    def resolve(self, cmd: str, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        params = dict(params)
        forced = params.pop("project", None)
        if forced:
            return self._match(str(forced)), params
        if cmd == "import":
            # The path decides, and only the default project takes new binaries.
            return self.default, params
        if cmd in AGGREGATE:
            return self.default, params
        if cmd == "diff":
            left = str(params.get("a") or "")
            right = str(params.get("b") or "")
            names = {self._owner_for(left), self._owner_for(right)}
            if len(names) != 1:
                raise RouteError(
                    f"diff needs both binaries in one project; {left!r} and {right!r} are in "
                    f"{', '.join(sorted(names))} — import them into one project first"
                )
            return names.pop(), params
        binary = params.get("binary")
        if binary:
            return self._owner_for(str(binary)), params
        return self.default, params

    def _collect(
        self, cmd: str, params: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Ask every daemon that is up, and note which ones were down."""
        merged: list[dict[str, Any]] = []
        projects: list[dict[str, Any]] = []
        for name in self.targets:
            up = self.alive(name)
            projects.append({"project": name, "url": self.targets[name].url, "alive": up})
            if not up:
                continue
            try:
                payload = self.client(name).call(cmd, **params)
            except (RemoteError, OSError) as ex:
                projects[-1]["error"] = str(ex)
                continue
            # `overview` answers under "binaries" too (it is the same list, enriched).
            for item in payload.get(cmd) or payload.get("binaries") or []:
                row = {"binary": item} if isinstance(item, str) else dict(item)
                row["project"] = name
                merged.append(row)
        return merged, projects

    def _aggregate(self, cmd: str, params: dict[str, Any]) -> dict[str, Any]:
        started = time.monotonic()
        merged, projects = self._collect(cmd, params)
        if not any(row["alive"] for row in projects) and self.autostart and self._start:
            # `overview` is an agent's first question; an empty answer would read as
            # "no programs" when the truth is "no daemon".  Start the default one.
            self._start(self.targets[self.default])
            merged, projects = self._collect(cmd, params)
        if not merged and not any(row["alive"] for row in projects):
            # An empty list would read as "this project has no programs" when the
            # truth is "nothing is running": say which, so the caller can start one.
            names = ", ".join(row["project"] for row in projects)
            raise RouteError(
                f"no daemon is running ({names}); `ghlab start` starts the default one, "
                "and any call that names a binary starts the project that owns it"
            )
        return {
            cmd: merged,
            "projects": projects,
            "elapsed_ms": int(1000 * (time.monotonic() - started)),
        }

    def call(self, cmd: str, **params: Any) -> Any:
        if cmd == "projects":
            return self.describe(refresh=bool(params.get("refresh")))
        if cmd in AGGREGATE and not params.get("project"):
            return self._aggregate(cmd, params)
        try:
            name, clean = self.resolve(cmd, params)
        except RouteError:
            # A down daemon cannot say which binaries it holds, so the owner lookup
            # fails before autostart gets a chance: start the default first, look
            # again, and only then touch the next project.
            if not (self.autostart and self._start is not None):
                raise
            name, clean = self._start_owner(cmd, params)
        try:
            return self.client(name).call(cmd, **clean)
        except (RemoteError, OSError):
            if not (self.autostart and not self.alive(name) and self._start is not None):
                raise
            if not self._start(self.targets[name]):
                raise
            return self.client(name).call(cmd, **clean)

    def _start_owner(self, cmd: str, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Start daemons one at a time until one of them owns the binary.

        Starting every project on the first miss costs one JVM each (~1 GB, 30-60 s)
        for a binary that only one of them has -- and left the rest running.  The
        default project is tried first because that is where `import` puts things.
        """
        order = [self.default] + [name for name in self.targets if name != self.default]
        for name in order:
            if self._start is None or self.alive(name):
                continue
            if not self._start(self.targets[name]):
                continue
            self._cache.pop(name, None)
            try:
                return self.resolve(cmd, params)
            except RouteError:
                continue  # this one was up already, just not the owner
        return self.resolve(cmd, params)  # raises with the current picture

    # ---- introspection -----------------------------------------------------
    def describe(self, *, refresh: bool = False) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        for name, target in self.targets.items():
            up = self.alive(name)
            row: dict[str, Any] = {
                "project": name,
                "url": target.url,
                "project_dir": target.project_dir,
                "project_name": target.project_name,
                "default": name == self.default,
                "alive": up,
                "binaries": self.binaries(name, refresh=refresh) if up else [],
            }
            if up:
                # what the daemon says it has open beats what the config says it should
                # have: a --url override or a moved project made the two disagree, and
                # `projects` printed the config path next to the daemon's binary count
                reported = ""
                with contextlib.suppress(Exception):
                    reported = str(self.client(name).info().get("project") or "")
                if reported and reported != target.project_dir:
                    row["configured_project_dir"] = target.project_dir
                    row["project_dir"] = reported
            rows.append(row)
        return {"projects": rows, "default": self.default, "count": len(rows)}


def from_config(
    *,
    start: Callable[[config.Target], bool] | None = None,
    autostart: bool = False,
) -> Router:
    cfg = config.load_config()
    return Router(
        targets=config.projects(cfg),
        default=config.default_project(cfg),
        start=start,
        autostart=autostart,
    )
