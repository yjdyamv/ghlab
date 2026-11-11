"""Machine-local setup: where Ghidra lives, and which daemon owns which project.

Two files, both optional:

- ``~/.ghlab/config.json`` -- ``ghidra``, ``projects`` (name -> daemon), ``default``.
  Written by ``ghlab setup``; every value has an environment variable that wins.
- ``~/.ghlab/focus`` -- the binary a bare ``-`` refers to.

The single-project legacy layout (``project_dir``/``project_name``/``port`` at the top
level) is still honoured: :func:`projects` synthesises an entry for it, so an existing
install keeps working without a migration step.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .protocol import DEFAULT_HOST, DEFAULT_PORT


def config_path() -> Path:
    """Resolved on every call so tests (and users) can point GHLAB_CONFIG elsewhere."""
    return Path(os.environ.get("GHLAB_CONFIG") or (Path.home() / ".ghlab" / "config.json"))


def atomic_write_text(path: Path, text: str) -> None:
    """Replace `path` atomically so a crash cannot leave a truncated file.

    Everything ghlab writes back -- notes, the decompile cache, this setup file --
    is read as if it were complete, and a half-written JSON file reads as "no
    findings" rather than as an error. Write a sibling temp file and rename it.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8", newline="\n")
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(OSError):
            tmp.unlink()


def load_config() -> dict[str, Any]:
    """Read the setup file; a missing or broken file is simply empty."""
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_config(data: dict[str, Any]) -> Path:
    path = config_path()
    atomic_write_text(path, json.dumps(data, indent=2, ensure_ascii=False) + chr(10))
    return path


def ghidra_dir() -> str:
    """GHIDRA_INSTALL_DIR from the environment, else from the setup file."""
    return os.environ.get("GHIDRA_INSTALL_DIR") or str(load_config().get("ghidra") or "")


def default_host() -> str:
    return os.environ.get("GHLAB_HOST") or DEFAULT_HOST


def default_port() -> int:
    return int(os.environ.get("GHLAB_PORT") or load_config().get("port") or DEFAULT_PORT)


@dataclass(frozen=True)
class Target:
    """One daemon: a Ghidra project plus the HTTP endpoint serving it."""

    name: str
    url: str
    project_dir: str
    project_name: str

    @property
    def label(self) -> str:
        return f"{self.name} ({self.project_name} @ {self.url})"


def _legacy_target(cfg: dict[str, Any]) -> Target | None:
    port = cfg.get("port")
    project_name = cfg.get("project_name")
    if not port and not project_name:
        return None
    name = str(project_name or "default")
    url = os.environ.get("GHLAB_URL") or f"http://{default_host()}:{port or DEFAULT_PORT}"
    return Target(
        name=name,
        url=url,
        project_dir=str(cfg.get("project_dir") or ""),
        project_name=str(project_name or name),
    )


def projects(cfg: dict[str, Any] | None = None) -> dict[str, Target]:
    """Every configured daemon, keyed by project name (order preserved)."""
    cfg = load_config() if cfg is None else cfg
    out: dict[str, Target] = {}
    raw = cfg.get("projects")
    if isinstance(raw, dict):
        for name, entry in raw.items():
            if not isinstance(entry, dict) or not entry.get("url"):
                continue
            out[str(name)] = Target(
                name=str(name),
                url=str(entry["url"]),
                project_dir=str(entry.get("project_dir") or ""),
                project_name=str(entry.get("project_name") or name),
            )
    if "GHLAB_URL" in os.environ:
        # An explicit URL wins over everything: that is how a caller pins one daemon.
        url = os.environ["GHLAB_URL"]
        name = str(cfg.get("default") or next(iter(out), "default"))
        return {
            name: Target(
                name=name,
                url=url,
                project_dir=str(cfg.get("project_dir") or ""),
                project_name=str(cfg.get("project_name") or name),
            )
        }
    if not out:
        legacy = _legacy_target(cfg)
        if legacy is not None:
            out[legacy.name] = legacy
        else:
            out["default"] = Target(
                name="default",
                url=f"http://{default_host()}:{DEFAULT_PORT}",
                project_dir=str(Path.home() / "re" / "proj"),
                project_name="ghlab",
            )
    return out


def default_project(cfg: dict[str, Any] | None = None) -> str:
    cfg = load_config() if cfg is None else cfg
    known = projects(cfg)
    wanted = str(cfg.get("default") or "")
    if wanted in known:
        return wanted
    return next(iter(known))


def port_free(port: int, host: str = "127.0.0.1") -> bool:
    """True when nothing is listening on the port (best effort, cheap)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) != 0


def discover_projects(
    roots: list[Path],
    *,
    known: dict[str, Target] | None = None,
    base_port: int | None = None,
    limit: int = 8,
) -> list[Target]:
    """Find Ghidra projects under `roots` that are not registered yet.

    A project is a directory holding ``<name>.gpr`` (a 0-byte marker in Ghidra 11+)
    next to ``<name>.rep`` -- that pair is what ``ProjectLocator`` looks for, so it is
    also the only thing worth recognising. Names already registered (by directory or
    by name) are skipped; each new project gets the next port that is both unused in
    the registry and free on the box.
    """
    known = known if known is not None else projects()
    taken_ports = {int(t.url.rsplit(":", 1)[-1].strip("/") or 0) for t in known.values()}
    taken_ports.update(range(1024))
    seen_dirs = {str(Path(t.project_dir).resolve()) for t in known.values() if t.project_dir}
    port = base_port or (max(taken_ports) + 1 if taken_ports else DEFAULT_PORT)

    found: list[Target] = []
    for root in roots:
        root = Path(root).expanduser()
        if not root.is_dir():
            continue
        for marker in sorted(root.rglob("*.gpr")):
            if len(found) >= limit:
                return found
            project_dir = marker.parent
            name = marker.stem
            if not (project_dir / f"{name}.rep").is_dir():
                continue  # a stray .gpr, not a project Ghidra would open
            if str(project_dir.resolve()) in seen_dirs or name in known:
                continue
            while port in taken_ports or not port_free(port):
                port += 1
                if port > 65535:
                    return found
            taken_ports.add(port)
            seen_dirs.add(str(project_dir.resolve()))
            found.append(
                Target(
                    name=name,
                    url=f"http://{default_host()}:{port}",
                    project_dir=str(project_dir),
                    project_name=name,
                )
            )
            port += 1
    return found


def register_project(
    name: str,
    *,
    url: str,
    project_dir: str,
    project_name: str,
    make_default: bool = False,
) -> Path:
    cfg = load_config()
    entry = {"url": url, "project_dir": project_dir, "project_name": project_name}
    known = _seed_projects(cfg)
    known[name] = entry
    cfg["projects"] = known
    if make_default or not cfg.get("default"):
        cfg["default"] = name
    # Keep the legacy top-level keys in step with the default project: older
    # commands, scripts and docs still read them.
    if cfg.get("default") == name:
        cfg["project_dir"] = project_dir
        cfg["project_name"] = project_name
        with_port = url.rsplit(":", 1)[-1].strip("/")
        if with_port.isdigit():
            cfg["port"] = int(with_port)
    return save_config(cfg)


def _seed_projects(cfg: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Start from whatever the config already knows, including the legacy layout.

    Without this, registering a second project on a legacy install silently forgot
    the first one (it only lived in the top-level keys).
    """
    raw = cfg.get("projects")
    if isinstance(raw, dict) and raw:
        # Once a registry exists it is the authority; the legacy keys only mirror
        # the default project, and re-seeding them would resurrect removed projects.
        return {str(k): dict(v) for k, v in raw.items() if isinstance(v, dict)}
    known: dict[str, dict[str, str]] = {}
    legacy = _legacy_target(cfg)
    if legacy is not None and legacy.project_dir:
        known[legacy.name] = {
            "url": legacy.url,
            "project_dir": legacy.project_dir,
            "project_name": legacy.project_name,
        }
        if not cfg.get("default"):
            cfg["default"] = legacy.name
    return known


def remove_project(name: str) -> bool:
    cfg = load_config()
    known = _seed_projects(cfg)
    if name not in known:
        return False
    del known[name]
    cfg["projects"] = known
    if cfg.get("default") == name or cfg.get("default") not in known:
        cfg["default"] = next(iter(known), "")
    if cfg.get("project_name") == name and cfg.get("default") in known:
        # Keep the legacy mirror pointing at a project that still exists.
        mirror = known[cfg["default"]]
        cfg["project_dir"] = mirror.get("project_dir", "")
        cfg["project_name"] = mirror.get("project_name", cfg["default"])
        tail = str(mirror.get("url", "")).rsplit(":", 1)[-1].strip("/")
        if tail.isdigit():
            cfg["port"] = int(tail)
    return bool(save_config(cfg))


def focus_path() -> Path:
    return Path(os.environ.get("GHLAB_FOCUS") or (Path.home() / ".ghlab" / "focus"))


def read_focus() -> str:
    try:
        return focus_path().read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def write_focus(binary: str) -> Path:
    path = focus_path()
    atomic_write_text(path, binary.strip() + chr(10))
    return path
