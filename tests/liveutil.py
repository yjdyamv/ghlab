"""Stand up a throwaway daemon on a tiny sample binary for the live tests.

Live tests used to lean on whatever the developer happened to have imported --
in practice a 34 MB WPS DLL or notepad.exe.  That is wrong twice over: the
suite fails on a machine that owns neither, and every scan sweeps millions of
instructions.  So: pick the smallest analysable binary the OS already ships,
import it into a temp project, and tear both down when the process exits.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import shutil
import socket
import tempfile
from pathlib import Path

from ghlab import cli
from ghlab.client import Client

# Smallest first.  hostname.exe (40 KB) has imports, strings and a real entry
# point, which is everything the generic tests need and nothing they don't.
_WINDOWS_SAMPLES = (
    r"C:\Windows\System32\hostname.exe",
    r"C:\Windows\System32\whoami.exe",
    r"C:\Windows\System32\notepad.exe",
)
_POSIX_SAMPLES = ("/bin/true", "/usr/bin/true", "/bin/ls")

_state: dict[str, str] = {}


def sample_binary() -> Path | None:
    """The binary the live tests analyse: GHLAB_TEST_BIN, else the smallest we know."""
    forced = os.environ.get("GHLAB_TEST_BIN", "").strip()
    if forced:
        path = Path(forced).expanduser()
        return path if path.exists() else None
    for candidate in _WINDOWS_SAMPLES if os.name == "nt" else _POSIX_SAMPLES:
        path = Path(candidate)
        if path.exists():
            return path
    return None


def skip_reason() -> str:
    """Why the live tests cannot run here -- empty string when they can."""
    if not cli.ghidra_dir():
        return "set GHIDRA_INSTALL_DIR (or run `ghlab setup`) to run live tests"
    if sample_binary() is None:
        return "no small sample binary found; set GHLAB_TEST_BIN=/path/to/binary"
    return ""


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _cleanup() -> None:
    if _state.get("owned") != "1":
        return
    # Teardown must never raise: it runs from atexit, where an exception is
    # swallowed by the interpreter anyway and just hides the real test result.
    with contextlib.suppress(Exception):
        cli.main(["stop", "--port", _state["port"]])
    shutil.rmtree(_state.get("project_dir", ""), ignore_errors=True)


def bootstrap() -> tuple[Client, str] | None:
    """(client, binary name) for the live tests, or None when we cannot run them.

    `GHLAB_URL` pins an existing daemon and is used as-is; otherwise a project
    is created under a temp dir on a free port, imported once, and killed on
    exit.  Nothing here touches the user's own projects or config.
    """
    if _state:
        client = Client(_state["url"], timeout=600)
        return (client, _state["binary"]) if client.alive() else None
    if skip_reason():
        return None

    sample = sample_binary()
    assert sample is not None  # skip_reason checked it

    existing = os.environ.get("GHLAB_URL", "").strip()
    if existing:
        client = Client(existing, timeout=600)
        if not client.alive():
            return None
        _state.update(url=existing, binary=sample.name, owned="0")
        return client, sample.name

    port = _free_port()
    project_dir = Path(tempfile.mkdtemp(prefix="ghlab-smoke-"))
    code = cli.main(
        [
            "start",
            "--port",
            str(port),
            "--project-dir",
            str(project_dir),
            "--project-name",
            "smoke",
            "--wait",
            "300",
        ]
    )
    if code != 0:
        shutil.rmtree(project_dir, ignore_errors=True)
        return None

    url = f"http://127.0.0.1:{port}/"
    client = Client(url, timeout=600)
    client.call("import", path=str(sample))
    _state.update(
        url=url, binary=sample.name, owned="1", port=str(port), project_dir=str(project_dir)
    )
    atexit.register(_cleanup)
    return client, sample.name
