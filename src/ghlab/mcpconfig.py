"""The MCP entry other agents read, and the surgery that puts it in their config file.

Every client stores the same three fields in a different dialect, and these files belong
to the user: they carry comments (Zed, VS Code, OpenCode), other servers, hand-made
formatting.  So nothing here re-serialises a whole file -- each merge touches only our
own entry, and a file that already says what we would say comes back byte-identical,
which is what makes re-running `setup --install-mcp` safe.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
from pathlib import Path
from typing import Any

from .config import atomic_write_text
from .protocol import DEFAULT_TIMEOUT

# Where each client keeps its config.  Zed, VS Code and Goose follow the platform's own
# convention (XDG on Linux, Library on macOS, %APPDATA% on Windows), so the table is built
# per OS instead of being one home-relative path for everybody.
SYSTEM = platform.system()  # "Windows" | "Darwin" | "Linux"; tests patch this

_COMMON: dict[str, str] = {
    "pi": "~/.pi/agent/mcp.json",
    "claude": "~/.claude.json",
    "gemini": "~/.gemini/settings.json",
    "cursor": "~/.cursor/mcp.json",
    "windsurf": "~/.codeium/windsurf/mcp_config.json",
    "opencode": "~/.config/opencode/opencode.json",
    "codex": "~/.codex/config.toml",
    "commandcode": "~/.commandcode/mcp.json",
}


def place(client: str) -> str:
    """The config file this client reads, as written for the current OS."""
    windows, mac = SYSTEM == "Windows", SYSTEM == "Darwin"
    if client == "zed":
        return "%APPDATA%/Zed/settings.json" if windows else "~/.config/zed/settings.json"
    if client == "vscode":
        if windows:
            return "%APPDATA%/Code/User/mcp.json"
        if mac:
            return "~/Library/Application Support/Code/User/mcp.json"
        return "~/.config/Code/User/mcp.json"
    if client == "goose":
        return (
            "%APPDATA%/Block/goose/config/config.yaml" if windows else "~/.config/goose/config.yaml"
        )
    return _COMMON[client]


DIALECT: dict[str, str] = {
    "pi": "json",
    "claude": "json",
    "gemini": "json",
    "cursor": "json",
    "windsurf": "json",
    "opencode": "opencode",
    "codex": "toml",
    "commandcode": "commandcode",
    "goose": "yaml",
    "zed": "zed",
    "vscode": "vscode",
}

# client -> (path, dialect)
FILES: dict[str, tuple[str, str]] = {
    name: (place(name), dialect) for name, dialect in DIALECT.items()
}

# Where our entry lives, per dialect.  A tuple means nested: opencode v2 keeps its
# servers one level down (`mcp.servers.<name>`), the others put them in the key itself.
CONTAINER: dict[str, tuple[str, ...]] = {
    "json": ("mcpServers",),
    "zed": ("context_servers",),
    "vscode": ("servers",),
    "opencode": ("mcp", "servers"),
    "commandcode": ("mcpServers",),
}

# pi reads these next to command/args/env; the timeout has to outlast a cold daemon
# (Ghidra takes 30-45s to answer the first call, pi's default per-call limit is 60s).
# How long a client may wait for the server process itself to answer its first request.
# 120s covers a cold `uv` (python download on a new machine) and a cold daemon start;
# the per-call budget is DEFAULT_TIMEOUT everywhere.
STARTUP_TIMEOUT = 120

PI_EXTRAS: dict[str, Any] = {
    "timeout": DEFAULT_TIMEOUT,
    "exposure": "deferred",
    "description": "reverse engineering over Ghidra: decompile, xrefs, patch, notes",
}

TABLE = "ghlab"


# How to tell the client is on this machine: a directory it owns, or its executable on
# PATH.  The config file alone is not enough -- ~/.codex/config.toml would otherwise be
# created for anyone whose home directory exists.
SIGNALS: dict[str, tuple[str, ...]] = {
    "pi": ("~/.pi",),
    "claude": ("~/.claude", "~/.claude.json", "exe:claude"),
    "gemini": ("~/.gemini", "exe:gemini"),
    "cursor": ("~/.cursor", "exe:cursor"),
    "windsurf": ("~/.codeium/windsurf",),
    "opencode": ("~/.config/opencode", "exe:opencode"),
    "codex": ("~/.codex", "exe:codex"),
    # not `exe:cmd`: on Windows that name is C:/Windows/System32/cmd.exe
    "commandcode": ("~/.commandcode",),
    "goose": ("~/.config/goose", "%APPDATA%/Block/goose"),
    "zed": ("~/.config/zed", "%APPDATA%/Zed", "/Applications/Zed.app", "exe:zed"),
    "vscode": (
        "~/.config/Code/User",
        "~/Library/Application Support/Code/User",
        "%APPDATA%/Code/User",
        "exe:code",
    ),
}


def _expand(place: str) -> Path:
    """`~` and `%VAR%`/`$VAR` both resolve, with a home-relative fallback when a var is unset."""
    text = os.path.expandvars(place)
    if text.startswith("%"):
        # %APPDATA% under a service account, or a var this shell simply does not have
        name, rest = text[1:].split("%", 1)
        base = Path.home() / "AppData" / name.capitalize()
        text = str(base) + rest
    return Path(os.path.expanduser(text))


def target(client: str) -> Path:
    """Where this client keeps its config on this machine."""
    return _expand(FILES[client][0])


def present(client: str) -> bool:
    """Is this client installed here?"""
    for hint in SIGNALS.get(client, ()):
        if hint.startswith("exe:"):
            if shutil.which(hint[4:]) is not None:
                return True
        elif _expand(hint).exists():
            return True
    return False


def installed() -> list[str]:
    """The clients found on this machine."""
    return [c for c in FILES if present(c)]


# -------------------------------------------------------------------------- render


def entry(client: str, payload: dict[str, Any]) -> Any:
    """Our entry in this client's shape: a dict for the JSON dialects, text for the rest."""
    command, args, env = payload["command"], payload["args"], payload["env"]
    dialect = FILES[client][1]
    if dialect == "opencode":
        return {
            "type": "local",
            "command": [command, *args],
            "environment": env,
            "enabled": True,
        }
    if dialect == "vscode":
        return {"type": "stdio", "command": command, "args": args, "env": env}
    if dialect == "commandcode":
        return {
            "transport": "stdio",
            "enabled": True,
            "command": command,
            "args": list(args),
            "env": dict(env),
        }
    if dialect == "toml":
        env_items = ", ".join(f"{json.dumps(k)} = {json.dumps(v)}" for k, v in env.items())
        return "\n".join(
            [
                f"[mcp_servers.{TABLE}]",
                f"command = {json.dumps(command)}",
                f"args = [{', '.join(json.dumps(a) for a in args)}]",
                f"env = {{ {env_items} }}",
                # codex kills a server that has not answered in 10s and a tool call
                # after 60s; the tool budget has to match the one every other client
                # gets, or a full `analyze` is cut off at 60s here and nowhere else.
                f"startup_timeout_sec = {STARTUP_TIMEOUT}",
                f"tool_timeout_sec = {DEFAULT_TIMEOUT}",
            ]
        )
    if dialect == "yaml":
        env_items = ", ".join(f"{json.dumps(k)}: {json.dumps(v)}" for k, v in env.items())
        return "\n".join(
            [
                f"  {TABLE}:",
                "    type: stdio",
                f"    cmd: {json.dumps(command)}",
                f"    args: [{', '.join(json.dumps(a) for a in args)}]",
                f"    envs: {{ {env_items} }}",
                "    enabled: true",
                f"    timeout: {DEFAULT_TIMEOUT}",
            ]
        )
    block: dict[str, Any] = {"command": command, "args": list(args), "env": dict(env)}
    if client == "pi":
        block.update(PI_EXTRAS)
    return block


def render(client: str, payload: dict[str, Any]) -> str:
    """The config text for one client, ready to paste (the shape `--print-mcp` prints)."""
    place = FILES[client][0]
    where = str(place)
    value = entry(client, payload)
    dialect = FILES[client][1]
    if dialect in ("toml", "yaml"):
        # paste-ready: both need their parent key, and ours is indented under it
        parent = "extensions" if dialect == "yaml" else None
        inner = f"{parent}:\n{value}" if parent else value
        return f"# {where}\n{inner}"
    doc: dict[str, Any] = {TABLE: value}
    for key in reversed(CONTAINER[dialect]):
        doc = {key: doc}
    comment = f"// {where}"
    if client == "zed":
        comment += " -- Zed reads `context_servers`, not `mcpServers`"
    elif client == "opencode":
        comment += (
            " -- `command` is one array, the env key is `environment`, "
            "and v2 keeps servers under `mcp.servers`"
        )
    elif client == "commandcode":
        comment += " -- `mcpServers`, with `transport: stdio` next to command/args/env"
    return f"{comment}\n{json.dumps(doc, indent=2)}"


# --------------------------------------------------------------------------- json


def _scan(text: str) -> list[tuple[str, int, int]]:
    """Structural tokens of JSON-with-comments: brackets, ':' and whole strings."""
    tokens: list[tuple[str, int, int]] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "{}[],:":
            tokens.append((ch, i, i + 1))
            i += 1
        elif ch == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            tokens.append(("s", i, j))
            i = j
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            i += 1
    return tokens


def _close(tokens: list[tuple[str, int, int]], index: int) -> int:
    """Index of the token closing the bracket opened at `index`, or -1 when unbalanced."""
    pairs = {"{": "}", "[": "]"}
    stack: list[str] = []
    for k in range(index, len(tokens)):
        kind = tokens[k][0]
        if kind in pairs:
            stack.append(pairs[kind])
        elif kind in "}]":
            if not stack or stack.pop() != kind:
                return -1
            if not stack:
                return k
    return -1


def _members(text: str, tokens: list[tuple[str, int, int]], obj: int) -> list[tuple[str, int, int]]:
    """(key, value_start, value_end) for each member of the object opened at token `obj`."""
    out: list[tuple[str, int, int]] = []
    k = obj + 1
    while k < len(tokens) and tokens[k][0] != "}":
        if tokens[k][0] != "s":
            k += 1
            continue
        key = text[tokens[k][1] + 1 : tokens[k][2] - 1]
        k += 1
        if k >= len(tokens) or tokens[k][0] != ":":
            continue
        k += 1
        if k >= len(tokens):
            break
        if tokens[k][0] in "{[":
            end = _close(tokens, k)
            if end < 0:
                return out
            out.append((key, tokens[k][1], tokens[end][2]))
            k = end + 1
        else:
            end = k
            while end + 1 < len(tokens) and tokens[end + 1][0] not in (",", "}"):
                end += 1
            out.append((key, tokens[k][1], tokens[end][2]))
            k = end + 1
        if k < len(tokens) and tokens[k][0] == ",":
            k += 1
    return out


def _indent_of(text: str, offset: int) -> str:
    """The indentation of the line holding `offset`."""
    line_start = text.rfind("\n", 0, offset) + 1
    match = re.match(r"[ \t]*", text[line_start:offset])
    return match.group(0) if match else ""


def _dump(value: Any, indent: str) -> str:
    """json.dumps at a nesting depth: every line but the first gets `indent`."""
    return json.dumps(value, indent=2).replace("\n", "\n" + indent)


def _add(text: str, tokens: list[tuple[str, int, int]], obj: int, key: str, value: Any) -> str:
    """Insert `"key": value` as the last member of the object at token `obj`."""
    close = _close(tokens, obj)
    if close < 0:
        raise ValueError("unbalanced object")
    members = _members(text, tokens, obj)
    close_at = tokens[close][1]
    indent = _indent_of(text, close_at)
    child = indent + "  "
    body = f"{json.dumps(key)}: {_dump(value, child)}"
    if members:
        cut = members[-1][2]
        return f"{text[:cut]},\n{child}{body}{text[cut:]}"
    return f"{text[: tokens[obj][2]]}\n{child}{body}\n{indent}{text[close_at:]}"


def _nest(path: tuple[str, ...], name: str, value: Any) -> Any:
    """`{path[0]: {path[1]: {... {name: value}}}}`, the innermost object last."""
    doc: Any = {name: value}
    for key in reversed(path):
        doc = {key: doc}
    return doc


def _put_member(
    text: str, tokens: list[tuple[str, int, int]], obj: int, name: str, value: Any
) -> str:
    """Set `obj[name] = value`, replacing an existing member in place."""
    ours = next((m for m in _members(text, tokens, obj) if m[0] == name), None)
    if ours is None:
        return _add(text, tokens, obj, name, value)
    indent = _indent_of(text, ours[1])
    return f"{text[: ours[1]]}{_dump(value, indent)}{text[ours[2] :]}"


def _put_path(
    text: str,
    tokens: list[tuple[str, int, int]],
    obj: int,
    path: tuple[str, ...],
    name: str,
    value: Any,
) -> str:
    """Set `obj[path[0]][path[1]]...[name] = value`, creating the keys it needs."""
    if not path:
        return _put_member(text, tokens, obj, name, value)
    key = path[0]
    found = next((m for m in _members(text, tokens, obj) if m[0] == key), None)
    if found is None:
        return _add(text, tokens, obj, key, _nest(path[1:], name, value))
    inner = next((k for k, t in enumerate(tokens) if t[0] == "{" and t[1] == found[1]), -1)
    if inner < 0:
        # the key exists but is not an object: replace it with the shape we need
        indent = _indent_of(text, found[1])
        return f"{text[: found[1]]}{_dump(_nest(path[1:], name, value), indent)}{text[found[2] :]}"
    return _put_path(text, tokens, inner, path[1:], name, value)


def merge_json(
    text: str, container: str | tuple[str, ...], name: str, value: dict[str, Any]
) -> str:
    """Put `{container: {name: value}}` into a JSON/JSONC document, keeping the rest."""
    path = (container,) if isinstance(container, str) else tuple(container)
    if not text.strip():
        return json.dumps(_nest(path, name, value), indent=2) + chr(10)
    tokens = _scan(text)
    root = next((k for k, t in enumerate(tokens) if t[0] == "{"), -1)
    if root < 0:
        raise ValueError("no top-level object")
    return _put_path(text, tokens, root, path, name, value)


def balanced(text: str) -> bool:
    """Cheap sanity check after an edit: every bracket closes in order."""
    stack: list[str] = []
    pairs = {"{": "}", "[": "]"}
    for kind, _start, _end in _scan(text):
        if kind in pairs:
            stack.append(pairs[kind])
        elif kind in "}]" and (not stack or stack.pop() != kind):
            return False
    return not stack


# --------------------------------------------------------------------- toml, yaml


def merge_toml(text: str, table: str, block: str) -> str:
    """Replace or append a TOML table (and any `table.*` sub-tables of ours)."""
    header = f"[{table}]"
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip() == header), -1)
    body = block.splitlines()
    if start < 0:
        head = text.rstrip("\n")
        return f"{head}\n\n{block}\n" if head else f"{block}\n"
    end = start + 1
    while end < len(lines):
        stripped = lines[end].strip()
        # a table of ours (`[table.env]`) is part of what we replace; any other table
        # starts the next section and has to survive
        if stripped.startswith("[") and not stripped.startswith(f"[{table}."):
            break
        end += 1
    tail = lines[end:]
    if tail and tail[0].strip():
        tail = ["", *tail]
    return "\n".join([*lines[:start], *body, *tail]).rstrip("\n") + "\n"


def merge_yaml(text: str, parent: str, block: str) -> str:
    """Replace or append a child block of a top-level YAML mapping."""
    lines = text.splitlines()
    body = block.splitlines()
    top = next(
        (i for i, line in enumerate(lines) if re.match(rf"^{re.escape(parent)}\s*:", line)), -1
    )
    if top < 0:
        head = text.rstrip("\n")
        return f"{head}\n{parent}:\n{block}\n"
    end = len(lines)
    for i in range(top + 1, len(lines)):
        line = lines[i]
        if line.strip() and not line.lstrip().startswith("#") and not line.startswith((" ", "\t")):
            end = i
            break
    for k in range(top + 1, end):
        match = re.match(rf"^(\s+){re.escape(TABLE)}\s*:", lines[k])
        if not match:
            continue
        indent = len(match.group(1))
        stop = k + 1
        while stop < end:
            line = lines[stop]
            if (
                line.strip()
                and not line.lstrip().startswith("#")
                and len(line) - len(line.lstrip()) <= indent
            ):
                break
            stop += 1
        return "\n".join([*lines[:k], *body, *lines[stop:]]).rstrip("\n") + "\n"
    return "\n".join([*lines[:end], *body, *lines[end:]]).rstrip("\n") + "\n"


def merge(client: str, text: str, payload: dict[str, Any]) -> str:
    """This client's config file text with our entry in it."""
    dialect = FILES[client][1]
    value = entry(client, payload)
    if dialect == "toml":
        assert isinstance(value, str)
        return merge_toml(text, f"mcp_servers.{TABLE}", value)
    if dialect == "yaml":
        assert isinstance(value, str)
        return merge_yaml(text, "extensions", value)
    assert isinstance(value, dict)
    return merge_json(text, CONTAINER[dialect], TABLE, value)


# -------------------------------------------------------------------------- install


def backup(path: Path) -> Path | None:
    """Keep the first version of a file we touch; a second run must not overwrite it."""
    if not path.exists():
        return None
    keep = path.with_name(path.name + ".ghlab.bak")
    if keep.exists():
        return keep
    keep.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return keep


def install(clients: list[str], payload: dict[str, Any], dry_run: bool = False) -> list[str]:
    """Write our entry into each client's config and say what happened, one line each."""
    report: list[str] = []
    for client in clients:
        path = target(client)
        where = str(path)
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        try:
            new = merge(client, text, payload)
        except ValueError as exc:
            report.append(f"{client:<9} failed    ({exc}; left {where} alone)")
            continue
        if FILES[client][1] in ("json", "zed", "vscode", "opencode") and not balanced(new):
            report.append(f"{client:<9} failed    (edit would unbalance {where}; left it alone)")
            continue
        if new == text:
            report.append(f"{client:<9} current   {where}")
            continue
        if dry_run:
            report.append(f"{client:<9} would     {where}")
            continue
        kept = backup(path)
        atomic_write_text(path, new)
        note = f" (backup: {kept.name})" if kept else ""
        report.append(f"{client:<9} wrote     {where}{note}")
    return report
