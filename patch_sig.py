"""Cheap signature sweep, error suggestions, and a `use` focus binary."""

from pathlib import Path

NL = chr(10)

# ------------------------------------------------------------------ session.py
p = Path("src/ghlab/session.py")
s = p.read_text(encoding="utf-8")

old = """    results = []
    for t in targets[:limit]:
        try:
            fn = t if not isinstance(t, (str, int)) else _function(e, str(t))
            if fn is None:
                results.append({"target": str(t), "error": "function not found"})
                continue
            key = None if a.get("refresh") else _decomp_cache_key(e, fn)"""
new = """    want_sig = bool(a.get("sig"))
    results = []
    for t in targets[:limit]:
        try:
            fn = t if not isinstance(t, (str, int)) else _function(e, str(t))
            if fn is None:
                results.append({"target": str(t), "error": "function not found"})
                continue
            if want_sig:
                # no decompiler: the prototype is already in the database, so a
                # 476-function sweep costs milliseconds and a few hundred tokens.
                item = brief(fn)
                item["signature"] = _prototype(fn)
                results.append(item)
                continue
            key = None if a.get("refresh") else _decomp_cache_key(e, fn)"""
assert s.count(old) == 1
s = s.replace(old, new, 1)
p.write_text(s, encoding="utf-8", newline=NL)

# ------------------------------------------------------------------ protocol.py
p = Path("src/ghlab/protocol.py")
s = p.read_text(encoding="utf-8")
s = s.replace(
    '("targets", "target", "match", "grep", "limit", "max_lines", "include_code", "include_callees", "include_callers", "timeout", "refresh"),',
    '(\n            "targets",\n            "target",\n            "match",\n            "grep",\n            "limit",\n            "max_lines",\n            "include_code",\n            "include_callees",\n            "include_callers",\n            "timeout",\n            "refresh",\n            "sig",\n        ),',
    1,
)
if '"sig"' not in s:
    raise SystemExit("decompile spec not patched")
s = s.replace(
    """    if cmd not in SPECS:
        known = ", ".join(sorted(SPECS))
        raise ProtocolError(f"unknown cmd {cmd!r}; known commands: {known}")""",
    """    if cmd not in SPECS:
        import difflib

        close = difflib.get_close_matches(cmd, sorted(SPECS), n=3, cutoff=0.5)
        hint = f" (did you mean {', '.join(close)}?)" if close else ""
        known = ", ".join(sorted(SPECS))
        raise ProtocolError(f"unknown cmd {cmd!r}{hint}; known commands: {known}")""",
    1,
)
p.write_text(s, encoding="utf-8", newline=NL)

# ------------------------------------------------------------------ cli.py
p = Path("src/ghlab/cli.py")
s = p.read_text(encoding="utf-8")

# 1. focus helpers + "-" resolution inside _call
old = """def _call(a: argparse.Namespace, cmd: str, params: dict[str, Any]) -> int:
    payload = {"cmd": cmd, **{k: v for k, v in params.items() if v is not None}}"""
if s.count(old) != 1:
    raise SystemExit("_call anchor changed")
new = """FOCUS_FILE = Path.home() / ".ghlab" / "focus"


def read_focus() -> str | None:
    try:
        name = FOCUS_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return name or None


def write_focus(binary: str) -> None:
    FOCUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    FOCUS_FILE.write_text(binary + chr(10), encoding="utf-8", newline=chr(10))


def _call(a: argparse.Namespace, cmd: str, params: dict[str, Any]) -> int:
    focus = read_focus()
    if params.get("binary") == "-":
        if not focus:
            print("ghlab: no focus binary yet; run `ghlab use <binary>` first", file=sys.stderr)
            return 2
        params["binary"] = focus
    payload = {"cmd": cmd, **{k: v for k, v in params.items() if v is not None}}"""
s = s.replace(old, new, 1)

# 2. fmt_decompile: signature-only mode has no code
old = """def fmt_decompile(r: dict[str, Any]) -> str:"""
new = """def fmt_use(args: argparse.Namespace) -> int:
    if not args.binary:
        focus = read_focus()
        print(focus or "ghlab: no focus binary set")
        return 0
    if args.binary == "-":
        print("ghlab: `use -` makes no sense", file=sys.stderr)
        return 2
    write_focus(args.binary)
    print(f"focus = {args.binary}")
    return 0


def fmt_decompile(r: dict[str, Any]) -> str:"""
assert s.count(old) == 1
s = s.replace(old, new, 1)

# 3. use subcommand + --sig flag
old = """    p = sub.add_parser("strings", parents=[common], help="search string data")"""
new = """    p = sub.add_parser("use", help="set/show the focus binary (then pass '-' as binary)")
    p.add_argument("binary", nargs="?", help="program name, e.g. notepad.exe")
    p.set_defaults(func=fmt_use)

    p = sub.add_parser("strings", parents=[common], help="search string data")"""
assert s.count(old) == 1
s = s.replace(old, new, 1)
p.write_text(s, encoding="utf-8", newline=NL)
print("patched")
