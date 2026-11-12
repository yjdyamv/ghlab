"""Replayable analysis scripts.

A pipeline is a text file with one ghlab command per line:

    # notepad triage - run with: ghlab run notepad.gh --set BIN=notepad.exe
    digest $BIN --top 6
    slice $BIN RegSetValueExW
    decompile $BIN -t FUN_140021ba8 -n 400 > out/FUN_140021ba8.c
    report $BIN > out/$BIN.md

`$VAR` / `${VAR}` come from `--set`, `>` and `>>` redirect a single step, `#` starts
a comment. The point is that a long analysis becomes a file you can re-run on the
next sample instead of a chat log you have to reconstruct.
"""

from __future__ import annotations

import re
import sys
import time
from collections.abc import Callable
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

VAR_RE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


class PipelineError(ValueError):
    pass


@dataclass
class Step:
    lineno: int
    argv: list[str]
    out: str | None = None
    append: bool = False
    line: str = ""

    @property
    def command(self) -> str:
        return self.argv[0] if self.argv else ""


def expand(text: str, variables: dict[str, str]) -> str:
    def sub(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        if name not in variables:
            known = ", ".join(sorted(variables)) or "none"
            raise PipelineError(f"undefined variable ${name} (known: {known})")
        return str(variables[name])

    return VAR_RE.sub(sub, text)


def split_line(line: str) -> list[str]:
    """POSIX-ish quoting that leaves Windows paths alone.

    shlex (posix mode) eats backslashes, so a redirect to C:\tmp\a.md would come
    out as C:tmpa.md. Here a backslash only escapes a quote; anywhere else it is a
    literal character, which is what people typing paths expect.
    """
    tokens: list[str] = []
    cur: list[str] = []
    quote = ""
    dq = '"'
    sq = "'"
    escapable = dq + sq + "\\"
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == quote:
                quote = ""
            elif ch == "\\" and quote == dq and i + 1 < len(line) and line[i + 1] in escapable:
                i += 1
                cur.append(line[i])
            else:
                cur.append(ch)
        elif ch in (" ", "	"):
            if cur:
                tokens.append("".join(cur))
                cur = []
        elif ch in (sq, dq):
            quote = ch
        elif ch == "\\" and i + 1 < len(line) and line[i + 1] in (sq, dq):
            i += 1
            cur.append(line[i])
        else:
            cur.append(ch)
        i += 1
    if quote:
        raise PipelineError(f"unbalanced {quote} quote")
    if cur:
        tokens.append("".join(cur))
    return tokens


def parse_script(text: str, variables: dict[str, str] | None = None) -> list[Step]:
    variables = dict(variables or {})
    steps: list[Step] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = split_line(expand(line, variables))
        except PipelineError as ex:
            raise PipelineError(f"line {lineno}: {ex}") from ex
        if not tokens:
            continue
        out: str | None = None
        append = False
        if ">" in tokens:
            i = tokens.index(">")
            out = tokens[i + 1] if i + 1 < len(tokens) else None
            if not out:
                raise PipelineError(f"line {lineno}: `>` needs a path")
            if len(tokens) > i + 2:
                raise PipelineError(f"line {lineno}: nothing may follow the redirect target")
            tokens = tokens[:i]
        elif ">>" in tokens:
            i = tokens.index(">>")
            out = tokens[i + 1] if i + 1 < len(tokens) else None
            if not out:
                raise PipelineError(f"line {lineno}: `>>` needs a path")
            if len(tokens) > i + 2:
                raise PipelineError(f"line {lineno}: nothing may follow the redirect target")
            append = True
            tokens = tokens[:i]
        steps.append(Step(lineno=lineno, argv=tokens, out=out, append=append, line=line))
    return steps


def _default_execute(argv: list[str]) -> int:
    from . import cli

    try:
        return int(cli.main(argv))
    except SystemExit as ex:  # argparse errors
        return int(ex.code or 1)


def run_steps(
    steps: list[Step],
    execute: Callable[[list[str]], int] | None = None,
    keep_going: bool = False,
    dry_run: bool = False,
    progress: TextIO | None = None,
    base: Path | None = None,
) -> dict[str, Any]:
    execute = execute or _default_execute
    progress = progress or sys.stderr
    results: list[dict[str, Any]] = []
    total = len(steps)
    failed = 0
    for index, step in enumerate(steps, 1):
        if dry_run:
            results.append({"line": step.lineno, "command": step.command, "status": "skipped"})
            continue
        started = time.monotonic()
        status, error = "ok", None
        try:
            if step.out:
                # a relative `> out/x.c` belongs to the script, not to whoever ran it:
                # the same script from another directory used to scatter `out/` around
                # and still report "ok"
                path = Path(step.out).expanduser()
                if not path.is_absolute() and base is not None:
                    path = base / path
                path.parent.mkdir(parents=True, exist_ok=True)
                mode = "a" if step.append else "w"
                with (
                    open(path, mode, encoding="utf-8", newline="\n") as fh,
                    redirect_stdout(fh),
                ):
                    code = execute(step.argv)
            else:
                code = execute(step.argv)
            if code:
                status, error = "failed", f"exit {code}"
        except KeyboardInterrupt:
            raise
        except Exception as ex:  # noqa: BLE001
            status, error = "failed", f"{type(ex).__name__}: {ex}"
        elapsed = round((time.monotonic() - started) * 1000)
        results.append(
            {
                "line": step.lineno,
                "command": step.command,
                "argv": step.argv,
                "out": step.out,
                "written": str(path) if step.out else "",
                "status": status,
                "error": error,
                "ms": elapsed,
            }
        )
        if status == "failed":
            failed += 1
            print(f"[{index}/{total}] {step.command}: FAILED - {error}", file=progress)
            if not keep_going:
                break
        else:
            print(f"[{index}/{total}] {step.command}: ok ({elapsed}ms)", file=progress)
    return {
        "script": None,
        "total": total,
        "ran": len(results),
        "failed": failed,
        "steps": results,
        "dry_run": dry_run,
    }


def run_file(
    path: str | Path,
    variables: dict[str, str] | None = None,
    keep_going: bool = False,
    dry_run: bool = False,
    execute: Callable[[list[str]], int] | None = None,
) -> dict[str, Any]:
    script = Path(path).expanduser()
    text = script.read_text(encoding="utf-8")
    summary = run_steps(
        parse_script(text, variables),
        execute=execute,
        keep_going=keep_going,
        dry_run=dry_run,
        base=script.parent,
    )
    summary["script"] = str(path)
    return summary
