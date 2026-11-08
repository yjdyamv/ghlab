"""Ghidra-side operations. Imports pyghidra lazily so the rest of ghlab works without it."""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import json
import os
import re
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

MONITOR = None
LOCK = threading.RLock()
_proj = None
_project_dir: Path | None = None
_project_name = "ghlab"
_programs: dict[str, dict[str, Any]] = {}
_FP_CACHE: dict[tuple[str, str, int], dict[str, Any]] = {}


# --------------------------------------------------------------------------- boot


def boot() -> None:
    """Start the Ghidra JVM (idempotent)."""
    global MONITOR
    if MONITOR is not None:
        return
    from pyghidra.launcher import HeadlessPyGhidraLauncher

    if not HeadlessPyGhidraLauncher.has_launched():
        HeadlessPyGhidraLauncher().start()
    from ghidra.util.task import ConsoleTaskMonitor

    MONITOR = ConsoleTaskMonitor()


def configure(project_dir: str | os.PathLike[str], project_name: str = "ghlab") -> None:
    global _project_dir, _project_name
    _project_dir = Path(project_dir).expanduser()
    _project_name = project_name


def project():
    global _proj
    if _proj is not None:
        return _proj
    from ghidra.base.project import GhidraProject
    from ghidra.framework.model import ProjectLocator

    if _project_dir is None:
        configure(Path.home() / "re" / "proj")
    loc = str(_project_dir)
    if ProjectLocator(loc, _project_name).exists():
        _proj = GhidraProject.openProject(loc, _project_name, True)
    else:
        os.makedirs(loc, exist_ok=True)
        _proj = GhidraProject.createProject(loc, _project_name, False)
    return _proj


# --------------------------------------------------------------------- accessors


def project_location() -> str:
    return f"{_project_dir}/{_project_name}" if _project_dir else "<unset>"


def binary_names() -> list[str]:
    proj = project()
    return sorted(str(f.getName()) for f in proj.getRootFolder().getFiles())


def _entry(binary: str) -> dict[str, Any]:
    """Open (and cache) one program; `binary` may be a unique substring."""
    if binary in _programs:
        return _programs[binary]
    names = binary_names()
    if binary not in names:
        cand = [n for n in names if binary.lower() in n.lower()]
        if len(cand) != 1:
            raise KeyError(f"binary {binary!r} not found; project has {names}")
        binary = cand[0]
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.flatapi import FlatProgramAPI

    program = project().openProgram("/", binary, False)
    decomp = DecompInterface()
    decomp.toggleCCode(True)
    decomp.toggleSyntaxTree(True)
    decomp.openProgram(program)
    entry = {"binary": binary, "program": program, "decomp": decomp, "api": FlatProgramAPI(program)}
    _programs[binary] = entry
    return entry


def _hex_addr(text: Any) -> int | None:
    """`0x1400019d0` and bare `1400019d0` are both addresses."""
    raw = str(text).strip()
    if raw.lower().startswith("0x") and re.fullmatch(r"0[xX][0-9a-fA-F]+", raw):
        return int(raw, 16)
    if re.fullmatch(r"[0-9a-fA-F]{6,}", raw):
        return int(raw, 16)
    return None


def _addr(entry: dict[str, Any], text: str):
    program = entry["program"]
    numeric = _hex_addr(text)
    if numeric is not None:
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(numeric)
    addr = entry["api"].toAddr(str(text))
    if addr is None:
        raise KeyError(f"address or symbol {text!r} not found")
    return addr


def _function(entry: dict[str, Any], target: str):
    program = entry["program"]
    fm = program.getFunctionManager()
    text = str(target)
    numeric = _hex_addr(text)
    if numeric is not None:
        addr = _addr(entry, text)
        fn = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        if fn is not None:
            return fn
    for sym in program.getSymbolTable().getAllSymbols(True):
        if str(sym.getName()) == text:
            fn = fm.getFunctionAt(sym.getAddress())
            if fn is not None:
                return fn
    return None


def _save(program, message: str) -> str:
    """Persist the program.

    Ghidra 12.2 leaves a transaction open from `GhidraProject.openProgram`, so
    `program.save(...)` fails with "Unable to lock due to active transaction".
    Saving through the project works (it manages the domain file itself).
    """
    attempts = (
        ("project.save(program)", lambda: project().save(program)),
        ("program.save(msg,monitor)", lambda: program.save(message, MONITOR)),
        ("domain.save(monitor)", lambda: program.getDomainFile().save(MONITOR)),
    )
    errors = []
    for label, fn in attempts:
        try:
            fn()
            return label
        except Exception as ex:  # noqa: BLE001
            errors.append(f"{label}: {type(ex).__name__}: {ex}")
    raise RuntimeError("cannot save program -> " + " | ".join(errors))


def brief(fn) -> dict[str, Any]:
    return {
        "name": str(fn.getName()),
        "addr": str(fn.getEntryPoint()),
        "prototype": str(fn.getPrototypeString(False, False)),
        "size": int(fn.getBody().getNumAddresses()),
        "thunk": bool(fn.isThunk()),
        "external": bool(fn.isExternal()),
    }


# ---------------------------------------------------------------------- commands


def ping(_: dict[str, Any]) -> dict[str, Any]:
    return {
        "service": "ghlab",
        "project": project_location(),
        "binaries": len(binary_names()),
        "loaded": sorted(_programs),
    }


def cmd_binaries(_: dict[str, Any]) -> dict[str, Any]:
    return {"binaries": binary_names()}


def cmd_import(a: dict[str, Any]) -> dict[str, Any]:
    from ghidra.app.script import GhidraScriptUtil
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.util import GhidraProgramUtilities
    from java.io import File

    path = Path(a["path"]).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"no such file: {path}")
    name = path.name
    proj = project()
    if proj.getRootFolder().getFile(name):
        return {"binary": name, "already_present": True}
    program = proj.importProgram(File(str(path)))
    if program is None:
        raise RuntimeError(f"Ghidra failed to import {path}")
    proj.saveAs(program, "/", name, True)
    if a.get("analyze", True):
        api = FlatProgramAPI(program)
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            if GhidraProgramUtilities.shouldAskToAnalyze(program):
                api.analyzeAll(program)
                GhidraProgramUtilities.markProgramAnalyzed(program)
        finally:
            GhidraScriptUtil.releaseBundleHostReference()
    proj.save(program)
    program.release(proj)
    return {"binary": name, "imported": True, "analyzed": bool(a.get("analyze", True))}


def cmd_analyze(a: dict[str, Any]) -> dict[str, Any]:
    """(Re)analyze a program: everything, or just the addresses you touched.

    Importing a large binary costs a minute of full analysis; patching one
    function should not. `--addr` disassembles and creates the function at that
    address, so the rest of the program stays as it was.
    """
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.app.script import GhidraScriptUtil

    started = time.time()
    e = _entry(a["binary"])
    p = e["program"]
    if a.get("full"):
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            e["api"].analyzeAll(p)
        finally:
            GhidraScriptUtil.releaseBundleHostReference()
        saved = _save(p, "ghlab analyze (full)")
        return {
            "binary": a["binary"],
            "mode": "full",
            "functions": int(p.getFunctionManager().getFunctionCount()),
            "saved_via": saved,
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    targets = _as_list(a.get("addr"))
    if not targets:
        raise ValueError("analyze needs --addr ADDR (repeatable) or --full")
    space = p.getAddressFactory().getDefaultAddressSpace()
    rows = []
    tx = p.startTransaction("ghlab analyze")
    try:
        for text in targets:
            offset = _hex_addr(text)
            if offset is None:
                raise KeyError(f"address {text!r} not found")
            addr = space.getAddress(offset)
            dis = DisassembleCommand(addr, None, True).applyTo(p)
            created = CreateFunctionCmd(addr).applyTo(p)
            fn = p.getFunctionManager().getFunctionAt(addr)
            rows.append(
                {
                    "addr": hex(offset),
                    "disassembled": bool(dis),
                    "created": bool(created),
                    "function": str(fn.getName()) if fn is not None else None,
                }
            )
    finally:
        p.endTransaction(tx, True)
    saved = _save(p, "ghlab analyze")
    return {
        "binary": a["binary"],
        "mode": "targeted",
        "addresses": rows,
        "functions": int(p.getFunctionManager().getFunctionCount()),
        "saved_via": saved,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def cmd_info(a: dict[str, Any]) -> dict[str, Any]:
    p = _entry(a["binary"])["program"]
    return {
        "name": str(p.getName()),
        "executable_path": str(p.getExecutablePath()),
        "language": str(p.getLanguageID()),
        "compiler": str(p.getCompiler()),
        "image_base": str(p.getImageBase()),
        "md5": str(p.getExecutableMD5()),
        "functions": int(p.getFunctionManager().getFunctionCount()),
        "symbols": int(p.getSymbolTable().getNumSymbols()),
        "memory_blocks": [str(b.getName()) for b in p.getMemory().getBlocks()],
    }


def cmd_functions(a: dict[str, Any]) -> dict[str, Any]:
    p = _entry(a["binary"])["program"]
    pat = re.compile(a.get("match") or ".*", re.I)
    limit = int(a.get("limit", 100))
    skip = int(a.get("offset", 0))
    total = 0
    out = []
    for fn in p.getFunctionManager().getFunctions(True):
        if not pat.search(str(fn.getName())):
            continue
        total += 1
        if total <= skip:
            continue
        if len(out) < limit:
            out.append(brief(fn))
    return {"binary": a["binary"], "matched": total, "functions": out}


def _grep_code(code: str, pattern: re.Pattern[str]) -> list[dict[str, Any]]:
    hits = []
    for i, line in enumerate(code.splitlines(), 1):
        if pattern.search(line):
            hits.append({"line": i, "text": line.strip()[:300]})
    return hits


# ------------------------------------------------------- decompiler disk cache


def _cache_dir() -> Path:
    base = _project_dir or (Path.home() / "re" / "proj")
    d = Path(base) / ".ghlab" / "cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _entry_comments(program, entry) -> str:
    from ghidra.program.model.listing import CommentType

    listing = program.getListing()
    parts = []
    for ctype in (CommentType.PLATE, CommentType.PRE, CommentType.POST, CommentType.EOL):
        try:
            parts.append(str(listing.getComment(ctype, entry) or ""))
        except Exception:  # noqa: BLE001
            parts.append("")
    return "|".join(parts)


def _decomp_cache_key(e, fn) -> str:
    """Program md5 + address + prototype + comments.

    Names are deliberately out of the key (renames keep the cache warm), but the
    prototype is in it (types change the emitted C) and so are comments (they are
    printed into the output). Instruction bytes are *not* in the key: the first
    decompile of a function rewrites code units, so a hash taken before the call
    would never match the one taken after it. Use `--refresh` after patching.
    """
    program = e["program"]
    h = hashlib.sha1()
    for part in (
        str(program.getExecutableMD5()),
        str(fn.getEntryPoint()),
        _prototype(fn),
        _entry_comments(program, fn.getEntryPoint()),
    ):
        h.update(part.encode("utf-8", "replace"))
        h.update(b"\x00")
    return h.hexdigest()


def _cache_read(key: str) -> str | None:
    path = _cache_dir() / (key + ".c")
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _cache_write(key: str, code: str) -> None:
    with contextlib.suppress(OSError):
        (_cache_dir() / (key + ".c")).write_text(code, encoding="utf-8")


def cmd_decompile(a: dict[str, Any]) -> dict[str, Any]:
    """Decompile a single target, an explicit list, or every function matching `match`.

    `grep` is applied server-side: only matching source lines come back, which keeps
    agent context small on large batches.
    """
    e = _entry(a["binary"])
    program = e["program"]
    fm = program.getFunctionManager()
    timeout = int(a.get("timeout", 60))
    max_lines = int(a.get("max_lines", 0))
    grep = re.compile(a["grep"], re.I) if a.get("grep") else None
    include_code = bool(a.get("include_code", grep is None))
    limit = int(a.get("limit", 25))

    targets: list[Any] = []
    if a.get("targets"):
        targets = list(a["targets"])
    elif "target" in a:  # tolerated for convenience
        targets = [a["target"]]
    if a.get("match"):
        pat = re.compile(a["match"], re.I)
        found = [fn for fn in fm.getFunctions(True) if pat.search(str(fn.getName()))]
        targets.extend(found[:limit])
    if not targets:
        raise ValueError("nothing to decompile: pass targets and/or match")

    results = []
    for t in targets[:limit]:
        try:
            fn = t if not isinstance(t, (str, int)) else _function(e, str(t))
            if fn is None:
                results.append({"target": str(t), "error": "function not found"})
                continue
            key = None if a.get("refresh") else _decomp_cache_key(e, fn)
            code = _cache_read(key) if key else None
            cached = code is not None
            if code is None:
                res = e["decomp"].decompileFunction(fn, timeout, MONITOR)
                if not res.decompileCompleted():
                    results.append({"target": str(t), "error": str(res.getErrorMessage())})
                    continue
                code = str(res.getDecompiledFunction().getC()).replace("\r\n", "\n")
                if key:
                    _cache_write(key, code)
            all_lines = code.splitlines()
            item = brief(fn)
            item["cached"] = cached
            item["lines"] = len(all_lines)
            item["signature"] = next(
                (ln.strip() for ln in all_lines if ln.strip().endswith(")")), ""
            )
            if grep is not None:
                hits = _grep_code(code, grep)
                item["grep_hits"] = len(hits)
                item["matched"] = hits[:20]
            if include_code:
                if max_lines and len(all_lines) > max_lines:
                    item["code"] = "\n".join(all_lines[:max_lines]) + "\n/* ... truncated */"
                else:
                    item["code"] = code
            if a.get("include_callees"):
                item["callees"] = [str(c.getName()) for c in fn.getCalledFunctions(MONITOR)][:40]
            if a.get("include_callers"):
                item["callers"] = [str(c.getName()) for c in fn.getCallingFunctions(MONITOR)][:40]
            results.append(item)
        except Exception as ex:  # noqa: BLE001
            results.append({"target": str(t), "error": f"{type(ex).__name__}: {ex}"})
    if grep is not None:
        results = [r for r in results if r.get("error") or r.get("grep_hits")]
    return {"binary": a["binary"], "decompiled": len(results), "results": results}


def cmd_strings(a: dict[str, Any]) -> dict[str, Any]:
    p = _entry(a["binary"])["program"]
    q = (a.get("query") or "").lower()
    limit = int(a.get("limit", 200))
    skip = int(a.get("offset", 0))
    out = []
    seen = 0
    scanned = 0
    it = p.getListing().getDefinedData(True)
    while it.hasNext():
        d = it.next()
        scanned += 1
        try:
            tname = str(d.getDataType().getName()).lower()
            if not any(k in tname for k in ("string", "unicode", "terminated", "char")):
                continue
            try:
                val = str(d.getValue())
            except Exception:  # noqa: BLE001 - a jpype call can raise anything
                val = str(d.getDefaultValueRepresentation())
        except Exception:  # noqa: BLE001 - skip data whose type has no value
            continue
        if val in ("", "None") or (q and q not in val.lower()):
            continue
        seen += 1
        if seen <= skip:
            continue
        out.append({"addr": str(d.getAddress()), "value": val[:400]})
        if len(out) >= limit:
            break
    return {
        "binary": a["binary"],
        "matched": seen,
        "defined_data_scanned": scanned,
        "strings": out,
    }


def cmd_xrefs(a: dict[str, Any]) -> dict[str, Any]:
    e = _entry(a["binary"])
    p = e["program"]
    targets = a.get("targets") or [a["target"]]
    out = []
    for t in targets:
        fn = _function(e, t)
        addr = fn.getEntryPoint() if fn else _addr(e, t)
        refs = []
        for r in p.getReferenceManager().getReferencesTo(addr):
            holder = p.getFunctionManager().getFunctionContaining(r.getFromAddress())
            refs.append(
                {
                    "from": str(r.getFromAddress()),
                    "type": str(r.getReferenceType()),
                    "in_function": str(holder.getName()) if holder else None,
                }
            )
        out.append({"target": str(t), "addr": str(addr), "xrefs": refs[:400]})
    return {"results": out}


def cmd_bytes(a: dict[str, Any]) -> dict[str, Any]:
    e = _entry(a["binary"])
    p = e["program"]
    addr = _addr(e, a["addr"])
    size = int(a.get("size", 64))
    mem = p.getMemory()
    data = bytes(mem.getByte(addr.add(i)) & 0xFF for i in range(size))
    return {
        "addr": str(addr),
        "hex": data.hex(),
        "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
    }


def cmd_rename(a: dict[str, Any]) -> dict[str, Any]:
    from ghidra.program.model.symbol import SourceType

    e = _entry(a["binary"])
    p = e["program"]
    fn = _function(e, a["target"])
    if fn is None:
        raise KeyError(f"function {a['target']!r} not found")
    tx = p.startTransaction("ghlab-rename")
    try:
        fn.setName(str(a["new"]), SourceType.USER_DEFINED)
    finally:
        p.endTransaction(tx, True)
    saved = _save(p, "ghlab rename")
    return {"renamed": str(fn.getName()), "addr": str(fn.getEntryPoint()), "saved_via": saved}


COMMENT_TYPES = {"plate", "pre", "post", "eol", "repeatable"}


def cmd_comment(a: dict[str, Any]) -> dict[str, Any]:
    """Write a listing comment. Ghidra 12 has no DECOMPILER comment type, so
    `decompiler` maps to PRE, which the decompiler renders above the function."""
    from ghidra.program.model.listing import CommentType

    e = _entry(a["binary"])
    p = e["program"]
    ctype = str(a.get("type", "plate")).lower()
    ctype = "pre" if ctype == "decompiler" else ctype
    if ctype not in COMMENT_TYPES:
        raise ValueError(f"type must be one of {sorted(COMMENT_TYPES | {'decompiler'})}")
    fn = _function(e, a["target"])
    addr = fn.getEntryPoint() if fn else _addr(e, a["target"])
    tx = p.startTransaction("ghlab-comment")
    try:
        p.getListing().setComment(addr, CommentType.valueOf(ctype.upper()), str(a["text"]))
    finally:
        p.endTransaction(tx, True)
    saved = _save(p, "ghlab comment")
    return {"addr": str(addr), "type": ctype, "ok": True, "saved_via": saved}


def cmd_graph(a: dict[str, Any]) -> dict[str, Any]:
    """Breadth-first call tree. direction: calling (callees) | called (callers)."""
    e = _entry(a["binary"])
    direction = str(a.get("direction", "calling"))
    depth = int(a.get("depth", 2))
    cap = int(a.get("limit", 80))
    root = _function(e, a["target"])
    if root is None:
        raise KeyError(f"function {a['target']!r} not found")

    def edges(fn):
        if direction == "called":
            return list(fn.getCallingFunctions(MONITOR))[:cap]
        return list(fn.getCalledFunctions(MONITOR))[:cap]

    nodes = [brief(root)]
    edges_out = []
    frontier = [root]
    seen = {str(root.getEntryPoint())}
    for _level in range(depth):
        nxt = []
        for fn in frontier:
            for callee in edges(fn):
                key = str(callee.getEntryPoint())
                edges_out.append({"from": str(fn.getName()), "to": str(callee.getName())})
                if key in seen or len(nodes) >= cap:
                    continue
                seen.add(key)
                nodes.append(brief(callee))
                nxt.append(callee)
        frontier = nxt
        if not frontier:
            break
    return {
        "binary": a["binary"],
        "direction": direction,
        "root": str(root.getName()),
        "nodes": nodes,
        "edges": edges_out[: cap * 2],
    }


# ------------------------------------------------------------------ triage

# Import-name classification. First match wins, so ordering is the priority:
# inject before exec before file (VirtualAlloc reads as injection).
RISK: dict[str, re.Pattern[str]] = {
    # anchors matter: bare substrings match OpenProcessToken, SendMessageW, ...
    "inject": re.compile(
        r"virtualalloc|virtualprotect|writeprocessmemory|createremotethread"
        r"|^openprocess$|^createthread$|queueuserapc|setthreadcontext"
        r"|rtlcreateuserthread|mapviewoffile|unmapviewoffile|ntunmapviewofsection"
    ),
    "exec": re.compile(
        r"createprocess|shellexecute|winexec$|loadlibrary|getprocaddress"
        r"|findresource|loadresource|createservice"
    ),
    "network": re.compile(
        r"winhttp|wininet|ws2_32|^wsa|^socket$|^connect$|^sendto$|^recvfrom$"
        r"|internetopen|internetread|urldownload|getaddrinfo|dnsquery|closesocket"
    ),
    "file": re.compile(
        r"^createfile|^writefile|^readfile|^deletefile|^movefile|^copyfile"
        r"|findfirstfile|findnextfile|setfileattributes|gettemppath|createdirectory"
    ),
    "registry": re.compile(
        r"regopenkey|regsetvalue|regcreatekey|regqueryvalue|regdeletekey|regsavekey"
    ),
    "crypto": re.compile(r"crypt|bcrypt|ncrypt|aes|rc4|md5|sha256|sha512|rsa"),
    "anti": re.compile(
        r"isdebuggerpresent|checkremotedebuggerpresent|outputdebugstring"
        r"|ntqueryinformationprocess|gettickcount|queryperformancecounter"
        r"|ntglobalflag|getforegroundwindow|toolhelp32snapshot"
    ),
    "ui": re.compile(r"messagebox|dialogbox|^createwindow|setwindowtext|getdlgitemtext"),
}

# (label, every one of these must be imported) — triage signals, not findings.
COMBOS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("alloc+exec", ("virtualalloc", "virtualprotect")),
    ("remote-thread", ("openprocess", "writeprocessmemory", "createremotethread")),
    ("dynamic-load", ("loadlibrary", "getprocaddress")),
    ("net+exec", ("socket", "createprocess")),
    ("persist", ("createservice",)),
    ("anti-debug", ("isdebuggerpresent",)),
)

STRING_KINDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("url", re.compile(r"^(https?|ftp)://", re.I)),
    ("ip", re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")),
    ("path", re.compile(r"^([A-Za-z]:\\|\\\\|%(temp|appdata|systemroot|programdata)%)", re.I)),
    ("registry", re.compile(r"^(HKEY_|SOFTWARE\\|SYSTEM\\)", re.I)),
    ("cmdline", re.compile(r"(cmd\.exe|powershell|schtasks|wscript|mshta)", re.I)),
    ("fmt", re.compile(r"%[-#0-9.]*(s|d|u|x|p)")),
    ("b64", re.compile(r"^[A-Za-z0-9+/]{16,}[+/=][A-Za-z0-9+/=]*$")),
    ("dll", re.compile(r"^[\w .-]+\.(dll|exe|sys|bat|ps1|vbs)$", re.I)),
)


def _classify_import(name: str) -> str | None:
    low = name.lower()
    for group, pat in RISK.items():
        if pat.search(low):
            return group
    return None


def _imports(program) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    try:
        it = program.getSymbolTable().getExternalSymbols()
    except Exception:  # noqa: BLE001
        return out
    for sym in it:
        try:
            name = str(sym.getName())
            ns = sym.getParentNamespace()
            lib = str(ns.getName()) if ns is not None else ""
            lib = re.sub(r"\.(dll|so|dylib)$", "", lib, flags=re.I).upper() or "?"
            if not name or (lib, name) in seen:
                continue
            seen.add((lib, name))
            out.append({"name": name, "lib": lib, "addr": str(sym.getAddress())})
        except Exception:  # noqa: BLE001
            continue
    return out


def _string_kind(value: str) -> str | None:
    for kind, pat in STRING_KINDS:
        if pat.search(value):
            return kind
    return None


def _scan_strings(program, per_kind: int = 3) -> dict[str, Any]:
    """One pass over defined data: total count + samples per interesting kind."""
    total = 0
    counts: Counter[str] = Counter()
    samples: dict[str, list[dict[str, str]]] = {k: [] for k, _ in STRING_KINDS}
    scanned = 0
    it = program.getListing().getDefinedData(True)
    while it.hasNext():
        d = it.next()
        scanned += 1
        try:
            tname = str(d.getDataType().getName()).lower()
            if not any(k in tname for k in ("string", "unicode", "terminated", "char")):
                continue
            try:
                val = str(d.getValue())
            except Exception:  # noqa: BLE001
                val = str(d.getDefaultValueRepresentation())
        except Exception:  # noqa: BLE001
            continue
        if not val or val == "None" or len(val) < 4:
            continue
        total += 1
        kind = _string_kind(val)
        if kind is None:
            continue
        counts[kind] += 1
        if len(samples[kind]) < per_kind:
            samples[kind].append({"addr": str(d.getAddress()), "value": val[:160]})
    return {"total": total, "scanned": scanned, "counts": dict(counts), "samples": samples}


def _entry_chain(program, depth: int = 3) -> list[dict[str, str]]:
    fm = program.getFunctionManager()
    try:
        entry_addr = program.getEntryPoint()
    except Exception:  # noqa: BLE001
        entry_addr = None
    if entry_addr is None:
        # getEntryPoint() can come back empty after the entry symbol is renamed,
        # so fall back to names, then to the first function in executable memory.
        wanted = ("entry", "_start", "maincrtstartup", "__scrt_common_main_seh")
        for sym in program.getSymbolTable().getAllSymbols(True):
            if str(sym.getName()).lower() in wanted:
                entry_addr = sym.getAddress()
                break
    if entry_addr is None:
        for fn in fm.getFunctions(True):
            if fn.isExternal() or fn.isThunk():
                continue
            if program.getMemory().getExecuteSet().contains(fn.getEntryPoint()):
                entry_addr = fn.getEntryPoint()
                break
    if entry_addr is None:
        return []
    chain: list[dict[str, str]] = []
    cur = fm.getFunctionContaining(entry_addr) or fm.getFunctionAt(entry_addr)
    if cur is None:
        return [{"name": "<entry>", "addr": str(entry_addr)}]
    while cur is not None and len(chain) < depth:
        chain.append({"name": str(cur.getName()), "addr": str(cur.getEntryPoint())})
        nxt = None
        try:
            for callee in cur.getCalledFunctions(MONITOR):
                if callee.isExternal() or callee.isThunk():
                    continue
                if str(callee.getName()).lower() in ("main", "wmain", "winmain", "wwinmain"):
                    nxt = callee
                    break
                if nxt is None:
                    nxt = callee
        except Exception:  # noqa: BLE001
            nxt = None
        cur = nxt
    return chain


def _hubs(program, top: int) -> list[dict[str, Any]]:
    """Functions with the most callers (where logic usually condenses)."""
    scored = []
    for fn in program.getFunctionManager().getFunctions(True):
        if fn.isExternal() or fn.isThunk():
            continue
        try:
            callers = list(fn.getCallingFunctions(MONITOR))
        except Exception:  # noqa: BLE001
            continue
        if callers:
            scored.append((len(callers), fn))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [
        {
            "name": str(fn.getName()),
            "addr": str(fn.getEntryPoint()),
            "callers": n,
            "size": int(fn.getBody().getNumAddresses()),
        }
        for n, fn in scored[:top]
    ]


def _size_buckets(program) -> dict[str, int]:
    buckets = {"<32": 0, "32-128": 0, "128-512": 0, ">512": 0}
    for fn in program.getFunctionManager().getFunctions(True):
        if fn.isExternal() or fn.isThunk():
            continue
        n = int(fn.getBody().getNumAddresses())
        key = "<32" if n < 32 else "32-128" if n < 128 else "128-512" if n < 512 else ">512"
        buckets[key] += 1
    return buckets


def cmd_digest(a: dict[str, Any]) -> dict[str, Any]:
    """One call, whole-picture triage — composition of existing commands only."""
    p = _entry(a["binary"])["program"]
    top = int(a.get("top", 8))
    per_kind = int(a.get("strings", 3))
    imports = _imports(p)
    names = [i["name"] for i in imports]
    low_names = [n.lower() for n in names]
    groups: dict[str, list[str]] = {k: [] for k in RISK}
    for n in names:
        kind = _classify_import(n)
        if kind:
            groups[kind].append(n)
    combos = [
        {"label": label, "hits": [r for r in required if any(r in n for n in low_names)]}
        for label, required in COMBOS
        if all(any(r in n for n in low_names) for r in required)
    ]
    blocks = list(p.getMemory().getBlocks())
    return {
        "binary": str(p.getName()),
        "md5": str(p.getExecutableMD5()),
        "language": str(p.getLanguageID()),
        "compiler": str(p.getCompiler()),
        "image_base": str(p.getImageBase()),
        "entry": _entry_chain(p, 3),
        "functions": int(p.getFunctionManager().getFunctionCount()),
        "imports": {
            "total": len(imports),
            "libs": dict(Counter(i["lib"] for i in imports).most_common()),
            "groups": {k: v[:12] for k, v in groups.items() if v},
        },
        "combos": combos,
        "strings": _scan_strings(p, per_kind),
        "hubs": _hubs(p, top),
        "sizes": _size_buckets(p),
        "memory": {
            "blocks": len(blocks),
            "executable": [str(b.getName()) for b in blocks if bool(b.isExecute())][:8],
        },
    }


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float)):
        return [str(value)]
    return [str(v) for v in value]


def cmd_find(a: dict[str, Any]) -> dict[str, Any]:
    """Locate candidates by structure (imports / strings / callees), not by name.

    Reads the persistent index, so repeats cost milliseconds instead of a full scan.
    """
    e = _entry(a["binary"])
    limit = int(a.get("limit", 20))
    any_mode = bool(a.get("any", False))
    filters = {
        "import": [re.compile(x, re.I) for x in _as_list(a.get("import"))],
        "string": [re.compile(x, re.I) for x in _as_list(a.get("string"))],
        "calls": [re.compile(x, re.I) for x in _as_list(a.get("calls"))],
    }
    active = {k: v for k, v in filters.items() if v}
    if not active:
        raise ValueError("pass at least one of import / string / calls")
    try:
        idx = load_index(e)
    except Exception:  # noqa: BLE001 - fall back to a live scan
        return _find_by_scan(a)
    rows = idx["rows"]
    hits: dict[int, dict[str, list[str]]] = {}

    def touch(offset: int, kind: str, detail: str) -> None:
        slot = hits.setdefault(offset, {"import": [], "string": [], "calls": []})
        bucket = slot[kind]
        if len(bucket) < 8 and detail not in bucket:
            bucket.append(detail)

    for offset, row in rows.items():
        for name in row["imports"]:
            for pat in active.get("import", []):
                if pat.search(name):
                    touch(offset, "import", name)
        for value in row["strings"]:
            for pat in active.get("string", []):
                if pat.search(value):
                    touch(offset, "string", value[:80])
        for name in row["callees"]:
            for pat in active.get("calls", []):
                if pat.search(name):
                    touch(offset, "calls", name)

    needed = len(active)
    kept = []
    for offset, matched in hits.items():
        kinds = sum(1 for k in active if matched[k])
        if (any_mode and kinds == 0) or (not any_mode and kinds < needed):
            continue
        row = rows[offset]
        kept.append((kinds, int(row["size"]), row, matched))
    kept.sort(key=lambda item: (item[0], item[1]), reverse=True)

    out = []
    for kinds, size, row, matched in kept[:limit]:
        out.append(
            {
                "name": row["name"],
                "addr": row["addr"],
                "size": size,
                "matched": {k: v for k, v in matched.items() if v},
                "filters_matched": kinds,
            }
        )
    return {
        "binary": a["binary"],
        "filters": {k: [pat.pattern for pat in v] for k, v in active.items()},
        "mode": "any" if any_mode else "all",
        "candidates": len(kept),
        "functions": out,
        "index": {"cached": idx["cached"], "built_at": idx["meta"].get("built_at")},
    }


def _find_by_scan(a: dict[str, Any]) -> dict[str, Any]:
    """Live scan fallback: used when the index cannot be built for a program."""
    e = _entry(a["binary"])
    p = e["program"]
    fm = p.getFunctionManager()
    limit = int(a.get("limit", 20))
    any_mode = bool(a.get("any", False))
    filters = {
        "import": [re.compile(x, re.I) for x in _as_list(a.get("import"))],
        "string": [re.compile(x, re.I) for x in _as_list(a.get("string"))],
        "calls": [re.compile(x, re.I) for x in _as_list(a.get("calls"))],
    }
    active = {k: v for k, v in filters.items() if v}
    if not active:
        raise ValueError("pass at least one of import / string / calls")

    hits: dict[str, dict[str, Any]] = {}

    def touch(fn, kind: str, detail: str) -> None:
        slot = hits.setdefault(
            str(fn.getEntryPoint()),
            {"function": fn, "matched": {"import": [], "string": [], "calls": []}},
        )
        bucket = slot["matched"][kind]
        if len(bucket) < 8 and detail not in bucket:
            bucket.append(detail)

    if active.get("import"):
        for sym in p.getSymbolTable().getExternalSymbols():
            name = str(sym.getName())
            if not any(pat.search(name) for pat in active["import"]):
                continue
            for ref in p.getReferenceManager().getReferencesTo(sym.getAddress()):
                fn = fm.getFunctionContaining(ref.getFromAddress())
                if fn is not None:
                    touch(fn, "import", name)

    if active.get("string"):
        it = p.getListing().getDefinedData(True)
        while it.hasNext():
            d = it.next()
            try:
                tname = str(d.getDataType().getName()).lower()
                if not any(k in tname for k in ("string", "unicode", "terminated", "char")):
                    continue
                val = str(d.getValue())
            except Exception:  # noqa: BLE001
                continue
            if not any(pat.search(val) for pat in active["string"]):
                continue
            for ref in p.getReferenceManager().getReferencesTo(d.getAddress()):
                fn = fm.getFunctionContaining(ref.getFromAddress())
                if fn is not None:
                    touch(fn, "string", val[:80])

    if active.get("calls"):
        for fn in fm.getFunctions(True):
            if fn.isExternal() or fn.isThunk():
                continue
            try:
                called = [str(c.getName()) for c in fn.getCalledFunctions(MONITOR)]
            except Exception:  # noqa: BLE001
                continue
            for name in called:
                if any(pat.search(name) for pat in active["calls"]):
                    touch(fn, "calls", name)

    needed = len(active)
    kept = []
    for slot in hits.values():
        matched = slot["matched"]
        kinds = sum(1 for k in active if matched[k])
        if (any_mode and kinds == 0) or (not any_mode and kinds < needed):
            continue
        fn = slot["function"]
        kept.append((kinds, int(fn.getBody().getNumAddresses()), fn, matched))
    kept.sort(key=lambda row: (row[0], row[1]), reverse=True)

    out = []
    for kinds, size, fn, matched in kept[:limit]:
        item = brief(fn)
        item["matched"] = {k: v for k, v in matched.items() if v}
        item["filters_matched"] = kinds
        item["size"] = size
        out.append(item)
    return {
        "binary": a["binary"],
        "filters": {k: [pat.pattern for pat in v] for k, v in active.items()},
        "mode": "any" if any_mode else "all",
        "candidates": len(kept),
        "functions": out,
    }


# --------------------------------------------------------------------- emulate

PARAM_REGS = ("RCX", "RDX", "R8", "R9")
MASK64 = (1 << 64) - 1


def _is_string_data(data) -> bool:
    try:
        tname = str(data.getDataType().getName()).lower()
    except Exception:  # noqa: BLE001
        return False
    return any(k in tname for k in ("string", "unicode", "terminated", "char"))


def _string_value(data) -> str | None:
    try:
        val = str(data.getValue())
    except Exception:  # noqa: BLE001
        try:
            val = str(data.getDefaultValueRepresentation())
        except Exception:  # noqa: BLE001
            return None
    if not val or val == "None":
        return None
    return val[:120]


def _fingerprint(program, fn, block_model) -> dict[str, Any]:
    """One pass over a function collecting everything a diff needs."""
    insns = 0
    strings: set[str] = set()
    consts: set[int] = set()
    it = program.getListing().getInstructions(fn.getBody(), True)
    while it.hasNext():
        insn = it.next()
        insns += 1
        for i in range(insn.getNumOperands()):
            try:
                scalar = insn.getScalar(i)
            except Exception:  # noqa: BLE001
                scalar = None
            if scalar is None:
                continue
            value = int(scalar.getValue())
            if abs(value) > 0xFF and len(consts) < 512:
                consts.add(value)
        if len(strings) < 256:
            for ref in insn.getReferencesFrom():
                data = program.getListing().getDataAt(ref.getToAddress())
                if data is not None and _is_string_data(data):
                    value = _string_value(data)
                    if value:
                        strings.add(value)
    ext: set[str] = set()
    callees: set[str] = set()
    calls = 0
    for callee in fn.getCalledFunctions(MONITOR):
        calls += 1
        name = str(callee.getName())
        if callee.isExternal() or callee.isThunk() or name.startswith("PTR_"):
            ext.add(_clean_name(name))
        elif len(callees) < 64:
            callees.add(name)
    blocks = 0
    cit = block_model.getCodeBlocksContaining(fn.getBody(), MONITOR)
    while cit.hasNext():
        cit.next()
        blocks += 1
    return {
        "name": str(fn.getName()),
        "addr": str(fn.getEntryPoint()),
        "offset": int(fn.getEntryPoint().getOffset()),
        "size": int(fn.getBody().getNumAddresses()),
        "insns": insns,
        "blocks": blocks,
        "calls": calls,
        "strings": strings,
        "consts": consts,
        "imports": ext,
        "callees": callees,
    }


_INDEX_SET_KEYS = ("strings", "imports", "consts", "callees")


def _ghlab_dir() -> Path:
    base = _project_dir or (Path.home() / "re" / "proj")
    d = Path(base) / ".ghlab"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _index_file(binary: str) -> Path:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(binary))
    return _ghlab_dir() / "index" / f"{slug}.json"


def _index_meta(program) -> dict[str, Any]:
    return {
        "md5": str(program.getExecutableMD5() or ""),
        "mods": int(program.getModificationNumber()),
        "language": str(program.getLanguageID()),
    }


def build_index(e) -> dict[int, dict[str, Any]]:
    """One scan of the whole program: per-function facts, reused by find/diff/similar."""
    from ghidra.program.model.block import BasicBlockModel

    program = e["program"]
    model = BasicBlockModel(program)
    rows: dict[int, dict[str, Any]] = {}
    for fn in program.getFunctionManager().getFunctions(True):
        try:
            if fn.isExternal() or fn.isThunk():
                continue
            row = _fingerprint(program, fn, model)
        except Exception:  # noqa: BLE001 - one odd function must not kill the scan
            continue
        # keep sets (diff/similar do set algebra) but cap what goes into the cache
        row["consts"] = set(sorted(row["consts"])[:200])
        row["strings"] = set(sorted(row["strings"])[:200])
        row["imports"] = set(sorted(row["imports"])[:64])
        row["callees"] = set(sorted(row["callees"])[:64])
        rows[int(row["offset"])] = row
    return rows


def _rows_to_cache(rows: dict[int, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(k): {**v, **{key: sorted(v[key]) for key in _INDEX_SET_KEYS}} for k, v in rows.items()
    }


def _rows_from_cache(raw: dict[str, dict[str, Any]]) -> dict[int, dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    for key, row in raw.items():
        rows[int(key)] = {**row, **{k: set(row.get(k) or []) for k in _INDEX_SET_KEYS}}
    return rows


def load_index(e, refresh: bool = False) -> dict[str, Any]:
    """Return the per-function fact table, rebuilding it when the program changed.

    Invalidation is (md5, modification number): any write through ghlab bumps the
    modification number, so a stale index can never be mistaken for a fresh one.
    """
    started = time.time()
    program = e["program"]
    meta = _index_meta(program)
    path = _index_file(str(e["binary"]))
    if not refresh and path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            cached_meta = raw.get("meta") or {}
            same = cached_meta.get("md5") == meta["md5"] and cached_meta.get("mods") == meta["mods"]
        except (OSError, ValueError):
            same = False
        if same:
            rows = _rows_from_cache(raw.get("rows") or {})
            return {
                "rows": rows,
                "meta": raw["meta"],
                "cached": True,
                "path": str(path),
                "bytes": path.stat().st_size,
                "elapsed_ms": int((time.time() - started) * 1000),
            }
    rows = build_index(e)
    payload = {
        "meta": {
            **meta,
            "built_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "functions": len(rows),
            "binary": str(e["binary"]),
        },
        "rows": _rows_to_cache(rows),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8", newline="\n")
    return {
        "rows": rows,
        "meta": payload["meta"],
        "cached": False,
        "path": str(path),
        "bytes": path.stat().st_size,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def cmd_index(a: dict[str, Any]) -> dict[str, Any]:
    """Build (or reuse) the fact index for one binary and report what is in it."""
    e = _entry(a["binary"])
    idx = load_index(e, refresh=bool(a.get("refresh")))
    rows = idx["rows"]
    strings = sum(len(r["strings"]) for r in rows.values())
    imports = {name for r in rows.values() for name in r["imports"]}
    return {
        "binary": str(a["binary"]),
        "cached": idx["cached"],
        "functions": len(rows),
        "strings": strings,
        "imports": len(imports),
        "built_at": idx["meta"].get("built_at"),
        "path": idx["path"],
        "bytes": idx["bytes"],
        "elapsed_ms": idx["elapsed_ms"],
    }


def _program_fingerprints(binary: str) -> dict[str, Any]:
    entry = _entry(binary)
    program = entry["program"]
    md5 = str(program.getExecutableMD5() or "")
    cache_key = (str(binary), md5, int(program.getModificationNumber()))
    if cache_key in _FP_CACHE:
        return _FP_CACHE[cache_key]
    idx = load_index(entry)
    out = {
        "binary": str(binary),
        "md5": md5,
        "program": program,
        "functions": idx["rows"],
        "index": {"cached": idx["cached"], "built_at": idx["meta"].get("built_at")},
    }
    _FP_CACHE[cache_key] = out
    return out


def _read_memory(program, start, size: int) -> bytes:
    """Read a range: MemoryMap.getBytes only takes a byte[] sink, not a length."""
    from jpype import JArray, JByte

    buf = JArray(JByte)(size)
    read = program.getMemory().getBytes(start, buf)
    return bytes((buf[i] & 0xFF) for i in range(read))


def _function_at(program, addr_text: Any):
    """Look a function up by address string, without needing an `_entry` handle."""
    offset = _hex_addr(addr_text)
    if offset is None:
        return None
    space = program.getAddressFactory().getDefaultAddressSpace()
    return program.getFunctionManager().getFunctionAt(space.getAddress(offset))


def _disasm_lines(program, fn, limit: int = 400) -> list[str]:
    """Instruction text with absolute addresses blanked, so two builds line up."""
    base = int(fn.getEntryPoint().getOffset())
    out: list[str] = []
    it = program.getListing().getInstructions(fn.getBody(), True)
    while it.hasNext() and len(out) < limit:
        insn = it.next()
        text = str(insn)
        text = re.sub(r"\b0x[0-9a-fA-F]{4,}\b", "ADDR", text)
        text = re.sub(r"\b[0-9a-fA-F]{6,}\b", "ADDR", text)
        offset = int(insn.getAddress().getOffset()) - base
        out.append(f"{offset:+#06x}  {text}")
    return out


def _disasm_diff(left_program, right_program, left_fn, right_fn, context: int = 2) -> list[str]:
    """Unified diff of the two functions' instruction streams (bounded)."""
    a = _disasm_lines(left_program, left_fn)
    b = _disasm_lines(right_program, right_fn)
    lines = difflib.unified_diff(a, b, fromfile="a", tofile="b", n=context, lineterm="")
    return list(lines)[:240]


def _sections(program) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for blk in program.getMemory().getBlocks():
        size = int(blk.getSize())
        if size <= 0 or size > (16 << 20):
            continue
        data = _read_memory(program, blk.getStart(), size)
        out[str(blk.getName())] = {
            "size": size,
            "md5": hashlib.md5(data).hexdigest(),
            "exec": bool(blk.isExecute()),
            "write": bool(blk.isWrite()),
        }
    return out


def _jaccard(left: set, right: set) -> float:
    if not left and not right:
        return 1.0
    union = len(left | right)
    return len(left & right) / union if union else 0.0


def _similarity(x: dict[str, Any], y: dict[str, Any]) -> float:
    size_ratio = min(x["size"], y["size"]) / max(x["size"], y["size"], 1)
    return (
        0.45 * _jaccard(x["strings"], y["strings"])
        + 0.30 * _jaccard(x["imports"], y["imports"])
        + 0.15 * _jaccard(x["consts"], y["consts"])
        + 0.10 * size_ratio
    )


def _delta(x: dict[str, Any], y: dict[str, Any], limit: int) -> dict[str, Any]:
    def diff_set(left: set, right: set) -> tuple[list, list]:
        added = sorted(right - left, key=str)[:limit]
        removed = sorted(left - right, key=str)[:limit]
        return list(map(str, added)), list(map(str, removed))

    s_add, s_del = diff_set(x["strings"], y["strings"])
    i_add, i_del = diff_set(x["imports"], y["imports"])
    c_add, c_del = diff_set(x["consts"], y["consts"])
    return {
        "size": [x["size"], y["size"]],
        "insns": [x["insns"], y["insns"]],
        "blocks": [x["blocks"], y["blocks"]],
        "calls": [x["calls"], y["calls"]],
        "strings_added": s_add,
        "strings_removed": s_del,
        "imports_added": i_add,
        "imports_removed": i_del,
        "consts_added": [hex(v) for v in c_add],
        "consts_removed": [hex(v) for v in c_del],
    }


def _changed(x: dict[str, Any], y: dict[str, Any]) -> bool:
    for key in ("size", "insns", "blocks", "calls"):
        if x[key] != y[key]:
            return True
    return any(x[key] != y[key] for key in ("strings", "consts", "imports"))


def _size_swing(entry: dict[str, Any]) -> int:
    """Biggest size change first; the tuple is (before, after) bytes."""
    before, after = entry["delta"]["size"]
    return abs(int(after) - int(before))


def cmd_diff(a: dict[str, Any]) -> dict[str, Any]:
    """Compare two programs in the project: what was added, removed, patched."""

    started = time.time()
    left = _program_fingerprints(a["a"])
    right = _program_fingerprints(a["b"])
    la, lb = left["functions"], right["functions"]
    limit = int(a.get("limit", 25))
    min_score = float(a.get("min_score", 0.55))
    detail = max(0, int(a.get("detail", 0)))

    pattern = None
    if a.get("match"):
        pattern = re.compile(str(a["match"]), re.I)
        la = {k: v for k, v in la.items() if pattern.search(v["name"])}
        lb = {k: v for k, v in lb.items() if pattern.search(v["name"])}

    pairs: list[tuple[int, int, str, float]] = []  # (a offset, b offset, how, score)
    used_a: set[int] = set()
    used_b: set[int] = set()

    def claim(how: str, score: float, key_a: int, key_b: int) -> None:
        pairs.append((key_a, key_b, how, score))
        used_a.add(key_a)
        used_b.add(key_b)

    # 1. identical (strings, imports) signature, unique on both sides
    def sig(fp: dict[str, Any]) -> tuple:
        return (frozenset(fp["strings"]), frozenset(fp["imports"]))

    bucket_a: dict[tuple, list[int]] = {}
    bucket_b: dict[tuple, list[int]] = {}
    for k, fp in la.items():
        bucket_a.setdefault(sig(fp), []).append(k)
    for k, fp in lb.items():
        bucket_b.setdefault(sig(fp), []).append(k)
    for key, offs in bucket_a.items():
        others = bucket_b.get(key) or []
        if len(offs) == 1 and len(others) == 1:
            claim("signature", 1.0, offs[0], others[0])

    # 2. same entry offset (same image layout, e.g. patched build)
    for k in list(la):
        if k in used_a or k not in lb or k in used_b:
            continue
        claim("address", 0.9, k, k)

    # 3. same symbol name
    by_name_b = {v["name"]: k for k, v in lb.items() if k not in used_b}
    for k, fp in la.items():
        if k in used_a:
            continue
        other = by_name_b.get(fp["name"])
        if other is not None and other not in used_b:
            claim("name", 0.85, k, other)

    # 4. greedy similarity for the rest
    rest_a = [k for k in la if k not in used_a]
    rest_b = [k for k in lb if k not in used_b]
    if rest_a and rest_b and len(rest_a) * len(rest_b) <= 4_000_000:
        scored = []
        for ka in rest_a:
            for kb in rest_b:
                score = _similarity(la[ka], lb[kb])
                if score >= min_score:
                    scored.append((score, ka, kb))
        scored.sort(reverse=True)
        for score, ka, kb in scored:
            if ka in used_a or kb in used_b:
                continue
            claim("similarity", round(score, 3), ka, kb)

    changed: list[dict[str, Any]] = []
    identical = 0
    for ka, kb, how, score in pairs:
        x, y = la[ka], lb[kb]
        if not _changed(x, y):
            identical += 1
            continue
        entry_delta = _delta(x, y, limit=6)
        changed.append(
            {
                "a": {"name": x["name"], "addr": x["addr"], "size": x["size"]},
                "b": {"name": y["name"], "addr": y["addr"], "size": y["size"]},
                "matched_by": how,
                "score": score,
                "delta": entry_delta,
            }
        )
    changed.sort(key=_size_swing)

    if detail:
        for entry in changed[:detail]:
            fa = _function_at(left["program"], entry["a"]["addr"])
            fb = _function_at(right["program"], entry["b"]["addr"])
            if fa is None or fb is None:
                continue
            try:
                entry["disasm"] = _disasm_diff(left["program"], right["program"], fa, fb)
            except Exception as exc:  # noqa: BLE001 - diff detail is best effort
                entry["disasm_error"] = f"{type(exc).__name__}: {exc}"

    added = [
        {"name": lb[k]["name"], "addr": lb[k]["addr"], "size": lb[k]["size"]}
        for k in lb
        if k not in used_b
    ]
    removed = [
        {"name": la[k]["name"], "addr": la[k]["addr"], "size": la[k]["size"]}
        for k in la
        if k not in used_a
    ]

    sec_a = _sections(left["program"])
    sec_b = _sections(right["program"])
    sections = {
        "added": sorted(set(sec_b) - set(sec_a)),
        "removed": sorted(set(sec_a) - set(sec_b)),
        "changed": sorted(n for n in set(sec_a) & set(sec_b) if sec_a[n]["md5"] != sec_b[n]["md5"]),
    }

    return {
        "a": {"binary": left["binary"], "md5": left["md5"], "functions": len(la)},
        "b": {"binary": right["binary"], "md5": right["md5"], "functions": len(lb)},
        "summary": {
            "matched": len(pairs),
            "identical": identical,
            "changed": len(changed),
            "added": len(added),
            "removed": len(removed),
            "by": dict(Counter(p[2] for p in pairs)),
        },
        "sections": sections,
        "changed": changed[:limit],
        "added": added[:limit],
        "removed": removed[:limit],
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def parse_arg_spec(text: Any) -> tuple[str, Any]:
    """Classify one argument: `"str"`, `L"wide"`, `0x1234`, `42`, `null`, `*symbol`."""
    t = str(text).strip()
    if len(t) >= 3 and t[:2] == 'L"' and t[-1] == '"':
        return ("wstr", t[2:-1])
    if len(t) >= 2 and t[0] == '"' and t[-1] == '"':
        return ("str", t[1:-1])
    if t.startswith("*") and len(t) > 1:
        return ("deref", t[1:])
    if t.lower() in ("", "null", "none"):
        return ("int", 0)
    try:
        return ("int", int(t, 0))
    except ValueError:
        return ("str", t)


def _symbol_addr(program, name: str) -> int | None:
    text = str(name)
    if text.lower().startswith("0x"):
        return int(text, 16)
    for sym in program.getSymbolTable().getAllSymbols(True):
        if str(sym.getName()) == text:
            return int(sym.getAddress().getOffset())
    return None


def _suggest_symbols(program, name: str, limit: int = 6) -> list[str]:
    low = str(name).lower()
    hits: list[str] = []
    for sym in program.getSymbolTable().getAllSymbols(True):
        text = str(sym.getName())
        if low in text.lower():
            hits.append(text)
            if len(hits) >= limit:
                break
    return hits


def _snapshot_writable(program, emu, budget: int = 2 << 20) -> list[tuple[int, bytes]]:
    """Bytes of every writable initialized non-code block, for a pre/post diff."""
    snap: list[tuple[int, bytes]] = []
    for blk in program.getMemory().getBlocks():
        if not (blk.isWrite() and blk.isInitialized()) or blk.isExecute():
            continue
        size = int(blk.getSize())
        if size <= 0 or size > (1 << 20) or budget <= 0:
            continue
        start = int(blk.getStart().getOffset())
        snap.append((start, _emu_bytes(emu, start, size)))
        budget -= size
    return snap


def _diff_runs(
    emu, baseline: list[tuple[int, bytes]], skip: list[tuple[int, int]], max_runs: int = 12
) -> list[tuple[int, bytes]]:
    """Contiguous byte runs that changed during the run, minus the seeded areas."""
    runs: list[tuple[int, bytes]] = []
    for start, old in baseline:
        new = _emu_bytes(emu, start, len(old))
        if new == old:
            continue
        idx, n = 0, len(old)
        while idx < n and len(runs) < max_runs:
            if new[idx] == old[idx]:
                idx += 1
                continue
            end = idx
            while end < n and new[end] != old[end]:
                end += 1
            pieces = [[start + idx, start + end]]
            for slo, shi in skip:
                nxt = []
                for plo, phi in pieces:
                    if phi <= slo or plo >= shi:
                        nxt.append([plo, phi])
                        continue
                    if plo < slo:
                        nxt.append([plo, slo])
                    if phi > shi:
                        nxt.append([shi, phi])
                pieces = nxt
            for plo, phi in pieces:
                if phi > plo:
                    runs.append((plo, new[plo - start : phi - start]))
            idx = end
    return runs[:max_runs]


def _u64(value: Any) -> int:
    try:
        return int(value) & MASK64
    except TypeError:  # java.math.BigInteger
        return value.longValue() & MASK64


def _scratch_block(program):
    """A writable block the emulator can park strings, a stack and buffers in."""
    mem = program.getMemory()
    for name in (".didat", ".data", ".bss", ".sbss"):
        blk = mem.getBlock(name)
        if blk is not None and blk.isWrite() and blk.getSize() >= 0x800:
            return blk
    for blk in mem.getBlocks():
        if blk.isWrite() and blk.getSize() >= 0x800 and blk.isInitialized():
            return blk
    raise ValueError("no writable block large enough for an emulation scratch area")


def _emu_bytes(emu, addr: int, size: int) -> bytes:
    raw = emu.readMemory(
        emu.getProgram().getAddressFactory().getDefaultAddressSpace().getAddress(addr),
        size,
    )
    return bytes((int(b) & 0xFF) for b in raw)


def _hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"   {off:04x}  {hexpart}  |{text}|")
    return "\n".join(lines)


def _call_target(program, addr: int) -> str | None:
    space = program.getAddressFactory().getDefaultAddressSpace()
    refs = program.getReferenceManager().getReferencesFrom(space.getAddress(addr))
    for ref in refs:
        sym = program.getSymbolTable().getPrimarySymbol(ref.getToAddress())
        if sym is not None:
            return str(sym.getName())
    return None


def _mem_read(emu, addr: int, size: int) -> bytes:
    return _emu_bytes(emu, addr, size)


def _mem_write(emu, addr: int, data: bytes) -> None:
    space = emu.getProgram().getAddressFactory().getDefaultAddressSpace()
    emu.writeMemory(space.getAddress(addr), data)


def _cstr(emu, addr: int, limit: int = 4096) -> bytes:
    out = bytearray()
    while len(out) < limit:
        byte = _mem_read(emu, addr + len(out), 1)[0]
        if byte == 0:
            break
        out.append(byte)
    return bytes(out)


# External calls can't be emulated, so the common CRT string/memory helpers are
# answered in Python instead: that is what makes decrypt_config()-style routines
# (memset + memcpy + strcpy) actually runnable.
STUB_NAMES = (
    "memset",
    "memcpy",
    "memmove",
    "strlen",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "strcmp",
    "strncmp",
    "wcscpy",
    "wcslen",
    "atoi",
)


def _stub_for(name: str | None) -> str | None:
    if not name:
        return None
    low = str(name).lower()
    if low.startswith("pt_"):
        low = low[3:]
    for known in STUB_NAMES:
        if known in low:
            return known
    return None


def _clean_name(name: str) -> str:
    text = str(name)
    found = re.match(r"^(?:PTR_|thunk_FUN_)(.*?)_[0-9a-fA-F]{6,}$", text)
    return found.group(1) if found else text


def _is_external_call(name: str | None) -> bool:
    if not name:
        return False
    low = str(name).lower()
    return low.startswith(("ptr_", "thunk_")) or ".dll" in low


def _apply_stub(emu, program, name: str) -> int:
    """Execute one CRT helper in Python; return the value for RAX."""
    name = name.split(":", 1)[0]
    regs = {r: _u64(emu.readRegister(program.getRegister(r))) for r in PARAM_REGS}
    a0, a1, a2 = regs["RCX"], regs["RDX"], regs["R8"]
    if name == "memset":
        _mem_write(emu, a0, bytes([a1 & 0xFF]) * max(0, a2))
        return a0
    if name in ("memcpy", "memmove"):
        _mem_write(emu, a0, _mem_read(emu, a1, max(0, a2)))
        return a0
    if name == "strlen":
        return len(_cstr(emu, a0))
    if name == "strcpy":
        data = _cstr(emu, a1) + b"\x00"
        _mem_write(emu, a0, data)
        return a0
    if name == "strncpy":
        data = _cstr(emu, a1)[: max(0, a2)]
        data += b"\x00" * (max(0, a2) - len(data))
        _mem_write(emu, a0, data)
        return a0
    if name == "strcat":
        data = _cstr(emu, a0) + _cstr(emu, a1) + b"\x00"
        _mem_write(emu, a0, data)
        return a0
    if name == "strncat":
        data = _cstr(emu, a0) + _cstr(emu, a1)[: max(0, a2)] + b"\x00"
        _mem_write(emu, a0, data)
        return a0
    if name in ("strcmp", "strncmp"):
        left, right = _cstr(emu, a0), _cstr(emu, a1)
        if name == "strncmp":
            left, right = left[:a2], right[:a2]
        return 0 if left == right else (1 if left > right else 0xFFFFFFFF)
    if name == "atoi":
        text = _cstr(emu, a0).decode("latin-1", "replace").strip()
        digits = "".join(c for c in text if c.isdigit() or c in "+-")
        try:
            return int(digits or "0", 10) & MASK64
        except ValueError:
            return 0
    return 0


def _resume_after_stub(emu, program, name: str) -> bool:
    """Pretend the external call at the current return address already happened."""
    sp_reg = emu.getStackPointerRegister()
    sp = _u64(emu.readRegister(sp_reg))
    ret = int.from_bytes(_mem_read(emu, sp, 8), "little")
    space = program.getAddressFactory().getDefaultAddressSpace()
    if not program.getMemory().contains(space.getAddress(ret)):
        return False
    result = _apply_stub(emu, program, name)
    emu.writeRegister(sp_reg, (sp + 8) & MASK64)
    emu.writeRegister(emu.getPCRegister(), ret)
    emu.writeRegister(program.getRegister("RAX"), result & MASK64)
    return True


def _callother_name(err: str) -> str | None:
    found = re.search(r"Unimplemented CALLOTHER pcodeop \(([^)]+)\)", str(err))
    return found.group(1) if found else None


def _skip_instruction(emu, program, addr) -> bool:
    """Step past an instruction whose p-code we cannot emulate (e.g. `lock` atomics)."""
    insn = program.getListing().getInstructionAt(addr)
    if insn is None:
        return False
    target = insn.getFallThrough()
    if target is None:
        target = insn.getAddress().add(int(insn.getLength()))
    emu.writeRegister(emu.getPCRegister(), int(target.getOffset()))
    return True


def cmd_emulate(a: dict[str, Any]) -> dict[str, Any]:
    """Run one function on the P-code emulator and report writes + return value.

    Purely in-emulator: `EmulatorHelper` keeps its own memory state, so nothing is
    written back to the program and no save is needed.
    """

    from ghidra.app.emulator import EmulatorHelper
    from ghidra.util.task import TimeoutTaskMonitor
    from java.util.concurrent import TimeUnit

    started = time.time()
    entry = _entry(a["binary"])
    program = entry["program"]
    lang = program.getLanguage()
    proc = str(lang.getProcessor()).lower()
    if "x86" not in proc:
        raise ValueError(
            "emulate currently supports x86/x86-64 only (Windows x64 calling convention); "
            f"this binary is {lang.getLanguageID()} (processor {proc})"
        )
    fn = _function(entry, a["target"])
    if fn is None:
        raise KeyError(f"function {a['target']!r} not found")

    max_insns = int(a.get("max_insns", 200000))
    ms = int(a.get("ms", 5000))
    block = _scratch_block(program)
    base = int(block.getStart().getOffset())
    size = int(block.getSize())
    if size < 0x1000:
        raise ValueError(f"scratch block {block.getName()} too small ({size:#x})")
    stack_top = base + size - 0x200
    sentinel = base + size - 0x10
    string_at = base + 0x40

    emu = EmulatorHelper(program)
    baseline = _snapshot_writable(program, emu)
    emu.writeMemory(
        program.getAddressFactory().getDefaultAddressSpace().getAddress(sentinel),
        b"\xcc\xcc\xcc\xcc",
    )
    emu.setBreakpoint(program.getAddressFactory().getDefaultAddressSpace().getAddress(sentinel))

    space = program.getAddressFactory().getDefaultAddressSpace()
    cursor = string_at
    buf_size = int(a.get("buffer") or 0)
    if buf_size > 0x700:
        raise ValueError("buffer is capped at 0x700 bytes inside the scratch block")
    buf_addr = base + 0x600
    if buf_size:
        emu.writeMemory(space.getAddress(buf_addr), b"\x00" * buf_size)
    string_limit = buf_addr if buf_size else stack_top - 0x400
    seeded_memory = []
    for spec in a.get("seed") or []:
        addr_text, _, hex_text = str(spec).partition("=")
        offset = _hex_addr(addr_text)
        if offset is None or not hex_text:
            raise ValueError(f"bad seed {spec!r}; expected ADDR=HEXBYTES")
        data = _hex_bytes(hex_text)
        emu.writeMemory(space.getAddress(offset), data)
        seeded_memory.append({"addr": hex(offset), "bytes": len(data)})
    words: list[int] = []
    seeded_strings: list[tuple[int, int]] = []
    arg_report = []
    for spec in a.get("args") or []:
        kind, value = parse_arg_spec(spec)
        if kind == "deref":
            addr = _symbol_addr(program, value)
            if addr is None:
                near = _suggest_symbols(program, value)
                raise KeyError(
                    f"symbol {value!r} not found"
                    + (f" — did you mean {', '.join(near)}?" if near else "")
                )
            word = int.from_bytes(_emu_bytes(emu, addr, 8), "little")
            arg_report.append(
                {"kind": "deref", "value": str(value), "addr": hex(addr), "word": hex(word)}
            )
            words.append(word)
            continue
        if kind in ("str", "wstr"):
            data = (
                value.encode("utf-8", "replace") + b"\x00"
                if kind == "str"
                else value.encode("utf-16-le", "replace") + b"\x00\x00"
            )
            if cursor + len(data) >= string_limit:
                raise ValueError(
                    "too many/large string arguments for the scratch area"
                    + (" (raise --buffer less or pass fewer strings)" if buf_size else "")
                )
            emu.writeMemory(space.getAddress(cursor), data)
            arg_report.append(
                {"kind": kind, "value": value, "addr": hex(cursor), "bytes": len(data)}
            )
            seeded_strings.append((cursor, cursor + len(data)))
            words.append(cursor)
            cursor += (len(data) + 7) & ~7
        else:
            arg_report.append({"kind": "int", "value": value})
            words.append(value)

    extra = max(0, len(words) - len(PARAM_REGS))
    sp = stack_top - 0x28 - 8 * extra
    emu.writeMemory(space.getAddress(sp), sentinel.to_bytes(8, "little"))
    emu.writeMemory(space.getAddress(sp + 8), b"\x00" * 0x20)  # shadow space
    for i, value in enumerate(words):
        if i < len(PARAM_REGS):
            emu.writeRegister(program.getRegister(PARAM_REGS[i]), value & MASK64)
        else:
            emu.writeMemory(
                space.getAddress(sp + 0x28 + 8 * (i - len(PARAM_REGS))),
                (value & MASK64).to_bytes(8, "little"),
            )
    emu.writeRegister(emu.getStackPointerRegister(), sp)
    emu.writeRegister(emu.getPCRegister(), fn.getEntryPoint().getOffset())

    monitor = TimeoutTaskMonitor.timeoutIn(max(1, ms), TimeUnit.MILLISECONDS)
    sentinel_addr = space.getAddress(sentinel)
    stop = "max-insns"
    insns = 0
    fault = None
    stubs: list[dict] = []
    skips: list[dict] = []
    last_valid_pc = fn.getEntryPoint()
    try:
        while insns < max_insns:
            pc = emu.getExecutionAddress()
            if pc.equals(sentinel_addr):
                stop = "returned"
                break
            if program.getMemory().contains(pc):
                last_valid_pc = pc
            if emu.step(monitor):
                insns += 1
                continue
            if monitor.didTimeout():
                stop = "timeout"
                break
            callee = _call_target(program, int(last_valid_pc.getOffset())) or ""
            stub = _stub_for(callee)
            if stub is None and _is_external_call(callee):
                stub = "external:" + _clean_name(callee)
            if stub and len(stubs) < 4000 and _resume_after_stub(emu, program, stub):
                stubs.append({"at": str(last_valid_pc), "fn": stub})
                continue
            op = _callother_name(str(emu.getLastError() or ""))
            if op and len(skips) < 2000 and _skip_instruction(emu, program, last_valid_pc):
                skips.append({"at": str(last_valid_pc), "op": op})
                continue
            stop = "fault"
            break
    except Exception as exc:  # noqa: BLE001 - emulator raises on bad memory
        stop = "fault"
        fault = f"{type(exc).__name__}: {exc}"

    if stop == "fault":
        pc = emu.getExecutionAddress()
        last = str(emu.getLastError() or "")
        fault = {
            "pc": str(pc),
            "error": last or fault or "emulation stopped",
            "call_site": str(last_valid_pc),
            "callee": _call_target(program, int(last_valid_pc.getOffset())),
            "mapped": bool(program.getMemory().contains(pc)),
            "on_instruction": program.getListing().getInstructionAt(pc) is not None,
        }

    seeded = [(base, base + size)]
    runs = _diff_runs(emu, baseline, seeded)
    writes = []
    for lo, data in runs:
        head = data[:64]
        writes.append(
            {
                "addr": hex(lo),
                "size": len(data),
                "hex": head.hex(),
                "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in head),
            }
        )
    tracked_bytes = sum(len(data) for _, data in runs)

    dumps = []
    if buf_size:
        data = _emu_bytes(emu, buf_addr, buf_size)
        dumps.append(
            {
                "addr": hex(buf_addr),
                "size": buf_size,
                "hex": data.hex(),
                "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
            }
        )
    for spec in a.get("dump") or []:
        text = str(spec)
        addr_text, _, size_text = text.partition(":")
        daddr = int(addr_text, 0)
        dlen = int(size_text, 0) if size_text else 64
        data = _emu_bytes(emu, daddr, dlen)
        dumps.append(
            {
                "addr": hex(daddr),
                "size": dlen,
                "hex": data.hex(),
                "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
            }
        )

    rax = _u64(emu.readRegister(program.getRegister("RAX"))) if _has_reg(program, "RAX") else 0
    return {
        "binary": a["binary"],
        "function": str(fn.getName()),
        "entry": str(fn.getEntryPoint()),
        "prototype": str(fn.getPrototypeString(False, False)),
        "arch": str(program.getLanguage().getLanguageID()),
        "args": arg_report,
        "stop": stop,
        "insns": insns,
        "stubs": stubs,
        "skips": skips,
        "ret": {"rax": rax, "rax_hex": hex(rax)},
        "writes": {"tracked": tracked_bytes, "ranges": writes},
        "dump": dumps,
        "buffer": {"addr": hex(buf_addr), "size": buf_size} if buf_size else None,
        "seeded": seeded_memory,
        "fault": fault,
        "scratch": {"block": str(block.getName()), "base": hex(base), "sp": hex(sp)},
        "elapsed_ms": int((time.time() - started) * 1000),
    }


# ------------------------------------------------------------------- decrypt

_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
_WHITESPACE = {chr(9), chr(10), chr(13)}
_SKIP_BYTES = {0x20, 0x09, 0x0A, 0x0D, 0x00}
_B64_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_WORD_BONUS = (
    "http",
    chr(92),
    ".exe",
    ".dll",
    ".com",
    "software",
    "microsoft",
    "cmd.exe",
    "password",
    "token",
    "config",
    "temp",
    "appdata",
    "registry",
    "currentversion",
)


def _decode_text(data: bytes) -> str:
    """Decode bytes for display; cp1252 never fails, so every candidate is showable."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", "replace")


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if b in _PRINTABLE) / len(data)


_WORD_RUN = re.compile(r"[A-Za-z]{4,}")


def _score_text(text: str) -> float:
    """How much this looks like a real string: printable, wordy, and config-ish."""
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in _WHITESPACE) / len(text)
    alnum = sum(1 for ch in text if ch.isalnum() or ch in " _-.:") / len(text)
    low = text.lower()
    bonus = 0.05 * sum(1 for w in _WORD_BONUS if w in low)
    return 0.4 * printable + 0.5 * alnum + bonus


def _looks_like_text(text: str) -> bool:
    """At least one 4+ letter run: separates real strings from xor noise."""
    return _WORD_RUN.search(text) is not None


def _rot(value: int, shift: int) -> int:
    shift %= 8
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _decrypt_candidates(
    data: bytes, ciphers: list[str], min_printable: float
) -> list[dict[str, Any]]:
    """Try the cheap ciphers malware actually uses and keep what looks like text."""
    out: list[dict[str, Any]] = []

    def consider(cipher: str, key: str, raw: bytes) -> None:
        text = _decode_text(raw)
        ratio = _printable_ratio(raw)
        score = _score_text(text)
        if ratio < min_printable or score < min_printable:
            return
        if not _looks_like_text(text):
            return
        out.append(
            {
                "cipher": cipher,
                "key": key,
                "text": text.rstrip(chr(0)),
                "printable": round(ratio, 3),
                "score": round(score, 3),
            }
        )

    if "xor" in ciphers:
        for k in range(256):
            consider("xor", hex(k), bytes(b ^ k for b in data))
    if "add" in ciphers:
        for k in range(256):
            consider("sub", hex(k), bytes((b - k) & 0xFF for b in data))
            consider("add", hex(k), bytes((b + k) & 0xFF for b in data))
    if "rot" in ciphers:
        for k in range(1, 8):
            consider("rol", str(k), bytes(_rot(b, -k) for b in data))
            consider("ror", str(k), bytes(_rot(b, k) for b in data))
    if "utf16" in ciphers and len(data) % 2 == 0:
        consider("utf16le", "-", data)
    if "base64" in ciphers:
        import base64

        stripped = bytes(b for b in data if b not in _SKIP_BYTES)
        if stripped and all(chr(b) in _B64_ALPHABET for b in stripped):
            try:
                raw = base64.b64decode(stripped + b"=" * (-len(stripped) % 4))
            except ValueError:
                raw = b""
            if raw:
                consider("base64", "-", raw)
    out.sort(key=lambda r: (-r["score"], len(r["text"])))
    return out


def cmd_decrypt(a: dict[str, Any]) -> dict[str, Any]:
    """Break a small blob: XOR/ADD/ROT/UTF-16/base64, ranked by how printable it is."""
    started = time.time()
    data = b""
    source = ""
    if a.get("hex"):
        data = _hex_bytes(a["hex"])
        source = "hex"
    else:
        if not a.get("binary"):
            raise ValueError("decrypt needs hex=... or binary=... with addr=...")
        entry = _entry(a["binary"])
        program = entry["program"]
        offset = _hex_addr(a.get("addr"))
        if offset is None:
            raise KeyError(f"address {a.get('addr')!r} not found")
        size = int(a.get("len", 0) or 64)
        if size <= 0 or size > 0x4000:
            raise ValueError("len must be between 1 and 16384")
        space = program.getAddressFactory().getDefaultAddressSpace()
        data = _read_memory(program, space.getAddress(offset), size)
        source = f"{a['binary']}@{hex(offset)}"
    ciphers = _as_list(a.get("ciphers")) or ["xor", "add", "rot", "utf16", "base64"]
    min_printable = float(a.get("min_printable", 0.85))
    limit = int(a.get("limit", 5))
    found = _decrypt_candidates(data, ciphers, min_printable)[:limit]
    return {
        "source": source,
        "size": len(data),
        "hex": data.hex(),
        "ciphers": ciphers,
        "candidates": found,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def _has_reg(program, name: str) -> bool:
    return program.getLanguage().getRegister(name) is not None


# ------------------------------------------------------------------ write ops

_PRIMITIVES = {
    "void": "VoidDataType",
    "char": "CharDataType",
    "uchar": "UnsignedCharDataType",
    "byte": "ByteDataType",
    "sbyte": "SignedByteDataType",
    "short": "ShortDataType",
    "ushort": "UnsignedShortDataType",
    "word": "WordDataType",
    "int": "IntegerDataType",
    "uint": "UnsignedIntegerDataType",
    "dword": "DWordDataType",
    "long": "LongDataType",
    "ulong": "UnsignedLongDataType",
    "longlong": "LongLongDataType",
    "ulonglong": "UnsignedLongLongDataType",
    "qword": "QWordDataType",
    "float": "FloatDataType",
    "double": "DoubleDataType",
    "bool": "BooleanDataType",
    "wchar": "WideCharDataType",
    "unicode": "UnicodeDataType",
}

_TYPE_ALIASES = {
    "int8": "sbyte",
    "uint8": "byte",
    "int16": "short",
    "uint16": "ushort",
    "int32": "int",
    "uint32": "uint",
    "int64": "longlong",
    "uint64": "ulonglong",
    "size_t": "ulonglong",
    "ssize_t": "longlong",
    "uintptr_t": "ulonglong",
    "intptr_t": "longlong",
    "ptrdiff_t": "longlong",
    "wchar_t": "wchar",
    "handle": "void*",
    "lpvoid": "void*",
    "lpcstr": "char*",
    "lpstr": "char*",
    "lpwstr": "wchar*",
    "signed char": "sbyte",
    "unsigned char": "uchar",
    "unsigned short": "ushort",
    "unsigned int": "uint",
    "unsigned long": "ulong",
    "unsigned long long": "ulonglong",
    "long long": "longlong",
    "signed int": "int",
    "signed short": "short",
}


def code_stamp() -> str:
    """Fingerprint of the installed package, so a stale daemon is detectable.

    Editing a handler and restarting the daemon used to be the only way to notice
    that the running process still served the old module; `ghlab start` now
    compares this stamp and restarts by itself.
    """
    root = Path(__file__).resolve().parent
    parts = []
    for path in sorted(root.glob("*.py")):
        try:
            st = path.stat()
        except OSError:
            continue
        parts.append(f"{path.name}:{st.st_size}:{int(st.st_mtime)}")
    return hashlib.md5("|".join(parts).encode()).hexdigest()[:12]


def _hex_bytes(text: str) -> bytes:
    """Parse `90 90` / `0x90 0x90` / `9090` into bytes."""
    raw = str(text).replace(" ", "").replace(",", "").replace("0x", "").replace(chr(92) + "x", "")
    if not raw:
        raise ValueError("empty hex string")
    try:
        return bytes.fromhex(raw)
    except ValueError:
        raise ValueError(f"expected hex bytes, got {text!r}") from None


def _byte_array(data: bytes):
    """Java byte[] (signed) from Python bytes."""
    from jpype import JArray, JByte

    arr = JArray(JByte)(len(data))
    for i, value in enumerate(data):
        arr[i] = value - 256 if value > 127 else value
    return arr


def _parse_type_spec(text: str) -> tuple[str, int, list[int]]:
    """Split 'char * * [16]' into (base, pointer_depth, [dims])."""
    spec = text.strip().rstrip(";").strip()
    while spec.lower().startswith(("const ", "volatile ", "struct ", "union ", "enum ")):
        spec = spec.split(None, 1)[1].strip()
    m = re.match(
        r"^(?P<base>[A-Za-z_][A-Za-z0-9_ ]*?)\s*(?P<stars>\*+)?\s*(?P<dims>(?:\[\s*\d+\s*\])*)$",
        spec,
    )
    if not m:
        raise ValueError(f"cannot parse type {text!r} (try 'char[64]', 'int*', 'void')")
    base = m.group("base").strip().lower()
    stars = len(m.group("stars") or "")
    dims = [int(d) for d in re.findall(r"\[\s*(\d+)\s*\]", m.group("dims") or "")]
    alias = _TYPE_ALIASES.get(base)
    if alias is not None:
        alias_base, alias_stars, _ = _parse_type_spec(alias)
        base, stars = alias_base, stars + alias_stars
    return base, stars, dims


def _datatype(program, text: str):
    """Build a Ghidra DataType from a small C-ish type expression."""
    import jpype
    from ghidra.program.model.data import ArrayDataType, PointerDataType

    base, stars, dims = _parse_type_spec(text)
    dtm = program.getDataTypeManager()
    dt = None
    if base in _PRIMITIVES:
        dt = jpype.JClass("ghidra.program.model.data." + _PRIMITIVES[base]).dataType
    if dt is None:
        dt = dtm.getDataType("/" + base)
    if dt is None:
        dt = dtm.getDataType(base)
    if dt is None:
        raise ValueError(
            f"unknown type {base!r} (primitives: {', '.join(sorted(_PRIMITIVES))}; "
            "other names must exist in the program's data type manager)"
        )
    for dim in reversed(dims):
        dt = ArrayDataType(dt, dim, 0)
    for _ in range(stars):
        dt = PointerDataType(dt)
    return dt


def _signature_parser(program, source_type):
    from ghidra.app.util.parser import FunctionSignatureParser

    dtm = program.getDataTypeManager()
    # 12.2 signature: (DataTypeManager, DataTypeQueryService); the service is optional here.
    for ctor in (
        lambda: FunctionSignatureParser(dtm, None),
        lambda: FunctionSignatureParser(dtm, source_type),
    ):
        try:
            return ctor()
        except Exception:  # noqa: BLE001 - the constructor arity changed between versions
            continue
    raise RuntimeError("could not construct FunctionSignatureParser")


def _block_writable(block) -> bool:
    """MemoryBlock exposes either isWriteable() or isWrite() depending on version."""
    for attr in ("isWriteable", "isWrite"):
        fn = getattr(block, attr, None)
        if fn is not None:
            try:
                return bool(fn())
            except Exception:  # noqa: BLE001 - isWriteable/isWrite differ by version
                continue
    return True


def cmd_patch(a: dict[str, Any]) -> dict[str, Any]:
    """Overwrite bytes in the program image (a real patch, saved to the project)."""
    e = _entry(a["binary"])
    p = e["program"]
    addr = _addr(e, str(a["addr"]))
    if a.get("nop"):
        data = b"\x90" * int(a["nop"])
    else:
        raw = str(a.get("bytes") or "").replace(" ", "").replace("\\x", "")
        if not raw:
            raise ValueError("nothing to write: pass bytes='9090' or nop=5")
        try:
            data = bytes.fromhex(raw)
        except ValueError:
            raise ValueError(f"bytes must be hex, got {a.get('bytes')!r}") from None
    mem = p.getMemory()
    before = bytes(mem.getByte(addr.add(i)) & 0xFF for i in range(len(data)))
    if a.get("expect") is not None:
        want = bytes.fromhex(str(a["expect"]).replace(" ", "").replace("\\x", ""))
        if len(want) != len(data):
            raise ValueError(
                f"expect is {len(want)} byte(s) but the write is {len(data)} byte(s) "
                "(they must describe the same range)"
            )
        if want != before:
            raise ValueError(
                f"expect mismatch at {addr}: found {before.hex()}, expected {want.hex()} (not patched)"
            )
    tx = p.startTransaction("ghlab-patch")
    block = mem.getBlock(addr)
    writable = _block_writable(block) if block is not None else True
    try:
        if block is not None and not writable:
            block.setWrite(True)
        # Ghidra refuses to overwrite bytes that belong to an instruction, so drop
        # the code units first and re-disassemble afterwards.
        p.getListing().clearCodeUnits(addr, addr.add(len(data) - 1), False)
        mem.setBytes(addr, _byte_array(data))
    finally:
        if block is not None and not writable:
            with contextlib.suppress(Exception):  # the block was read-only already
                block.setWrite(False)
        p.endTransaction(tx, True)
    from ghidra.app.cmd.disassemble import DisassembleCommand

    tx = p.startTransaction("ghlab-patch-disasm")
    try:
        DisassembleCommand(addr, None, True).applyTo(p)
    finally:
        p.endTransaction(tx, True)
    after = bytes(mem.getByte(addr.add(i)) & 0xFF for i in range(len(data)))
    saved = _save(p, "ghlab patch")
    return {
        "addr": str(addr),
        "before": before.hex(),
        "after": after.hex(),
        "size": len(data),
        "saved_via": saved,
    }


def _prototype(fn) -> str:
    """Prototype string across Ghidra versions (overloads differ per class)."""
    for args in ((True, False), (True,), ()):
        try:
            return str(fn.getPrototypeString(*args))
        except Exception:  # noqa: BLE001 - the overload set differs by version
            continue
    return str(fn.getName())


def _apply_signature(e, target: Any, decl: str) -> dict[str, Any]:
    """Set a function prototype from C-ish text. Caller owns the transaction."""
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.program.model.symbol import SourceType

    p = e["program"]
    fn = _function(e, str(target))
    if fn is None:
        raise KeyError(f"function {target!r} not found")
    # parse() takes a FunctionSignature; fn.getSignature() hands us one (a
    # FunctionDefinitionDataType) without any jpype casting games.
    fdef = _signature_parser(p, SourceType.USER_DEFINED).parse(fn.getSignature(), decl)
    new_name = str(fdef.getName() or "").strip()
    cmd = ApplyFunctionSignatureCmd(fn.getEntryPoint(), fdef, SourceType.USER_DEFINED)
    ok = bool(cmd.applyTo(p))
    # ApplyFunctionSignatureCmd keeps the old name; the declaration is the
    # authority on what the function is called.
    if ok and new_name and new_name != str(fn.getName()):
        fn.setName(new_name, SourceType.USER_DEFINED)
    after = p.getFunctionManager().getFunctionAt(fn.getEntryPoint())
    return {
        "kind": "signature",
        "applied": ok,
        "addr": str(fn.getEntryPoint()),
        "prototype": _prototype(after) if after is not None else str(fdef.getPrototypeString()),
        "message": str(cmd.getStatusMsg()),
    }


def _apply_data(e, target: Any, decl: str) -> dict[str, Any]:
    """Define a data type at an address. Caller owns the transaction."""
    from ghidra.app.cmd.data import CreateDataCmd

    p = e["program"]
    addr = _addr(e, str(target))
    dt = _datatype(p, decl)
    cmd = CreateDataCmd(addr, dt)
    ok = bool(cmd.applyTo(p))
    data = p.getListing().getDataAt(addr) if ok else None
    return {
        "kind": "data",
        "applied": ok,
        "addr": str(addr),
        "datatype": str(data.getDataType().getName()) if data is not None else str(dt.getName()),
        "size": int(dt.getLength()),
        "value": str(data.getValue()) if data is not None and data.getValue() is not None else None,
        "message": str(cmd.getStatusMsg()),
    }


def _is_signature(decl: str) -> bool:
    return "(" in decl and ")" in decl


def cmd_set_type(a: dict[str, Any]) -> dict[str, Any]:
    """Apply a function prototype ('int f(char *s, unsigned n)') or a data type
    ('char[64]', 'void*', 'DWORD') at an address."""
    e = _entry(a["binary"])
    p = e["program"]
    decl = str(a["decl"]).strip()
    apply_one = _apply_signature if _is_signature(decl) else _apply_data
    tx = p.startTransaction("ghlab-set-type")
    try:
        out = apply_one(e, a["target"], decl)
    finally:
        p.endTransaction(tx, True)
    out["saved_via"] = _save(p, "ghlab set-type")
    return out


def _load_type_map(path: str) -> list[dict[str, str]]:
    """Read a signature/type map.

    JSON: {"signatures": {target: decl}, "data": {target: decl}} or a flat object.
    Text: one `target = decl` per line, `#` comments.
    """
    p = Path(str(path)).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"type map not found: {p}")
    text = p.read_text(encoding="utf-8")
    items: list[dict[str, str]] = []
    if p.suffix.lower() == ".json":
        raw = json.loads(text)
        if not isinstance(raw, dict):
            raise ValueError("type map JSON must be an object")
        groups = {"signatures": raw.pop("signatures", None), "data": raw.pop("data", None)}
        for kind, group in groups.items():
            if isinstance(group, dict):
                items += [
                    {"kind": kind, "target": str(k), "decl": str(v)} for k, v in group.items()
                ]
        items += [
            {
                "kind": "signatures" if _is_signature(str(v)) else "data",
                "target": str(k),
                "decl": str(v),
            }
            for k, v in raw.items()
        ]
    else:
        for lineno, line in enumerate(text.splitlines(), 1):
            body = line.split("#", 1)[0].strip()
            if not body:
                continue
            target, sep, decl = body.partition("=")
            if not sep or not decl.strip():
                raise ValueError(f"{p}:{lineno}: expected `target = declaration`")
            decl = decl.strip()
            items.append(
                {
                    "kind": "signatures" if _is_signature(decl) else "data",
                    "target": target.strip(),
                    "decl": decl,
                }
            )
    if not items:
        raise ValueError(f"type map {p} is empty")
    return items


def cmd_types(a: dict[str, Any]) -> dict[str, Any]:
    """Bulk-apply a signature/type map: one transaction, one save.

    This is how external knowledge enters the project (headers, PDB dumps, notes from
    a colleague) without 200 separate `set-type` round-trips and 200 saves.
    """
    items = _load_type_map(str(a["from"]))
    e = _entry(a["binary"])
    p = e["program"]
    applied: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    if a.get("dry_run"):
        return {
            "binary": str(a["binary"]),
            "planned": len(items),
            "items": items,
            "dry_run": True,
        }
    tx = p.startTransaction("ghlab-types")
    try:
        for item in items:
            try:
                fn = _apply_signature if item["kind"] == "signatures" else _apply_data
                out = fn(e, item["target"], item["decl"])
                out["target"] = item["target"]
                out["decl"] = item["decl"]
                (applied if out["applied"] else failed).append(out)
            except Exception as ex:  # noqa: BLE001 - jpype call, can raise anything
                failed.append(
                    {
                        "target": item["target"],
                        "decl": item["decl"],
                        "error": f"{type(ex).__name__}: {ex}",
                    }
                )
    finally:
        p.endTransaction(tx, True)
    saved = _save(p, "ghlab types")
    return {
        "binary": str(a["binary"]),
        "applied": applied,
        "failed": failed,
        "count": len(applied),
        "saved_via": saved,
        "source": str(a["from"]),
    }


def cmd_pdb(a: dict[str, Any]) -> dict[str, Any]:
    """Apply a matching PDB's symbols/types to a program.

    Ghidra ships the whole PDB pipeline (`PdbUniversalAnalyzer.doAnalysis`), so this is
    a thin wrapper: sanity-check the file, run inside a transaction, keep the log. It is
    a refusal rather than a partial import when the PDB does not match the binary.
    """
    import jpype
    from java.io import File

    e = _entry(a["binary"])
    p = e["program"]
    path = Path(str(a["file"])).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"pdb not found: {path}")
    analyzer = jpype.JClass("ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer")
    reader = jpype.JClass("ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions")()
    applicator = jpype.JClass("ghidra.app.util.pdb.pdbapplicator.PdbApplicatorOptions")()
    log = jpype.JClass("ghidra.app.util.importer.MessageLog")()
    before = int(p.getFunctionManager().getFunctionCount())
    analyzer.setAllowUntrustedOption(p, bool(a.get("untrusted", True)))
    tx = p.startTransaction("ghlab-pdb")
    try:
        ok = bool(
            analyzer.doAnalysis(
                p, File(str(path)).getAbsoluteFile(), reader, applicator, log, MONITOR
            )
        )
    finally:
        p.endTransaction(tx, True)
    out = {
        "applied": ok,
        "file": str(path),
        "functions_before": before,
        "functions_after": int(p.getFunctionManager().getFunctionCount()),
        "log": str(log)[:2000],
    }
    if ok:
        out["saved_via"] = _save(p, "ghlab pdb")
    return out


BOOKMARK_TYPES = ("Note", "Info", "Warning", "Error", "Analysis")


def cmd_bookmark(a: dict[str, Any]) -> dict[str, Any]:
    """Ghidra bookmarks, so findings show up in the GUI too."""
    e = _entry(a["binary"])
    p = e["program"]
    bm = p.getBookmarkManager()
    action = str(a.get("action", "add")).lower()
    btype = str(a.get("type") or "Note")
    category = str(a.get("category") or "ghlab")
    if action == "list":
        out = []
        cap = int(a.get("limit", 100))
        it = bm.getBookmarksIterator()
        while it.hasNext() and len(out) < cap:
            b = it.next()
            if a.get("type") and str(b.getTypeString()) != btype:
                continue
            out.append(
                {
                    "addr": str(b.getAddress()),
                    "type": str(b.getTypeString()),
                    "category": str(b.getCategory()),
                    "comment": str(b.getComment()),
                }
            )
        return {"bookmarks": out, "count": len(out)}
    target = a.get("target") or a.get("addr")
    if not target:
        raise ValueError("bookmark needs --addr/--target")
    addr = _addr(e, str(target))
    if action == "remove":
        doomed = []
        it = bm.getBookmarksIterator()
        while it.hasNext():
            b = it.next()
            if (
                str(b.getAddress()) == str(addr)
                and str(b.getCategory()) == category
                and str(b.getTypeString()) == btype
            ):
                doomed.append(b)
        tx = p.startTransaction("ghlab-bookmark")
        try:
            for b in doomed:
                bm.removeBookmark(b)
        finally:
            p.endTransaction(tx, True)
        _save(p, "ghlab bookmark")
        return {"removed": len(doomed), "addr": str(addr), "category": category}
    if action != "add":
        raise ValueError("action must be add, list or remove")
    tx = p.startTransaction("ghlab-bookmark")
    try:
        bm.setBookmark(addr, btype, category, str(a.get("comment") or ""))
    finally:
        p.endTransaction(tx, True)
    _save(p, "ghlab bookmark")
    return {"added": True, "addr": str(addr), "type": btype, "category": category}


# ------------------------------------------------------------------- evidence


_CLAIM_KINDS = ("const", "string", "import", "calls", "size", "bytes", "symbol", "name")


def _parse_claim(text: Any) -> dict[str, str]:
    """Split `const=0x41` / `size>=200` into kind, operator and value."""
    raw = str(text).strip()
    if not raw:
        raise ValueError("empty claim")
    for op in (">=", "<=", ">", "<"):
        head, found, value = raw.partition(op)
        if found and value.strip():
            return {"kind": head.strip().lower(), "op": op, "value": value.strip(), "raw": raw}
    kind, found, value = raw.partition("=")
    if not found or not value.strip():
        raise ValueError(
            f"claim {raw!r} must look like kind=value; kinds: {', '.join(_CLAIM_KINDS)}"
        )
    return {"kind": kind.strip().lower(), "op": "=", "value": value.strip(), "raw": raw}


def _claim_facts(program, fn) -> dict[str, Any]:
    """Everything a claim can be checked against, collected in one pass."""
    listing = program.getListing()
    consts: set[int] = set()
    strings: set[str] = set()
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext():
        insn = it.next()
        for i in range(insn.getNumOperands()):
            try:
                scalar = insn.getScalar(i)
            except Exception:  # noqa: BLE001 - jpype call, can raise anything
                scalar = None
            if scalar is not None:
                consts.add(int(scalar.getValue()))
        for ref in insn.getReferencesFrom():
            data = listing.getDataAt(ref.getToAddress())
            if data is not None and _is_string_data(data):
                value = _string_value(data)
                if value:
                    strings.add(value)
    calls: set[str] = set()
    imports: set[str] = set()
    for callee in fn.getCalledFunctions(MONITOR):
        name = str(callee.getName())
        calls.add(name)
        if callee.isExternal() or callee.isThunk() or name.startswith("PTR_"):
            imports.add(_clean_name(name))
    return {
        "name": str(fn.getName()),
        "size": int(fn.getBody().getNumAddresses()),
        "consts": consts,
        "strings": strings,
        "calls": calls,
        "imports": imports,
    }


def _const_views(value: int) -> set[int]:
    """The same constant as Ghidra may store it: signed, unsigned, 32- or 16-bit.

    `(HKEY)0xffffffff80000001` from decompiled C turns up as a negative long, so a
    claim written in the form a human reads has to match every plausible spelling.
    """
    wide = _u64(value)
    return {value, wide, wide & 0xFFFFFFFF, wide & 0xFFFF}


def _claim_int(text: Any) -> int:
    """Parse `0x41`, `65` or `'65'` the same way everywhere."""
    return int(str(text).strip(), 0)


def _compare(value: int, op: str, want: int) -> bool:
    if op == "=":
        return value == want
    if op == ">=":
        return value >= want
    if op == "<=":
        return value <= want
    if op == ">":
        return value > want
    return value < want


def _claim_bytes(entry, addr_text: str | None, spec: dict[str, str]) -> tuple[bool | None, str]:
    if not addr_text:
        return None, "a bytes claim needs the note to sit on an address (--at)"
    want = re.sub(r"[^0-9a-fA-F?]", "", spec["value"])
    if len(want) % 2:
        return None, "bytes claim needs an even number of hex digits (use ?? for wildcards)"
    program = entry["program"]
    got = _read_memory(program, _addr(entry, addr_text), len(want) // 2).hex()
    pattern = "".join("." if c in "?" else c for c in want.lower())
    ok = re.fullmatch(pattern, got) is not None
    return ok, f"{addr_text} holds {got}"


def _claim_symbol(entry, spec: dict[str, str]) -> tuple[bool | None, str]:
    pat = re.compile(spec["value"], re.I)
    hits = [
        str(sym.getName())
        for sym in entry["program"].getSymbolTable().getAllSymbols(True)
        if pat.search(str(sym.getName()))
    ]
    if hits:
        return True, f"symbol {hits[0]}"
    return False, "no symbol matches"


def _check_claim(
    entry, fn, facts: dict[str, Any] | None, addr_text: str | None, claim: str
) -> tuple[bool | None, str]:
    """Re-evaluate one claim. Returns (ok, detail); ok is None when it cannot be judged."""
    spec = _parse_claim(claim)
    kind, op, value = spec["kind"], spec["op"], spec["value"]
    if kind not in _CLAIM_KINDS:
        raise ValueError(f"unknown claim kind {kind!r} (kinds: {', '.join(_CLAIM_KINDS)})")
    if kind == "bytes":
        return _claim_bytes(entry, addr_text, spec)
    if kind == "symbol":
        return _claim_symbol(entry, spec)
    if fn is None or facts is None:
        return None, "note is not attached to a function; point --at at one"
    if kind == "size":
        want = _claim_int(value)
        return _compare(facts["size"], op, want), f"{facts['size']} bytes"
    if kind == "name":
        ok = re.search(value, facts["name"], re.I) is not None
        return ok, facts["name"]
    if kind == "const":
        want = _claim_int(value)
        found = [c for c in facts["consts"] if any(_compare(v, op, want) for v in _const_views(c))]
        if found:
            shown = ", ".join(hex(c) for c in sorted(found)[:3])
            return True, f"{len(found)} match(es) of {len(facts['consts'])} constants: {shown}"
        return False, f"no constant matches ({len(facts['consts'])} scanned)"
    pat = re.compile(value, re.I)
    pool = sorted(facts["strings"] if kind == "string" else facts["calls"])
    if kind == "import":
        pool = sorted(facts["imports"])
    hits = [x for x in pool if pat.search(x)]
    label = {"string": "strings", "calls": "callees", "import": "imports"}[kind]
    if hits:
        return True, f"{label}: {hits[0][:60]}"
    return False, f"no {label} match ({len(pool)} scanned)"


def _check_claims(entry, fn, addr_text: str | None, claims: list[str]) -> list[dict[str, Any]]:
    facts: dict[str, Any] | None = None
    if fn is not None:
        try:
            facts = _claim_facts(entry["program"], fn)
        except Exception:  # noqa: BLE001 - jpype call, can raise anything
            facts = None
    out = []
    for claim in claims:
        try:
            ok, detail = _check_claim(entry, fn, facts, addr_text, claim)
        except Exception as ex:  # noqa: BLE001 - jpype call, can raise anything
            ok, detail = None, f"{type(ex).__name__}: {ex}"
        out.append({"claim": str(claim), "ok": ok, "detail": detail})
    return out


def _claims_status(rows: list[dict[str, Any]]) -> str:
    if any(r.get("ok") is False for r in rows):
        return "fail"
    if any(r.get("ok") is None for r in rows):
        return "unknown"
    return "pass"


# ------------------------------------------------------------------- findings


def _notes_dir() -> Path:
    base = _project_dir or (Path.home() / "re" / "proj")
    d = Path(base) / ".ghlab" / "notes"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _notes_file(binary: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(binary))
    return _notes_dir() / (safe + ".json")


def _load_notes(binary: str) -> list[dict[str, Any]]:
    path = _notes_file(binary)
    if not path.exists():
        return []
    try:
        return list(json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, OSError):
        return []


def _store_notes(binary: str, notes: list[dict[str, Any]]) -> None:
    _notes_file(binary).write_text(json.dumps(notes, indent=2) + "\n", encoding="utf-8")


def cmd_note(a: dict[str, Any]) -> dict[str, Any]:
    """Append a durable finding (JSON on disk + a Ghidra bookmark), or retract one.

    `delete=ID` removes a finding that turned out to be wrong: an audit that only
    ever adds is how a findings store rots into noise.
    """

    binary = str(a["binary"])
    notes = _load_notes(binary)
    if a.get("delete"):
        gone = {_claim_int(x) for x in _as_list(a["delete"])}
        keep = [n for n in notes if _claim_int(n.get("id", 0)) not in gone]
        if len(keep) == len(notes):
            raise KeyError(f"no note with id {sorted(gone)}")
        _store_notes(binary, keep)
        return {
            "binary": binary,
            "deleted": sorted(gone),
            "remaining": len(keep),
            "path": str(_notes_file(binary)),
        }
    at = a.get("at")
    claims = _as_list(a.get("assert") or [])
    addr = None
    name = None
    e = None
    fn = None
    if claims and not (at or a.get("addr")):
        raise ValueError("claims describe a function, so --at ADDR/NAME is required as well")
    if at or a.get("addr"):
        e = _entry(binary)
        target = at or a.get("addr")
        fn = _function(e, str(target))
        addr = str(fn.getEntryPoint()) if fn is not None else str(_addr(e, str(target)))
        name = str(fn.getName()) if fn is not None else None
        bm = e["program"].getBookmarkManager()
        tx = e["program"].startTransaction("ghlab-note")
        try:
            bm.setBookmark(_addr(e, addr), "Note", str(a.get("tag") or "ghlab"), str(a["text"]))
        finally:
            e["program"].endTransaction(tx, True)
    checked: list[dict[str, Any]] = []
    if e is not None and claims:
        checked = _check_claims(e, fn, addr, claims)
    next_id = max((_claim_int(n.get("id", 0)) for n in notes), default=0) + 1
    note = {
        "id": next_id,
        "binary": binary,
        "addr": addr,
        "function": name,
        "tag": str(a.get("tag") or "note"),
        "text": str(a["text"]),
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    if checked:
        note["claims"] = checked
        note["check"] = {
            "at": note["created"],
            "status": _claims_status(checked),
            "results": checked,
        }
    notes.append(note)
    _store_notes(binary, notes)
    return {"note": note, "total": len(notes), "path": str(_notes_file(binary))}


def cmd_verify(a: dict[str, Any]) -> dict[str, Any]:
    """Re-evaluate the claims attached to this binary's findings.

    A note is only worth as much as its ability to survive a re-run: this walks
    the stored claims, recomputes them from the program, and records pass/fail.
    """

    binary = str(a["binary"])
    e = _entry(binary)
    notes = _load_notes(binary)
    want = a.get("id")
    ids = {_claim_int(x) for x in _as_list(want)} if want else None
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    rows = []
    passed = failed = unknown = skipped = 0
    for n in notes:
        nid = _claim_int(n.get("id", 0))
        if ids is not None and nid not in ids:
            continue
        claims = list(n.get("claims") or [])
        if not claims:
            skipped += 1
            continue
        fn = None
        addr = n.get("addr")
        if addr:
            try:
                fn = _function(e, str(addr))
            except Exception:  # noqa: BLE001 - jpype call, can raise anything
                fn = None
        results = _check_claims(e, fn, addr, [str(c.get("claim")) for c in claims])
        status = _claims_status(results)
        n["check"] = {"at": now, "status": status, "results": results}
        n["claims"] = results
        passed += sum(1 for r in results if r.get("ok") is True)
        failed += sum(1 for r in results if r.get("ok") is False)
        unknown += sum(1 for r in results if r.get("ok") is None)
        rows.append(
            {
                "id": nid,
                "addr": addr,
                "function": n.get("function"),
                "tag": n.get("tag"),
                "text": n.get("text"),
                "status": status,
                "results": results,
            }
        )
    if rows:
        _store_notes(binary, notes)
    return {
        "binary": binary,
        "checked": len(rows),
        "passed": passed,
        "failed": failed,
        "unknown": unknown,
        "unchecked_notes": skipped,
        "status": "fail" if failed else ("unknown" if unknown else "pass"),
        "notes": rows,
        "checked_at": now,
        "path": str(_notes_file(binary)),
    }


def cmd_notes(a: dict[str, Any]) -> dict[str, Any]:
    binary = str(a["binary"])
    notes = _load_notes(binary)
    tag = a.get("tag")
    at = a.get("at")
    query = a.get("query")
    out = []
    for n in notes:
        if tag and n.get("tag") != tag:
            continue
        if (
            at
            and at.lower() not in (n.get("addr") or "").lower()
            and at.lower() not in ((n.get("function") or "").lower())
        ):
            continue
        if query and query.lower() not in (n.get("text") or "").lower():
            continue
        out.append(n)
    cap = int(a.get("limit", 200))
    return {
        "notes": out[:cap],
        "count": len(out),
        "total": len(notes),
        "path": str(_notes_file(binary)),
    }


def cmd_report(a: dict[str, Any]) -> dict[str, Any]:
    """Markdown report: triage digest + findings, ready to paste into a writeup."""
    binary = str(a["binary"])
    d = cmd_digest({"binary": binary, "top": int(a.get("top", 6)), "strings": 2})
    notes = _load_notes(binary)
    imports = d.get("imports") or {}
    strings = d.get("strings") or {}
    lines = [f"# {binary}", ""]
    lines.append(
        "- md5 `{}` | {} | {} | {} functions | {} strings | {} imports".format(
            str(d.get("md5", ""))[:16],
            d.get("language", "?"),
            d.get("compiler", "?"),
            d.get("functions", "?"),
            strings.get("total", "?"),
            imports.get("total", "?"),
        )
    )
    entry = d.get("entry") or []
    if entry:
        lines.append("- entry chain: " + " -> ".join(f"{e.get('name')}" for e in entry[:4]))
    groups = imports.get("groups") or {}
    hot = [f"{k} ({v})" for k, v in groups.items() if v]
    if hot:
        lines.append("- import groups: " + ", ".join(hot))
    combos = d.get("combos") or []
    if combos:
        lines.append(
            "- capability combos: "
            + "; ".join(f"{c.get('label')} [{', '.join(c.get('hits') or [])}]" for c in combos)
        )
    hubs = d.get("hubs") or []
    if hubs:
        lines += ["", "## Call-graph hubs", ""]
        for h in hubs:
            lines.append(
                f"- `{h.get('addr')}` {h.get('name')} — {h.get('callers')} callers, {h.get('size')}b"
            )
    sizes = d.get("sizes") or {}
    if sizes:
        lines += ["", "## Function sizes", ""]
        lines.append(" | ".join(f"{k}: {v}" for k, v in sizes.items()))
    claimed = [n for n in notes if n.get("claims")]
    if claimed:
        lines.append(f"- claims: {len(claimed)} note(s) carry evidence, see Findings")
    else:
        lines.append("- claims: _none — pass `-a const=0x41` to make a finding checkable_")
    lines += ["", "## Findings"]
    if not notes:
        lines += ["", "_none yet — `ghlab note BIN ...` while you work_"]
    by_tag: dict[str, list[dict[str, Any]]] = {}
    for n in notes:
        by_tag.setdefault(str(n.get("tag") or "note"), []).append(n)
    for tag in sorted(by_tag):
        lines += ["", f"### {tag}"]
        for n in by_tag[tag]:
            where = n.get("addr") or ""
            fn = n.get("function")
            label = f"`{where}` {fn}" if fn else (f"`{where}`" if where else "(general)")
            lines.append(f"- {label} — {n.get('text')}")
            for row in n.get("claims") or []:
                ok = row.get("ok")
                mark = "OK" if ok is True else ("FAIL" if ok is False else "??")
                lines.append(f"  - [{mark}] {row.get('claim')} ({row.get('detail')})")
    markdown = chr(10).join(lines) + chr(10)
    return {"markdown": markdown, "notes": len(notes), "binary": binary}


def cmd_cross_xref(a: dict[str, Any]) -> dict[str, Any]:
    """Search a string/import across every program in the project.

    Answers "which of my samples also talks to this host / imports this API"
    without opening them one by one.
    """
    pat = re.compile(str(a["query"]), re.I)
    limit = int(a.get("limit", 20))
    bins = [str(a["binary"])] if a.get("binary") else binary_names()
    out = []
    for b in bins:
        try:
            e = _entry(b)
        except Exception as ex:  # noqa: BLE001
            out.append({"binary": b, "error": f"{type(ex).__name__}: {ex}"})
            continue
        program = e["program"]
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        hits = []
        scanned = 0
        errors = 0
        it = program.getListing().getDefinedData(True)
        while it.hasNext() and len(hits) < limit:
            scanned += 1
            d = it.next()
            try:
                if not _is_string_data(d):
                    continue
                value = _string_value(d)
            except Exception:  # noqa: BLE001
                errors += 1
                continue
            if not value or not pat.search(value):
                continue
            refs = []
            for ref in rm.getReferencesTo(d.getAddress()):
                frm = ref.getFromAddress()
                fn = fm.getFunctionContaining(frm)
                refs.append({"from": str(frm), "function": str(fn.getName()) if fn else None})
            hits.append({"addr": str(d.getAddress()), "value": value[:120], "refs": refs[:6]})
        if hits:
            out.append(
                {
                    "binary": b,
                    "matches": hits,
                    "count": len(hits),
                    "scanned": scanned,
                    "errors": errors,
                }
            )
    return {"query": a["query"], "searched": len(bins), "binaries": out}


def _forward_slice(start_fn, depth: int, limit: int) -> dict[str, Any]:
    """Everything `start_fn` can reach, with the shortest path to each import.

    Reverse `slice` answers "what has to run for this API to be called"; this
    answers "if this runs, what can it do" - the question you ask about a
    function you just found with `find`.
    """
    reached: dict[str, dict[str, Any]] = {}
    seen = {str(start_fn.getEntryPoint())}
    frontier = [(start_fn, [str(start_fn.getName())])]
    functions_seen = 1
    for level in range(1, depth + 1):
        nxt = []
        for fn, path in frontier:
            try:
                callees = list(fn.getCalledFunctions(MONITOR))
            except Exception:  # noqa: BLE001
                continue
            for callee in callees:
                name = str(callee.getName())
                if callee.isExternal() or callee.isThunk() or name.startswith("PTR_"):
                    key = _clean_name(name)
                    if key not in reached:
                        reached[key] = {"import": key, "depth": level, "path": [*path, key]}
                    continue
                key = str(callee.getEntryPoint())
                if key in seen:
                    continue
                seen.add(key)
                functions_seen += 1
                nxt.append((callee, [*path, name]))
        frontier = nxt
        if not frontier:
            break
    rows = sorted(reached.values(), key=lambda r: (r["depth"], r["import"]))[:limit]
    return {
        "from": str(start_fn.getName()),
        "addr": str(start_fn.getEntryPoint()),
        "direction": "forward",
        "functions_seen": functions_seen,
        "reached": rows,
        "total_imports": len(reached),
    }


def cmd_slice(a: dict[str, Any]) -> dict[str, Any]:
    """Shortest caller chain that reaches an import (or a named function).

    Reverse BFS from every function that touches `to`, stopping when a function
    matches `from` (entry/main/WinMain/DllMain by default). This answers "what
    has to run for this API to be called" without reading 800 functions.
    """
    e = _entry(a["binary"])
    p = e["program"]
    fm = p.getFunctionManager()
    if str(a.get("direction") or "back").lower() == "forward":
        start = _function(e, a["to"])
        if start is None:
            raise KeyError(f"function {a['to']!r} not found")
        out = _forward_slice(start, int(a.get("depth", 6)), int(a.get("limit", 40)))
        out["binary"] = a["binary"]
        return out
    to_pat = re.compile(str(a["to"]), re.I)
    from_pat = re.compile(
        str(
            a.get("from") or r"^(entry|main|wmain|winmain|wwinmain|dllmain|_start|maincrtstartup)$"
        ),
        re.I,
    )
    depth = int(a.get("depth", 12))
    limit = int(a.get("limit", 4))

    def matching_callee(fn) -> str | None:
        try:
            for callee in fn.getCalledFunctions(MONITOR):
                if to_pat.search(str(callee.getName())):
                    return str(callee.getName())
        except Exception:  # noqa: BLE001
            return None
        return None

    def callers(fn) -> list[Any]:
        try:
            return [
                c for c in fn.getCallingFunctions(MONITOR) if not c.isExternal() and not c.isThunk()
            ]
        except Exception:  # noqa: BLE001
            return []

    roots: list[tuple[Any, str]] = []
    it = fm.getFunctions(True)
    while it.hasNext() and len(roots) < limit * 4:
        fn = it.next()
        try:
            if fn.isExternal() or fn.isThunk():
                continue
        except Exception:  # noqa: BLE001
            continue
        name = str(fn.getName())
        if to_pat.search(name):
            roots.append((fn, name))
            continue
        callee = matching_callee(fn)
        if callee:
            roots.append((fn, callee))

    found_paths = []
    for fn, why in roots[:limit]:
        prev: dict[str, Any] = {}
        seen = {str(fn.getEntryPoint())}
        frontier = [fn]
        found = None
        for _ in range(depth):
            if not frontier:
                break
            nxt = []
            for cur in frontier:
                if from_pat.search(str(cur.getName())):
                    found = cur
                    break
                for c in callers(cur):
                    key = str(c.getEntryPoint())
                    if key in seen:
                        continue
                    seen.add(key)
                    prev[key] = cur
                    nxt.append(c)
            if found is not None:
                break
            frontier = nxt
        chain: list[dict[str, str]] = []
        if found is not None:
            cur = found
            while True:
                chain.append({"name": str(cur.getName()), "addr": str(cur.getEntryPoint())})
                key = str(cur.getEntryPoint())
                if key not in prev:
                    break
                cur = prev[key]
        entry_item = {
            "function": str(fn.getName()),
            "addr": str(fn.getEntryPoint()),
            "via": why,
            "reaches_entry": found is not None,
            "path": list(reversed(chain)),
            "depth": len(chain),
        }
        if a.get("code"):
            try:
                res = e["decomp"].decompileFunction(fn, 60, MONITOR)
                if res.decompileCompleted():
                    code = str(res.getDecompiledFunction().getC()).replace("\r\n", "\n")
                    entry_item["code"] = "\n".join(code.splitlines()[:60])
            except Exception:  # noqa: BLE001
                pass
        found_paths.append(entry_item)
    found_paths.sort(key=lambda x: (not x["reaches_entry"], x["depth"] or 999))
    return {"binary": a["binary"], "to": a["to"], "candidates": len(roots), "paths": found_paths}


def cmd_similar(a: dict[str, Any]) -> dict[str, Any]:
    """Rank functions of another program by fingerprint similarity to `target`.

    Uses the same fingerprints as `diff` (strings, imports, constants, size), so
    "I saw this in sample A, where is it in sample B" works without symbols.
    """
    from ghidra.program.model.block import BasicBlockModel

    e = _entry(a["binary"])
    fn = _function(e, a["target"])
    if fn is None:
        raise KeyError(f"function {a['target']!r} not found")
    mine = _fingerprint(e["program"], fn, BasicBlockModel(e["program"]))
    min_score = float(a.get("min_score", 0.4))
    limit = int(a.get("limit", 10))
    bins = (
        [str(a["against"])]
        if a.get("against")
        else [b for b in binary_names() if b != str(a["binary"])]
    )
    hits: list[dict[str, Any]] = []
    for b in bins:
        try:
            prints = _program_fingerprints(b)
        except Exception as ex:  # noqa: BLE001
            hits.append({"binary": b, "error": f"{type(ex).__name__}: {ex}"})
            continue
        for fp in prints["functions"].values():
            shared_str = mine["strings"] & fp["strings"]
            shared_imp = mine["imports"] & fp["imports"]
            shared_con = mine["consts"] & fp["consts"]
            score = _similarity(mine, fp)
            if not (shared_str or shared_imp or shared_con):
                # nothing but size/instruction shape in common: 29-byte stubs
                # all look alike, so cap these below any sensible threshold
                score = min(score, 0.3)
            if score < min_score:
                continue
            hits.append(
                {
                    "binary": b,
                    "name": fp["name"],
                    "addr": fp["addr"],
                    "score": round(score, 3),
                    "size": fp["size"],
                    "insns": fp["insns"],
                    "shared_strings": sorted(shared_str)[:3],
                    "shared_imports": sorted(shared_imp)[:4],
                }
            )
    hits.sort(key=lambda h: h.get("score", 0), reverse=True)
    return {
        "binary": a["binary"],
        "target": mine["name"],
        "addr": mine["addr"],
        "strings": len(mine["strings"]),
        "imports": len(mine["imports"]),
        "compared": len(bins),
        "matches": hits[:limit],
    }


def _select_functions(e, spec: str, limit: int) -> list[Any]:
    """Resolve `name:^FUN_`, `import:RegSet`, `calls:X`, `string:Auto`, `const:0x41`,
    `addr:0x140001000,0x140002000` or `all` into a bounded list of functions."""
    program = e["program"]
    kind, _, value = str(spec).partition(":")
    kind = kind.strip().lower() or "all"
    value = value.strip()
    known = ("all", "name", "import", "calls", "string", "const", "addr")
    if kind not in known:
        raise ValueError(f"unknown selector {kind!r} (kinds: {', '.join(known)})")
    pat = re.compile(value, re.I) if value else None
    wanted_addrs = set()
    if kind == "addr":
        for chunk in value.split(","):
            numeric = _hex_addr(chunk)
            if numeric is None:
                raise ValueError(f"bad address {chunk!r} in selector")
            wanted_addrs.add(numeric)
    out: list[Any] = []
    for fn in program.getFunctionManager().getFunctions(True):
        if fn.isExternal() or fn.isThunk():
            continue
        ok = False
        if kind == "all":
            ok = True
        elif kind == "name":
            ok = bool(pat and pat.search(str(fn.getName())))
        elif kind == "addr":
            ok = int(fn.getEntryPoint().getOffset()) in wanted_addrs
        elif kind in ("import", "calls"):
            ok = bool(pat) and any(
                pat.search(str(c.getName())) for c in fn.getCalledFunctions(MONITOR)
            )
        else:  # string / const need the instruction-level facts
            try:
                facts = _claim_facts(program, fn)
            except Exception:  # noqa: BLE001 - jpype call, can raise anything
                continue
            if pat is None:
                continue
            pool = facts["strings"] if kind == "string" else {str(c) for c in facts["consts"]}
            ok = any(pat.search(x) for x in pool)
        if ok:
            out.append(fn)
            if len(out) >= limit:
                break
    return out


def _map_rows(e, functions: list[Any], op: str, grep: re.Pattern[str] | None, hits: int):
    """One row per function: only what matched, never the whole body."""
    program = e["program"]
    rows = []
    for fn in functions:
        item = brief(fn)
        item["matched"] = []
        item["hits"] = 0
        if op == "decompile":
            code = None
            with contextlib.suppress(Exception):  # cache key touches jpype
                code = _cache_read(_decomp_cache_key(e, fn))
            if code is None:
                res = e["decomp"].decompileFunction(fn, 60, MONITOR)
                if not res.decompileCompleted():
                    item["error"] = str(res.getErrorMessage())
                    rows.append(item)
                    continue
                code = str(res.getDecompiledFunction().getC()).replace("\r\n", "\n")
                with contextlib.suppress(OSError):
                    _cache_write(_decomp_cache_key(e, fn), code)
            if grep is not None:
                found = _grep_code(code, grep)
                item["hits"] = len(found)
                item["matched"] = found[:hits]
            else:
                item["lines"] = len(code.splitlines())
        else:
            try:
                facts = _claim_facts(program, fn)
            except Exception as ex:  # noqa: BLE001 - jpype call, can raise anything
                item["error"] = f"{type(ex).__name__}: {ex}"
                rows.append(item)
                continue
            pool = {
                "strings": sorted(facts["strings"]),
                "imports": sorted(facts["imports"]),
                "calls": sorted(facts["calls"]),
                "consts": [hex(c) for c in sorted(facts["consts"])],
            }[op]
            found = [x for x in pool if grep is None or grep.search(x)]
            item["hits"] = len(found)
            item["matched"] = [{"text": x} for x in found[:hits]]
        rows.append(item)
    return rows


def cmd_map(a: dict[str, Any]) -> dict[str, Any]:
    """Run one operation over a *set* of functions and return only what matched.

    This is the batch primitive: "decompile every function that calls RegSetValueExW
    and show me the lines mentioning Autosave" used to cost one HTTP round-trip per
    function; now it is one call that returns nothing but the hits.
    """

    started = time.time()
    e = _entry(a["binary"])
    op = str(a.get("op") or "decompile").lower()
    known = ("decompile", "strings", "imports", "calls", "consts")
    if op not in known:
        raise ValueError(f"unknown op {op!r} (ops: {', '.join(known)})")
    limit = int(a.get("limit", 200))
    hits = int(a.get("hits", 5))
    grep = re.compile(str(a["grep"]), re.I) if a.get("grep") else None
    functions = _select_functions(e, str(a.get("from") or "all"), limit)
    rows = _map_rows(e, functions, op, grep, hits)
    matched = [
        r for r in rows if r["hits"] or r.get("error") or (op == "decompile" and grep is None)
    ]
    return {
        "binary": str(a["binary"]),
        "from": str(a.get("from") or "all"),
        "op": op,
        "grep": a.get("grep"),
        "selected": len(functions),
        "scanned": len(rows),
        "matched": len(matched),
        "hits": sum(r["hits"] for r in rows),
        "results": matched[:limit],
        "elapsed_ms": int((time.time() - started) * 1000),
    }


# ---- journal: what has been done to this project (agent memory across turns)

MUTATING = (
    "import",
    "analyze",
    "rename",
    "comment",
    "patch",
    "set_type",
    "bookmark",
    "note",
    "types",
    "pdb",
)


def _journal_file() -> Path:
    base = _project_dir or (Path.home() / "re" / "proj")
    d = Path(base) / ".ghlab"
    d.mkdir(parents=True, exist_ok=True)
    return d / "journal.jsonl"


def _journal_summary(cmd: str, params: dict[str, Any], result: Any) -> str:
    """One line a human (or a later agent turn) can read without the payload."""
    r = result if isinstance(result, dict) else {}
    if cmd == "rename":
        return f"{params.get('target')} -> {r.get('new') or params.get('new')}"
    if cmd == "patch":
        return f"{params.get('addr')} {r.get('before')} -> {r.get('after')}"
    if cmd == "set_type":
        return f"{params.get('target')} {r.get('decl') or params.get('decl')}"
    if cmd == "types":
        return f"{r.get('applied')} applied / {r.get('failed')} failed from {params.get('from')}"
    if cmd == "pdb":
        return f"{params.get('file')} applied={r.get('applied')}"
    if cmd == "note":
        return f"[{params.get('tag') or '-'}] {str(params.get('text'))[:100]}"
    if cmd == "bookmark":
        return f"{params.get('action') or 'set'} {params.get('addr') or params.get('target')}"
    if cmd == "import":
        return f"{params.get('path')} analyzed={r.get('analyzed')}"
    if cmd == "analyze":
        return f"{r.get('mode')} {params.get('addr') or ''}".strip()
    return ""


def _journal_append(cmd: str, params: dict[str, Any], result: Any, error: str = "") -> None:
    entry = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "op": cmd,
        "binary": params.get("binary") or params.get("path"),
        "summary": _journal_summary(cmd, params, result),
    }
    if error:
        entry["error"] = error
    try:
        with open(_journal_file(), "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + chr(10))
    except OSError:
        pass  # a missing journal must never break the operation itself


def cmd_journal(a: dict[str, Any]) -> dict[str, Any]:
    """Read the mutation log: what was renamed, patched, typed, noted, and when."""
    path = _journal_file()
    entries: list[dict[str, Any]] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    binary = a.get("binary")
    op = a.get("op")
    since = a.get("since")
    if binary:
        entries = [e for e in entries if e.get("binary") == binary]
    if op:
        entries = [e for e in entries if e.get("op") == op]
    if since:
        entries = [e for e in entries if str(e.get("at", "")) >= str(since)]
    limit = int(a.get("limit") or 50)
    total = len(entries)
    entries = entries[-limit:]
    return {
        "path": str(path),
        "total": total,
        "shown": len(entries),
        "entries": entries,
    }


def _journal_entries() -> list[dict[str, Any]]:
    path = _journal_file()
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def cmd_overview(_: dict[str, Any]) -> dict[str, Any]:
    """One line per program: size, strings, imports, notes, claims, last change.

    `digest` answers "what is this binary"; this answers "what is in this project",
    so an agent can pick a target without one call per sample.
    """
    started = time.time()
    journal = _journal_entries()
    rows = []
    for binary in binary_names():
        try:
            e = _entry(binary)
            program = e["program"]
            index = load_index(e)
            strings: set[str] = set()
            imports: set[str] = set()
            for fp in (index.get("rows") or {}).values():
                strings.update(fp.get("strings") or ())
                imports.update(fp.get("imports") or ())
            notes = _load_notes(binary)
            with_claims = [n for n in notes if n.get("claims")]
            failing = [n for n in with_claims if (n.get("check") or {}).get("status") == "fail"]
            last = next(
                (j for j in reversed(journal) if j.get("binary") in (binary, str(binary))), None
            )
            rows.append(
                {
                    "binary": binary,
                    "md5": str(program.getExecutableMD5()),
                    "language": str(program.getLanguageID()),
                    "compiler": str(program.getCompiler()),
                    "functions": len(index.get("rows") or {}),
                    "strings": len(strings),
                    "imports": len(imports),
                    "notes": len(notes),
                    "claims": len(with_claims),
                    "failing_claims": len(failing),
                    "index": index.get("index", {}),
                    "last": {"at": last["at"], "op": last["op"], "summary": last.get("summary")}
                    if last
                    else None,
                }
            )
        except Exception as ex:  # noqa: BLE001 - one bad program must not hide the rest
            rows.append({"binary": binary, "error": f"{type(ex).__name__}: {ex}"})
    return {
        "binaries": rows,
        "project": project_location(),
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def cmd_audit(a: dict[str, Any]) -> dict[str, Any]:
    """Re-check every stored claim in the project and list what no longer holds.

    `verify` is per binary; this is the project-wide question an agent asks after
    a re-analysis or a patch: which of my beliefs are now wrong?
    """
    started = time.time()
    target = a.get("binary")
    bins = [str(target)] if target else binary_names()
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    findings = []
    checked = 0
    passed = failed = unknown = 0
    for binary in bins:
        e = _entry(binary)
        notes = _load_notes(binary)
        touched = False
        for note in notes:
            claims = [str(c.get("claim")) for c in (note.get("claims") or [])]
            if not claims:
                continue
            addr = note.get("addr")
            fn = None
            if addr:
                try:
                    fn = _function(e, str(addr))
                except Exception:  # noqa: BLE001 - jpype call, can raise anything
                    fn = None
            results = _check_claims(e, fn, addr, claims)
            status = _claims_status(results)
            note["check"] = {"at": now, "status": status, "results": results}
            note["claims"] = results
            touched = True
            checked += 1
            passed += sum(1 for r in results if r.get("ok") is True)
            failed += sum(1 for r in results if r.get("ok") is False)
            unknown += sum(1 for r in results if r.get("ok") is None)
            if status != "pass":
                findings.append(
                    {
                        "binary": binary,
                        "id": note.get("id"),
                        "addr": addr,
                        "function": note.get("function"),
                        "tag": note.get("tag"),
                        "text": note.get("text"),
                        "status": status,
                        "results": [r for r in results if r.get("ok") is not True],
                    }
                )
        if touched:
            _store_notes(binary, notes)
    return {
        "binaries": bins,
        "notes_checked": checked,
        "claims": {"passed": passed, "failed": failed, "unknown": unknown},
        "status": "fail" if failed else ("unknown" if unknown else "pass"),
        "findings": findings,
        "checked_at": now,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def dispatch(cmd: str, params: dict[str, Any]) -> Any:
    with LOCK:
        try:
            result = HANDLERS[cmd](params)
        except Exception as ex:
            if cmd in MUTATING:
                _journal_append(cmd, params, None, f"{type(ex).__name__}: {ex}")
            raise
        if cmd in MUTATING:
            _journal_append(cmd, params, result)
        return result


def cmd_campaign(a: dict[str, Any]) -> dict[str, Any]:
    """Cluster every program in the project by shared imports and strings.

    The unit is the whole program (union of its function fingerprints), so two
    builds of the same tool collapse into one cluster while an unrelated binary
    stays alone. Single linkage: a shared loader stub should pull samples together.
    """

    from . import campaign

    started = time.time()
    min_score = float(a.get("min_score", 0.35))
    bins = [str(a["binary"])] if a.get("binary") else binary_names()
    profiles: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    for b in bins:
        try:
            prints = _program_fingerprints(b)
        except Exception as ex:  # noqa: BLE001
            errors.append({"binary": b, "error": f"{type(ex).__name__}: {ex}"})
            continue
        profiles[b] = campaign.profile_from_fingerprints(prints)
    clusters = campaign.cluster_programs(profiles, min_score)
    limit = int(a.get("limit") or 0)
    if limit:
        clusters = clusters[:limit]
    return {
        "binaries": len(profiles),
        "min_score": min_score,
        "clusters": clusters,
        "errors": errors,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def cmd_family(a: dict[str, Any]) -> dict[str, Any]:
    """Cross-sample report for one family: profiles, shared evidence, and notes.

    `campaign` answers "which samples belong together"; this answers "what do we
    already know about this family" - the per-program profile plus the notes each
    sample carries, so a report can be written without re-reading any of them.
    """
    from . import campaign

    started = time.time()
    min_score = float(a.get("min_score", 0.35))
    target = str(a["binary"]) if a.get("binary") else None
    bins = binary_names()
    profiles: dict[str, dict[str, Any]] = {}
    prints_by: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    for b in bins:
        try:
            prints = _program_fingerprints(b)
        except Exception as ex:  # noqa: BLE001
            errors.append({"binary": b, "error": f"{type(ex).__name__}: {ex}"})
            continue
        prints_by[b] = prints
        profiles[b] = campaign.profile_from_fingerprints(prints)
    clusters = campaign.cluster_programs(profiles, min_score)
    if target:
        clusters = [c for c in clusters if target in c["members"]]
        if not clusters:
            raise KeyError(f"{target} is not in the project")

    reports = []
    for cluster in clusters:
        programs = []
        for member in cluster["members"]:
            prints = prints_by[member]
            fns = prints.get("functions") or {}
            hubs: Counter[str] = Counter()
            for fp in fns.values():
                for callee in fp.get("callees") or ():
                    hubs[callee] += 1
            notes = _load_notes(member)
            programs.append(
                {
                    "binary": member,
                    "md5": prints.get("md5"),
                    "functions": len(fns),
                    "strings": len(profiles[member]["strings"]),
                    "imports": len(profiles[member]["imports"]),
                    "hubs": [{"name": n, "callers": k} for n, k in hubs.most_common(3)],
                    "notes": len(notes),
                    "tags": sorted({str(n["tag"]) for n in notes if n.get("tag")}),
                }
            )
        reports.append({**cluster, "programs": programs})
    limit = int(a.get("limit") or 0)
    if limit:
        reports = reports[:limit]
    return {
        "min_score": min_score,
        "binaries": len(profiles),
        "clusters": reports,
        "errors": errors,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


HANDLERS = {
    "ping": ping,
    "binaries": cmd_binaries,
    "import": cmd_import,
    "analyze": cmd_analyze,
    "info": cmd_info,
    "functions": cmd_functions,
    "decompile": cmd_decompile,
    "strings": cmd_strings,
    "xrefs": cmd_xrefs,
    "bytes": cmd_bytes,
    "rename": cmd_rename,
    "comment": cmd_comment,
    "graph": cmd_graph,
    "digest": cmd_digest,
    "find": cmd_find,
    "decrypt": cmd_decrypt,
    "index": cmd_index,
    "diff": cmd_diff,
    "emulate": cmd_emulate,
    "patch": cmd_patch,
    "set_type": cmd_set_type,
    "bookmark": cmd_bookmark,
    "note": cmd_note,
    "notes": cmd_notes,
    "verify": cmd_verify,
    "map": cmd_map,
    "types": cmd_types,
    "pdb": cmd_pdb,
    "report": cmd_report,
    "cross_xref": cmd_cross_xref,
    "slice": cmd_slice,
    "similar": cmd_similar,
    "campaign": cmd_campaign,
    "family": cmd_family,
    "journal": cmd_journal,
    "overview": cmd_overview,
    "audit": cmd_audit,
}
