"""Ghidra-side operations. Imports pyghidra lazily so the rest of ghlab works without it."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
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
    entry = {"program": program, "decomp": decomp, "api": FlatProgramAPI(program)}
    _programs[binary] = entry
    return entry


def _addr(entry: dict[str, Any], text: str):
    program = entry["program"]
    text = str(text)
    if text.lower().startswith("0x"):
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(
            int(text, 16)
        )
    addr = entry["api"].toAddr(text)
    if addr is None:
        raise KeyError(f"address or symbol {text!r} not found")
    return addr


def _function(entry: dict[str, Any], target: str):
    program = entry["program"]
    fm = program.getFunctionManager()
    text = str(target)
    if text.lower().startswith("0x"):
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
    try:
        (_cache_dir() / (key + ".c")).write_text(code, encoding="utf-8")
    except OSError:
        pass


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
                item["callees"] = [
                    str(c.getName()) for c in fn.getCalledFunctions(MONITOR)
                ][:40]
            if a.get("include_callers"):
                item["callers"] = [
                    str(c.getName()) for c in fn.getCallingFunctions(MONITOR)
                ][:40]
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
            except Exception:
                val = str(d.getDefaultValueRepresentation())
        except Exception:
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
                edges_out.append(
                    {"from": str(fn.getName()), "to": str(callee.getName())}
                )
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
        "edges": edges_out[:cap * 2],
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
    return [str(v) for v in value]


def cmd_find(a: dict[str, Any]) -> dict[str, Any]:
    """Locate candidates by structure (imports / strings / calls), not by name."""
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
    calls = 0
    for callee in fn.getCalledFunctions(MONITOR):
        calls += 1
        name = str(callee.getName())
        if callee.isExternal() or callee.isThunk() or name.startswith("PTR_"):
            ext.add(_clean_name(name))
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
    }


def _program_fingerprints(binary: str) -> dict[str, Any]:
    from ghidra.program.model.block import BasicBlockModel

    entry = _entry(binary)
    program = entry["program"]
    md5 = str(program.getExecutableMD5() or "")
    cache_key = (str(binary), md5, int(program.getModificationNumber()))
    if cache_key in _FP_CACHE:
        return _FP_CACHE[cache_key]
    model = BasicBlockModel(program)
    prints: dict[int, dict[str, Any]] = {}
    it = program.getFunctionManager().getFunctions(True)
    while it.hasNext():
        fn = it.next()
        try:
            if fn.isExternal():
                continue
            fp = _fingerprint(program, fn, model)
        except Exception:  # noqa: BLE001
            continue
        prints[fp["offset"]] = fp
    out = {"binary": str(binary), "md5": md5, "program": program, "functions": prints}
    _FP_CACHE[cache_key] = out
    return out


def _read_memory(program, start, size: int) -> bytes:
    """Read a range: MemoryMap.getBytes only takes a byte[] sink, not a length."""
    from jpype import JArray, JByte

    buf = JArray(JByte)(size)
    read = program.getMemory().getBytes(start, buf)
    return bytes((buf[i] & 0xFF) for i in range(read))


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
    for key in ("strings", "consts", "imports"):
        if x[key] != y[key]:
            return True
    return False


def cmd_diff(a: dict[str, Any]) -> dict[str, Any]:
    """Compare two programs in the project: what was added, removed, patched."""
    import time

    started = time.time()
    left = _program_fingerprints(a["a"])
    right = _program_fingerprints(a["b"])
    la, lb = left["functions"], right["functions"]
    limit = int(a.get("limit", 25))
    min_score = float(a.get("min_score", 0.55))

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

    changed = []
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
    changed.sort(key=lambda c: -abs(c["delta"]["size"][1] - c["delta"]["size"][0]))

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
        "changed": sorted(
            n for n in set(sec_a) & set(sec_b) if sec_a[n]["md5"] != sec_b[n]["md5"]
        ),
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
    return low.startswith("ptr_") or ".dll" in low or low.startswith("thunk_")


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
    import time

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
    emu.setBreakpoint(
        program.getAddressFactory().getDefaultAddressSpace().getAddress(sentinel)
    )

    space = program.getAddressFactory().getDefaultAddressSpace()
    cursor = string_at
    buf_size = int(a.get("buffer") or 0)
    if buf_size > 0x700:
        raise ValueError("buffer is capped at 0x700 bytes inside the scratch block")
    buf_addr = base + 0x600
    if buf_size:
        emu.writeMemory(space.getAddress(buf_addr), b"\x00" * buf_size)
    string_limit = buf_addr if buf_size else stack_top - 0x400
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
    prev_pc = fn.getEntryPoint()
    last_valid_pc = fn.getEntryPoint()
    try:
        while insns < max_insns:
            pc = emu.getExecutionAddress()
            if pc.equals(sentinel_addr):
                stop = "returned"
                break
            if program.getMemory().contains(pc):
                last_valid_pc = pc
            prev_pc = pc
            if emu.step(monitor):
                insns += 1
                continue
            if monitor.didTimeout():
                stop = "timeout"
                break
            callee = _call_target(program, int(last_valid_pc.getOffset()))
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
        daddr = int(addr_text, 0) if addr_text.lower().startswith("0x") else int(addr_text, 0)
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
        "fault": fault,
        "scratch": {"block": str(block.getName()), "base": hex(base), "sp": hex(sp)},
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
    from ghidra.program.model.data import ArrayDataType, PointerDataType, StructureDataType

    base, stars, dims = _parse_type_spec(text)
    dtm = program.getDataTypeManager()
    dt = None
    if base in _PRIMITIVES:
        dt = getattr(jpype.JClass("ghidra.program.model.data." + _PRIMITIVES[base]), "dataType")
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
        except Exception:
            continue
    raise RuntimeError("could not construct FunctionSignatureParser")


def _block_writable(block) -> bool:
    """MemoryBlock exposes either isWriteable() or isWrite() depending on version."""
    for attr in ("isWriteable", "isWrite"):
        fn = getattr(block, attr, None)
        if fn is not None:
            try:
                return bool(fn())
            except Exception:
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
            try:
                block.setWrite(False)
            except Exception:
                pass
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
        except Exception:
            continue
    return str(fn.getName())


def cmd_set_type(a: dict[str, Any]) -> dict[str, Any]:
    """Apply a function prototype ('int f(char *s, unsigned n)') or a data type
    ('char[64]', 'void*', 'DWORD') at an address."""
    from ghidra.app.cmd.data import CreateDataCmd
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.program.model.symbol import SourceType

    e = _entry(a["binary"])
    p = e["program"]
    decl = str(a["decl"]).strip()
    if "(" in decl and ")" in decl:
        fn = _function(e, a["target"])
        if fn is None:
            raise KeyError(f"function {a['target']!r} not found")
        # parse() takes a FunctionSignature; fn.getSignature() hands us one (a
        # FunctionDefinitionDataType) without any jpype casting games.
        fdef = _signature_parser(p, SourceType.USER_DEFINED).parse(fn.getSignature(), decl)
        new_name = str(fdef.getName() or "").strip()
        tx = p.startTransaction("ghlab-signature")
        try:
            cmd = ApplyFunctionSignatureCmd(fn.getEntryPoint(), fdef, SourceType.USER_DEFINED)
            ok = bool(cmd.applyTo(p))
            # ApplyFunctionSignatureCmd keeps the old name; the declaration is the
            # authority on what the function is called.
            if ok and new_name and new_name != str(fn.getName()):
                fn.setName(new_name, SourceType.USER_DEFINED)
        finally:
            p.endTransaction(tx, True)
        saved = _save(p, "ghlab signature")
        after = p.getFunctionManager().getFunctionAt(fn.getEntryPoint())
        return {
            "kind": "signature",
            "applied": ok,
            "addr": str(fn.getEntryPoint()),
            "prototype": _prototype(after) if after is not None else str(fdef.getPrototypeString()),
            "message": str(cmd.getStatusMsg()),
            "saved_via": saved,
        }
    addr = _addr(e, str(a["target"]))
    dt = _datatype(p, decl)
    tx = p.startTransaction("ghlab-set-data")
    try:
        cmd = CreateDataCmd(addr, dt)
        ok = bool(cmd.applyTo(p))
    finally:
        p.endTransaction(tx, True)
    saved = _save(p, "ghlab data")
    data = p.getListing().getDataAt(addr) if ok else None
    return {
        "kind": "data",
        "applied": ok,
        "addr": str(addr),
        "datatype": str(data.getDataType().getName()) if data is not None else str(dt.getName()),
        "size": int(dt.getLength()),
        "value": str(data.getValue()) if data is not None and data.getValue() is not None else None,
        "message": str(cmd.getStatusMsg()),
        "saved_via": saved,
    }


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
    """Append a durable finding (JSON on disk + a Ghidra bookmark)."""
    import time

    binary = str(a["binary"])
    notes = _load_notes(binary)
    at = a.get("at")
    addr = None
    name = None
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
    note = {
        "id": len(notes) + 1,
        "binary": binary,
        "addr": addr,
        "function": name,
        "tag": str(a.get("tag") or "note"),
        "text": str(a["text"]),
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    notes.append(note)
    _store_notes(binary, notes)
    return {"note": note, "total": len(notes), "path": str(_notes_file(binary))}


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
        if at and at.lower() not in (n.get("addr") or "").lower() and at.lower() not in (
            (n.get("function") or "").lower()
        ):
            continue
        if query and query.lower() not in (n.get("text") or "").lower():
            continue
        out.append(n)
    cap = int(a.get("limit", 200))
    return {"notes": out[:cap], "count": len(out), "total": len(notes), "path": str(_notes_file(binary))}


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
            lines.append(f"- `{h.get('addr')}` {h.get('name')} — {h.get('callers')} callers, {h.get('size')}b")
    sizes = d.get("sizes") or {}
    if sizes:
        lines += ["", "## Function sizes", ""]
        lines.append(" | ".join(f"{k}: {v}" for k, v in sizes.items()))
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
                {"binary": b, "matches": hits, "count": len(hits), "scanned": scanned, "errors": errors}
            )
    return {"query": a["query"], "searched": len(bins), "binaries": out}


def cmd_slice(a: dict[str, Any]) -> dict[str, Any]:
    """Shortest caller chain that reaches an import (or a named function).

    Reverse BFS from every function that touches `to`, stopping when a function
    matches `from` (entry/main/WinMain/DllMain by default). This answers "what
    has to run for this API to be called" without reading 800 functions.
    """
    e = _entry(a["binary"])
    p = e["program"]
    fm = p.getFunctionManager()
    to_pat = re.compile(str(a["to"]), re.I)
    from_pat = re.compile(
        str(a.get("from") or r"^(entry|main|wmain|winmain|wwinmain|dllmain|_start|maincrtstartup)$"),
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
            return [c for c in fn.getCallingFunctions(MONITOR) if not c.isExternal() and not c.isThunk()]
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
    bins = [str(a["against"])] if a.get("against") else [
        b for b in binary_names() if b != str(a["binary"])
    ]
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


def dispatch(cmd: str, params: dict[str, Any]) -> Any:
    with LOCK:
        return HANDLERS[cmd](params)


def cmd_campaign(a: dict[str, Any]) -> dict[str, Any]:
    """Cluster every program in the project by shared imports and strings.

    The unit is the whole program (union of its function fingerprints), so two
    builds of the same tool collapse into one cluster while an unrelated binary
    stays alone. Single linkage: a shared loader stub should pull samples together.
    """
    import time

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


HANDLERS = {
    "ping": ping,
    "binaries": cmd_binaries,
    "import": cmd_import,
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
    "diff": cmd_diff,
    "emulate": cmd_emulate,
    "patch": cmd_patch,
    "set_type": cmd_set_type,
    "bookmark": cmd_bookmark,
    "note": cmd_note,
    "notes": cmd_notes,
    "report": cmd_report,
    "cross_xref": cmd_cross_xref,
    "slice": cmd_slice,
    "similar": cmd_similar,
    "campaign": cmd_campaign,
}
