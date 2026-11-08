"""Ghidra-side operations. Imports pyghidra lazily so the rest of ghlab works without it."""

from __future__ import annotations

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
    return entry["api"].toAddr(text)


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
            res = e["decomp"].decompileFunction(fn, timeout, MONITOR)
            if not res.decompileCompleted():
                results.append({"target": str(t), "error": str(res.getErrorMessage())})
                continue
            code = str(res.getDecompiledFunction().getC()).replace("\r\n", "\n")
            all_lines = code.splitlines()
            item = brief(fn)
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
        for sym in program.getSymbolTable().getAllSymbols(True):
            if str(sym.getName()).lower() in ("entry", "_start", "maincrtstartup"):
                entry_addr = sym.getAddress()
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
}


def dispatch(cmd: str, params: dict[str, Any]) -> Any:
    with LOCK:
        return HANDLERS[cmd](params)
