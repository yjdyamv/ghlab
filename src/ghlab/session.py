"""Ghidra-side operations. Imports pyghidra lazily so the rest of ghlab works without it."""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import itertools
import json
import os
import re
import shutil
import threading
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import config, render

# The daemon's ConsoleTaskMonitor: the handle `job`/`cancel` reach through.
MONITOR: Any = None
LOCK = threading.RLock()
# What the dispatcher is running right now. Requests are threaded, but every
# Ghidra call takes LOCK, so exactly one command runs at a time and this is also
# the answer to "why is my request queued?". Set *inside* the lock: a command
# still waiting for LOCK is queued, not running.
_INFLIGHT: dict[str, Any] = {"cmd": None, "started": 0.0, "since": None}
# Commands that must answer *while* something else runs: the status question, the
# queue, and the interruption.  Everything else serializes on LOCK.
_UNLOCKED: tuple[str, ...] = ("ping", "job", "cancel")
# Background jobs: a long scan queued from an agent that then has to wait for it
# anyway is a timeout waiting to happen, and no way to watch or stop it.
JOBS: dict[str, dict[str, Any]] = {}
MAX_JOBS_KEPT = 50
_JOB_SEQ = itertools.count(1)
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
    # A TaskMonitorAdapter ignores cancel() unless cancellation was enabled, and the
    # default is disabled: without this line `ghlab cancel` flipped nothing at all and
    # a two-minute analysis ran to the end (measured: cancel at 6s, job ended at 127s
    # with the same 130s it takes uncancelled).
    MONITOR.setCancelEnabled(True)


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
        configure(Path(config.default_project_dir()))
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


def _num(a: dict[str, Any], key: str, default: int, *, minimum: int | None = None) -> int:
    """One integer argument, with a message that names it.

    `limit=all` used to surface as `ValueError: invalid literal for int() with base 10:
    'all'`, which names neither the argument nor the fix.  `True` is refused rather than
    becoming 1: a boolean in a numeric slot is a caller bug, not a limit of one.
    """
    value = a.get(key, default)
    if isinstance(value, bool):
        raise ValueError(f"{key} must be a number, got {value!r}")
    try:
        out = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a number, got {value!r}") from None
    if minimum is not None and out < minimum:
        raise ValueError(f"{key} must be >= {minimum}, got {out}")
    return out


def _binary_hint(binary: str, names: list[str]) -> str:
    """Why a name missed, in the terms the caller used: a path, a typo, an empty project."""
    if not names:
        return "the project has no programs yet; `ghlab import <path>` adds one"
    if any(sep in binary for sep in ("/", "\\")):
        return f"that looks like a path; programs are named by file name ({len(names)} available)"
    near = difflib.get_close_matches(binary, names, n=2, cutoff=0.6)
    if near:
        return f"did you mean {', '.join(near)}?"
    shown = ", ".join(names[:12]) + (" ..." if len(names) > 12 else "")
    return f"project has {shown}"


def _entry(binary: str) -> dict[str, Any]:
    """Open (and cache) one program; `binary` may be a unique substring."""
    if binary in _programs:
        _programs[binary]["used"] = time.monotonic()
        return _programs[binary]
    names = binary_names()
    if binary not in names:
        cand = [n for n in names if binary.lower() in n.lower()]
        if len(cand) > 1:
            shown = ", ".join(cand[:8]) + (" ..." if len(cand) > 8 else "")
            raise KeyError(
                f"binary {binary!r} matches {len(cand)} programs ({shown}); name one exactly"
            )
        if not cand:
            raise KeyError(f"binary {binary!r} not found: {_binary_hint(binary, names)}")
        binary = cand[0]
        # the substring spelling may still hit an already-open program
        if binary in _programs:
            _programs[binary]["used"] = time.monotonic()
            return _programs[binary]
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.flatapi import FlatProgramAPI

    # Opened through the domain file, *not* through `GhidraProject.openProgram`:
    # that one starts a transaction named "Batch Processing" and remembers its id
    # in a private map.  Keeping a program open for minutes (instead of one
    # import/save cycle) makes that bookkeeping drift from the real transaction
    # stack, and one failed save leaves it permanently stale -- every later save
    # then dies with "Attempted to end Transaction more than once".  Going through
    # `getDomainObject` means we own every transaction we open, and a save is just
    # a save.
    proj = project()
    domain_file = proj.getProjectData().getFile("/" + binary)
    if domain_file is None:
        raise KeyError(f"program {binary!r} is not in the project any more")
    from java.lang import Object as JavaObject

    # The consumer is only an identity token for Ghidra's open-object bookkeeping;
    # it must be the same object when the program is released again.
    consumer = JavaObject()
    program = domain_file.getDomainObject(consumer, True, False, MONITOR)
    decomp = DecompInterface()
    decomp.toggleCCode(True)
    decomp.toggleSyntaxTree(True)
    decomp.openProgram(program)
    entry = {
        "binary": binary,
        "proj": proj,
        "file": domain_file,
        "consumer": consumer,
        "program": program,
        "decomp": decomp,
        "api": FlatProgramAPI(program, MONITOR),
        "used": time.monotonic(),
    }
    _programs[binary] = entry
    _evict_lru(keep=binary)
    return entry


def _evict_lru(keep: str) -> None:
    """Close the least recently used programs; an open program costs heap for life.

    Every open program keeps its lists, symbol index and decompiler alive for as
    long as the daemon runs, so a session that touched twenty binaries ends up
    holding all twenty. `GHLAB_MAX_OPEN_PROGRAMS` (default 4) caps that; the one
    being asked for is never evicted.
    """
    cap = max(1, int(os.environ.get("GHLAB_MAX_OPEN_PROGRAMS", "4")))
    while len(_programs) > cap:
        candidates = [name for name in _programs if name != keep]
        if not candidates:
            return
        victim = min(candidates, key=lambda name: _programs[name].get("used", 0.0))
        entry = _programs.pop(victim)
        with contextlib.suppress(Exception):  # jpype: already closed, or never opened
            entry["decomp"].dispose()
        with contextlib.suppress(Exception):
            # release through the consumer it was opened with, so Ghidra closes the
            # domain object instead of thinking it still has a user
            entry["program"].release(entry.get("consumer") or entry["proj"])
        for key in [k for k in _FP_CACHE if k[0] == victim]:
            _FP_CACHE.pop(key, None)


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


def _symbols_named(program, name: str, limit: int = 8) -> list[Any]:
    """Exact symbol lookup through the indexed tables (never a full scan).

    `getAllSymbols(True)` walks every symbol in the program: on a 34 MB binary
    with 300k+ symbols that costs ~7 s per call, which is why `xrefs` used to
    look broken. `getGlobalSymbols`/`getSymbols` hit the name index instead.
    """
    text = str(name)
    table = program.getSymbolTable()
    out: list[Any] = []
    for getter in ("getGlobalSymbols", "getSymbols"):
        fn = getattr(table, getter, None)
        if fn is None:
            continue
        try:
            hits = fn(text)
        except Exception:  # noqa: BLE001 - jpype raises for odd overloads
            continue
        for sym in hits or []:
            out.append(sym)
            if len(out) >= limit:
                return out
    if out:
        return out
    # Namespaced spellings (`USER32.DLL::GetWindowLongW`) are not in the index.
    for sym in table.getAllSymbols(True):
        if str(sym.getName()) == text or str(sym.getName(True)) == text:
            out.append(sym)
            if len(out) >= limit:
                break
    return out


def _function(entry: dict[str, Any], target: str):
    program = entry["program"]
    fm = program.getFunctionManager()
    text = str(target)
    numeric = _hex_addr(text)
    if numeric is not None:
        addr = _addr(entry, text)
        return fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
    for sym in _symbols_named(program, text):
        fn = fm.getFunctionAt(sym.getAddress())
        if fn is not None:
            return fn
    return None


def _end_open_transactions(program: Any, limit: int = 4) -> int:
    """End whatever transaction Ghidra left open on this program.

    `GhidraProject.openProgram` starts one, names it "Batch Processing", and
    expects `GhidraProject.save`/`GhidraProject.close` to end it.  We keep programs
    open for minutes instead of one import/save cycle, so that bookkeeping and the
    real transaction stack drift apart: after one failed save, Ghidra hits
    "Attempted to end Transaction more than once" (its stale id is no longer on
    top) and then refuses every following save with "Unable to lock due to active
    transaction" -- one bad program, wedged for the life of the daemon.

    Ending the leftover here, before each save, keeps the two in step.  A handle
    that has already been ended throws; `getCurrentTransactionInfo` happily
    returns those, so the throw is the signal to stop.
    """
    ended = 0
    for _ in range(limit):
        try:
            tx = program.getCurrentTransactionInfo()
            if tx is None:
                break
            program.endTransaction(int(tx.getID()), True)
        except Exception:  # noqa: BLE001 - jpype raises whatever Java chose
            break
        ended += 1
    return ended


def _domain_save(program: Any) -> None:
    """Save the domain file, after ending whatever transaction Ghidra left on top.

    GhidraProject's own `save` does this with the id it remembers; that id is
    useless once it is stale ("Transaction not found"), so clear the stack first.
    """
    _end_open_transactions(program)
    program.getDomainFile().save(MONITOR)


def _save(program, message: str, entry: dict[str, Any] | None = None) -> str:
    """Persist the program through its domain file.

    One way in, and it is the domain file: `_entry` opens programs with
    `DomainFile.getDomainObject`, which leaves no transaction behind, so a save is
    "end our own transaction, then save".

    `GhidraProject.save` is deliberately *not* used as a fallback.  It ends the id
    it remembered from `openProgram`; if that save ever fails, the id stays and the
    next save ends a transaction that is not on the stack -- "Attempted to end
    Transaction more than once", then "Unable to lock due to active transaction"
    forever.  A fallback chain over a stateful resource makes a bad state worse.

    A failure worth retrying is still "Unable to lock due to active transaction":
    Ghidra's auto-analysis can open one behind our back right after a commit, so the
    first attempt may lose the race by a few milliseconds.  If both attempts fail,
    the program is dropped from the cache: the next request reopens it from disk,
    which is the only repair available from Python (the stale bookkeeping lives in a
    private field of GhidraProject).

    Pass `entry` when the change alters what the decompiler prints: the disk cache
    is keyed by md5/prototype/comments only, so patched bytes would otherwise keep
    answering from stale source until someone remembered `--refresh`.
    """
    label = "domain.save(monitor)"
    errors: list[str] = []
    for attempt in range(2):
        try:
            _domain_save(program)
        except Exception as ex:  # noqa: BLE001 - reported, not swallowed
            errors.append(f"{label}: {type(ex).__name__}: {ex}")
            time.sleep(0.25 * (attempt + 1))
            continue
        if entry is not None:
            _cache_purge(entry)
        return label
    forgotten = _forget_program(program)
    raise RuntimeError(
        f"cannot save program for {message!r} -> "
        + " | ".join(errors)
        + f" | tx: {_tx_state(program)}"
        + ("" if forgotten else " | program was not in the open cache")
    )


def _forget_program(program: Any) -> bool:
    """Drop one program from the open cache so the next request reopens it.

    The repair for a program that refuses to save: the stale bookkeeping is inside
    Ghidra's own objects, so the only clean state reachable from Python is "closed".
    """
    for name, entry in list(_programs.items()):
        cached = entry.get("program")
        if not (cached is program or _same_program(cached, program)):
            continue
        _programs.pop(name, None)
        with contextlib.suppress(Exception):
            entry["decomp"].dispose()
        with contextlib.suppress(Exception):
            entry["program"].release(entry.get("consumer") or entry["proj"])
        for key in [k for k in _FP_CACHE if k[0] == name]:
            _FP_CACHE.pop(key, None)
        return True
    return False


def _same_program(a: Any, b: Any) -> bool:
    """jpype hands out one proxy per Java object, but not always *that* proxy."""
    if a is b:
        return True
    try:
        return bool(a.equals(b))
    except Exception:  # noqa: BLE001 - jpype raises whatever Java chose
        return False


def _tx_state(program: Any) -> str:
    """What transaction Ghidra thinks is current -- for save failures, which are all
    about exactly that."""
    with contextlib.suppress(Exception):
        tx = program.getCurrentTransactionInfo()
        if tx is None:
            return "none"
        return f"id={tx.getID()} {tx.getDescription()}"
    return "?"


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
    out = {
        "service": "ghlab",
        "project": project_location(),
        "binaries": len(binary_names()),
        "loaded": sorted(_programs),
        # the code this process is actually running: `ghlab status` compares it with
        # what is installed, and it must not depend on finding a pidfile first
        "stamp": code_stamp(),
    }
    if readonly():
        out["readonly"] = True
    busy = in_flight()
    if busy:
        out["busy"] = busy
    return out


def cmd_binaries(_: dict[str, Any]) -> dict[str, Any]:
    return {"binaries": binary_names()}


def _language_id(text: str) -> str:
    """Validate the `processor:endian:size:variant` form Ghidra's LanguageID takes.

    The point is to fail at the CLI with the shape you got wrong, instead of deep in
    the importer with `No Language matched: x86_64`.
    """
    parts = str(text).split(":")
    if len(parts) != 4 or not all(part.strip() for part in parts):
        raise ValueError(
            f"language {text!r} must look like x86:LE:64:default "
            "(processor:endian:size:variant); `ghlab import --show-loaders FILE` lists them"
        )
    return ":".join(part.strip() for part in parts)


def _load_spec_rows(path: Path) -> list[dict[str, Any]]:
    """Every (loader, language, compiler spec) this JVM could import `path` with.

    Preferred specs first: for a PE that is the one `import` will pick, and for a raw
    image the preferred flag is the only hint among the hundreds of languages the
    Binary loader offers.
    """
    from ghidra.app.util.bin import FileByteProvider
    from ghidra.app.util.opinion import LoaderService
    from ghidra.formats.gfilesystem import FSRL
    from java.io import File
    from java.nio.file import AccessMode

    provider = FileByteProvider(File(str(path)), FSRL.fromString(path.as_uri()), AccessMode.READ)
    try:
        rows = []
        found = LoaderService.getSupportedLoadSpecs(provider, LoaderService.ACCEPT_ALL)
        for loader, specs in found.items():
            for spec in specs:
                pair = spec.getLanguageCompilerSpec()
                rows.append(
                    {
                        "loader": str(loader.getName()),
                        "language": str(pair.getLanguageID()),
                        "cspec": str(pair.getCompilerSpecID()),
                        "preferred": bool(spec.isPreferred()),
                        "base": f"0x{int(spec.getDesiredImageBase()):x}",
                    }
                )
        return sorted(
            rows, key=lambda r: (not r["preferred"], r["loader"], r["language"], r["cspec"])
        )
    finally:
        provider.close()


def _auto_import(path: Path, language: str, cspec: str) -> Any:
    """Import with an explicit language/compiler spec; return the new program.

    The signature is pinned down here because every obvious guess fails on a real
    JVM: it is `(File|FSRL, Project, folderPath, Language, CompilerSpec, consumer,
    MessageLog, TaskMonitor)` -- eight arguments, the fourth a `Language` (not the
    `LanguageCompilerSpecPair` the name suggests), and a middle consumer/log pair
    that makes a shorter call fail with "wrong number of arguments".

    The returned program is *not* in the project: `importByLookingForLcs` hands back
    an in-memory program, so the caller still has to `saveAs` it.
    """
    from ghidra.app.util.importer import AutoImporter, MessageLog
    from ghidra.program.model.lang import LanguageCompilerSpecPair
    from java.io import File

    pair = LanguageCompilerSpecPair(language, cspec)
    try:
        results = AutoImporter.importByLookingForLcs(
            File(str(path)),
            project().getProject(),  # the jpype project wrapper is not a `Project`
            "/",
            pair.getLanguage(),
            pair.getCompilerSpec(),
            None,
            MessageLog(),
            MONITOR,
        )
    except Exception as ex:  # jpype raises whatever Java class the JVM chose
        raise RuntimeError(
            f"importByLookingForLcs({language}:{cspec}) failed -> {type(ex).__name__}: {ex}"
        ) from ex
    if results is None:
        raise RuntimeError(f"AutoImporter returned nothing for {path}")
    return results.getPrimaryDomainObject()


def _image_base(program: Any, text: str) -> Any:
    space = program.getAddressFactory().getDefaultAddressSpace()
    return space.getAddress(int(str(text), 0))


def _analyze_all(program: Any, watch: Any = None) -> None:
    """Run Ghidra's full analysis, with a monitor the daemon can cancel.

    Two things were learned the hard way on a real JVM.  `FlatProgramAPI.analyzeAll`
    builds its own `ConsoleTaskMonitor` unless it is handed one, so a job cancelled
    mid-analysis ran to the end anyway; and driving `AutoAnalysisManager` ourselves
    (even with `initializeOptions`) produced 455 one-byte functions where `analyzeAll`
    produces 522 real ones, because the function-body analyzers are scheduled by the
    API layer, not by `startAnalysis`.

    So: keep `analyzeAll`, and give it our monitor through the constructor.
    """
    from ghidra.app.script import GhidraScriptUtil
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.util import GhidraProgramUtilities

    monitor = watch or MONITOR
    flat = FlatProgramAPI(program, monitor)
    GhidraScriptUtil.acquireBundleHostReference()
    try:
        flat.analyzeAll(program)
    except Exception:
        # a cancelled analysis throws out of the analyzers; that is the cancel taking
        # effect, not a failure, so leave the program marked unanalyzed and let the job
        # thread report "cancelled"
        if not monitor.isCancelled():
            raise
        return
    finally:
        GhidraScriptUtil.releaseBundleHostReference()
    if not monitor.isCancelled():
        GhidraProgramUtilities.markProgramAnalyzed(program)


def cmd_import(a: dict[str, Any]) -> dict[str, Any]:
    from java.io import File

    path = Path(a["path"]).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"no such file: {path}")
    if a.get("show_loaders"):
        return {"path": str(path), "load_specs": _load_spec_rows(path)}
    name = str(a.get("name") or path.name)
    if a.get("language"):
        language = _language_id(str(a["language"]))
        cspec = str(a.get("cspec") or "default")
    else:
        language = cspec = ""
    proj = project()
    existing = proj.getRootFolder().getFile(name)
    if existing is not None and not a.get("overwrite"):
        return {"binary": name, "already_present": True}
    if existing is not None:
        existing.delete()
    if language:
        program = _auto_import(path, language, cspec)
    else:
        program = proj.importProgram(File(str(path)))
    if program is None:
        raise RuntimeError(f"Ghidra failed to import {path}")
    if a.get("base") not in (None, ""):
        # Rebasing has to happen before the first save: analysis fixes addresses,
        # and a program moved after that keeps referring to the old ones.
        with _edit(program, "ghlab import base"):
            program.setImageBase(_image_base(program, str(a["base"])), True)
    proj.saveAs(program, "/", name, True)
    if not language:
        if a.get("analyze", True):
            _analyze_all(program)
        # `proj.save` here, not a domain save: the program GhidraProject just imported
        # is one *it* opened, so its "Batch Processing" transaction is on the stack and
        # a bare domain save would refuse to take the write lock.  `close` ends that
        # transaction and releases it, which is the other half of the import cycle.
        proj.save(program)
    else:
        # An `AutoImporter` program is not in GhidraProject's bookkeeping at all (`close`
        # answers "unknown consumer"), so analysing it in place leaves the write lock
        # held by the transaction `saveAs` started and the following save dies with
        # "Unable to lock due to active transaction".  Hand the file over instead:
        # reopen it through the cache, which is the path that is known to save cleanly.
        with contextlib.suppress(Exception):
            proj.close(program)
        e = _entry(name)
        with _edit(e["program"], "ghlab import"):
            if a.get("analyze", True):
                _analyze_all(e["program"])
        _save(e["program"], "ghlab import", e)
        program = e["program"]
    out = {
        "binary": name,
        "imported": True,
        "analyzed": bool(a.get("analyze", True)),
        "image_base": str(program.getImageBase()),
    }
    if language:
        out["language"] = language
        out["cspec"] = cspec
    if not language:
        with contextlib.suppress(Exception):
            proj.close(program)  # ends import's transaction *and* releases it
    return out


def cmd_analyze(a: dict[str, Any]) -> dict[str, Any]:
    """(Re)analyze a program: everything, or just the addresses you touched.

    Importing a large binary costs a minute of full analysis; patching one
    function should not. `--addr` disassembles and creates the function at that
    address, so the rest of the program stays as it was.
    """
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd

    started = time.time()
    e = _entry(a["binary"])
    p = e["program"]
    if a.get("full"):
        _analyze_all(p)
        saved = _save(p, "ghlab analyze (full)", e)
        return {
            "binary": a["binary"],
            "mode": "full",
            "functions": int(p.getFunctionManager().getFunctionCount()),
            "saved_via": saved,
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    targets = _as_list(a.get("addr"))
    if not targets:
        raise ValueError(
            "analyze needs --addr ADDR (repeatable) or --full "
            "(a background full analysis is `ghlab job analyze <binary> -a full=yes`)"
        )
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
    saved = _save(p, "ghlab analyze", e)
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
    limit = _num(a, "limit", 100)
    skip = _num(a, "offset", 0)
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
    base = _project_dir or Path(config.default_project_dir())
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


def _cache_bucket(md5: Any) -> Path:
    """One directory per program, so a write can drop exactly one program's cache.

    Keys already carry the md5; the flat layout worked until a mutation had to
    invalidate it -- deleting by bucket is one rmtree, deleting by prefix is a
    glob over every program in the project.
    """
    return _cache_dir() / str(md5)


def _cache_read(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _cache_write(path: Path, code: str) -> None:
    # Empty output means the decompiler gave up mid-run; caching that would turn
    # one failure into a permanent one.
    if not code.strip():
        return
    with contextlib.suppress(OSError):
        config.atomic_write_text(path, code)


def _cache_purge(e: dict[str, Any]) -> int:
    """Drop every decompile cached for this program: a write changed what it emits."""
    bucket = _cache_bucket(e["program"].getExecutableMD5())
    if not bucket.is_dir():
        return 0
    removed = len(list(bucket.glob("*.c")))
    shutil.rmtree(bucket, ignore_errors=True)
    return removed


def cmd_decompile(a: dict[str, Any]) -> dict[str, Any]:
    """Decompile a single target, an explicit list, or every function matching `match`.

    `grep` is applied server-side: only matching source lines come back, which keeps
    agent context small on large batches.
    """
    e = _entry(a["binary"])
    program = e["program"]
    fm = program.getFunctionManager()
    timeout = _num(a, "timeout", 60)
    max_lines = _num(a, "max_lines", 0)
    grep = re.compile(a["grep"], re.I) if a.get("grep") else None
    include_code = bool(a.get("include_code", grep is None))
    limit = _num(a, "limit", 25)

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

    want_sig = bool(a.get("sig"))
    results = []
    for t in targets[:limit]:
        try:
            fn = t if not isinstance(t, (str, int)) else _function(e, str(t))
            if fn is None:
                hint = _function_suggestions(program, str(t))
                results.append({"target": str(t), "error": f"function not found{hint}"})
                continue
            if want_sig:
                # no decompiler: the prototype is already in the database, so a
                # 476-function sweep costs milliseconds and a few hundred tokens.
                item = brief(fn)
                item["signature"] = _prototype(fn)
                results.append(item)
                continue
            key = _decomp_cache_key(e, fn)
            cache_path = _cache_bucket(program.getExecutableMD5()) / (key + ".c")
            # `refresh` skips the *read*, not the write: a refreshed call that did not
            # store its result left the next call decompiling again, so "refresh once,
            # then read" never warmed anything.
            code = None if a.get("refresh") else _cache_read(cache_path)
            cached = code is not None
            if code is None:
                res = e["decomp"].decompileFunction(fn, timeout, MONITOR)
                if not res.decompileCompleted():
                    results.append({"target": str(t), "error": _decomp_failure(res)})
                    continue
                code = str(res.getDecompiledFunction().getC()).replace("\r\n", "\n")
                with contextlib.suppress(OSError):
                    _cache_write(cache_path, code)
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
                # `matched` already means "how many functions matched" elsewhere;
                # a list of source lines under that name reads wrong (it cost me a
                # broken smoke test to notice).
                item["hits"] = hits[:20]
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
    return {
        "binary": a["binary"],
        "decompiled": sum(1 for r in results if "error" not in r),
        "results": results,
    }


def _string_refs(program, address, max_refs: int = 8) -> list[dict[str, Any]]:
    """Functions that reference a string, most useful first (biggest first)."""
    fm = program.getFunctionManager()
    rm = program.getReferenceManager()
    rows: dict[str, dict[str, Any]] = {}
    try:
        refs = rm.getReferencesTo(address)
    except Exception:  # noqa: BLE001 - jpype call, can raise anything
        return []
    for ref in refs:
        try:
            fn = fm.getFunctionContaining(ref.getFromAddress())
        except Exception:  # noqa: BLE001
            continue
        if fn is None or fn.isExternal() or fn.isThunk():
            continue
        key = str(fn.getEntryPoint())
        if key in rows:
            continue
        rows[key] = {
            "function": str(fn.getName()),
            "addr": key,
            "size": int(fn.getBody().getNumAddresses()),
            "from": str(ref.getFromAddress()),
        }
        if len(rows) >= max_refs:
            break
    return sorted(rows.values(), key=lambda r: -r["size"])


def cmd_imports(a: dict[str, Any]) -> dict[str, Any]:
    """List imports with caller counts, filtered by name and/or risk group.

    `digest` shows risk groups as counts; this is the drill-down: how many distinct
    functions call this API, and which group it belongs to.
    """
    started = time.time()
    p = _entry(a["binary"])["program"]
    pattern = a.get("match") or a.get("query")
    rx = re.compile(str(pattern), re.I) if pattern else None
    group = a.get("group")
    if group and group not in RISK:
        raise ValueError(f"unknown group {group!r}; pick one of {', '.join(sorted(RISK))}")
    limit = _num(a, "limit", 0)
    fm = p.getFunctionManager()
    rm = p.getReferenceManager()
    rows: list[dict[str, Any]] = []
    for imp in _imports(p):
        name = imp["name"]
        kind = _classify_import(name)
        if rx is not None and rx.search(name) is None and rx.search(imp["lib"]) is None:
            continue
        if group and kind != group:
            continue
        callers: dict[str, dict[str, Any]] = {}
        try:
            # external symbols live in their own space: the address string is
            # "EXTERNAL:00000004", so let the factory parse it (not _hex_addr).
            addr = p.getAddressFactory().getAddress(imp["addr"])
        except Exception:  # noqa: BLE001 - jpype call, can raise anything
            addr = None
        if addr is not None:
            try:
                for ref in rm.getReferencesTo(addr):
                    fn = fm.getFunctionContaining(ref.getFromAddress())
                    if fn is None or fn.isExternal() or fn.isThunk():
                        continue
                    key = str(fn.getEntryPoint())
                    callers[key] = {
                        "function": str(fn.getName()),
                        "size": int(fn.getBody().getNumAddresses()),
                    }
            except Exception:  # noqa: BLE001
                pass
        top = sorted(callers.values(), key=lambda c: -c["size"])[:3]
        rows.append(
            {
                "name": name,
                "lib": imp["lib"],
                "risk": kind,
                "callers": len(callers),
                "top": top,
            }
        )
    rows.sort(key=lambda r: (-r["callers"], r["name"]))
    if limit:
        rows = rows[:limit]
    return {
        "binary": a["binary"],
        "total": len(rows),
        "with_callers": sum(1 for r in rows if r["callers"]),
        "groups": dict(Counter(r["risk"] for r in rows if r["risk"]).most_common()),
        "imports": rows,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


_STACK_REF = re.compile(r"\[(?:RSP|RBP|ESP|EBP)[\s,+\-]")
# The last operand of an instruction, when it is an immediate: `MOV [RAX+0x8],0x4`.
_LAST_IMM = re.compile(r",\s*(-?(?:0x)?[0-9a-f]+)\s*$", re.I)


def _demangle(program, name: str) -> str | None:
    """Readable form of a mangled C++ name, or None when it is not mangled.

    Ghidra already ships both demanglers (Itanium and MSVC), so this adds no
    dependency; the entry point moved between versions, so every signature is
    tried and a miss stays quiet rather than failing the whole listing.
    """
    if not name or not name.startswith(("_Z", "?")):
        return None
    try:
        from ghidra.app.util.demangler import DemanglerUtil
    except Exception:  # noqa: BLE001 - unit tests have no Ghidra on the path
        return None
    attempts = (
        lambda: DemanglerUtil.demangle(program, name),
        lambda: DemanglerUtil.demangle(name),
    )
    for attempt in attempts:
        try:
            obj = attempt()
        except Exception:  # noqa: BLE001
            continue
        if obj is None:
            continue
        for getter in ("getSignature", "getNamespaceString"):
            read = getattr(obj, getter, None)
            if read is None:
                continue
            try:
                text = str(read())
            except Exception:  # noqa: BLE001
                continue
            if text and text != "null":
                return text
    return None


def cmd_exports(a: dict[str, Any]) -> dict[str, Any]:
    """Entries a binary makes callable from outside (PE exports, ELF .dynsym).

    `imports` answers "what does this call"; this is the mirror question, plus the
    demangled name, which is the first thing a reader wants from a C++ DLL.
    """
    started = time.time()
    binary = a["binary"]
    p = _entry(binary)["program"]
    pattern = a.get("match") or a.get("query")
    rx = re.compile(str(pattern), re.I) if pattern else None
    limit = _num(a, "limit", 0)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for sym in p.getSymbolTable().getAllSymbols(True):
        try:
            if not sym.isExternalEntryPoint():
                continue
            name = str(sym.getName())
        except Exception:  # noqa: BLE001 - jpype call, can raise anything
            continue
        if not name or name in seen:
            continue
        demangled = _demangle(p, name)
        readable = demangled or name
        if rx is not None and rx.search(f"{name} {readable}") is None:
            continue
        seen.add(name)
        rows.append({"name": name, "demangled": demangled, "addr": str(sym.getAddress())})
    rows.sort(key=lambda r: (r["demangled"] or r["name"]).lower())
    total = len(rows)
    if limit:
        rows = rows[:limit]
    return {
        "binary": binary,
        "total": total,
        "demangled": sum(1 for r in rows if r["demangled"]),
        "truncated": bool(limit) and total > len(rows),
        "exports": rows,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def _split_operands(text: str) -> list[str]:
    """Split an instruction rendering on the commas that are not inside brackets."""
    parts: list[str] = []
    depth = 0
    cur = ""
    for ch in text:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
            continue
        cur += ch
    parts.append(cur)
    return parts


def _imm_of(text: str) -> int | None:
    """The integer value of the last operand, or None when it is not an immediate."""
    found = _LAST_IMM.search(text)
    if found is None:
        return None
    try:
        return int(found.group(1), 0)
    except ValueError:
        return None


def _imm_spec(text: str) -> Callable[[int], bool]:
    """A predicate for `--imm 4`, `--imm 0x4` or a range like `--imm 0..5`."""
    raw = str(text).strip()
    if ".." in raw:
        low_text, _, high_text = raw.partition("..")
        low = int(low_text, 0) if low_text else -(2**63)
        high = int(high_text, 0) if high_text else 2**63 - 1
        if low > high:
            raise ValueError(f"bad imm range {raw!r}; the low end is above the high end")
        return lambda value: low <= value <= high
    wanted = int(raw, 0)
    return lambda value: value == wanted


_BRACKETS = re.compile(r"\[([^\]]*)\]")
_DISP_TERM = re.compile(r"([+-])\s*(0x[0-9a-f]+|[0-9]+)", re.I)


def _displacements(text: str) -> set[int]:
    """Signed displacements inside memory operands: `[RAX + -0x40]` is -64, not 64.

    The old code matched `offset` with a signed-hex regex, which happily
    matched the tail of `[RCX + R13*0x1 + -0x40]` and reported 12 phantom
    writers of `+0x40`. Numbers beat patterns here.
    """
    out: set[int] = set()
    for body in _BRACKETS.findall(text):
        for sign, value in _DISP_TERM.findall(body):
            number = int(value, 0)
            out.add(-number if sign == "-" else number)
    return out


_NO_DEST_OPS = frozenset({"CALL", "JMP", "PUSH", "CMP", "TEST", "BT", "LEA"})


def _is_dest_operand(text: str, offset: int) -> bool:
    """True when the memory operand carrying `offset` is the one being written.

    `CALL qword ptr [RAX+0x40]` reads, it does not store; `LEA` computes an
    address without touching memory. Treating the first operand of every
    instruction as a destination turned virtual calls into false "writers of
    +0x40" and cost a full sweep to notice.
    """
    mnemonic = text.split(None, 1)[0].upper() if text.strip() else ""
    if mnemonic in _NO_DEST_OPS:
        return False
    return offset in _displacements(_split_operands(text)[0])


def _insn_sites(
    program: Any,
    offset: int,
    start: Any | None = None,
    end: Any | None = None,
    limit: int = 60,
    op: re.Pattern[str] | None = None,
    skip_stack: bool = True,
    imm: Callable[[int], bool] | None = None,
    dest_only: bool = False,
) -> tuple[list[dict[str, Any]], int]:
    """Instructions whose rendering touches a given displacement, with owner function."""
    listing = program.getListing()
    fm = program.getFunctionManager()
    out: list[dict[str, Any]] = []
    scanned = 0
    for block in program.getMemory().getBlocks():
        if not block.isExecute():
            continue
        lo, hi = block.getStart(), block.getEnd()
        if start is not None and hi.compareTo(start) < 0:
            continue
        if end is not None and lo.compareTo(end) > 0:
            continue
        if start is not None and lo.compareTo(start) < 0:
            lo = start
        if end is not None and hi.compareTo(end) > 0:
            hi = end
        it = listing.getInstructions(lo, True)
        while it.hasNext():
            insn = it.next()
            if end is not None and insn.getAddress().compareTo(end) > 0:
                break
            scanned += 1
            text = str(insn)
            if op is not None and not op.search(text.split(" ", 1)[0]):
                continue
            if "[" not in text:  # no memory operand, so no displacement to match
                continue
            if skip_stack and _STACK_REF.search(text):
                continue
            if offset not in _displacements(text):
                continue
            if dest_only and not _is_dest_operand(text, offset):
                continue
            if imm is not None:
                value = _imm_of(text)
                if value is None or not imm(value):
                    continue
            fn = fm.getFunctionContaining(insn.getAddress())
            out.append(
                {
                    "addr": str(insn.getAddress()),
                    "function": fn.getName() if fn else "",
                    "text": text,
                }
            )
            if len(out) >= limit:
                return out, scanned
    return out, scanned


def _sequence_hits(
    events: list[tuple[int, frozenset[int]]],
    order: list[int],
    window: int,
) -> list[dict[str, int]]:
    """Instruction windows where `order` appears in that order within `window`.

    A struct copy looks like `[obj+0x8]`, `[obj+0x10]`, `[obj+0x18]` in ascending
    order inside a handful of instructions.  Counting per-offset hits cannot see
    that shape; the order and the distance are the evidence.
    """
    hits: list[dict[str, int]] = []
    total = len(events)
    i = 0
    while i < total:
        index, offsets = events[i]
        if order[0] not in offsets:
            i += 1
            continue
        need = 1
        j = i + 1
        last = i
        while j < total and need < len(order):
            if events[j][0] - index > window:
                break
            if order[need] in events[j][1]:
                need += 1
                last = j
            j += 1
        if need == len(order):
            hits.append({"start": index, "end": events[last][0]})
            i = last + 1
        else:
            i += 1
    return hits


def _scan_sequence(
    binary: str,
    p: Any,
    offsets: list[int],
    window: int,
    start: Any | None,
    end: Any | None,
    limit: int,
    skip_stack: bool,
    began: float,
) -> dict[str, Any]:
    """One pass, then ask for the ordered pattern -- not k separate sweeps."""
    wanted = set(offsets)
    listing = p.getListing()
    fm = p.getFunctionManager()
    lo = start or p.getMinAddress()
    hi = end
    events: list[tuple[int, frozenset[int]]] = []
    texts: list[str] = []
    addrs: list[str] = []
    owners: list[str] = []
    scanned = 0
    it = listing.getInstructions(lo, True)
    index = -1
    while it.hasNext():
        insn = it.next()
        if hi is not None and insn.getAddress().compareTo(hi) > 0:
            break
        scanned += 1
        index += 1
        text = str(insn)
        if "[" not in text:  # no memory operand
            continue
        if skip_stack and _STACK_REF.search(text):
            continue
        found = _displacements(text) & wanted
        if not found:
            continue
        events.append((index, frozenset(found)))
        texts.append(text)
        addrs.append(str(insn.getAddress()))
        fn = fm.getFunctionContaining(insn.getAddress())
        owners.append(fn.getName() if fn else "")
    hits = _sequence_hits(events, offsets, window)
    sites = []
    for hit in hits:
        first = next(k for k, event in enumerate(events) if event[0] == hit["start"])
        last = next(k for k, event in enumerate(events) if event[0] == hit["end"])
        sites.append(
            {
                "addr": addrs[first],
                "function": owners[first],
                "text": texts[first],
                "span": f"{hit['start']}..{hit['end']}",
                "sequence": texts[first : last + 1],
            }
        )
        if len(sites) >= limit:
            break
    return {
        "binary": binary,
        "offset": ",".join(f"{value:#x}" for value in offsets),
        "pattern": "seq " + " -> ".join(f"{value:#x}" for value in offsets),
        "skip_stack": skip_stack,
        "imm": None,
        "writes_only": False,
        "window": window,
        "scanned": scanned,
        "sites": sites,
        "truncated": len(hits) > len(sites),
        "matched_functions": [
            {"function": name, "offsets": sorted({f"{value:#x}" for value in offsets})}
            for name in sorted({site["function"] for site in sites if site["function"]})
        ],
        "elapsed_ms": int((time.monotonic() - began) * 1000),
    }


def _scan_several(
    binary: str,
    p: Any,
    offsets: list[int],
    start: Any | None,
    end: Any | None,
    limit: int,
    op: re.Pattern[str] | None,
    skip_stack: bool,
    imm: Callable[[int], bool] | None,
    writes: bool,
    began: float,
) -> dict[str, Any]:
    """Functions that touch *every* offset, not just one.

    Same-offset-different-struct noise is the reason this exists: `+0x178` is a
    pointer in one class and a dword in another, and `+0x40` is everywhere. Ask
    for three fields at once and the wrong structs drop out by themselves.
    """
    per_offset: dict[int, list[dict[str, Any]]] = {}
    scanned = 0
    for offset in offsets:
        sites, done = _insn_sites(
            p, offset, start, end, max(limit, 5000), op, skip_stack, imm, writes
        )
        scanned += done
        per_offset[offset] = sites
    owners = None
    for sites in per_offset.values():
        names = {site["function"] for site in sites}
        owners = names if owners is None else owners & names
    keep = owners or set()
    out: list[dict[str, Any]] = []
    for offset in offsets:
        for site in per_offset[offset]:
            if site["function"] in keep:
                out.append({**site, "offset": f"{offset:#x}"})
    out.sort(key=lambda site: (site["function"], int(site["addr"], 16)))
    summary = [
        {
            "function": name,
            "offsets": sorted({site["offset"] for site in out if site["function"] == name}),
        }
        for name in sorted(keep)
    ]
    return {
        "binary": binary,
        "offset": ",".join(f"{value:#x}" for value in offsets),
        "pattern": "",
        "skip_stack": skip_stack,
        "imm": None,
        "writes_only": writes,
        "scanned": scanned,
        "sites": out[:limit],
        "truncated": len(out) > limit,
        "matched_functions": summary,
        "elapsed_ms": int((time.monotonic() - began) * 1000),
    }


def _is_param(high: Any) -> bool:
    """HighParam is a class, not a flag: `isParameter()` does not exist on it."""
    if high is None:
        return False
    return "HighParam" in str(high.getClass().getSimpleName())


def _varnode_constant(var: Any) -> int | None:
    """Signed 64-bit value of a constant varnode, or None."""
    if var is None or not var.isConstant():
        return None
    raw = int(var.getOffset())
    return raw - (1 << 64) if raw >= 1 << 63 else raw


def _pointer_base(pointer: Any, depth: int = 8) -> tuple[Any, int]:
    """Peel `base + constant` chains off an address expression.

    At high p-code the displacement is not a separate operand: it is folded into
    `INT_ADD(base, const)` / `PTRSUB(base, const)` nodes. Walking down to the
    varnode that carries the parameter is what makes the offset attributable.
    """
    from ghidra.program.model.pcode import PcodeOp  # the JVM only exists after boot()

    add = int(PcodeOp.INT_ADD)
    ptrsub = int(PcodeOp.PTRSUB)
    ptradd = int(PcodeOp.PTRADD)
    passthrough = {
        int(value)
        for value in (
            getattr(PcodeOp, "COPY", None),
            getattr(PcodeOp, "CAST", None),
            getattr(PcodeOp, "INT_ZEXT", None),
            getattr(PcodeOp, "INT_SEXT", None),
        )
        if value is not None
    }
    displacement = 0
    current = pointer
    for _ in range(depth):
        if current is None:
            return None, displacement
        definition = current.getDef()
        if definition is None:
            return current, displacement
        kinds = int(definition.getOpcode())
        ins = list(definition.getInputs())
        if kinds == add and len(ins) >= 2:
            left, right = _varnode_constant(ins[0]), _varnode_constant(ins[1])
            if right is None and left is not None:
                displacement += left
                current = ins[1]
                continue
            if right is not None:
                displacement += right
                current = ins[0]
                continue
            return current, displacement
        if kinds in (ptrsub, ptradd) and len(ins) >= 2:
            value = _varnode_constant(ins[1])
            if value is not None and kinds == ptrsub:
                displacement += value
            elif value is not None and kinds == ptradd:
                # PTRADD(base, index, element_size): only the element size is fixed
                size = _varnode_constant(ins[2]) if len(ins) > 2 else None
                if size is None:
                    return current, displacement
                displacement += size
            current = ins[0]
            continue
        if kinds in passthrough and ins:
            current = ins[0]
            continue
        return current, displacement
    return current, displacement


def _param_accesses(hf: Any) -> list[dict[str, Any]]:
    """Every `[base+disp]` access in a decompiled function, with its base variable.

    The same offset means different things on different objects -- `ctx+0x178` is a
    mode int while `doc+0x178` is a pointer -- so an offset alone is not a fact.
    """
    from ghidra.program.model.pcode import PcodeOp  # the JVM only exists after boot()

    load = int(PcodeOp.LOAD)
    store = int(PcodeOp.STORE)
    rows: list[dict[str, Any]] = []
    it = hf.getPcodeOps()
    while it.hasNext():
        op = it.next()
        kinds = int(op.getOpcode())
        if kinds not in (load, store):
            continue
        ins = list(op.getInputs())
        pointer = ins[1] if len(ins) >= 2 else None
        base, displacement = _pointer_base(pointer)
        if base is None:
            continue
        name = str(base.getHigh().getName()) if base.getHigh() is not None else "?"
        if kinds == load:
            width = op.getOutput()
        else:
            width = ins[2] if len(ins) >= 3 else None
        rows.append(
            {
                "offset": f"{displacement:#x}" if displacement >= 0 else f"-{abs(displacement):#x}",
                "base": name,
                "kind": "param" if _is_param(base.getHigh()) else "local",
                "op": "load" if kinds == load else "store",
                "size": int(width.getSize()) if width is not None else 0,
            }
        )
    return rows


def cmd_offsets(a: dict[str, Any]) -> dict[str, Any]:
    """Which parameter or local does each struct offset belong to?"""
    binary = a["binary"]
    e = _entry(binary)
    target = str(a["target"])
    fn = _function(e, target)
    if fn is None:
        hint = _function_suggestions(e["program"], target)
        raise KeyError(f"function {target!r} not found{hint}")
    began = time.monotonic()
    res = e["decomp"].decompileFunction(fn, _num(a, "timeout", 60), MONITOR)
    if not res.decompileCompleted():
        return {
            "binary": binary,
            "function": str(fn.getName()),
            "error": str(res.getErrorMessage()),
            "accesses": [],
            "elapsed_ms": int((time.monotonic() - began) * 1000),
        }
    hf = res.getHighFunction()
    rows = _param_accesses(hf)
    wanted = str(a.get("offset", "")).strip()
    if wanted:
        value = int(wanted, 0)
        rows = [row for row in rows if row["offset"] in (f"{value:#x}", f"-{value:#x}")]
    debug: dict[str, Any] = {}
    if a.get("debug"):
        hist: dict[int, int] = {}
        count = 0
        it = hf.getPcodeOps()
        while it.hasNext():
            count += 1
            code = int(it.next().getOpcode())
            hist[code] = hist.get(code, 0) + 1
        from ghidra.program.model.pcode import PcodeOp  # the JVM only exists after boot()

        sample = []
        it2 = hf.getPcodeOps()
        while it2.hasNext() and len(sample) < 4:
            op2 = it2.next()
            if int(op2.getOpcode()) not in (int(PcodeOp.LOAD), int(PcodeOp.STORE)):
                continue
            parts = []
            for var in list(op2.getInputs()):
                base = var.getHigh()
                parts.append(
                    {
                        "const": bool(var.isConstant()),
                        "offset": int(var.getOffset()),
                        "name": str(base.getName()) if base is not None else "?",
                        "param": _is_param(base),
                        "type": str(base.getClass().getSimpleName()) if base is not None else "?",
                    }
                )
            sample.append({"op": int(op2.getOpcode()), "inputs": parts})
        debug = {
            "ops": count,
            "opcodes": hist,
            "high_ok": hf is not None,
            "load": int(PcodeOp.LOAD),
            "store": int(PcodeOp.STORE),
            "sample": sample,
        }
    counts: dict[tuple[str, str, str], int] = {}
    for row in rows:
        key = (row["base"], row["kind"], row["offset"])
        counts[key] = counts.get(key, 0) + 1
    limit = _num(a, "limit", 120)
    accesses = [
        {"base": base, "kind": kind, "offset": offset, "count": count}
        for (base, kind, offset), count in sorted(
            counts.items(),
            key=lambda item: (item[0][1] != "param", item[0][1], item[0][0], item[0][2]),
        )
    ]
    return {
        "binary": binary,
        "function": str(fn.getName()),
        "prototype": _prototype(fn),
        "error": None,
        "accesses": accesses[:limit],
        "truncated": len(accesses) > limit,
        "sites": rows[:limit],
        "debug": debug or None,
        "elapsed_ms": int((time.monotonic() - began) * 1000),
    }


_SIZED_TYPES = {1: "byte", 2: "ushort", 4: "int", 8: "longlong"}
_GHIDRA_TYPES = {
    "byte": "ByteDataType",
    "ushort": "WordDataType",
    "int": "IntegerDataType",
    "uint": "DWordDataType",
    "longlong": "LongLongDataType",
    "ulonglong": "QWordDataType",
    "float": "FloatDataType",
    "double": "DoubleDataType",
}


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _parse_overrides(text: str | None) -> dict[int, str]:
    """`0x18=float,0x20=void *` -> {0x18: 'float', 0x20: 'void *'}."""
    out: dict[int, str] = {}
    for item in str(text or "").split(","):
        if not item.strip():
            continue
        if "=" not in item:
            raise ValueError(f"bad override {item!r}; expected OFFSET=TYPE")
        key, _, value = item.partition("=")
        try:
            out[int(key.strip(), 0)] = value.strip() or "int"
        except ValueError:
            raise ValueError(f"bad override {item!r}; expected OFFSET=TYPE") from None
    return out


def _infer_struct(
    rows: list[dict[str, Any]],
    name: str,
    base: str,
    overrides: dict[int, str] | None = None,
) -> dict[str, Any]:
    """Turn one base variable's field accesses into a C struct definition.

    The vote is by access width, because width is the one thing p-code carries:
    a field always loaded as 4 bytes is an `int` until a human says otherwise
    (`overrides` wins). Gaps are materialised as padding so every offset in the
    decl is the offset in the code -- a struct that silently pack-tightens would
    describe a layout the program does not have.
    """
    overrides = overrides or {}
    buckets: dict[int, dict[str, Any]] = {}
    for row in rows:
        if row.get("base") != base:
            continue
        try:
            offset = int(str(row["offset"]), 0)
        except ValueError:
            continue
        if offset < 0:  # `[base - 0x8]` is a container_of trick, not a field
            continue
        bucket = buckets.setdefault(
            offset, {"offset": offset, "widths": Counter(), "loads": 0, "stores": 0}
        )
        width = int(row.get("size") or 0) or 4
        bucket["widths"][width] += 1
        bucket["loads" if row.get("op") == "load" else "stores"] += 1
    if not buckets:
        return {
            "name": name,
            "base": base,
            "size": 0,
            "fields": [],
            "decl": f"// no field access on {base!r} in this function",
            "confidence": "none",
        }
    fields: list[dict[str, Any]] = []
    for offset in sorted(buckets):
        bucket = buckets[offset]
        width = bucket["widths"].most_common(1)[0][0]
        kind = overrides.get(offset, _SIZED_TYPES.get(width, f"byte[{width}]"))
        fields.append(
            {
                "offset": offset,
                "name": f"field_{offset:#x}",
                "size": width,
                "type": kind,
                "loads": bucket["loads"],
                "stores": bucket["stores"],
                "widths": dict(sorted(bucket["widths"].items())),
            }
        )
    total = _align(max(f["offset"] + f["size"] for f in fields), 8)
    lines = [f"struct {name} {{"]
    cursor = 0
    for field in fields:
        if field["offset"] > cursor:
            lines.append(f"    byte gap_{cursor:#x}[{field['offset'] - cursor:#x}];")
        suffix = f"  // {field['loads']} load(s), {field['stores']} store(s)"
        lines.append(f"    {field['type']:<12} {field['name']};{suffix}")
        cursor = field["offset"] + field["size"]
    if total > cursor:
        lines.append(f"    byte gap_{cursor:#x}[{total - cursor:#x}];")
    lines.append("};")
    return {
        "name": name,
        "base": base,
        "size": total,
        "fields": fields,
        "decl": "\n".join(lines),
        "confidence": "measured" if len(fields) > 1 else "single-field",
    }


def _install_struct(program: Any, spec: dict[str, Any]) -> str:
    """Put the inferred type into the program so `set-type` can name it.

    Only the type is installed, never applied to a parameter: rewriting a
    signature behind the user's back would need `ApplyFunctionSignatureCmd` and a
    prototype nobody asked for. `ghlab set-type FUNC "int f(Foo *p)"` does that
    in one visible step.
    """
    import ghidra.program.model.data as dtypes  # the JVM only exists after boot()
    from ghidra.program.model.data import DataTypeConflictHandler

    manager = program.getDataTypeManager()
    struct = dtypes.StructureDataType(spec["name"], spec["size"], manager)
    for field in spec["fields"]:
        wanted = str(field["type"])
        if wanted.replace(" ", "").endswith("*"):
            data_type = dtypes.PointerDataType()
        elif wanted in _GHIDRA_TYPES:
            data_type = getattr(dtypes, _GHIDRA_TYPES[wanted])()
        else:
            raise ValueError(
                f"cannot create field {field['name']} of type {wanted!r}; "
                f"known: {', '.join(sorted(_GHIDRA_TYPES))}, or NAME * for a pointer"
            )
        # jpype overloads are matched on *argument order*: StructureDataType.add takes
        # (DataType, int offset, String name, String comment), and (int, DataType, ...)
        # matched nothing -- found on the first real `struct --create` run
        struct.add(
            data_type,
            int(field["offset"]),
            str(field["name"]),
            f"{field['loads']} load(s), {field['stores']} store(s)",
        )
    manager.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)
    return str(struct.getPathName())


@contextlib.contextmanager
def _edit(program: Any, reason: str = "ghlab") -> Any:
    """One transaction, so a failure half-way cannot leave the program dirty."""
    tx = program.startTransaction(reason)
    try:
        yield program
    finally:
        program.endTransaction(tx, True)


def _decomp_failure(res: Any) -> str:
    """Why the decompiler refused, in words a caller can act on.

    `DecompileResults.getErrorMessage()` is empty when the monitor was already
    cancelled, so the reply used to be the useless sentence "decompiler said: ".
    """
    why = str(res.getErrorMessage() or "").strip()
    return why or (
        "it returned nothing and gave no reason "
        "(a cancelled job can leave the monitor flagged; retry)"
    )


def cmd_struct(a: dict[str, Any]) -> dict[str, Any]:
    """What struct is behind `[param+0x18]`?  Infer it from the field accesses."""
    began = time.monotonic()
    binary = a["binary"]
    e = _entry(binary)
    p = e["program"]
    target = str(a["target"])
    fn = _function(e, target)
    if fn is None:
        raise KeyError(f"function {target!r} not found{_function_suggestions(p, target)}")
    res = e["decomp"].decompileFunction(fn, _num(a, "timeout", 60), MONITOR)
    if not res.decompileCompleted():
        raise ValueError(f"decompiler said: {_decomp_failure(res)}")
    rows = _param_accesses(res.getHighFunction())
    # A parameter is what a struct pointer usually is; only fall back to locals
    # when this function keeps its object on the stack.
    params = [row for row in rows if row["kind"] == "param"]
    rows = params or rows
    bases: Counter = Counter(row["base"] for row in rows)
    if not bases:
        raise ValueError(f"{fn.getName()} touches no memory through a variable")
    base = a.get("base") or bases.most_common(1)[0][0]
    if base not in bases:
        raise ValueError(f"{base!r} is not a base variable here; saw {', '.join(sorted(bases))}")
    overrides = _parse_overrides(a.get("types"))
    for offset in str(a.get("pointer") or "").replace(",", " ").split():
        overrides[int(offset, 0)] = "void *"
    want = a.get("offset")
    if want not in (None, ""):
        only = int(str(want), 0)
        rows = [row for row in rows if row["base"] == base and int(row["offset"], 0) == only]
    name = a.get("name") or f"{fn.getName()}_{re.sub(r'W', '', base)}_t".replace("__", "_")
    spec = _infer_struct(rows, name, base, overrides)
    out: dict[str, Any] = {
        "binary": binary,
        "function": fn.getName(),
        "prototype": str(fn.getPrototypeString(False, False)),
        "bases": dict(bases.most_common()),
        "accesses": len(rows),
        **spec,
        "elapsed_ms": int(1000 * (time.monotonic() - began)),
    }
    if spec["fields"] and a.get("create") in (True, "yes", "true", "1"):
        with _edit(p):
            out["created"] = _install_struct(p, spec)
        # save *after* the transaction closes: Ghidra refuses with
        # "Unable to lock due to active transaction", which is what the first real
        # `struct --create` run got back from all three save paths
        out["saved_via"] = _save(p, "ghlab struct", e)
    return out


def _parse_hex_pattern(text: str) -> tuple[bytes, bytes]:
    """'48 8B ?? 05' -> (values, masks); `??` becomes a zero mask byte."""
    compact = re.sub(r"[\s,]+", "", str(text))
    if not compact:
        raise ValueError("hex pattern is empty")
    if len(compact) % 2:
        raise ValueError(f"{text!r} has an odd number of hex digits")
    values, masks = bytearray(), bytearray()
    for i in range(0, len(compact), 2):
        pair = compact[i : i + 2]
        if pair == "??":
            values.append(0)
            masks.append(0)
        elif re.fullmatch(r"[0-9A-Fa-f]{2}", pair):
            values.append(int(pair, 16))
            masks.append(0xFF)
        elif "?" in pair:
            raise ValueError(f"only whole-byte wildcards (??) are supported, saw {pair!r}")
        else:
            raise ValueError(f"{pair!r} is not a hex byte")
    if not any(masks):
        raise ValueError("hex pattern has no fixed byte; `bytes` reads a region instead")
    return bytes(values), bytes(masks)


def _scan_bounds(p, a: dict[str, Any]):
    """[start, end] from `range` or `func`; (None, None) means the whole program."""
    start = end = None
    rng = a.get("range")
    if rng:
        lo_text, _, hi_text = str(rng).partition("-")
        lo = _hex_addr(lo_text)
        hi = _hex_addr(hi_text) if hi_text else None
        if lo is None or hi is None:
            raise ValueError(f"bad range {rng!r}; expected 0xSTART-0xEND")
        space = p.getAddressFactory().getDefaultAddressSpace()
        start, end = space.getAddress(lo), space.getAddress(hi)
    if a.get("func"):
        fn = _function(_entry(str(a["binary"])), str(a["func"]))
        if fn is None:
            # A miss used to surface as "'NoneType' object has no attribute
            # 'getBody'", which reads like a bug in scan rather than in the name.
            hint = _function_suggestions(p, str(a["func"]), limit=3)
            raise KeyError(f"no function at or containing {a['func']!r}" + hint)
        start, end = fn.getBody().getMinAddress(), fn.getBody().getMaxAddress()
    return start, end


def _byte_hit(mem, p, addr, values: bytes, masks: bytes) -> dict[str, Any]:
    data, _ = _read_region(mem, addr, len(values))
    block = mem.getBlock(addr)
    fn = p.getFunctionManager().getFunctionContaining(addr)
    return {
        "addr": str(addr),
        "block": str(block.getName()) if block is not None else None,
        "function": str(fn.getName()) if fn is not None else None,
        "bytes": data.hex(),
        "pattern": "".join(f"{v:02x}" if m else "??" for v, m in zip(values, masks, strict=True)),
    }


def _scan_bytes(binary, p, spec: str, start, end, limit: int, began: float) -> dict[str, Any]:
    """Where does this byte pattern occur?  One masked search per hit, not per byte."""
    values, masks = _parse_hex_pattern(spec)
    mem = p.getMemory()
    needles, mask = _byte_array(values), _byte_array(masks)
    matches: list[dict[str, Any]] = []
    blocks_scanned = 0
    for block in mem.getBlocks():
        if not block.isInitialized():
            continue
        lo, hi = block.getStart(), block.getEnd()
        if start is not None and hi.compareTo(start) < 0:
            continue
        if end is not None and lo.compareTo(end) > 0:
            continue
        cursor = lo if start is None or lo.compareTo(start) >= 0 else start
        stop = hi if end is None or hi.compareTo(end) <= 0 else end
        if cursor.compareTo(stop) > 0:
            continue
        blocks_scanned += 1
        while True:
            found = mem.findBytes(cursor, needles, mask, True, MONITOR)
            if found is None or found.compareTo(stop) > 0:
                break
            matches.append(_byte_hit(mem, p, found, values, masks))
            if len(matches) >= limit:
                return {
                    "binary": str(binary),
                    "hex": str(spec),
                    "blocks_scanned": blocks_scanned,
                    "matches": matches,
                    "truncated": True,
                    "elapsed_ms": int((time.monotonic() - began) * 1000),
                }
            cursor = found.add(1)
    return {
        "binary": str(binary),
        "hex": str(spec),
        "blocks_scanned": blocks_scanned,
        "matches": matches,
        "truncated": False,
        "elapsed_ms": int((time.monotonic() - began) * 1000),
    }


def cmd_scan(a: dict[str, Any]) -> dict[str, Any]:
    """Find what touches a struct field, or where a byte pattern occurs.

    Two questions share one sweep: "who reads/writes +0x54" needs no type
    information (a displacement search over the code), and "where does this
    signature occur" is a masked byte search (`hex` with `??` wildcards).
    """
    binary = a["binary"]
    p = _entry(binary)["program"]
    limit = _num(a, "limit", 60)
    if limit <= 0:
        raise ValueError("limit must be positive")
    start, end = _scan_bounds(p, a)
    began = time.monotonic()
    if a.get("hex") not in (None, ""):
        return _scan_bytes(binary, p, str(a["hex"]), start, end, limit, began)
    if a.get("offset") in (None, ""):
        raise ValueError("scan needs offset=<n> (field displacement) or hex=<pattern>")
    offsets = [int(part, 0) for part in str(a["offset"]).split(",") if part.strip()]
    if not offsets:
        raise ValueError("offset must be >= 0")
    if any(value < 0 for value in offsets):
        raise ValueError("offset must be >= 0")
    offset = offsets[0]
    op = re.compile(str(a["op"]), re.I) if a.get("op") else None
    pattern = re.compile(rf"[+-]\s*{offset:#x}\]", re.I)
    imm = _imm_spec(str(a["imm"])) if a.get("imm") not in (None, "") else None
    writes = bool(a.get("writes"))
    if len(offsets) < 2:
        a["sequence"] = False
    if a.get("sequence"):
        window = _num(a, "window", 32)
        if window < 1:
            raise ValueError("window must be >= 1")
        return _scan_sequence(
            binary, p, offsets, window, start, end, limit, not a.get("stack"), began
        )
    if len(offsets) > 1:
        return _scan_several(
            binary, p, offsets, start, end, limit, op, not a.get("stack"), imm, writes, began
        )
    sites, scanned = _insn_sites(p, offset, start, end, limit, op, not a.get("stack"), imm, writes)
    return {
        "binary": binary,
        "offset": f"{offset:#x}",
        "pattern": pattern.pattern,
        "skip_stack": not bool(a.get("stack")),
        "imm": str(a["imm"]) if a.get("imm") not in (None, "") else None,
        "writes_only": writes,
        "scanned": scanned,
        "sites": sites,
        "truncated": len(sites) >= limit,
        "elapsed_ms": int((time.monotonic() - began) * 1000),
    }


def _strings_file(binary: str) -> Path:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(binary))
    return _ghlab_dir() / "strings" / f"{slug}.json"


def _string_text(d) -> str:
    try:
        return str(d.getValue())[:400]
    except Exception:  # noqa: BLE001 - a jpype call can raise anything
        return str(d.getDefaultValueRepresentation())[:400]


def _iter_string_data(program):
    """Yield defined data items whose type reads as a string."""
    it = program.getListing().getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            tname = str(d.getDataType().getName()).lower()
        except Exception:  # noqa: BLE001 - skip data whose type cannot be read
            continue
        if any(k in tname for k in ("string", "unicode", "terminated", "char")):
            yield d


def load_strings(e, refresh: bool = False) -> dict[str, Any]:
    """Whole string table of a program, cached on disk per (md5, modification).

    Building it walks every defined data item (461k on a 34 MB DLL, ~28k of them
    strings), which cost ~2.2 s on every `strings` call. Rows are `[addr, value]`.
    """
    started = time.time()
    program = e["program"]
    meta = _index_meta(program)
    path = _strings_file(str(e["binary"]))
    if not refresh and path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            cached_meta = raw.get("meta") or {}
            same = cached_meta.get("md5") == meta["md5"] and cached_meta.get("mods") == meta["mods"]
        except (OSError, ValueError):
            same = False
        if same:
            return {
                "strings": raw.get("strings") or [],
                "meta": raw["meta"],
                "cached": True,
                "path": str(path),
                "elapsed_ms": int((time.time() - started) * 1000),
            }
    rows = [[str(d.getAddress()), _string_text(d)] for d in _iter_string_data(program)]
    payload = {
        "meta": {
            **meta,
            "built_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "strings": len(rows),
        },
        "strings": rows,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8", newline=chr(10))
    return {
        "strings": rows,
        "meta": payload["meta"],
        "cached": False,
        "path": str(path),
        "elapsed_ms": int((time.time() - started) * 1000),
    }


_ASSERT_WORDS = (
    "failure",
    "failed",
    "assert",
    "invalid",
    "not supported",
    "unsupported",
    "unexpected",
    "should ",
    "error",
)
_ASSERT_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_:<>~@$]{2,80}::[A-Za-z_~][A-Za-z0-9_~]{1,60}")


def _assert_name(text: str) -> str | None:
    """`Foo::bar : failure` -> `Foo::bar`.

    Assertions are the cheapest names in a stripped binary: plain C strings,
    one per call site, and they spell out the method that wrote them.
    """
    low = text.lower()
    if "::" not in text or not any(word in low for word in _ASSERT_WORDS):
        return None
    m = _ASSERT_NAME_RE.search(text)
    return m.group(0) if m else None


def _assert_strings(program, min_len: int = 12, budget: int = 64 << 20):
    """Yield `(address, text)` for printable runs that look like assertions.

    Reads non-executable blocks directly instead of trusting the string typing:
    only a fraction of the literals get typed, and the untyped ones are exactly
    the interesting ones.
    """
    address_space = program.getAddressFactory().getDefaultAddressSpace()
    printable = re.compile(b"[ -~]{%d,200}" % min_len)
    used = 0
    for blk in program.getMemory().getBlocks():
        if not blk.isInitialized() or blk.isExecute():
            continue
        size = int(blk.getSize())
        if size <= 0:
            continue
        base = int(blk.getStart().getOffset())
        chunk = 1 << 20
        offset = 0
        while offset < size and used < budget:
            take = min(chunk, size - offset)
            try:
                data = _read_memory(program, blk.getStart().add(offset), take)
            except Exception:  # noqa: BLE001 - unreadable blocks are not fatal
                offset += take
                continue
            used += take
            for m in printable.finditer(data):
                text = m.group().decode("latin-1")
                yield address_space.getAddress(base + offset + m.start()), text
            offset += take


def _names_file(binary: str) -> Path:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(binary))
    return _ghlab_dir() / "names" / f"{slug}.json"


def build_names(entry, min_len: int = 12, budget: int = 64 << 20) -> dict[str, dict[str, Any]]:
    """Map recovered `Class::Method` names to the functions that assert on them."""
    program = entry["program"]
    refman = program.getReferenceManager()
    fm = program.getFunctionManager()
    rows: dict[str, dict[str, Any]] = {}
    for addr, text in _assert_strings(program, min_len=min_len, budget=budget):
        name = _assert_name(text)
        if name is None:
            continue
        row = rows.setdefault(name, {"text": text[:160], "functions": [], "addrs": [], "sites": 0})
        row["sites"] += 1
        for ref in refman.getReferencesTo(addr):
            holder = fm.getFunctionContaining(ref.getFromAddress())
            if holder is None:
                continue
            holder_name = str(holder.getName())
            if holder_name in row["functions"]:
                continue
            row["functions"].append(holder_name)
            row["addrs"].append(str(holder.getEntryPoint()))
    return rows


def load_names(entry, refresh: bool = False, min_len: int = 12) -> dict[str, Any]:
    """Name table of one program, cached on disk per (md5, modification)."""
    started = time.time()
    program = entry["program"]
    meta = _index_meta(program)
    path = _names_file(str(entry["binary"]))
    if not refresh and path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            cached_meta = raw.get("meta") or {}
            same = cached_meta.get("md5") == meta["md5"] and cached_meta.get("mods") == meta["mods"]
        except (OSError, ValueError):
            same = False
        if same:
            return {
                "names": raw.get("names") or {},
                "meta": raw["meta"],
                "cached": True,
                "path": str(path),
                "elapsed_ms": int((time.time() - started) * 1000),
            }
    names = build_names(entry, min_len=min_len)
    payload = {
        "meta": {**meta, "built_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "names": len(names)},
        "names": names,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8", newline=chr(10))
    return {
        "names": names,
        "meta": payload["meta"],
        "cached": False,
        "path": str(path),
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def cmd_names(a: dict[str, Any]) -> dict[str, Any]:
    """Recover method names from assertion strings."""
    entry = _entry(a["binary"])
    table = load_names(entry, refresh=bool(a.get("refresh")), min_len=_num(a, "min_len", 12))
    query = a.get("query") or ""
    pattern = re.compile(query, re.I) if query else None
    rows = []
    for name, row in sorted(table["names"].items()):
        if pattern is not None and not pattern.search(name):
            continue
        rows.append({"name": name, **row})
    limit = _num(a, "limit", 200)
    return {
        "binary": a["binary"],
        "count": len(table["names"]),
        "matched": len(rows),
        "names": rows[:limit],
        "cached": table["cached"],
        "built_at": table["meta"].get("built_at"),
        "elapsed_ms": table["elapsed_ms"],
    }


def cmd_strings(a: dict[str, Any]) -> dict[str, Any]:
    entry = _entry(a["binary"])
    p = entry["program"]
    q = (a.get("query") or "").lower()
    limit = _num(a, "limit", 200)
    skip = _num(a, "offset", 0)
    want_refs = bool(a.get("refs"))
    table = load_strings(entry, refresh=bool(a.get("refresh")))
    out = []
    by_function: Counter[str] = Counter()
    seen = 0
    for addr, val in table["strings"]:
        if not val or val == "None" or (q and q not in val.lower()):
            continue
        seen += 1
        if seen <= skip:
            continue
        row = {"addr": addr, "value": val}
        if want_refs:
            row["functions"] = _string_refs(p, p.getAddressFactory().getAddress(addr))
            for fn in row["functions"]:
                by_function[fn["function"]] += 1
        out.append(row)
        if len(out) >= limit:
            break
    result = {
        "binary": a["binary"],
        "matched": seen,
        "defined_data_scanned": table["meta"].get("strings", 0),
        "cached": table["cached"],
        "strings": out,
    }
    if want_refs:
        result["by_function"] = [
            {"function": name, "strings": n} for name, n in by_function.most_common(20)
        ]
    return result


def cmd_xrefs(a: dict[str, Any]) -> dict[str, Any]:
    e = _entry(a["binary"])
    p = e["program"]
    targets = a.get("targets") or [a["target"]]
    out = []
    for t in targets:
        # A hex target is already an address; asking for a *function* there used
        # to fall back to a full symbol scan (seconds per call).
        addr = _addr(e, t) if _hex_addr(t) is not None else None
        if addr is None:
            fn = _function(e, t)
            addr = fn.getEntryPoint() if fn else _addr(e, t)
        refs = []
        limit = _num(a, "limit", 400)
        for r in p.getReferenceManager().getReferencesTo(addr):
            holder = p.getFunctionManager().getFunctionContaining(r.getFromAddress())
            refs.append(
                {
                    "from": str(r.getFromAddress()),
                    "type": str(r.getReferenceType()),
                    "in_function": str(holder.getName()) if holder else None,
                }
            )
            if len(refs) >= limit:
                break
        out.append({"target": str(t), "addr": str(addr), "xrefs": refs})
    return {"results": out}


# A `bytes` answer is meant for an agent's context: 64 KiB is already ~200 KB of
# hex, and the read itself must be one call, not one call per byte.
MAX_BYTES = 65536


def _zero_bytes(n: int):
    """A zeroed Java byte[] of length n, for a JVM call that fills it in place.

    Not named `_byte_array`: that name already means "Python bytes -> Java byte[]"
    (see the patch path), and a second definition silently shadowed it.
    """
    from jpype import JArray, JByte

    return JArray(JByte)(n)


def _read_region(mem, addr, size: int) -> tuple[bytes, bool]:
    """Read up to `size` bytes at `addr`, clamped to the containing initialized block.

    `Memory.getBytes(Address, byte[])` is the sink form the JVM accepts; asking
    `getByte(addr.add(i))` in a Python loop costs one crossing per byte and a
    100 MB request turns into a hang instead of an error.
    """
    block = mem.getBlock(addr)
    if block is None or not block.isInitialized():
        raise ValueError(f"{addr} is not in initialized memory")
    available = int(block.getEnd().subtract(addr)) + 1
    want = min(size, available)
    buf = _zero_bytes(want)
    got = int(mem.getBytes(addr, buf))
    data = bytes(buf[i] & 0xFF for i in range(got))
    return data, want < size or got < want


def cmd_bytes(a: dict[str, Any]) -> dict[str, Any]:
    e = _entry(a["binary"])
    p = e["program"]
    addr = _addr(e, a["addr"])
    size = _num(a, "size", 64)
    if size <= 0:
        raise ValueError("size must be positive")
    capped = min(size, MAX_BYTES)
    data, truncated = _read_region(p.getMemory(), addr, capped)
    return {
        "addr": str(addr),
        "hex": data.hex(),
        "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
        "size": len(data),
        # Either the block ended or MAX_BYTES did: both mean "ask for less, or ask
        # for the next chunk", and silently returning a short read hides that.
        "truncated": truncated or capped < size,
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
    return {
        "addr": str(addr),
        "type": ctype,
        "text": str(a["text"]),
        "ok": True,
        "saved_via": saved,
    }


def cmd_graph(a: dict[str, Any]) -> dict[str, Any]:
    """Breadth-first call tree. direction: calling (callees) | called (callers)."""
    e = _entry(a["binary"])
    direction = str(a.get("direction", "calling"))
    depth = _num(a, "depth", 2)
    cap = _num(a, "limit", 80)
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
    result = {
        "binary": a["binary"],
        "direction": direction,
        "root": str(root.getName()),
        "nodes": nodes,
        "edges": edges_out[: cap * 2],
    }
    fmt = str(a.get("format") or "").lower()
    if fmt:
        if fmt not in render.RENDERERS:
            raise ValueError(
                f"unknown format {fmt!r}; pick one of {', '.join(sorted(render.RENDERERS))}"
            )
        text = render.RENDERERS[fmt](result)
        result["format"] = fmt
        result["bytes"] = len(text.encode("utf-8"))
        out = a.get("out")
        if out:
            path = Path(str(out)).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            result["path"] = str(path)
        else:
            result["rendered"] = text
    return result


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
    top = _num(a, "top", 8)
    per_kind = _num(a, "strings", 3)
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
    limit = _num(a, "limit", 20)
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
    limit = _num(a, "limit", 20)
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
    base = _project_dir or Path(config.default_project_dir())
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


def _hex_const(value: Any) -> str:
    """Constants arrive as ints from the index and as text through a cache round trip."""
    try:
        return hex(int(str(value), 0) if isinstance(value, str) else int(value))
    except (TypeError, ValueError):
        return str(value)


def _delta(x: dict[str, Any], y: dict[str, Any], limit: int) -> dict[str, Any]:
    def diff_set(left: set, right: set) -> tuple[list, list]:
        # keep the raw values: strings are compared as text, constants as integers
        return sorted(right - left, key=str)[:limit], sorted(left - right, key=str)[:limit]

    s_add, s_del = diff_set(x["strings"], y["strings"])
    i_add, i_del = diff_set(x["imports"], y["imports"])
    c_add, c_del = diff_set(x["consts"], y["consts"])
    return {
        "size": [x["size"], y["size"]],
        "insns": [x["insns"], y["insns"]],
        "blocks": [x["blocks"], y["blocks"]],
        "calls": [x["calls"], y["calls"]],
        "strings_added": [str(v) for v in s_add],
        "strings_removed": [str(v) for v in s_del],
        "imports_added": [str(v) for v in i_add],
        "imports_removed": [str(v) for v in i_del],
        "consts_added": [_hex_const(v) for v in c_add],
        "consts_removed": [_hex_const(v) for v in c_del],
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


def _semantic_profile(entry: dict[str, Any]) -> dict[str, Any]:
    """What a program is *made of*, at whole-binary granularity.

    Function-level fingerprints answer "which function changed"; this answers "what
    kind of capability changed" — a new import, a new URL, a new magic constant.
    """
    program = entry["program"]
    imports: dict[str, str | None] = {}
    for imp in _imports(program):
        name = str(imp["name"])
        imports[name] = _classify_import(name)
    rows = load_strings(entry)["strings"]
    strings = {str(value) for _addr, value in rows if len(str(value)) >= 4}
    consts: set[int] = set()
    for row in _program_fingerprints(str(entry["binary"]))["functions"].values():
        consts.update(int(c) for c in (row.get("consts") or ()))
    return {"imports": imports, "strings": strings, "consts": consts}


def _semantic_delta(left: dict[str, Any], right: dict[str, Any], limit: int = 40) -> dict[str, Any]:
    """Compare two ``_semantic_profile`` results. Pure: no Ghidra objects.

    Output is capped but never silently: every list carries its true length in
    ``counts`` so a caller can tell "3 new imports" from "40 of 900".
    """
    l_imp: dict[str, str | None] = left["imports"]
    r_imp: dict[str, str | None] = right["imports"]
    imp_added = sorted(set(r_imp) - set(l_imp))
    imp_removed = sorted(set(l_imp) - set(r_imp))
    risk: dict[str, dict[str, int]] = {}
    for name in imp_added + imp_removed:
        group = r_imp.get(name) or l_imp.get(name) or "other"
        bucket = risk.setdefault(group or "other", {"added": 0, "removed": 0})
        bucket["added" if name in imp_added else "removed"] += 1
    str_added = sorted(right["strings"] - left["strings"])
    str_removed = sorted(left["strings"] - right["strings"])
    con_added = sorted(right["consts"] - left["consts"])
    con_removed = sorted(left["consts"] - right["consts"])
    return {
        "imports": {
            "added": imp_added[:limit],
            "removed": imp_removed[:limit],
            "counts": {"added": len(imp_added), "removed": len(imp_removed)},
            "by_risk": risk,
        },
        "strings": {
            "added": str_added[:limit],
            "removed": str_removed[:limit],
            "counts": {"added": len(str_added), "removed": len(str_removed)},
        },
        "constants": {
            "added": [hex(c) for c in con_added[:limit]],
            "removed": [hex(c) for c in con_removed[:limit]],
            "counts": {"added": len(con_added), "removed": len(con_removed)},
            "note": "constants come from the per-function index, which keeps the first 200 per function",
        },
        "truncated": any(
            len(v) > limit
            for v in (imp_added, imp_removed, str_added, str_removed, con_added, con_removed)
        ),
    }


def cmd_diff(a: dict[str, Any]) -> dict[str, Any]:
    """Compare two programs in the project: what was added, removed, patched."""

    started = time.time()
    left = _program_fingerprints(a["a"])
    right = _program_fingerprints(a["b"])
    la, lb = left["functions"], right["functions"]
    limit = _num(a, "limit", 25)
    min_score = float(a.get("min_score", 0.55))
    detail = max(0, _num(a, "detail", 0))

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

    payload: dict[str, Any] = {
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
    note = _same_md5_note(left["md5"], right["md5"], identical, len(changed))
    if note:
        payload["note"] = note
    if a.get("semantic"):
        payload["semantic"] = _semantic_delta(
            _semantic_profile(left), _semantic_profile(right), limit=limit
        )
    return payload


def _same_md5_note(a_md5: Any, b_md5: Any, identical: int, changed: int) -> str:
    """Say so when two *identical files* differ only in how far each was analysed.

    An imported-but-unanalysed copy has no instructions worth fingerprinting, so every
    function reads as "changed" against an analysed twin -- a false alarm that the
    summary alone (`identical 0, changed 455`) made look like real drift.
    """
    if not a_md5 or a_md5 != b_md5 or identical or not changed:
        return ""
    return (
        "both programs have the same md5, so every difference above comes from how "
        "far each one was analysed, not from different code; run `ghlab analyze` on "
        "the one with fewer strings/imports"
    )


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
    for sym in _symbols_named(program, text, limit=1):
        return int(sym.getAddress().getOffset())
    return None


def _suggest_symbols(program, name: str, limit: int = 6, budget: int = 200_000) -> list[str]:
    """Substring suggestions, but never an unbounded walk of a huge symbol table."""
    low = str(name).lower()
    hits: list[str] = []
    for seen, sym in enumerate(program.getSymbolTable().getAllSymbols(True)):
        if seen >= budget:
            break
        text = str(sym.getName())
        if low in text.lower():
            hits.append(text)
            if len(hits) >= limit:
                break
    return hits


def _function_suggestions(program, target: str, limit: int = 5) -> str:
    """`FUN_14001e02` -> "(did you mean FUN_14001e02c, ...)" for a typo'd name."""
    import difflib

    names = [str(fn.getName()) for fn in program.getFunctionManager().getFunctions(True)]
    close = difflib.get_close_matches(str(target), names, n=limit, cutoff=0.6)
    if not close:
        close = _suggest_symbols(program, str(target), limit)
    return f" (did you mean {', '.join(close)}?)" if close else ""


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


def _int32(value: int) -> int:
    """Low 32 bits of ``value`` read as a signed integer."""
    low = value & 0xFFFFFFFF
    return low - (1 << 32) if low >= (1 << 31) else low


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


def _stub_int(text: str) -> int | None:
    """Stub values accept decimal, `0x` hex and negative numbers."""
    raw = str(text).strip().replace("_", "")
    try:
        return int(raw, 0)
    except ValueError:
        return None


def _parse_stub_spec(text: str) -> tuple[str, int | None, int | None, int]:
    """Split ``TARGET=RET`` / ``TARGET[ARGn=VAL]=RET`` into its four fields.

    ``TARGET`` is an address or a symbol name, ``ARGn`` is 1..4 for the Windows x64
    integer argument registers, and both ``VAL`` and ``RET`` accept ``0x`` prefixes.
    """
    spec = str(text).strip()
    head, sep, ret_text = spec.rpartition("=")
    if not sep or not head:
        raise ValueError(f"bad stub {text!r}; expected TARGET=RET or TARGET[ARGn=VAL]=RET")
    target = head.strip()
    arg: int | None = None
    arg_value: int | None = None
    if target.endswith("]") and "[" in target:
        target, _, cond = target.partition("[")
        cond = cond[:-1].strip()
        name, sep2, val_text = cond.partition("=")
        if not sep2 or not name.lower().startswith("arg"):
            raise ValueError(f"bad stub condition {cond!r}; expected ARGn=VALUE")
        index = name[3:].strip()
        if index not in ("1", "2", "3", "4"):
            raise ValueError(f"bad argument index in {cond!r}; use ARG1..ARG4")
        arg = int(index)
        arg_value = _stub_int(val_text.strip())
        if arg_value is None:
            raise ValueError(f"bad argument value in {cond!r}")
    target = target.strip()
    if not target:
        raise ValueError(f"bad stub {text!r}; no target")
    ret = _stub_int(ret_text.strip())
    if ret is None:
        raise ValueError(f"bad return value in {text!r}")
    return target, arg, arg_value, ret


def _resolve_stubs(program, specs: list[Any] | None) -> list[dict[str, Any]]:
    """Turn ``--stub`` strings into ``{addr, arg, arg_value, ret, spec}`` records."""
    out: list[dict[str, Any]] = []
    for text in specs or []:
        target, arg, arg_value, ret = _parse_stub_spec(str(text))
        offset = _hex_addr(target)
        if offset is None:
            offset = _symbol_addr(program, target)
        if offset is None:
            raise ValueError(f"stub target {target!r} is neither an address nor a symbol")
        out.append(
            {"addr": offset, "arg": arg, "arg_value": arg_value, "ret": ret, "spec": str(text)}
        )
    return out


def _stub_hit(program, emu, insn, stubs: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the stub that replaces this call, if any."""
    if not stubs:
        return None
    flows = insn.getFlows()
    if flows is None or len(flows) != 1:
        return None
    target = int(flows[0].getOffset())
    for spec in stubs:
        if spec["addr"] != target:
            continue
        if spec["arg"] is not None:
            reg = program.getRegister(PARAM_REGS[spec["arg"] - 1])
            if reg is None:
                continue
            have = _u64(emu.readRegister(reg)) & 0xFFFFFFFF
            if have != spec["arg_value"] & 0xFFFFFFFF:
                continue
        return spec
    return None


def _s64(value: int) -> int:
    """Wrap ``value`` into the signed 64-bit range.

    JPype raises OverflowError for anything above ``2**63-1``, so a stub returning
    -100 must be written as -100, not as ``0xFFFF_FFFF_FFFF_FF9C``.
    """
    low = value & MASK64
    return low - (1 << 64) if low >= (1 << 63) else low


def _apply_call_stub(emu, program, insn, spec: dict[str, Any]) -> bool:
    """Skip a call and pretend it returned ``spec['ret']`` in RAX."""
    target = insn.getFallThrough()
    if target is None:
        target = insn.getAddress().add(int(insn.getLength()))
    rax = program.getRegister("RAX")
    if rax is not None:
        emu.writeRegister(rax, _s64(spec["ret"]))
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

    max_insns = _num(a, "max_insns", 200000)
    ms = _num(a, "ms", 5000)
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
    buf_size = _num(a, "buffer", 0)
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
    stubs_cfg = _resolve_stubs(program, a.get("stub"))
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
            if stubs_cfg:
                here = program.getListing().getInstructionAt(pc)
                if here is not None and str(here.getMnemonicString()).upper() == "CALL":
                    hit = _stub_hit(program, emu, here, stubs_cfg)
                    if hit is not None and _apply_call_stub(emu, program, here, hit):
                        stubs.append({"at": str(pc), "fn": hit["spec"]})
                        insns += 1
                        continue
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
    # A function returning -260 leaves 0xfffffefc in RAX; report both readings so a
    # caller does not have to know whether the source prototype was signed.
    rax_i32 = _int32(rax)
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
        "ret": {"rax": rax, "rax_hex": hex(rax), "rax_i32": rax_i32},
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
        if not a.get("binary"):
            raise ValueError("decrypt needs hex=... or binary=... with addr=...")
        if not a.get("addr"):
            # opening the program first only to report a missing argument made the
            # message `KeyError: 'address None not found'`
            raise ValueError("decrypt needs addr=<address> with a binary, or hex=...")
        entry = _entry(a["binary"])
        program = entry["program"]
        offset = _hex_addr(a.get("addr"))
        if offset is None:
            raise KeyError(f"address {a.get('addr')!r} not found")
        size = _num(a, "len", 64)
        if size <= 0 or size > 0x4000:
            raise ValueError("len must be between 1 and 16384")
        space = program.getAddressFactory().getDefaultAddressSpace()
        data = _read_memory(program, space.getAddress(offset), size)
        source = f"{a['binary']}@{hex(offset)}"
    ciphers = _as_list(a.get("ciphers")) or ["xor", "add", "rot", "utf16", "base64"]
    min_printable = float(a.get("min_printable", 0.85))
    limit = _num(a, "limit", 5)
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


_STAMP: str | None = None


def code_stamp(refresh: bool = False) -> str:
    """Fingerprint of the code this process loaded, so a stale daemon is detectable.

    Cached on first use: a daemon that re-hashed the files on every call would always
    report the *installed* code -- the one thing that just changed -- and `ghlab start`
    would never notice that the running process still serves the old module.
    `refresh=True` re-reads (for a caller that has just written the files).
    """
    global _STAMP
    if _STAMP is not None and not refresh:
        return _STAMP
    root = Path(__file__).resolve().parent
    parts = []
    for path in sorted(root.glob("*.py")):
        try:
            st = path.stat()
        except OSError:
            continue
        parts.append(f"{path.name}:{st.st_size}:{int(st.st_mtime)}")
    _STAMP = hashlib.md5("|".join(parts).encode()).hexdigest()[:12]
    return _STAMP


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
    _write_bytes(p, addr, data)
    after = bytes(mem.getByte(addr.add(i)) & 0xFF for i in range(len(data)))
    backup = _record_patch(str(a["binary"]), addr, before, after)
    saved = _save(p, "ghlab patch", e)
    return {
        "binary": str(a["binary"]),
        "addr": str(addr),
        "before": before.hex(),
        "after": after.hex(),
        "size": len(data),
        "saved_via": saved,
        "backup": backup["file"],
        "reversible": backup["reversible"],
    }


def cmd_revert(a: dict[str, Any]) -> dict[str, Any]:
    """Put back the bytes an earlier `patch` overwrote.

    The patches are a stack per project: `addr` unwinds that address only, `all`
    unwinds everything, newest first. Refuses when the bytes have moved on since
    the patch (that is a different edit, not an undo) unless `force` is set.
    """
    e = _entry(a["binary"])
    p = e["program"]
    want_addr = str(a["addr"]) if a.get("addr") else None
    every = bool(a.get("all"))
    if not want_addr and not every:
        raise ValueError("revert needs addr=<address> or all=yes")
    records = _patch_records(str(a["binary"]))
    if want_addr:
        wanted = str(_addr(e, want_addr))
        records = [r for r in records if str(r.get("addr")) == wanted]
    if not records:
        raise ValueError("no recorded patch" + (f" at {want_addr}" if want_addr else ""))
    todo = records[::-1] if every else records[-1:]
    mem = p.getMemory()
    done = []
    for rec in todo:
        if not rec.get("reversible"):
            raise ValueError(
                f"the patch at {rec['addr']} was {rec.get('size')} byte(s); it was recorded "
                "without its original bytes and cannot be reverted"
            )
        addr = _addr(e, str(rec["addr"]))
        before = bytes.fromhex(str(rec["before"]))
        current = bytes(mem.getByte(addr.add(i)) & 0xFF for i in range(len(before)))
        if current != bytes.fromhex(str(rec.get("after", ""))) and not a.get("force"):
            raise ValueError(
                f"{rec['addr']} changed since the patch: now {current.hex()}, "
                f"patched {rec.get('after')}; pass force=yes to overwrite anyway"
            )
        _write_bytes(p, addr, before, label="ghlab-revert")
        saved = _save(p, "ghlab revert", e)
        with contextlib.suppress(OSError):
            Path(str(rec["file"])).unlink()
        done.append(
            {
                "addr": str(rec["addr"]),
                "restored": before.hex(),
                "was": current.hex(),
                "saved_via": saved,
            }
        )
    return {
        "binary": a["binary"],
        "reverted": done,
        "remaining": len(_patch_records(str(a["binary"]))),
    }


def _patch_dir() -> Path:
    """Where the bytes a `patch` overwrote are kept so they can be put back."""
    base = _project_dir or Path(config.default_project_dir())
    d = Path(base) / ".ghlab" / "patches"
    d.mkdir(parents=True, exist_ok=True)
    return d


# A patch is a handful of instructions; anything near this size is a bulk rewrite
# whose "before" would be a second copy of the binary inside the project directory.
MAX_RECORDED_PATCH = 4096


def _patch_records(binary: str | None = None) -> list[dict[str, Any]]:
    """Recorded patches, oldest first (the order a revert should unwind).

    Two binaries in one project share address strings like "0x401000", so a
    revert must never look at another binary's records.
    """
    out: list[dict[str, Any]] = []
    for path in sorted(_patch_dir().glob("*.json")):
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        if binary is not None and str(rec.get("binary")) != str(binary):
            continue
        rec["file"] = str(path)
        out.append(rec)
    out.sort(key=lambda r: (r.get("at", ""), r.get("seq", 0)))
    return out


def _record_patch(binary: str, addr, before: bytes, after: bytes) -> dict[str, Any]:
    """Save what a patch destroyed; a revert is only possible because of this."""
    seq = max((int(rec.get("seq", 0)) for rec in _patch_records()), default=0) + 1
    stamp = time.strftime("%Y%m%dT%H%M%S")
    rec = {
        "binary": binary,
        "addr": str(addr),
        "size": len(before),
        "before": before.hex(),
        "after": after.hex(),
        "at": stamp,
        "seq": seq,
        "reversible": len(before) <= MAX_RECORDED_PATCH,
    }
    if not rec["reversible"]:
        rec.pop("before")
    path = _patch_dir() / f"{seq:04d}-{str(addr).replace('0x', '')}-{stamp}.json"
    config.atomic_write_text(path, json.dumps(rec, ensure_ascii=False) + chr(10))
    rec["file"] = str(path)
    return rec


def _write_bytes(program, addr, data: bytes, label: str = "ghlab-patch") -> None:
    """Replace bytes and re-disassemble (Ghidra demands clearing code units first)."""
    mem = program.getMemory()
    tx = program.startTransaction(label)
    block = mem.getBlock(addr)
    writable = _block_writable(block) if block is not None else True
    try:
        if block is not None and not writable:
            block.setWrite(True)
        program.getListing().clearCodeUnits(addr, addr.add(len(data) - 1), False)
        mem.setBytes(addr, _byte_array(data))
    finally:
        if block is not None and not writable:
            with contextlib.suppress(Exception):  # the block was read-only already
                block.setWrite(False)
        program.endTransaction(tx, True)
    from ghidra.app.cmd.disassemble import DisassembleCommand

    tx = program.startTransaction(f"{label}-disasm")
    try:
        DisassembleCommand(addr, None, True).applyTo(program)
    finally:
        program.endTransaction(tx, True)


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
    out["saved_via"] = _save(p, "ghlab set-type", e)
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
    saved = _save(p, "ghlab types", e)
    return {
        "binary": str(a["binary"]),
        "applied": applied,
        "failed": failed,
        "count": len(applied),
        "saved_via": saved,
        "source": str(a["from"]),
    }


def _apply_pdb(program: Any, path: Path, untrusted: bool) -> tuple[bool, str]:
    """Run the PDB through `PdbUniversalAnalyzer.doAnalysis`, inside an analysis session.

    Two JVM facts forced this shape.  Calling `doAnalysis` directly fails with
    `IllegalArgumentException: No active analysis session`, because the applicator asks
    `TransientProgramProperties` for state with analysis-session scope, and that needs
    `AutoAnalysisManager.isAnalyzing()` to be true -- which only holds while
    `startAnalysis` is running.  And the option writers
    (`setAllowUntrustedOption`/`setPdbFileOption`) go through the same check, so their
    refusal must not abort the import.

    So: queue a stand-in analyzer whose `added` runs the real thing, and start the
    session.  This exact sequence is verified on a real Ghidra 12.2 JVM against a
    debug-built DLL and its MSF PDB (149 -> 5848 functions, symbols applied).
    """
    import jpype
    from java.io import File

    analyzer = jpype.JClass("ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer")
    reader = jpype.JClass("ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions")()
    applicator = jpype.JClass("ghidra.app.util.pdb.pdbapplicator.PdbApplicatorOptions")()
    manager = jpype.JClass("ghidra.app.plugin.core.analysis.AutoAnalysisManager")
    AnalyzerType = jpype.JClass("ghidra.app.services.AnalyzerType")
    AnalysisPriority = jpype.JClass("ghidra.app.services.AnalysisPriority")
    outcome: dict[str, Any] = {}

    def run(_p: Any, _set: Any, monitor: Any, msg_log: Any) -> bool:
        # the session hands us the log the analyzer writes into; the manager's own log
        # stays empty, and an empty log is how `pdb` would hide its own reason
        outcome["log"] = msg_log
        try:
            outcome["applied"] = bool(
                analyzer.doAnalysis(
                    _p,
                    File(str(path)).getAbsoluteFile(),
                    reader,
                    applicator,
                    msg_log,
                    monitor,
                )
            )
        except Exception as ex:  # re-raised below, with the reason kept
            outcome["error"] = f"{type(ex).__name__}: {ex}"
            raise
        return bool(outcome["applied"])

    proxy = jpype.JProxy(
        "ghidra.app.services.Analyzer",
        dict={
            "getName": lambda: "ghlab-pdb",
            "getAnalysisType": lambda: AnalyzerType.BYTE_ANALYZER,
            "getDefaultEnablement": lambda _p: True,
            "supportsOneTimeAnalysis": lambda: True,
            "getDescription": lambda: "apply a PDB",
            "getPriority": lambda: AnalysisPriority.LOW_PRIORITY,
            "canAnalyze": lambda _p: True,
            "added": run,
            "removed": lambda _p, _s, _m, _l: False,
            "registerOptions": lambda _o, _p: None,
            "optionsChanged": lambda _o, _p: None,
            "analysisEnded": lambda _p: None,
            "isPrototype": lambda: False,
        },
    )
    with contextlib.suppress(Exception):
        analyzer.setAllowUntrustedOption(program, untrusted)
    mgr = manager.getAnalysisManager(program)
    mgr.scheduleOneTimeAnalysis(proxy, program.getMemory())
    # `startAnalysis` does not open a transaction of its own -- its callers do -- so
    # without this the analyzer's first write is `db.NoTransactionException`.
    with _edit(program, "ghlab-pdb"):
        mgr.startAnalysis(MONITOR)
    if "error" in outcome:
        raise RuntimeError(f"pdb: {outcome['error']}")
    text = outcome.get("log")
    return bool(outcome.get("applied")), str(text if text is not None else mgr.getMessageLog())[
        :2000
    ]


def cmd_pdb(a: dict[str, Any]) -> dict[str, Any]:
    """Apply a matching PDB's symbols/types to a program.

    Ghidra ships the whole PDB pipeline (`PdbUniversalAnalyzer.doAnalysis`); this wraps
    it (see `_apply_pdb` for why it needs an analysis session), keeps the analyzer log,
    and reports how many functions the program has before and after.  A PDB that does
    not match the binary comes back as `applied: false` with the reason in `log`.
    """
    e = _entry(a["binary"])
    p = e["program"]
    path = Path(str(a["file"])).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"pdb not found: {path}")
    before = int(p.getFunctionManager().getFunctionCount())
    ok, log = _apply_pdb(p, path, bool(a.get("untrusted", True)))
    out = {
        "applied": ok,
        "file": str(path),
        "functions_before": before,
        "functions_after": int(p.getFunctionManager().getFunctionCount()),
        "log": log,
    }
    if ok:
        out["saved_via"] = _save(p, "ghlab pdb", e)
    return out


MAX_FID_FUNCTIONS = 20000


def _name_snapshot(program: Any, limit: int = MAX_FID_FUNCTIONS) -> tuple[dict[str, str], bool]:
    """{entry address: function name}, plus "did we stop before the end".

    `fid` reports what identification changed by diffing names in the program, not by
    reading FunctionID's result objects: those live in an internal package whose shape
    is not a promise, while names are the thing the user actually asked for.
    """
    out: dict[str, str] = {}
    funcs = program.getFunctionManager().getFunctions(True)
    while funcs.hasNext():
        fn = funcs.next()
        out[str(fn.getEntryPoint())] = str(fn.getName())
        if len(out) >= limit:
            return out, bool(funcs.hasNext())
    return out, False


def _renamed(before: dict[str, str], after: dict[str, str]) -> list[dict[str, str]]:
    """Functions whose name differs between the two snapshots, both spellings kept."""
    return [
        {"addr": addr, "was": was, "now": after[addr]}
        for addr, was in before.items()
        if addr in after and after[addr] != was
    ]


def _fid_folder() -> str:
    """The directory Ghidra loads FunctionID databases from.

    `fid --list` has to name it: the error message for "no libraries" points at this
    folder, and on the first real run the folder was the one thing it did not print.
    """
    import jpype

    root = Path(str(jpype.JClass("ghidra.framework.Application").getUserSettingsDirectory()))
    return str(root / "FunctionID")


def _fid_libraries() -> list[str]:
    """The .fidb files Ghidra would search, from the user settings directory."""
    import jpype

    root = Path(str(jpype.JClass("ghidra.framework.Application").getUserSettingsDirectory()))
    if not root.is_dir():
        return []
    return sorted(str(p) for p in root.rglob("*.fidb"))


def _run_fid_analyzer(program: Any) -> str:
    """Run this Ghidra's FunctionID analyzer over `program`; return its class name.

    Discovered through ClassSearcher instead of imported by path: FunctionID is an
    optional module and its package has moved between releases, so a hard-coded class
    name is a guess about one build.  If the module is absent the error says how many
    analyzers were searched, which is the difference between "not installed" and
    "name changed again".
    """
    import jpype
    from ghidra.app.util.importer import MessageLog
    from ghidra.util.classfinder import ClassSearcher

    base = jpype.JClass("ghidra.app.services.Analyzer").class_
    found = []
    seen = 0
    for cls in ClassSearcher.getClasses(base) or []:
        seen += 1
        if "fid" in str(cls.getSimpleName()).lower():
            found.append(cls)
    if not found:
        raise RuntimeError(
            f"this Ghidra has no FunctionID analyzer (searched {seen} analyzers); "
            "install the FunctionID module and at least one .fidb library"
        )
    cls = found[0]
    analyzer = cls.getDeclaredConstructor().newInstance()
    # Options are optional: a missing FunctionID option package must not stop matching.
    with contextlib.suppress(Exception):
        analyzer.registerOptions(program.getOptions("FunctionID"))
    # `added` takes four arguments -- (Program, AddressSetView, TaskMonitor, MessageLog)
    # -- and the memory is the whole set that matters here.  Passing three (the shape
    # the Analyzer interface suggests) fails with "No matching overloads found".
    with _edit(program, "ghlab fid"):
        analyzer.added(program, program.getMemory(), MONITOR, MessageLog())
    return str(cls.getSimpleName())


def cmd_fid(a: dict[str, Any]) -> dict[str, Any]:
    """Name library functions using the user's FunctionID databases (.fidb).

    Identification is a mutation: a match renames the function to the library's name,
    which is what a reader wants and why this cannot run under GHLAB_READONLY.  A
    binary with no installed library is refused rather than reported as "0 matches",
    because those two situations call for different actions.
    """
    if not a.get("list") and not a.get("binary"):
        raise ValueError("fid needs binary=<name>, or list=yes to see the databases")
    libs = _fid_libraries()
    if a.get("list"):
        return {"libraries": libs, "count": len(libs), "folder": _fid_folder()}
    e = _entry(str(a["binary"]))
    p = e["program"]
    if not libs:
        raise ValueError(
            "no .fidb libraries are installed; put one in Ghidra's FunctionID folder "
            "(`ghlab fid --list` shows the directory Ghidra searches)"
        )
    cap = _num(a, "limit", 200)
    started = time.monotonic()
    before, truncated = _name_snapshot(p)
    analyzer = _run_fid_analyzer(p)
    after, _ = _name_snapshot(p)
    changed = _renamed(before, after)
    out = {
        "binary": str(p.getName()),
        "analyzer": analyzer,
        "libraries": libs,
        "scanned": len(before),
        "renamed": len(changed),
        "functions": changed[:cap],
        "truncated": truncated or len(changed) > cap,
        "elapsed_ms": int(1000 * (time.monotonic() - started)),
    }
    if changed:
        out["saved_via"] = _save(p, "ghlab fid", e)
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
        cap = _num(a, "limit", 100)
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


def _claim_int_or(text: Any, default: int = 1 << 30) -> int:
    """Sort key for finding ids: integers on disk, but a hand-edited file is possible."""
    try:
        return _claim_int(text)
    except (TypeError, ValueError):
        return default


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
    base = _project_dir or Path(config.default_project_dir())
    d = Path(base) / ".ghlab" / "notes"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _notes_file(binary: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(binary))
    return _notes_dir() / (safe + ".json")


def _load_notes(binary: str) -> list[dict[str, Any]]:
    return _load_notes_path(_notes_file(binary))


def _load_notes_path(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        return list(json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, OSError):
        return []


def _store_notes(binary: str, notes: list[dict[str, Any]]) -> None:
    if readonly():
        # audit/verify stay usable, they just do not remember: read-only means the
        # project files on disk are not this daemon's to write.
        return
    config.atomic_write_text(_notes_file(binary), json.dumps(notes, indent=2) + "\n")


def cmd_note(a: dict[str, Any]) -> dict[str, Any]:
    """Append a durable finding (JSON on disk + a Ghidra bookmark), or retract one.

    `delete=ID` removes a finding that turned out to be wrong: an audit that only
    ever adds is how a findings store rots into noise.
    """

    binary = str(a["binary"])
    if readonly():
        # `_store_notes` would drop it silently, and a finding that vanishes without a
        # word is worse than a refusal: say why, and let the caller use a writable daemon
        raise PermissionError(
            "daemon is read-only (GHLAB_READONLY=1); a note would be dropped, not stored"
        )
    notes = _load_notes(binary)
    text = str(a.get("text") or "").strip()
    if a.get("delete"):
        if a["delete"] is True:
            # `delete` without an id used to be parsed as the number `True`, which
            # failed with "invalid literal for int()"; say what is missing instead
            raise ValueError(
                "note delete needs the finding's id: delete=<id> (or delete=<id>,<id>)"
            )
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
    if not text:
        raise ValueError("note needs text=..., or delete=<id> to retract one")
    at = a.get("at")
    claims = _as_list(a.get("assert") or [])
    for raw in claims:
        kind = _parse_claim(raw)["kind"]
        if kind not in _CLAIM_KINDS:
            # stored as an uncheckable claim, it only ever answers "unknown" -- say so
            # now, while the author is still here, and before anything is written
            raise ValueError(
                f"claim {raw!r} has unknown kind {kind!r}; kinds: {', '.join(_CLAIM_KINDS)}"
            )
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
            bm.setBookmark(_addr(e, addr), "Note", str(a.get("tag") or "ghlab"), text)
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
        "text": text,
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
    """Read findings back.  Without `binary`, every program's findings, tagged with
    the program they came from -- finding ids are per program, so the name has to
    travel with them."""
    binary = str(a["binary"]) if a.get("binary") else ""
    if binary:
        notes = _load_notes(binary)
        path = str(_notes_file(binary))
        programs = 1
    else:
        files = sorted(_notes_dir().glob("*.json"))
        notes = []
        for file in files:
            for note in _load_notes_path(file):
                note.setdefault("binary", file.stem)
                notes.append(note)
        notes.sort(key=lambda n: (str(n.get("binary")), _claim_int_or(n.get("id"))))
        path = str(_notes_dir())
        programs = len(files)
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
    cap = _num(a, "limit", 200)
    return {
        "notes": out[:cap],
        "count": len(out),
        "total": len(notes),
        "path": path,
        "programs": programs,
    }


def cmd_report(a: dict[str, Any]) -> dict[str, Any]:
    """Markdown report: triage digest + findings, ready to paste into a writeup."""
    binary = str(a["binary"])
    d = cmd_digest({"binary": binary, "top": _num(a, "top", 6), "strings": 2})
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
    limit = _num(a, "limit", 20)
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
        out = _forward_slice(start, _num(a, "depth", 6), _num(a, "limit", 40))
        out["binary"] = a["binary"]
        return out
    to_pat = re.compile(str(a["to"]), re.I)
    from_pat = re.compile(
        str(
            a.get("from") or r"^(entry|main|wmain|winmain|wwinmain|dllmain|_start|maincrtstartup)$"
        ),
        re.I,
    )
    depth = _num(a, "depth", 12)
    limit = _num(a, "limit", 4)

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
    limit = _num(a, "limit", 10)
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
            cache_path = None
            with contextlib.suppress(Exception):  # cache key touches jpype
                cache_path = _cache_bucket(program.getExecutableMD5()) / (
                    _decomp_cache_key(e, fn) + ".c"
                )
                code = _cache_read(cache_path)
            if code is None:
                res = e["decomp"].decompileFunction(fn, 60, MONITOR)
                if not res.decompileCompleted():
                    item["error"] = str(res.getErrorMessage())
                    rows.append(item)
                    continue
                code = str(res.getDecompiledFunction().getC()).replace("\r\n", "\n")
                if cache_path is not None:
                    with contextlib.suppress(OSError):
                        _cache_write(cache_path, code)
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
    limit = _num(a, "limit", 200)
    hits = _num(a, "hits", 5)
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
    "revert",
    "set_type",
    "bookmark",
    "note",
    "types",
    "pdb",
    "fid",
)


def _mutates(cmd: str, args: dict[str, Any]) -> bool:
    """`struct` is a question ... unless `create=yes` installs the type."""
    if cmd == "struct":
        return args.get("create") in (True, "yes", "true", "1")
    return cmd in MUTATING


def readonly() -> bool:
    """Was this daemon asked to refuse every change?  (GHLAB_READONLY=1)

    A daemon handed to someone else (a model, a colleague's script) should be able
    to answer questions without being able to edit the project.  Checked per call,
    not cached, so a test can flip it.
    """
    return os.environ.get("GHLAB_READONLY", "").strip().lower() not in ("", "0", "no", "false")


def _journal_file() -> Path:
    base = _project_dir or Path(config.default_project_dir())
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
    if cmd == "revert":
        addrs = ", ".join(str(row.get("addr")) for row in r.get("reverted") or [])
        return f"restored {addrs}"
    if cmd == "set_type":
        return f"{params.get('target')} {r.get('decl') or params.get('decl')}"
    if cmd == "types":
        return f"{r.get('applied')} applied / {r.get('failed')} failed from {params.get('from')}"
    if cmd == "pdb":
        return f"{params.get('file')} applied={r.get('applied')}"
    if cmd == "fid":
        return f"{r.get('renamed')} renamed via {r.get('analyzer')}"
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
    limit = _num(a, "limit", 50)
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


def _job_args(text: Any) -> dict[str, Any]:
    """`k=v;k2=v2` -> params.

    `;` separates pairs because the values themselves are full of commas
    (`targets=a,b`, `types=0x18=float,0x20=void *`), and a separator that also
    occurs inside values is a parser bug waiting to be reported.
    """
    out: dict[str, Any] = {}
    # an MCP client may send the pairs as a JSON array (its schema says string, but the
    # `args` name is also a list for other tools, so clients that normalise by name
    # hand us `[str]`); joining keeps that working instead of parsing "['targets'
    pairs = ";".join(str(x) for x in text) if isinstance(text, (list, tuple)) else str(text or "")
    for pair in pairs.split(";"):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise ValueError(f"bad args item {pair!r}; expected key=value, pairs split on ';'")
        key, _, value = pair.partition("=")
        out[key.strip()] = value.strip()
    return out


def _job_view(job: dict[str, Any], with_result: bool = False) -> dict[str, Any]:
    """The line a client gets: identity, state, cost -- and the output on request."""
    started = float(job["started_at"] or 0.0)
    ended = float(job["ended_at"] or 0.0)
    elapsed = (ended or time.monotonic()) - started if started else 0.0
    out: dict[str, Any] = {
        "job": job["id"],
        "cmd": job["cmd"],
        "state": job["state"],
        "requested": job["requested"],
        "elapsed_ms": int(1000 * elapsed) if started else 0,
    }
    if job["error"]:
        out["error"] = job["error"]
    if with_result and job["state"] == "done":
        out["result"] = job["result"]
    return out


def _monitor_cancelled() -> bool:
    if MONITOR is None:
        return False
    with contextlib.suppress(Exception):
        return bool(MONITOR.isCancelled())
    return False


def _monitor_reset() -> None:
    """Clear the shared cancel flag before and after a job.

    One monitor serves the whole daemon, so a stale flag would make the *next*
    command abort immediately; a job must leave it as it found it.
    """
    if MONITOR is None:
        return
    with contextlib.suppress(Exception):
        MONITOR.clearCancelled()


def _job_trim() -> None:
    """Forget the oldest finished jobs once there are more than MAX_JOBS_KEPT."""
    while len(JOBS) > MAX_JOBS_KEPT:
        finished = [j for j in JOBS.values() if j["state"] in ("done", "failed", "cancelled")]
        if not finished:
            return
        JOBS.pop(min(finished, key=lambda j: float(j["ended_at"] or 0.0))["id"], None)


def _job_thread(job_id: str) -> None:
    """Worker: goes through `dispatch`, so locking, journal and in_flight all apply.

    A job started this way is a queued command, not a second Ghidra thread: it waits
    for LOCK like any request.  Its `dispatch` marks it as in flight, so `GET /` and
    `ping` report the job -- not the `job` call that started it.
    """
    job = JOBS[job_id]
    # Take the lock *before* declaring the job running: a job cancelled while it was
    # queued must never run, and the only moment where that is decidable is after we
    # hold the lock the job was waiting for.  LOCK is an RLock, so `dispatch` taking
    # it again below is free.
    with LOCK:
        if job["cancelled"]:
            job["state"] = "cancelled"
            job["ended_at"] = time.monotonic()
            return
        job["state"] = "running"
        job["started_at"] = time.monotonic()
        _monitor_reset()
        try:
            job["result"] = dispatch(job["cmd"], job["params"])
            job["state"] = "cancelled" if job["cancelled"] or _monitor_cancelled() else "done"
        except BaseException as ex:  # noqa: BLE001 - a worker thread must not die silently
            job["state"] = "cancelled" if job["cancelled"] or _monitor_cancelled() else "failed"
            if job["state"] == "failed":
                job["error"] = f"{type(ex).__name__}: {ex}"
        finally:
            job["ended_at"] = time.monotonic()
            _monitor_reset()
            _job_trim()


def _job_id(value: Any) -> str:
    """The `j3` in whatever a client sent.

    MCP wraps parameters whose CLI flag is repeatable (`--id`) in a list, so a tool
    call arrives as `["j3"]`; `job` and `cancel` used to look that bracket up.
    """
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    return str(value or "").strip()


def cmd_job(a: dict[str, Any]) -> dict[str, Any]:
    """Run a command in the background; `list=yes` shows the queue, `id=` one result.

    The parameters are validated here, before the thread starts: a typo must come back
    as a protocol error to the caller, not as a failed job nobody is watching.
    """
    from . import protocol

    if a.get("list") or a.get("id"):
        wanted = _job_id(a.get("id"))
        if wanted:
            job = JOBS.get(str(wanted))
            if job is None:
                raise KeyError(f"no job {wanted!r}; `job list=yes` shows the kept ones")
            return {"jobs": [_job_view(job, with_result=True)]}
        jobs = sorted(JOBS.values(), key=lambda j: float(j["started_at"] or 0.0))
        return {
            "jobs": [_job_view(j) for j in jobs],
            "running": sum(1 for j in jobs if j["state"] in ("queued", "running")),
        }
    run = str(a.get("run") or "")
    if not run:
        raise ValueError(
            "job needs run=<command>; e.g. job run=decompile binary=fw.bin args=targets=main"
        )
    params = _job_args(a.get("args"))
    if a.get("binary"):
        params["binary"] = str(a["binary"])
    _, params = protocol.validate({"cmd": run, **params})
    job = {
        "id": f"j{next(_JOB_SEQ)}",
        "cmd": run,
        "params": params,
        "state": "queued",
        "requested": time.strftime("%H:%M:%S"),
        "started_at": 0.0,
        "ended_at": 0.0,
        "result": None,
        "error": None,
        "cancelled": False,
    }
    JOBS[job["id"]] = job
    worker = threading.Thread(target=_job_thread, args=(job["id"],), name=job["id"], daemon=True)
    worker.start()
    if a.get("wait"):
        worker.join()
        return _job_view(JOBS[job["id"]], with_result=True)
    return _job_view(job)


def cmd_cancel(a: dict[str, Any]) -> dict[str, Any]:
    """Ask a running or queued job to stop.

    Ghidra checks its monitor between steps, so this stops *between* steps: a single
    long decompile finishes first.  Saying that in the reply is cheaper than letting a
    caller conclude the flag did nothing.
    """
    if a.get("all"):
        targets = [j for j in JOBS.values() if j["state"] in ("queued", "running")]
        idle = "nothing is queued or running; cancel has nothing to stop"
    else:
        jid = _job_id(a.get("id"))
        if not jid:
            raise ValueError("cancel needs id=<job> or all=yes")
        job = JOBS.get(jid)
        if job is None:
            raise KeyError(f"no job {jid!r}; `job list=yes` shows the kept ones")
        # a finished job has nothing to cancel, and flipping the monitor anyway left it
        # flagged for every later decompile (found on a real run: `cancel j1` on a done
        # job wedged the decompiler until the daemon restarted)
        targets = [job] if job["state"] in ("queued", "running") else []
        idle = f"{jid} is {job['state']}; nothing to cancel"
    for job in targets:
        job["cancelled"] = True
        if job["state"] == "queued":
            job["state"] = "cancelled"
            job["ended_at"] = time.monotonic()
    if not targets:
        return {"cancel_requested": [], "note": idle}
    with contextlib.suppress(Exception):
        if MONITOR is not None:
            MONITOR.cancel()
    return {
        "cancel_requested": [j["id"] for j in targets],
        "note": "Ghidra checks between steps; a long single step finishes first",
    }


def dispatch(cmd: str, params: dict[str, Any]) -> Any:
    """Run one command.  Everything that touches Ghidra takes LOCK first.

    `ping`, `job` and `cancel` do not: they exist to *ask about* or *interrupt* a
    running command, so queueing them behind it would answer the wrong question.
    """
    if cmd in _UNLOCKED:
        return _run(cmd, params, track=False)
    with LOCK:
        # `ping` is served to *ask* what is running, so it must never claim to be
        # the thing that is running. Everything else is marked only once it holds
        # the lock: a request queued behind a slow decompile is not "running".
        return _run(cmd, params, track=cmd != "ping")


def _run(cmd: str, params: dict[str, Any], track: bool) -> Any:
    if track:
        _INFLIGHT["cmd"] = cmd
        _INFLIGHT["started"] = time.monotonic()
        _INFLIGHT["since"] = time.strftime("%H:%M:%S")
    try:
        if not _jobs_active():
            # a job cancelled *after* it had already finished never reached the reset in
            # _job_thread, so the monitor stayed flagged and every later decompile came
            # back "decompiler said: " with no message at all
            _monitor_reset()
        if _mutates(cmd, params) and readonly():
            raise PermissionError(
                f"daemon is read-only (GHLAB_READONLY=1); {cmd!r} changes the project"
            )
        try:
            result = HANDLERS[cmd](params)
        except Exception as ex:
            if _mutates(cmd, params):
                _journal_append(cmd, params, None, f"{type(ex).__name__}: {ex}")
            raise
        if _mutates(cmd, params):
            _journal_append(cmd, params, result)
        return result
    finally:
        if track:
            _INFLIGHT["cmd"] = None
            _INFLIGHT["started"] = 0.0
            _INFLIGHT["since"] = None


def _jobs_active() -> bool:
    """Is anything queued or running?  (A stale cancel flag is cleared when not.)"""
    return any(j["state"] in ("queued", "running") for j in JOBS.values())


def in_flight() -> dict[str, Any]:
    """What the daemon is doing right now (empty when idle).

    Ghidra calls are serialized by LOCK, so an abandoned long call blocks every
    other *command*; GET / keeps answering. Reporting the running command is how
    you tell "slow" from "wedged" without attaching a debugger.
    """
    cmd = _INFLIGHT.get("cmd")
    if not cmd:
        return {}
    started = float(_INFLIGHT.get("started") or 0.0)
    return {
        "cmd": cmd,
        "elapsed_s": round(time.monotonic() - started, 1) if started else None,
        "since": _INFLIGHT.get("since"),
    }


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
    limit = _num(a, "limit", 0)
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
    limit = _num(a, "limit", 0)
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
    "names": cmd_names,
    "scan": cmd_scan,
    "offsets": cmd_offsets,
    "struct": cmd_struct,
    "imports": cmd_imports,
    "exports": cmd_exports,
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
    "revert": cmd_revert,
    "set_type": cmd_set_type,
    "bookmark": cmd_bookmark,
    "note": cmd_note,
    "notes": cmd_notes,
    "verify": cmd_verify,
    "map": cmd_map,
    "types": cmd_types,
    "pdb": cmd_pdb,
    "fid": cmd_fid,
    "report": cmd_report,
    "cross_xref": cmd_cross_xref,
    "slice": cmd_slice,
    "similar": cmd_similar,
    "campaign": cmd_campaign,
    "family": cmd_family,
    "journal": cmd_journal,
    "overview": cmd_overview,
    "audit": cmd_audit,
    "job": cmd_job,
    "cancel": cmd_cancel,
}
