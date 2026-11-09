"""`ghlab` command line: daemon lifecycle plus one-shot queries."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, NoReturn

from . import __version__, session
from .client import Client, RemoteError
from .config import (  # noqa: F401 - re-exported for callers and tests
    config_path,
    default_project,
    discover_projects,
    focus_path,
    ghidra_dir,
    load_config,
    projects,
    read_focus,
    register_project,
    remove_project,
    save_config,
    write_focus,
)
from .protocol import DEFAULT_HOST, DEFAULT_PORT
from .router import RouteError, from_config

REPO = Path(__file__).resolve().parents[2]
LOGDIR = Path.home() / "re" / "logs"


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


# ------------------------------------------------------------------ formatting


def fmt_binaries(r: dict[str, Any]) -> str:
    names = r.get("binaries") or []
    return "\n".join(names) if names else "(project is empty — use `ghlab import PATH`)"


def fmt_analyze(r: dict[str, Any]) -> str:
    if r["mode"] == "full":
        return (
            f"# full analysis of {r['binary']}: {r['functions']} function(s) "
            f"({r['elapsed_ms']}ms, {r['saved_via']})"
        )
    out = [
        f"# targeted analysis of {r['binary']}: {r['functions']} function(s) "
        f"({r['elapsed_ms']}ms, {r['saved_via']})"
    ]
    for row in r["addresses"]:
        state = []
        if row["disassembled"]:
            state.append("disassembled")
        if row["created"]:
            state.append("function created")
        out.append(
            f"  {row['addr']}  {row['function'] or '-'}  [{', '.join(state) or 'unchanged'}]"
        )
    return "\n".join(out)


def fmt_info(r: dict[str, Any]) -> str:
    keys = (
        "name",
        "executable_path",
        "language",
        "compiler",
        "image_base",
        "md5",
        "functions",
        "symbols",
    )
    lines = [f"{k:15} {r.get(k)}" for k in keys]
    lines.append(f"{'memory_blocks':15} {', '.join(r.get('memory_blocks') or [])}")
    return "\n".join(lines)


def fmt_functions(r: dict[str, Any]) -> str:
    rows = [f"{f['addr']}  {f['size']:>6}  {f['name']}" for f in r.get("functions") or []]
    head = f"# {r.get('matched')} matched, showing {len(rows)}"
    return "\n".join([head, *rows])


def fmt_decompile(r: dict[str, Any]) -> str:
    if not r.get("results"):
        return "(no function matched; widen -m/-g or raise -n)"
    out = []
    for item in r.get("results") or []:
        if item.get("error"):
            out.append(f"!! {item.get('target')}: {item['error']}")
            continue
        if item.get("signature") and "lines" not in item:
            out.append(f"  {item['addr']}  {item['size']:>6}b  {item['signature']}")
            continue
        out.append(
            f"== {item['name']} @ {item['addr']}  ({item['lines']} lines)  {item['prototype']}"
        )
        if item.get("grep_hits") is not None:
            out.append(f"   match: {item['grep_hits']} line(s)")
            for hit in item.get("hits") or []:
                out.append(f"   L{hit['line']:<4} {hit['text']}")
        if item.get("code"):
            out.append(item["code"].rstrip())
        for key in ("callees", "callers"):
            if item.get(key):
                out.append(f"   {key}: {', '.join(item[key])}")
    return "\n".join(out)


def fmt_imports(r: dict[str, Any]) -> str:
    groups = ", ".join(f"{k} {v}" for k, v in r["groups"].items()) or "-"
    out = [
        f"# {r['total']} import(s), {r['with_callers']} with callers  "
        f"({r['elapsed_ms']}ms)  groups: {groups}"
    ]
    for imp in r["imports"]:
        risk = f" [{imp['risk']}]" if imp["risk"] else ""
        top = ", ".join(f"{c['function']} ({c['size']}b)" for c in imp["top"]) or "-"
        out.append(f"  {imp['name']:<34} {imp['lib']:<10} callers {imp['callers']:>3}{risk}  {top}")
    return chr(10).join(out)


def fmt_names(r: dict[str, Any]) -> str:
    state = "cached" if r.get("cached") else "built"
    out = [
        f"== {r['binary']} : {r['count']} name(s) from assertion strings "
        f"({state}, {r['elapsed_ms']}ms)"
    ]
    rows = r.get("names") or []
    if not rows:
        out.append("   (no assertion string matched)")
        return chr(10).join(out)
    if r["matched"] > len(rows):
        out[0] += f"  [showing {len(rows)} of {r['matched']}]"
    for row in rows:
        fns = ", ".join(row["functions"][:3]) or "?"
        out.append(f"  {row['name']:<48} {fns}")
    return chr(10).join(out)


def fmt_scan(r: dict[str, Any]) -> str:
    out = [
        f"== {r['binary']} : {r['scanned']} instruction(s) scanned for {r['pattern']} "
        f"({r['elapsed_ms']}ms)"
    ]
    sites = r.get("sites") or []
    if not sites:
        out.append("   (no instruction touches this offset)")
        return chr(10).join(out)
    out.append(f"   {len(sites)} hit(s)" + ("  [truncated]" if r.get("truncated") else ""))
    filters = []
    if r.get("imm"):
        filters.append(f"imm {r['imm']}")
    if r.get("writes_only"):
        filters.append("writes only")
    if filters:
        out[0] += "  [" + ", ".join(filters) + "]"
    for s in sites:
        out.append(f"   {s['addr']}  {s['function'] or '-':<24} {s['text']}")
        for extra in (s.get("sequence") or [])[1:]:
            out.append(f"   {'':<12}  {'':<24} {extra}")
    return chr(10).join(out)


def fmt_strings(r: dict[str, Any]) -> str:
    body = []
    for s in r.get("strings") or []:
        fns = s.get("functions")
        where = ""
        if fns:
            where = "  <- " + ", ".join(f"{f['function']} ({f['size']}b)" for f in fns)
        elif fns == []:
            where = "  <- (unreferenced)"
        body.append(f"{s['addr']}  {s['value']}{where}")
    head = f"# {r.get('matched')} match(es), {r.get('defined_data_scanned')} data items scanned"
    if r.get("by_function"):
        head += "\n# busiest: " + ", ".join(
            f"{f['function']} ({f['strings']})" for f in r["by_function"][:5]
        )
    return "\n".join([head, *body])


def fmt_xrefs(r: dict[str, Any]) -> str:
    out = []
    for item in r.get("results") or []:
        out.append(f"== {item['target']} @ {item['addr']}: {len(item['xrefs'])} xref(s)")
        for x in item["xrefs"]:
            out.append(f"   {x['from']}  {x['type']:<16} {x['in_function'] or '-'}")
    return "\n".join(out)


def fmt_graph(r: dict[str, Any]) -> str:
    if r.get("path"):
        return f"{r.get('format')} graph written to {r['path']} ({r.get('bytes')} bytes)"
    if r.get("rendered"):
        return r["rendered"]
    out = [
        f"# {r['direction']} {r['root']}: {len(r.get('nodes') or [])} node(s)",
    ]
    for e in r.get("edges") or []:
        out.append(f"   {e['from']} -> {e['to']}")
    return "\n".join(out)


def fmt_diff(r: dict[str, Any]) -> str:
    s = r["summary"]
    by = ", ".join(f"{k}:{v}" for k, v in sorted((s.get("by") or {}).items()))
    sec = r.get("sections") or {}
    out = [
        f"== {r['a']['binary']} -> {r['b']['binary']}  "
        f"{r['a']['functions']} -> {r['b']['functions']} functions  ({r['elapsed_ms']}ms)",
        f"   md5 {r['a']['md5'][:12]} -> {r['b']['md5'][:12]}",
        f"   matched {s['matched']} (identical {s['identical']}, changed {s['changed']}) "
        f"| only-a {s['removed']} | only-b {s['added']}  [{by}]",
        "   sections  changed:"
        f" {', '.join(sec.get('changed') or []) or '-'}"
        f"  added: {', '.join(sec.get('added') or []) or '-'}"
        f"  removed: {', '.join(sec.get('removed') or []) or '-'}",
    ]
    if r.get("changed"):
        out.append("changed")
    for c in r.get("changed") or []:
        d = c["delta"]
        sign = d["size"][1] - d["size"][0]
        out.append(
            f"   {c['a']['addr']} {c['a']['name']}  {d['size'][0]}b -> {d['size'][1]}b "
            f"({sign:+d})  insns {d['insns'][0]}->{d['insns'][1]} "
            f"blocks {d['blocks'][0]}->{d['blocks'][1]}  [{c['matched_by']} {c['score']}]"
        )
        if c["a"]["name"] != c["b"]["name"]:
            out.append(f"     renamed -> {c['b']['name']}")
        for key, label in (
            ("strings_added", "strings +"),
            ("strings_removed", "strings -"),
            ("imports_added", "imports +"),
            ("imports_removed", "imports -"),
            ("consts_added", "consts +"),
            ("consts_removed", "consts -"),
        ):
            vals = d.get(key) or []
            if vals:
                out.append(f"     {label}{len(vals):>2}: {', '.join(vals)}")
        for line in c.get("disasm") or []:
            out.append(f"     {line}")
        if c.get("disasm_error"):
            out.append(f"     (disassembly diff failed: {c['disasm_error']})")
    if r.get("added"):
        out.append("only in " + r["b"]["binary"])
        for f in r["added"]:
            out.append(f"   + {f['addr']}  {f['name']}  ({f['size']}b)")
    if r.get("removed"):
        out.append("only in " + r["a"]["binary"])
        for f in r["removed"]:
            out.append(f"   - {f['addr']}  {f['name']}  ({f['size']}b)")
    if not (r.get("changed") or r.get("added") or r.get("removed")):
        out.append("   (no functional difference found)")
    sem = r.get("semantic")
    if sem:
        out.extend(_semantic_lines(sem))
    return "\n".join(out)


def _semantic_lines(sem: dict[str, Any]) -> list[str]:
    """Render the "what is this binary made of" half of `diff --semantic`."""
    out = ["semantic"]
    imp = sem.get("imports") or {}
    counts = imp.get("counts") or {}
    if counts.get("added") or counts.get("removed"):
        out.append(f"   imports +{counts.get('added', 0)} -{counts.get('removed', 0)}")
        for name in imp.get("added") or []:
            out.append(f"     api + {name}")
        for name in imp.get("removed") or []:
            out.append(f"     api - {name}")
        risk = imp.get("by_risk") or {}
        hot = [
            f"{g} +{v.get('added', 0)} -{v.get('removed', 0)}"
            for g, v in sorted(risk.items())
            if v.get("added") or v.get("removed")
        ]
        if hot:
            out.append(f"     by risk: {'; '.join(hot)}")
    else:
        out.append("   imports unchanged")
    st = sem.get("strings") or {}
    st_counts = st.get("counts") or {}
    out.append(f"   strings +{st_counts.get('added', 0)} -{st_counts.get('removed', 0)}")
    for text in st.get("added") or []:
        out.append(f"     text + {text[:96]}")
    for text in st.get("removed") or []:
        out.append(f"     text - {text[:96]}")
    con = sem.get("constants") or {}
    con_counts = con.get("counts") or {}
    if con_counts.get("added") or con_counts.get("removed"):
        out.append(f"   constants +{con_counts.get('added', 0)} -{con_counts.get('removed', 0)}")
        for value in con.get("added") or []:
            out.append(f"     const + {value}")
        for value in con.get("removed") or []:
            out.append(f"     const - {value}")
    if sem.get("truncated"):
        out.append("   (lists capped; counts above are the true totals)")
    return out


def fmt_decrypt(r: dict[str, Any]) -> str:
    out = [
        f"# {r['source']}  {r['size']} byte(s)  ciphers: {', '.join(r['ciphers'])}"
        f"  ({r['elapsed_ms']}ms)",
        f"   hex       {r['hex'][:96]}{'...' if len(r['hex']) > 96 else ''}",
    ]
    if not r.get("candidates"):
        out.append("   no candidate passed the printability floor (try --min-printable 0.6)")
    for c in r.get("candidates") or []:
        out.append(f"   [{c['cipher']} {c['key']}] printable {c['printable']} score {c['score']}")
        out.append(f"     {c['text']}")
    return "\n".join(out)


def fmt_emulate(r: dict[str, Any]) -> str:
    args = "  ".join(
        f"{a['kind']}:{a.get('value')}" + (f"@{a['addr']}" if a.get("addr") else "")
        for a in r.get("args") or []
    )
    out = [
        f"# {r['function']} @ {r['entry']}  {r['arch']}  ({r['insns']} insns, "
        f"{r['elapsed_ms']}ms, stop={r['stop']})",
        f"   prototype {r['prototype']}",
    ]
    if args:
        out.append(f"   args      {args}")
    out.append(f"   return    {r['ret']['rax_hex']} ({r['ret']['rax']})")
    if r.get("stubs"):
        seen: dict[str, int] = {}
        for s in r["stubs"]:
            seen[s["fn"]] = seen.get(s["fn"], 0) + 1
        summary = ", ".join(f"{k} x{v}" for k, v in sorted(seen.items()))
        out.append(f"   stubs     {len(r['stubs'])} external call(s) answered: {summary}")
    wr = r.get("writes") or {}
    out.append(f"   writes    {wr.get('tracked', 0)} byte(s)")
    for w in wr.get("ranges") or []:
        out.append(f"     {w['addr']}  {w['size']}b  {w['hex'][:64]}")
        if w.get("ascii"):
            out.append(f"       |{w['ascii']}|")
    buf = r.get("buffer")
    for d in r.get("dump") or []:
        label = "buffer" if buf and d["addr"] == buf["addr"] else "dump"
        out.append(f"   {label} {d['addr']} {d['size']}b")
        out.append(_hexblock(d["hex"], d["ascii"]))
    if r.get("skips"):
        ops = Counter(s["op"] for s in r["skips"])
        out.append(
            "   skipped   "
            + ", ".join(f"{k}x{v}" for k, v in sorted(ops.items()))
            + " instruction(s) (p-code op not emulated)"
        )
    f = r.get("fault")
    if f:
        out.append(
            f"   !! fault at {f['pc']} ({'mapped' if f['mapped'] else 'unmapped'}) "
            f"after call to {f.get('callee') or '?'} at {f['call_site']}"
        )
        out.append(f"      {f['error']}")
        if f.get("on_instruction") is False:
            out.append(
                "      note: PC is not on a decoded instruction — a stubbed call returned 0 "
                "and the code branched on it; give inputs with --arg or expect the fault"
            )
    return "\n".join(out)


def _hexblock(hexstr: str, ascii_: str, width: int = 16) -> str:
    data = bytes.fromhex(hexstr)
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = ascii_[off : off + width]
        lines.append(f"     {off:04x}  {hexpart}  |{text}|")
    return "\n".join(lines)


def fmt_index(r: dict[str, Any]) -> str:
    state = "cached" if r["cached"] else "built"
    out = [
        f"{r['binary']}: {r['functions']} functions, {r['strings']} string refs, "
        f"{r['imports']} imports ({state}, {r['elapsed_ms']}ms, {r['bytes'] // 1024} KiB)"
    ]
    if r.get("built_at"):
        out.append(f"  built_at {r['built_at']}")
    out.append(f"  {r['path']}")
    return chr(10).join(out)


def fmt_find(r: dict[str, Any]) -> str:
    filters = " ".join(f"{k}={v}" for k, v in (r.get("filters") or {}).items())
    out = [f"# {r.get('candidates')} candidate(s) mode={r.get('mode')} {filters}"]
    if not r.get("functions"):
        out.append("   (nothing matched; loosen the patterns or use --any)")
    for f in r.get("functions") or []:
        why = " | ".join(f"{k}: {', '.join(v)}" for k, v in (f.get("matched") or {}).items())
        out.append(f"   {f['addr']}  {f['size']:>5}b  {f['name']:<28} {why}")
    return "\n".join(out)


def fmt_digest(r: dict[str, Any]) -> str:
    imp = r.get("imports") or {}
    st = r.get("strings") or {}
    chain = " -> ".join(f"{c['name']}@{c['addr']}" for c in r.get("entry") or [])
    libs_all = list((imp.get("libs") or {}).items())
    libs = ", ".join(f"{k}:{v}" for k, v in libs_all[:5])
    if len(libs_all) > 5:
        libs += f" +{len(libs_all) - 5} libs"
    out = [
        f"== {r['binary']}  {r['language']}  base {r['image_base']}",
        f"   md5 {r['md5']}  compiler {r.get('compiler')}",
        f"   entry {chain or '-'}",
        f"   {r.get('functions')} functions | {st.get('total', 0)} strings | "
        f"{imp.get('total', 0)} imports ({libs})",
    ]
    combos = r.get("combos") or []
    if combos:
        out.append("combos")
        for c in combos:
            out.append(f"   !! {c['label']}: {', '.join(c['hits'])}")
    groups = imp.get("groups") or {}
    if groups:
        out.append("imports by risk")
        for kind, names in groups.items():
            more = f" +{len(names)}..." if len(names) >= 12 else ""
            out.append(f"   {kind:<9} {', '.join(names[:12])}{more}")
    counts = st.get("counts") or {}
    samples = st.get("samples") or {}
    if counts:
        out.append("strings")
        for kind, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            vals = " | ".join(s["value"] for s in (samples.get(kind) or []))
            out.append(f"   {kind:<8}({n}) {vals}")
    hubs = r.get("hubs") or []
    if hubs:
        out.append("hubs (most callers)")
        for h in hubs:
            out.append(f"   {h['callers']:>3}x  {h['addr']}  {h['name']}  ({h['size']}b)")
    sizes = r.get("sizes") or {}
    if sizes:
        out.append("sizes   " + "  ".join(f"{k}:{v}" for k, v in sizes.items()))
    body = "\n".join(out)
    return f"{body}\n~{len(body) // 4} tokens"


def fmt_patch(r: dict[str, Any]) -> str:
    return (
        f"patched {r['size']} byte(s) at {r['addr']}\n"
        f"  {r['before']} -> {r['after']}\n"
        f"  saved via {r['saved_via']}"
    )


def fmt_set_type(r: dict[str, Any]) -> str:
    status = "ok   " if r["applied"] else "FAILED"
    if r["kind"] == "signature":
        out = [f"{status} {r['addr']}  {r['prototype']}"]
    else:
        out = [f"{status} {r['addr']}  {r['datatype']} ({r['size']}b)"]
        if r.get("value") is not None:
            out.append(f"  value: {r['value']}")
    if r.get("message") and r["message"] not in ("None", "null"):
        out.append(f"  {r['message']}")
    return "\n".join(out)


def fmt_bookmark(r: dict[str, Any]) -> str:
    if "bookmarks" in r:
        if not r["bookmarks"]:
            return "(no bookmarks)"
        return "\n".join(
            f"  [{b['type']}] {b['addr']}  "
            + (f"{b['category']}: " if b["category"] else "")
            + b["comment"]
            for b in r["bookmarks"]
        )
    if r.get("removed"):
        return f"removed bookmark at {r['addr']} ({r['category']})"
    return f"bookmarked {r['addr']} ({r['type']}, {r['category']})"


def _claim_lines(rows: list[dict[str, Any]], indent: str = "  ") -> list[str]:
    out = []
    for row in rows or []:
        ok = row.get("ok")
        mark = "OK" if ok is True else ("FAIL" if ok is False else "??")
        out.append(f"{indent}[{mark}] {row.get('claim')} - {row.get('detail')}")
    return out


def fmt_note(r: dict[str, Any]) -> str:
    if "deleted" in r:
        return f"deleted note(s) {', '.join(str(i) for i in r['deleted'])}; {r['remaining']} left"
    n = r["note"]
    where = f"{n['addr']} {n.get('function') or ''}".strip() or "(general)"
    out = [
        f"note #{n['id']} [{n['tag']}] {where}",
        f"  {n['text']}",
    ]
    out += _claim_lines(n.get("claims") or [])
    out.append(f"  ({r['total']} total, {r['path']})")
    return "\n".join(out)


def fmt_verify(r: dict[str, Any]) -> str:
    if not r["checked"]:
        return f"(no claims to check; {r['unchecked_notes']} note(s) carry none)"
    head = (
        f"{r['binary']}: {r['status'].upper()} - {r['checked']} finding(s), "
        f"{r['passed']} pass / {r['failed']} fail / {r['unknown']} unknown"
    )
    out = [head]
    for n in r["notes"]:
        where = f"{n.get('addr') or ''} {n.get('function') or ''}".strip() or "(general)"
        out.append(f"  #{n['id']} [{n.get('status')}] {where} - {n.get('text')}")
        out += _claim_lines(n.get("results") or [], "      ")
    if r["failed"]:
        out.append(
            "  a FAIL means the claim no longer holds: re-read the function before trusting it"
        )
    return "\n".join(out)


def fmt_notes(r: dict[str, Any]) -> str:
    if not r["notes"]:
        return f"(no notes matched; {r['total']} stored in {r['path']})"
    out = []
    for n in r["notes"]:
        where = f"{n.get('addr') or ''} {n.get('function') or ''}".strip() or "(general)"
        out.append(f"  #{n['id']} [{n['tag']}] {where}\n      {n['text']}")
    out.append(f"  ({r['count']} shown / {r['total']} total)")
    return "\n".join(out)


def fmt_pdb(r: dict[str, Any]) -> str:
    before, after = r["functions_before"], r["functions_after"]
    if not r["applied"]:
        out = [f"PDB refused: {r['file']} (functions unchanged at {before})"]
        text = (r.get("log") or "").strip()
        if text:
            out += [f"  {line}" for line in text.splitlines()[:6]]
        return chr(10).join(out)
    out = [f"applied {r['file']}: functions {before} -> {after} ({r.get('saved_via') or ''})"]
    for line in (r.get("log") or "").strip().splitlines()[:6]:
        out.append(f"  {line}")
    return chr(10).join(out)


def fmt_types(r: dict[str, Any]) -> str:
    if r.get("dry_run"):
        out = [f"{r['planned']} item(s) planned from {r.get('source') or 'map'} (dry run)"]
        for item in r["items"][:40]:
            out.append(f"  {item['kind'][:4]} {item['target']} = {item['decl']}")
        return "\n".join(out)
    out = [
        f"{r['count']} applied / {len(r['failed'])} failed from {r['source']} "
        f"({r.get('saved_via') or 'not saved'})"
    ]
    for item in r["applied"]:
        detail = item.get("prototype") or item.get("datatype") or ""
        out.append(f"  OK  {item.get('addr') or item.get('target')} -> {detail}")
    for item in r["failed"]:
        out.append(f"  ERR {item.get('target')}: {item.get('error') or item.get('message')}")
    return "\n".join(out)


def fmt_map(r: dict[str, Any]) -> str:
    head = f"{r['from']} -> {r['op']}"
    if r.get("grep"):
        head += f" (grep: {r['grep']})"
    head += f", {r['matched']}/{r['scanned']} function(s), {r['hits']} hit(s), {r['elapsed_ms']}ms"
    if not r["matched"]:
        return f"{head}\n  (nothing matched - widen --from or drop --grep)"
    out = [head]
    for item in r["results"]:
        label = f"  {item.get('addr')} {item.get('name')} ({item.get('size')}b)"
        if item.get("error"):
            out.append(f"{label}\n      error: {item['error']}")
            continue
        out.append(f"{label} {item['hits']} hit(s)")
        for hit in item["hits"]:
            if "line" in hit:
                out.append(f"      {hit['line']}: {str(hit.get('text', ''))[:110]}")
            else:
                out.append(f"      {str(hit.get('text', ''))[:110]}")
    return "\n".join(out)


def fmt_report(r: dict[str, Any]) -> str:
    return r["markdown"].rstrip("\n")


def fmt_cross_xref(r: dict[str, Any]) -> str:
    if not r["binaries"]:
        return f"(no match for {r['query']!r} in {r['searched']} program(s))"
    out = [f"{r['query']} -> {len(r['binaries'])} program(s) of {r['searched']} searched"]
    for b in r["binaries"]:
        if b.get("error"):
            out.append(f"  {b['binary']}: {b['error']}")
            continue
        out.append(f"  {b['binary']}: {b['count']} hit(s)")
        for m in b["matches"][:6]:
            users = ", ".join(str(x.get("function") or x.get("from")) for x in m["refs"][:3]) or "-"
            out.append(f"    {m['addr']}  {m['value'][:70]}")
            out.append(f"      used by: {users}")
    return "\n".join(out)


def fmt_slice(r: dict[str, Any]) -> str:
    if r.get("direction") == "forward":
        head = (
            f"# {r['from']} @ {r['addr']}  reaches {r['total_imports']} import(s) "
            f"via {r['functions_seen']} function(s)"
        )
        if not r.get("reached"):
            return head + chr(10) + "  (reaches no external call within the depth limit)"
        out = [head]
        for item in r["reached"]:
            out.append(f"  {item['import']}  (depth {item['depth']})")
            out.append("    " + " -> ".join(item["path"]))
        return chr(10).join(out)
    if not r["paths"]:
        return f"(nothing calls {r['to']!r})"
    out = []
    for p in r["paths"]:
        tag = "reaches entry" if p["reaches_entry"] else "no entry path"
        out.append(f"{p['function']} @ {p['addr']}  via {p['via']}  [{tag}]")
        if p["path"]:
            out.append("  " + " <- ".join(f"{s['name']}" for s in reversed(p["path"])))
        if p.get("code"):
            out.append("")
            out.append(p["code"])
    return "\n".join(out)


def fmt_similar(r: dict[str, Any]) -> str:
    head = f"{r['target']} @ {r['addr']}  ({r['strings']} strings, {r['imports']} imports)"
    if not r["matches"]:
        return f"{head}\n(no match above threshold in {r['compared']} program(s))"
    out = [head]
    for m in r["matches"]:
        if m.get("error"):
            out.append(f"  {m['binary']}: {m['error']}")
            continue
        out.append(f"  {m['score']:.2f}  {m['binary']}:{m['name']} @ {m['addr']} ({m['size']}b)")
        extra = []
        if m["shared_strings"]:
            extra.append("str: " + ", ".join(str(s)[:30] for s in m["shared_strings"]))
        if m["shared_imports"]:
            extra.append("imp: " + ", ".join(m["shared_imports"]))
        if extra:
            out.append("        " + " | ".join(extra))
    return "\n".join(out)


def fmt_overview(r: dict[str, Any]) -> str:
    if not r["binaries"]:
        return "(project is empty; import something first)"
    out = [f"# {len(r['binaries'])} program(s) in {r['project']}  ({r['elapsed_ms']}ms)"]
    out.append(f"  {'binary':<24} {'fn':>5} {'str':>5} {'imp':>4} {'notes':>5} {'claims':>6}  last")
    for b in r["binaries"]:
        if b.get("error"):
            out.append(f"  {b['binary']:<24} ! {b['error']}")
            continue
        claims = str(b["claims"])
        if b["failing_claims"]:
            claims += f" ({b['failing_claims']} FAIL)"
        last = b.get("last")
        tail = f"{last['op']} {last['summary']}"[:40] if last else "-"
        out.append(
            f"  {b['binary']:<24} {b['functions']:>5} {b['strings']:>5} {b['imports']:>4} "
            f"{b['notes']:>5} {claims:>6}  {tail}"
        )
    return chr(10).join(out)


def fmt_audit(r: dict[str, Any]) -> str:
    head = (
        f"# audit: {r['notes_checked']} note(s) with claims  "
        f"{r['claims']['passed']} ok / {r['claims']['failed']} fail / "
        f"{r['claims']['unknown']} unknown  ({r['elapsed_ms']}ms)"
    )
    if not r["findings"]:
        return head + chr(10) + "every stored claim still holds"
    out = [head]
    for f in r["findings"]:
        out.append(f"  [{f['status'].upper()}] {f['binary']} #{f['id']} {f['function'] or '-'}")
        out.append(f"        {f['text']}")
        for row in f["results"]:
            mark = {True: "OK", False: "FAIL"}.get(row.get("ok"), "??")
            out.append(f"        {mark} {row['claim']} - {row['detail']}")
    return chr(10).join(out)


def fmt_journal(r: dict[str, Any]) -> str:
    if not r["entries"]:
        return "(nothing recorded yet; mutating commands append here automatically)"
    out = [f"# {r['shown']} of {r['total']} entry(s)  {r['path']}"]
    for e in r["entries"]:
        flag = "  ERR" if e.get("error") else ""
        detail = e.get("summary") or e.get("error") or ""
        out.append(f"  {e['at']}  {e['op']:<9} {e.get('binary') or '-':<20} {detail}{flag}")
    return chr(10).join(out)


def fmt_family(r: dict[str, Any]) -> str:
    if not r["clusters"]:
        return "(no family found; lower --min-score)"
    out = []
    for c in r["clusters"]:
        out.append(f"# family of {c['size']}  max_score {c['max_score']}  ({r['elapsed_ms']}ms)")
        for prog in c["programs"]:
            hub = ", ".join(f"{h['name']} x{h['callers']}" for h in prog["hubs"]) or "-"
            out.append(
                f"  {prog['binary']}  {prog['functions']} fn  {prog['strings']} str  "
                f"{prog['imports']} imp  notes {prog['notes']}  [{prog['md5'][:8]}]"
            )
            out.append(f"    hubs  {hub}")
            if prog["tags"]:
                out.append(f"    tags  {', '.join(prog['tags'])}")
        if c["shared_imports"]:
            out.append(f"  shared imports  {', '.join(c['shared_imports'])}")
        if c["shared_strings"]:
            out.append(f"  shared strings  {', '.join(c['shared_strings'])}")
    return chr(10).join(out)


def fmt_campaign(r: dict[str, Any]) -> str:
    out = [
        f"{r['binaries']} program(s) -> {len(r['clusters'])} cluster(s) at min_score {r['min_score']}"
    ]
    for i, c in enumerate(r["clusters"], 1):
        out.append(f"  [{i}] {c['size']} member(s), max {c['max_score']:.2f}")
        out.append("      " + ", ".join(c["members"]))
        if c["shared_imports"]:
            out.append("      imports: " + ", ".join(c["shared_imports"][:6]))
        if c["shared_strings"]:
            out.append("      strings: " + ", ".join(c["shared_strings"][:4]))
    for e in r.get("errors") or []:
        out.append(f"  {e['binary']}: {e['error']}")
    return "\n".join(out)


FORMATTERS = {
    "binaries": fmt_binaries,
    "info": fmt_info,
    "analyze": fmt_analyze,
    "functions": fmt_functions,
    "decompile": fmt_decompile,
    "strings": fmt_strings,
    "scan": fmt_scan,
    "imports": fmt_imports,
    "names": fmt_names,
    "xrefs": fmt_xrefs,
    "graph": fmt_graph,
    "digest": fmt_digest,
    "find": fmt_find,
    "index": fmt_index,
    "diff": fmt_diff,
    "emulate": fmt_emulate,
    "decrypt": fmt_decrypt,
    "patch": fmt_patch,
    "set_type": fmt_set_type,
    "bookmark": fmt_bookmark,
    "note": fmt_note,
    "verify": fmt_verify,
    "notes": fmt_notes,
    "report": fmt_report,
    "map": fmt_map,
    "types": fmt_types,
    "pdb": fmt_pdb,
    "cross_xref": fmt_cross_xref,
    "slice": fmt_slice,
    "similar": fmt_similar,
    "campaign": fmt_campaign,
    "family": fmt_family,
    "journal": fmt_journal,
    "overview": fmt_overview,
    "audit": fmt_audit,
}


# ------------------------------------------------------------- daemon lifecycle


def _ghidra_env_ok() -> bool:
    found = ghidra_dir()
    if found and Path(found).expanduser().is_dir():
        os.environ["GHIDRA_INSTALL_DIR"] = str(Path(found).expanduser())
        return True
    print(
        "ghlab: GHIDRA_INSTALL_DIR is not set (run `ghlab setup --ghidra <dir>`, or export it)",
        file=sys.stderr,
    )
    return False


def cmd_serve(args) -> int:
    from .server import serve

    if not _ghidra_env_ok():
        return 2
    serve(args.host, args.port, args.project_dir, args.project_name)
    return 0


def _rotate_log(path: Path, limit: int = 8 << 20) -> None:
    """Keep one previous log file.

    Rotation happens before the detached daemon opens the log: on Windows an
    open handle cannot be renamed, so the running process must never own it.
    """
    try:
        if not path.exists() or path.stat().st_size <= limit:
            return
        backup = path.with_name(path.name + ".1")
        backup.unlink(missing_ok=True)
        path.replace(backup)
    except OSError:
        pass


def _pidfile(path: Path) -> dict[str, Any]:
    """Read the daemon pidfile; tolerate the old plain-pid format."""
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return {}
    if raw.startswith("{"):
        try:
            return dict(json.loads(raw))
        except json.JSONDecodeError:
            return {}
    return {"pid": int(raw)} if raw.isdigit() else {}


def _check(name: str, ok: bool, detail: str, fix: str = "", warn: bool = False) -> dict[str, Any]:
    return {
        "check": name,
        "status": "ok" if ok else ("warn" if warn else "fail"),
        "detail": detail,
        "fix": "" if ok else fix,
    }


def cmd_doctor(args) -> int:
    """Answer "why does this not work on this machine" before the agent has to ask.

    Every check is local and cheap; none of them starts a JVM. Output is meant to be
    pasted into a bug report, so `--json` carries the same facts.
    """
    checks: list[dict[str, Any]] = []

    env_dir = ghidra_dir()
    source = "env" if os.environ.get("GHIDRA_INSTALL_DIR") else ("setup file" if env_dir else "")
    install = Path(env_dir).expanduser() if env_dir else None
    checks.append(
        _check(
            "GHIDRA_INSTALL_DIR",
            bool(install and install.is_dir()),
            str(install) + f" ({source})" if install else "not set",
            r"run `ghlab setup --ghidra <dir>` (or export GHIDRA_INSTALL_DIR), e.g. 'C:\ghidra_12.2_PUBLIC'",
        )
    )
    headless = install / "support" / "analyzeHeadless" if install else None
    checks.append(
        _check(
            "ghidra launcher",
            bool(headless and headless.exists()),
            str(headless) if headless else "(skipped)",
            "this does not look like a Ghidra install; check the folder contains support/analyzeHeadless",
        )
    )

    java = shutil.which("java") or (
        str(Path(os.environ["JAVA_HOME"]) / "bin" / "java") if os.environ.get("JAVA_HOME") else ""
    )
    checks.append(
        _check(
            "java",
            bool(java and Path(java).exists()),
            java or "not found",
            "install a JDK (Ghidra 12 needs 21+) or set JAVA_HOME",
        )
    )

    have_jpype = have_pyghidra = False
    try:
        import jpype  # noqa: F401

        have_jpype = True
    except Exception:  # noqa: BLE001
        pass
    try:
        import pyghidra  # noqa: F401

        have_pyghidra = True
    except Exception:  # noqa: BLE001
        pass
    checks.append(
        _check(
            "pyghidra + jpype",
            have_jpype and have_pyghidra,
            f"jpype={have_jpype} pyghidra={have_pyghidra} ({sys.executable})",
            "install them offline from the Ghidra bundle: "
            "uv pip install --python <venv> --no-index --find-links <Ghidra>/Ghidra/Features/PyGhidra/pypkg/dist jpype1 pyghidra",
        )
    )

    wheels: list[str] = []
    if install:
        dist = install / "Ghidra" / "Features" / "PyGhidra" / "pypkg" / "dist"
        wheels = [p.name for p in sorted(dist.glob("*.whl"))] if dist.is_dir() else []
    tag = f"cp{sys.version_info.major}{sys.version_info.minor}"
    platform_wheel = any(tag in w or w.endswith("-any.whl") for w in wheels)
    checks.append(
        _check(
            "offline wheels",
            bool(wheels) and platform_wheel,
            f"{len(wheels)} wheel(s)"
            + (f", none for {tag}" if wheels and not platform_wheel else ""),
            f"the bundle has no wheel for {tag}; either use a matching interpreter or install from PyPI",
            warn=True,
        )
    )

    url = (
        getattr(args, "url", None)
        or os.environ.get("GHLAB_URL")
        or f"http://{args.host}:{args.port}/"
    )
    client = Client(url)
    running = False
    detail = f"not reachable at {url}"
    try:
        ping = client.call("ping")
        running = True
        count = ping.get("binaries")
        if isinstance(count, list):  # older daemons answered with the list itself
            count = len(count)
        detail = (
            f"{url} project={ping.get('project')} binaries={count} busy={ping.get('busy') or '-'}"
        )
    except Exception as ex:  # noqa: BLE001
        detail = f"{type(ex).__name__}: {ex}"
    checks.append(
        _check(
            "daemon",
            running,
            detail,
            f"start one: ghlab start --port {args.port} --project-dir <dir> --project-name <name>",
        )
    )

    if running:
        pid_path = Path(args.project_dir).expanduser() / ".ghlab.pid"
        local = _pidfile(pid_path)
        want = session.code_stamp()
        have = local.get("stamp")
        checks.append(
            _check(
                "daemon code",
                have == want,
                f"running={have or 'unknown'} installed={want}",
                "the daemon is on older code; ghlab start restarts it",
                warn=True,
            )
        )

    project = Path(args.project_dir).expanduser()
    writable = False
    try:
        project.mkdir(parents=True, exist_ok=True)
        probe = project / ".ghlab-write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        writable = True
    except OSError as ex:
        detail = f"{project}: {ex}"
    checks.append(
        _check(
            "project dir",
            writable,
            detail if not writable else str(project),
            "pick a writable folder with --project-dir",
        )
    )

    checks.append(
        _check(
            "versions",
            True,
            f"ghlab {__version__} | python {platform.python_version()} | {platform.platform()}",
        )
    )

    failures = [c for c in checks if c["status"] == "fail"]
    if args.json:
        print(json.dumps({"ok": not failures, "checks": checks}, indent=2, ensure_ascii=False))
        return 1 if failures else 0
    mark = {"ok": "ok  ", "warn": "warn", "fail": "FAIL"}
    for c in checks:
        print(f"  {mark[c['status']]}  {c['check']:<20} {c['detail']}")
        if c["fix"]:
            print(f"        -> {c['fix']}")
    if failures:
        print(f"{chr(10)}{len(failures)} check(s) failed")
        return 1
    print(f"{chr(10)}all checks passed")
    return 0


def _mcp_snippet(cfg: dict[str, Any]) -> str:
    """The two config shapes an agent client needs, filled in from this machine."""
    port = int(cfg.get("port") or DEFAULT_PORT)
    known = projects(cfg)
    env: dict[str, str] = {"GHLAB_TIMEOUT": "900", "GHLAB_AUTOSTART": "1"}
    if len(known) > 1:
        # More than one project: the router needs the registry, and a pinned
        # GHLAB_URL would collapse it back to a single daemon.
        env["GHLAB_CONFIG"] = str(config_path())
    else:
        env["GHLAB_URL"] = f"http://{cfg.get('host') or DEFAULT_HOST}:{port}"
        env["GHLAB_PROJECT_DIR"] = str(cfg.get("project_dir") or "")
        env["GHLAB_PROJECT_NAME"] = str(cfg.get("project_name") or "ghlab")
        env["GHLAB_PORT"] = str(port)
    payload: dict[str, Any] = {
        "command": sys.executable,
        "args": ["-m", "ghlab.mcp"],
        "env": env,
    }
    return chr(10).join(
        [
            f"config: {config_path()} ({len(known)} project(s): {', '.join(known)})",
            "pi  (~/.pi/agent/mcp.json):",
            json.dumps({"mcpServers": {"ghlab": {**payload, "exposure": "deferred"}}}, indent=2),
            "",
            "Claude Code / other MCP clients (claude_desktop_config.json shape):",
            json.dumps({"mcpServers": {"ghlab": payload}}, indent=2),
        ]
    )


def cmd_setup(args) -> int:
    """Write ~/.ghlab/config.json so no environment variables are needed.

    `--print-mcp` is the useful half for wiring a *different* agent: it prints the
    config with the real interpreter path, daemon URL and autostart env baked in.
    """
    cfg = load_config()
    changed = False
    if args.ghidra:
        candidate = Path(args.ghidra).expanduser()
        if not (candidate / "support" / "analyzeHeadless").exists():
            print(
                f"ghlab: {candidate} does not look like a Ghidra install "
                "(no support/analyzeHeadless)",
                file=sys.stderr,
            )
            return 2
        cfg["ghidra"] = str(candidate)
        changed = True
    if not args.add_project:
        # --project-dir/--port describe the default project; when adding a project
        # they describe the one being added, so they must not touch the legacy keys.
        for key, value in (
            ("project_dir", args.cfg_project_dir),
            ("project_name", args.cfg_project_name),
            ("port", args.cfg_port),
        ):
            if value:
                cfg[key] = value
                changed = True
    if args.discover is not None:
        roots = [Path(p).expanduser() for p in (args.discover or [Path.home() / "re"])]
        known = projects(cfg)
        found = discover_projects(roots, known=known, base_port=args.add_port)
        if not found:
            print(f"no unregistered Ghidra project under {', '.join(str(r) for r in roots)}")
        for target in found:
            print(f"found {target.name:<12} {target.project_dir}  -> {target.url}")
            if not args.dry_run:
                register_project(
                    target.name,
                    url=target.url,
                    project_dir=target.project_dir,
                    project_name=target.project_name,
                )
        if found and not args.dry_run:
            cfg = load_config()
            changed = True
            print(
                f"registered {len(found)} project(s); run `ghlab start --port <port>` per project"
            )
    if args.add_project:
        port = args.cfg_port or (args.add_port or 0)
        if not port:
            print("ghlab: --add-project needs --port", file=sys.stderr)
            return 2
        url = f"http://{getattr(args, 'host', None) or DEFAULT_HOST}:{port}"
        project_dir = args.cfg_project_dir or str(Path.home() / "re" / "proj")
        project_name = args.cfg_project_name or args.add_project
        register_project(
            args.add_project,
            url=url,
            project_dir=project_dir,
            project_name=project_name,
            make_default=bool(args.default_project),
        )
        cfg = load_config()
        changed = True
        print(f"registered project {args.add_project} -> {url} ({project_name})")
    if args.remove_project:
        if not remove_project(args.remove_project):
            print(f"ghlab: no such project {args.remove_project!r}", file=sys.stderr)
            return 2
        cfg = load_config()
        changed = True
        print(f"removed project {args.remove_project}")
    if args.default_project:
        cfg["default"] = args.default_project
        save_config(cfg)
        changed = True
        print(f"default project = {args.default_project}")
    if changed:
        path = save_config(cfg)
        print(f"wrote {path}")
    if not cfg:
        print("nothing configured yet; try `ghlab setup --ghidra <dir> --project-dir <dir>")
        return 1
    if args.print_mcp or not changed:
        print(_mcp_snippet(cfg))
    else:
        print(f"ghidra      {cfg.get('ghidra') or '(unset)'}")
        print(f"project     {cfg.get('project_dir')} ({cfg.get('project_name')})")
        print(
            f"daemon      http://{cfg.get('host') or DEFAULT_HOST}:{cfg.get('port') or DEFAULT_PORT}/"
        )
        print("next        ghlab start && ghlab doctor")
        print("")
        print(_mcp_snippet(cfg))
    return 0


def _autostart_enabled() -> bool:
    return os.environ.get("GHLAB_AUTOSTART", "").strip().lower() in {"1", "true", "yes", "on"}


def _start_target(target: Any) -> bool:
    """Start a daemon for one configured project (used by --project / autostart)."""
    port = int(str(target.url).rsplit(":", 1)[-1].strip("/") or DEFAULT_PORT)
    args = argparse.Namespace(
        host=str(target.url).split("//")[-1].rsplit(":", 1)[0] or DEFAULT_HOST,
        port=port,
        project_dir=target.project_dir or str(Path.home() / "re" / "proj"),
        project_name=target.project_name or target.name,
        wait=400,
    )
    return cmd_start(args) == 0


def fmt_projects(r: dict[str, Any]) -> str:
    rows = r.get("projects") or []
    if not rows:
        return "no projects configured; run `ghlab setup --ghidra DIR --add-project NAME --port N`"
    out = [f"# {len(rows)} project(s), default = {r.get('default')}"]
    out.append(f"  {'project':<10} {'state':<6} {'binaries':>4}  url / dir")
    for row in rows:
        mark = "*" if row.get("default") else " "
        state = "up" if row.get("alive") else "down"
        count = str(len(row.get("binaries") or []))
        detail = row.get("url") or ""
        if row.get("project_dir"):
            detail += f"  ({row['project_dir']})"
        out.append(f" {mark}{row['project']:<10} {state:<6} {count:>4}  {detail}")
        for name in (row.get("binaries") or [])[:6]:
            out.append(f"      {name}")
        if len(row.get("binaries") or []) > 6:
            out.append(f"      ... +{len(row['binaries']) - 6} more")
    return chr(10).join(out)


def cmd_projects(args) -> int:
    router = from_config(start=_start_target, autostart=_autostart_enabled())
    try:
        payload = router.describe(refresh=args.refresh)
    except RouteError as ex:
        print(f"ghlab: {ex}", file=sys.stderr)
        return 2
    if args.json:
        _print_json(payload)
    else:
        print(fmt_projects(payload))
    return 0


def cmd_start(args) -> int:
    client = Client(f"http://{args.host}:{args.port}/")
    pid_path = Path(args.project_dir).expanduser() / ".ghlab.pid"
    running = client.alive()
    if running:
        info = _pidfile(pid_path)
        want = session.code_stamp()
        have = info.get("stamp")
        if have == want:
            print(f"already up on {args.host}:{args.port} (pid {info.get('pid')}, code {want})")
            return 0
        # a daemon on old code silently answers with old behaviour; restart it
        print(
            f"ghlab: running daemon has code {have or 'unknown'}, installed is {want}; restarting"
        )
        if info.get("pid"):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(int(info["pid"]), 15)
            pid_path.unlink(missing_ok=True)
            for _ in range(60):
                if not Client(f"http://{args.host}:{args.port}/").alive():
                    break
                time.sleep(0.5)
    if not _ghidra_env_ok():
        return 2
    LOGDIR.mkdir(parents=True, exist_ok=True)
    _rotate_log(LOGDIR / "ghlab.log")
    log = open(LOGDIR / "ghlab.log", "ab")  # noqa: SIM115 - handed to the detached child
    cmd = [
        sys.executable,
        "-m",
        "ghlab",
        "serve",
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--project-dir",
        args.project_dir,
        "--project-name",
        args.project_name,
    ]
    kwargs: dict[str, Any] = {
        "stdout": log,
        "stderr": log,
        "stdin": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "nt":
        kwargs["creationflags"] = (
            subprocess.DETACHED_PROCESS
            | subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.CREATE_NO_WINDOW
        )
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(cmd, **kwargs)
    print(f"ghlab: spawning pid {proc.pid}, log {LOGDIR / 'ghlab.log'}")
    deadline = time.time() + args.wait
    while time.time() < deadline:
        if client.alive():
            real = _pidfile(Path(args.project_dir).expanduser() / ".ghlab.pid").get("pid")
            print(f"ready on http://{args.host}:{args.port}/ (pid {real or proc.pid})")
            return 0
        if proc.poll() is not None:
            print(f"ghlab: daemon exited with {proc.returncode}", file=sys.stderr)
            return 3
        print(".", end="", flush=True)
        time.sleep(2)
    print(f"\nghlab: not ready after {args.wait}s", file=sys.stderr)
    return 4


def _port_owner(host: str, port: int) -> int | None:
    """PID listening on host:port, without a psutil dependency."""
    if os.name != "nt":
        return _port_owner_posix(port)
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    needle = f"{host}:{port}"
    for line in out.splitlines():
        if needle in line and "LISTENING" in line:
            tail = line.split()[-1]
            return int(tail) if tail.isdigit() else None
    return None


def _port_owner_posix(port: int) -> int | None:
    """lsof (macOS/BSD) or ss (Linux); both optional, so failure is not fatal."""
    for cmd in (
        ["lsof", "-ti", f"tcp:{port}", "-sTCP:LISTEN"],
        ["ss", "-ltnp", f"sport = :{port}"],
    ):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            line = line.strip()
            if line.isdigit():
                return int(line)
            if "pid=" in line:
                tail = line.split("pid=")[1].split(",")[0]
                if tail.isdigit():
                    return int(tail)
    return None


def _force_kill(pid: int) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
        else:
            os.kill(pid, 9)


def _pidfile_by_port(port: int) -> Path | None:
    """The pidfile whose recorded port matches, or None.

    `stop --port P` used to read the *default* project's pidfile, so stopping a
    throwaway daemon on another port signalled whatever was running there.
    """
    seen: list[Path] = []
    for target in projects(load_config()).values():
        path = Path(target.project_dir).expanduser() / ".ghlab.pid"
        if path in seen:
            continue
        seen.append(path)
        if not path.exists():
            continue
        if int(_pidfile(path).get("port") or 0) == port:
            return path
    return None


def cmd_stop(args) -> int:
    explicit = getattr(args, "project_dir", None)
    pid_path = (
        Path(explicit).expanduser() / ".ghlab.pid" if explicit else _pidfile_by_port(args.port)
    )
    if pid_path is None:
        owner = _port_owner(args.host, args.port)
        if not owner:
            print(f"ghlab: nothing listening on {args.host}:{args.port}")
            return 0
        _force_kill(int(owner))
        client = Client(f"http://{args.host}:{args.port}/")
        for _ in range(40):
            if not client.alive():
                break
            time.sleep(0.25)
        print(f"ghlab: killed pid {owner} holding {args.host}:{args.port} (no pidfile)")
        return 0 if not client.alive() else 1
    if not pid_path.exists():
        print("ghlab: no pidfile; nothing to stop")
        return 0
    info = _pidfile(pid_path)
    if not info.get("pid"):
        print("ghlab: pidfile is unreadable; nothing to stop")
        pid_path.unlink(missing_ok=True)
        return 0
    pid = int(info["pid"])
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        print(f"ghlab: pid {pid} already gone")
    except PermissionError as ex:
        print(f"ghlab: cannot signal pid {pid}: {ex}", file=sys.stderr)
        return 1
    else:
        print(f"ghlab: signalled pid {pid}")
    # the venv python is a shim that re-execs the real interpreter, so the pid we
    # recorded is the child; wait for the port to actually free, then clean up the
    # shim parent and anything else still holding the port
    client = Client(f"http://{args.host}:{args.port}/")
    for _ in range(30):
        if not client.alive():
            break
        time.sleep(0.5)
    if client.alive():
        for extra in (info.get("parent"), _port_owner(args.host, args.port)):
            if extra and int(extra) != pid:
                _force_kill(int(extra))
        for _ in range(20):
            if not client.alive():
                break
            time.sleep(0.25)
    pid_path.unlink(missing_ok=True)
    if client.alive():
        print(f"ghlab: still answering on {args.host}:{args.port}", file=sys.stderr)
        return 1
    return 0


def cmd_status(args) -> int:
    client = Client(f"http://{args.host}:{args.port}/")
    pid_path = Path(args.project_dir).expanduser() / ".ghlab.pid"
    want = session.code_stamp()
    try:
        info = client.call("ping")
    except Exception as ex:  # noqa: BLE001
        print(f"ghlab: down ({type(ex).__name__}: {ex})")
        return 1
    local = _pidfile(pid_path)
    info["url"] = client.url
    info["code"] = {
        "running": local.get("stamp"),
        "installed": want,
        "stale": bool(local.get("stamp")) and local.get("stamp") != want,
    }
    if args.json:
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return 0
    code = info["code"]
    state = "STALE (restart with `ghlab start`)" if code["stale"] else "current"
    busy = info.get("busy") or {}
    tail = f"  busy={busy['cmd']} {busy.get('elapsed_s')}s" if busy else ""
    print(
        f"up  {client.url}  project={info.get('project')}  "
        f"binaries={info.get('binaries')}  loaded={len(info.get('loaded') or [])}  "
        f"code={code['running'] or 'unknown'} [{state}]{tail}"
    )
    return 0


# --------------------------------------------------------------------- parser


class _Parser(argparse.ArgumentParser):
    """ArgumentParser that suggests a command on a typo instead of dumping 40 choices."""

    def error(self, message: str) -> NoReturn:
        import difflib

        choices: list[str] = []
        for action in self._actions:
            if isinstance(action, argparse._SubParsersAction):
                choices = list(action.choices)
        hit = difflib.get_close_matches(
            message.split("'")[1] if "'" in message else "", choices, n=2
        )
        if hit and "invalid choice" in message:
            message = f"unknown command (did you mean {', '.join(hit)}?)"
        super().error(message)


def build_parser() -> argparse.ArgumentParser:
    common = _Parser(add_help=False)
    common.add_argument("--url", default=os.environ.get("GHLAB_URL"))
    common.add_argument("--json", action="store_true", help="emit raw JSON")

    # Defaults come from `ghlab setup` so a fresh shell (or an agent) needs no flags;
    # anything typed on the command line still wins.
    cfg = load_config()
    daemon = _Parser(add_help=False)
    daemon.add_argument("--host", default=cfg.get("host") or DEFAULT_HOST)
    daemon.add_argument("--port", type=int, default=int(cfg.get("port") or DEFAULT_PORT))
    daemon.add_argument(
        "--project-dir", default=str(cfg.get("project_dir") or (Path.home() / "re" / "proj"))
    )
    daemon.add_argument("--project-name", default=str(cfg.get("project_name") or "ghlab"))

    ap = _Parser(
        prog="ghlab",
        description="Warm Ghidra bridge: persistent headless Ghidra behind a JSON API.",
    )
    ap.add_argument("--version", action="version", version=f"ghlab {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve", parents=[daemon], help="run the daemon in the foreground")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("start", parents=[daemon], help="start the daemon detached")
    p.add_argument("--wait", type=int, default=120)
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("stop", parents=[daemon], help="stop a detached daemon")
    # No inherited default: `stop --port 8766` must not read another project's
    # pidfile and kill that daemon instead (that bug killed a WPS daemon once).
    p.set_defaults(func=cmd_stop, project_dir=None)

    p = sub.add_parser("status", parents=[common, daemon], help="daemon health")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("setup", parents=[common], help="remember this machine's Ghidra + project")
    p.add_argument("--ghidra", help="Ghidra install folder (contains support/analyzeHeadless)")
    p.add_argument("--project-dir", dest="cfg_project_dir", help="where the Ghidra project lives")
    p.add_argument("--project-name", dest="cfg_project_name", help="Ghidra project name")
    p.add_argument("--port", type=int, dest="cfg_port", help="daemon port")
    p.add_argument("--add-project", metavar="NAME", help="register another project (needs --port)")
    p.add_argument("--add-port", type=int, help="port of the project being added")
    p.add_argument("--remove-project", metavar="NAME", help="forget a registered project")
    p.add_argument("--default-project", metavar="NAME", help="which project bare commands use")
    p.add_argument(
        "--discover",
        nargs="*",
        metavar="DIR",
        help="find Ghidra projects (*.gpr + *.rep) under DIR (default: ~/re) and register them",
    )
    p.add_argument(
        "--dry-run", action="store_true", help="with --discover: only list what was found"
    )
    p.add_argument("--print-mcp", action="store_true", help="print MCP config snippets and exit")
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser(
        "projects", parents=[common], help="list configured projects, their daemons and binaries"
    )
    p.add_argument("--refresh", action="store_true", help="drop the cached binary lists")
    p.set_defaults(func=cmd_projects, json=False, refresh=False)

    p = sub.add_parser(
        "doctor",
        parents=[daemon],
        help="check this machine: Ghidra, JDK, pyghidra, daemon, project dir",
    )
    p.add_argument("--url", help="daemon URL to probe (default: GHLAB_URL or host:port)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("ping", parents=[common], help="daemon + project summary")
    p.set_defaults(func=lambda a: _call(a, "ping"))

    p = sub.add_parser("binaries", parents=[common], help="list programs")
    p.set_defaults(func=lambda a: _call(a, "binaries"))

    p = sub.add_parser("import", parents=[common], help="import + analyze a binary")
    p.add_argument("path")
    p.add_argument("--no-analyze", action="store_true")
    p.set_defaults(func=lambda a: _call(a, "import", {"path": a.path, "analyze": not a.no_analyze}))

    p = sub.add_parser("analyze", parents=[common], help="re-analyze everything or one address")
    p.add_argument("binary")
    p.add_argument(
        "--addr",
        dest="addr",
        action="append",
        default=[],
        metavar="ADDR",
        help="disassemble and create the function here (repeatable)",
    )
    p.add_argument("--full", action="store_true", help="run the whole auto-analysis again")
    p.set_defaults(
        func=lambda a: _call(a, "analyze", {"binary": a.binary, "addr": a.addr, "full": a.full})
    )

    p = sub.add_parser("info", parents=[common], help="program metadata")
    p.add_argument("binary")
    p.set_defaults(func=lambda a: _call(a, "info", {"binary": a.binary}))

    p = sub.add_parser("functions", parents=[common], help="list functions")
    p.add_argument("binary")
    p.add_argument("-m", "--match", default=None, help="regex on function name")
    p.add_argument("-n", "--limit", type=int, default=60)
    p.set_defaults(
        func=lambda a: _call(
            a, "functions", {"binary": a.binary, "match": a.match, "limit": a.limit}
        )
    )

    p = sub.add_parser("decompile", parents=[common], help="decompile one or many functions")
    p.add_argument("binary")
    p.add_argument("-t", "--target", action="append", default=[], help="symbol or 0xaddr")
    p.add_argument("-m", "--match", default=None, help="regex: decompile every matching function")
    p.add_argument("-g", "--grep", default=None, help="keep only lines matching this regex")
    p.add_argument("-n", "--limit", type=int, default=25, help="max functions")
    p.add_argument("--max-lines", type=int, default=0)
    p.add_argument("--refresh", action="store_true", help="ignore the decompiler cache")
    p.add_argument("--sig", action="store_true", help="signatures only (no decompiler)")
    p.add_argument("--code", action="store_true", help="include full source even when grepping")
    p.add_argument("--callees", action="store_true")
    p.add_argument("--callers", action="store_true")
    p.set_defaults(
        func=lambda a: _call(
            a,
            "decompile",
            {
                "binary": a.binary,
                "targets": a.target or None,
                "match": a.match,
                "grep": a.grep,
                "limit": a.limit,
                "max_lines": a.max_lines,
                "sig": a.sig,
                "include_code": True if (a.code or a.max_lines) else None,
                "include_callees": a.callees,
                "include_callers": a.callers,
            },
        )
    )

    p = sub.add_parser("imports", parents=[common], help="imports with callers and risk group")
    p.add_argument("binary")
    p.add_argument("-m", "--match", help="regex on import or library name")
    p.add_argument("-q", "--query", help="alias for --match")
    p.add_argument("--group", help="only this risk group (inject, network, file, ...)")
    p.add_argument("-n", "--limit", type=int, default=0, help="max rows (0 = all)")
    p.set_defaults(
        func=lambda a: _call(
            a,
            "imports",
            {
                "binary": a.binary,
                "match": a.match,
                "query": a.query,
                "group": a.group,
                "limit": a.limit,
            },
        )
    )

    p = sub.add_parser("names", parents=[common], help="method names from assertion strings")
    p.add_argument("binary")
    p.add_argument("-q", "--query", help="regex on the recovered name")
    p.add_argument("-n", "--limit", type=int, default=200, help="max rows")
    p.add_argument("--min-len", type=int, default=12, help="shortest printable run to consider")
    p.add_argument("--refresh", action="store_true", help="rebuild the cached table")
    p.set_defaults(
        func=lambda a: _call(
            a,
            "names",
            {
                "binary": a.binary,
                "query": a.query,
                "limit": a.limit,
                "min_len": a.min_len,
                "refresh": a.refresh,
            },
        )
    )

    p = sub.add_parser("use", help="set/show the focus binary (then pass '-' as binary)")
    p.add_argument("binary", nargs="?", help="program name, e.g. notepad.exe")
    p.set_defaults(func=cmd_use)

    p = sub.add_parser(
        "scan", parents=[common], help="instructions that touch a struct field offset"
    )
    p.add_argument("binary")
    p.add_argument("offset", help="displacement, e.g. 0x54")
    p.add_argument("--range", default=None, help="0xSTART-0xEND to limit the sweep")
    p.add_argument("--func", dest="in_func", default=None, help="limit to one function")
    p.add_argument("-n", "--limit", type=int, default=60)
    p.add_argument("--op", default=None, help="regex on the mnemonic, e.g. ^MOV")
    p.add_argument("--stack", action="store_true", help="also match [RSP]/[RBP] locals")
    p.add_argument(
        "--imm",
        default=None,
        help="only instructions whose last operand is this immediate (4, 0x4 or 0..5)",
    )
    p.add_argument(
        "--writes",
        action="store_true",
        help="only instructions that write the field (offset in the destination operand)",
    )
    p.add_argument(
        "--sequence",
        action="store_true",
        help="require the listed offsets in this order inside one window (finds struct copies)",
    )
    p.add_argument(
        "--window",
        type=int,
        default=32,
        help="instructions allowed between the offsets (default 32)",
    )
    p.set_defaults(
        func=lambda a: _call(
            a,
            "scan",
            {
                "binary": a.binary,
                "offset": a.offset,
                "range": a.range,
                "func": a.in_func,
                "limit": a.limit,
                "op": a.op,
                "stack": a.stack,
                "imm": a.imm,
                "writes": a.writes,
                "sequence": a.sequence,
                "window": a.window,
            },
        ),
    )

    p = sub.add_parser("xrefs", parents=[common], help="references to address/function")
    p.add_argument("binary")
    p.add_argument("target", nargs="+")
    p.set_defaults(func=lambda a: _call(a, "xrefs", {"binary": a.binary, "targets": a.target}))

    p = sub.add_parser("bytes", parents=[common], help="raw memory")
    p.add_argument("binary")
    p.add_argument("addr")
    p.add_argument("--size", type=int, default=64)
    p.set_defaults(
        func=lambda a: _call(a, "bytes", {"binary": a.binary, "addr": a.addr, "size": a.size})
    )

    p = sub.add_parser("rename", parents=[common], help="rename a function")
    p.add_argument("binary")
    p.add_argument("target")
    p.add_argument("new")
    p.set_defaults(
        func=lambda a: _call(a, "rename", {"binary": a.binary, "target": a.target, "new": a.new})
    )

    p = sub.add_parser("comment", parents=[common], help="set a comment")
    p.add_argument("binary")
    p.add_argument("target")
    p.add_argument("text")
    p.add_argument("--type", default="plate")
    p.set_defaults(
        func=lambda a: _call(
            a,
            "comment",
            {"binary": a.binary, "target": a.target, "text": a.text, "type": a.type},
        )
    )

    p = sub.add_parser("graph", parents=[common], help="call tree, optionally rendered")
    p.add_argument("--format", choices=("dot", "mermaid", "svg"), help="render instead of text")
    p.add_argument("--out", help="write the rendered graph here (svg/dot/mermaid)")
    p.add_argument("binary")
    p.add_argument("target")
    p.add_argument("-d", "--depth", type=int, default=2)
    p.add_argument("--direction", choices=("calling", "called"), default="calling")
    p.set_defaults(
        func=lambda a: _call(
            a,
            "graph",
            {
                "binary": a.binary,
                "target": a.target,
                "depth": a.depth,
                "direction": a.direction,
                "format": a.format,
                "out": a.out,
            },
        )
    )
    p = sub.add_parser("diff", parents=[common], help="compare two programs in the project")
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument(
        "-m", "--match", default=None, help="regex over function names (applied to both)"
    )
    p.add_argument("-n", "--limit", type=int, default=25)
    p.add_argument(
        "--min-score",
        dest="min_score",
        type=float,
        default=0.55,
        help="similarity floor for the last-resort matcher (0-1)",
    )
    p.add_argument(
        "--detail",
        type=int,
        default=0,
        help="include an instruction-level diff for N changed functions",
    )
    p.add_argument(
        "--semantic",
        action="store_true",
        help="also diff what the binaries are made of: imports, strings, constants",
    )
    p.set_defaults(
        func=lambda a: _call(
            a,
            "diff",
            {
                "a": a.a,
                "b": a.b,
                "match": a.match,
                "limit": a.limit,
                "min_score": a.min_score,
                "detail": a.detail,
                "semantic": a.semantic,
            },
        )
    )

    p = sub.add_parser("emulate", parents=[common], help="run a function on the P-code emulator")
    p.add_argument("binary")
    p.add_argument("target")
    p.add_argument(
        "--arg",
        dest="args",
        action="append",
        default=[],
        metavar="V",
        help='repeatable: 123, 0x40, "text", L"wide text", null (string args are placed in memory)',
    )
    p.add_argument("--max-insns", type=int, default=200000)
    p.add_argument("--ms", type=int, default=5000, help="wall-clock budget")
    p.add_argument(
        "--buffer",
        type=int,
        default=0,
        metavar="SIZE",
        help="reserve a zeroed output buffer (read back after the run; pass its address as an arg)",
    )
    p.add_argument(
        "--dump",
        dest="dump",
        action="append",
        default=[],
        metavar="ADDR[:SIZE]",
        help="read this memory range back afterwards (repeatable)",
    )
    p.add_argument(
        "--seed",
        dest="seed",
        action="append",
        default=[],
        metavar="ADDR=HEX",
        help="preload bytes into emulator memory before the run (repeatable)",
    )
    p.add_argument(
        "--stub",
        dest="stub",
        action="append",
        default=[],
        metavar="FN[ARGn=V]=RET",
        help=(
            "skip a call and pretend it returned RET, optionally only when the n-th "
            "integer argument equals V (repeatable, e.g. FUN_x[arg2=0xe000000b]=120)"
        ),
    )
    p.set_defaults(
        func=lambda a: _call(
            a,
            "emulate",
            {
                "binary": a.binary,
                "target": a.target,
                "args": a.args,
                "max_insns": a.max_insns,
                "ms": a.ms,
                "dump": a.dump,
                "buffer": a.buffer,
                "seed": a.seed,
                "stub": a.stub,
            },
        )
    )

    p = sub.add_parser("decrypt", parents=[common], help="break a small blob of ciphertext")
    p.add_argument("binary", nargs="?", help="read the blob from this program's memory")
    p.add_argument("--addr", help="address of the blob (with a binary)")
    p.add_argument("--len", type=int, default=64, help="bytes to read (default 64)")
    p.add_argument("--hex", help="ciphertext as hex, instead of reading memory")
    p.add_argument(
        "--ciphers",
        dest="ciphers",
        action="append",
        default=[],
        metavar="C",
        help="repeatable: xor, add, rot, utf16, base64 (default all)",
    )
    p.add_argument("--min-printable", dest="min_printable", type=float, default=0.85)
    p.add_argument("-n", "--limit", type=int, default=5)
    p.set_defaults(
        func=lambda a: _call(
            a,
            "decrypt",
            {
                "binary": a.binary,
                "addr": a.addr,
                "len": a.len,
                "hex": a.hex,
                "ciphers": a.ciphers,
                "min_printable": a.min_printable,
                "limit": a.limit,
            },
        )
    )

    p = sub.add_parser("digest", parents=[common], help="one-shot triage report")
    p.add_argument("binary")
    p.add_argument("--top", type=int, default=8, help="how many call-graph hubs")
    p.add_argument("--strings", type=int, default=3, help="samples per string kind")
    p.set_defaults(
        func=lambda a: _call(a, "digest", {"binary": a.binary, "top": a.top, "strings": a.strings})
    )

    p = sub.add_parser("index", parents=[common], help="build or reuse the fact index")
    p.add_argument("binary")
    p.add_argument("--refresh", action="store_true", help="rebuild even if it looks fresh")
    p.set_defaults(func=lambda a: _call(a, "index", {"binary": a.binary, "refresh": a.refresh}))

    p = sub.add_parser("find", parents=[common], help="locate candidates by structure")
    p.add_argument("binary")
    p.add_argument(
        "-i",
        "--import",
        dest="import_",
        action="append",
        default=[],
        help="regex on imported symbol names (repeatable)",
    )
    p.add_argument(
        "-s", "--string", action="append", default=[], help="regex on string data (repeatable)"
    )
    p.add_argument(
        "-c", "--calls", action="append", default=[], help="regex on callee names (repeatable)"
    )
    p.add_argument("-n", "--limit", type=int, default=20)
    p.add_argument("--any", action="store_true", help="any filter instead of all")
    p.set_defaults(
        func=lambda a: _call(
            a,
            "find",
            {
                "binary": a.binary,
                "import": a.import_ or None,
                "string": a.string or None,
                "calls": a.calls or None,
                "limit": a.limit,
                "any": a.any,
            },
        )
    )
    p = sub.add_parser("patch", parents=[common], help="overwrite bytes (a real patch)")
    p.add_argument("binary")
    p.add_argument("addr")
    p.add_argument("bytes", nargs="?", help="hex bytes, e.g. 9090 or '90 90'")
    p.add_argument("--nop", type=int, help="write N 0x90 bytes instead")
    p.add_argument("--expect", help="refuse unless the current bytes match this hex")
    p.set_defaults(
        func=lambda a: _call(
            a,
            "patch",
            {
                "binary": a.binary,
                "addr": a.addr,
                "bytes": a.bytes,
                "nop": a.nop,
                "expect": a.expect,
            },
        )
    )

    p = sub.add_parser("set-type", parents=[common], help="apply a prototype or a data type")
    p.add_argument("binary")
    p.add_argument("target", help="function name/address, or a data address")
    p.add_argument("decl", help="'int f(char *s, unsigned n)' or 'char[64]' / 'void*'")
    p.set_defaults(
        func=lambda a: _call(
            a, "set_type", {"binary": a.binary, "target": a.target, "decl": a.decl}
        )
    )

    p = sub.add_parser("bookmark", parents=[common], help="Ghidra bookmarks")
    p.add_argument("binary")
    p.add_argument("--list", dest="action", action="store_const", const="list")
    p.add_argument("--remove", dest="action", action="store_const", const="remove")
    p.add_argument("--addr")
    p.add_argument("--target")
    p.add_argument("--type", default="Note", choices=list(session.BOOKMARK_TYPES))
    p.add_argument("--category")
    p.add_argument("--text", help="bookmark comment")
    p.add_argument("-n", "--limit", type=int, default=100)
    p.set_defaults(
        action="add",
        func=lambda a: _call(
            a,
            "bookmark",
            {
                "binary": a.binary,
                "action": a.action,
                "addr": a.addr,
                "target": a.target,
                "type": a.type,
                "category": a.category,
                "comment": a.text,
                "limit": a.limit,
            },
        ),
    )

    p = sub.add_parser("note", parents=[common], help="record a durable finding")
    p.add_argument("binary")
    p.add_argument("text")
    p.add_argument("--at", help="function name or address")
    p.add_argument("--tag", default="note", help="group findings (auth, crypto, bug, ...)")
    p.add_argument(
        "--delete", type=int, action="append", metavar="ID", help="retract findings by id"
    )
    p.add_argument(
        "-a",
        "--assert",
        dest="assert_",
        action="append",
        metavar="KIND=VALUE",
        help="checkable claim, e.g. const=0x41 / string=Autosave / import=RegSetValueExW",
    )
    p.set_defaults(
        func=lambda a: _call(
            a,
            "note",
            {
                "binary": a.binary,
                "text": a.text,
                "at": a.at,
                "tag": a.tag,
                "assert": a.assert_,
                "delete": a.delete,
            },
        )
    )

    p = sub.add_parser("verify", parents=[common], help="re-check the claims of stored findings")
    p.add_argument("binary")
    p.add_argument("--id", action="append", type=int, help="only these note ids")
    p.set_defaults(func=lambda a: _call(a, "verify", {"binary": a.binary, "id": a.id}))

    p = sub.add_parser("map", parents=[common], help="run one op over many functions, keep hits")
    p.add_argument("binary")
    p.add_argument(
        "--from",
        dest="from_",
        default="all",
        help="all | name:RE | import:RE | calls:RE | string:RE | const:HEX | addr:0x..,0x..",
    )
    p.add_argument(
        "--op",
        default="decompile",
        choices=["decompile", "strings", "imports", "calls", "consts"],
        help="what to collect per function",
    )
    p.add_argument("-g", "--grep", help="regex: keep only matching lines/entries")
    p.add_argument("-n", "--limit", type=int, default=200, help="max functions")
    p.add_argument("--hits", type=int, default=5, help="max hits per function")
    p.set_defaults(
        func=lambda a: _call(
            a,
            "map",
            {
                "binary": a.binary,
                "from": a.from_,
                "op": a.op,
                "grep": a.grep,
                "limit": a.limit,
                "hits": a.hits,
            },
        )
    )

    p = sub.add_parser("notes", parents=[common], help="list recorded findings")
    p.add_argument("binary")
    p.add_argument("--tag")
    p.add_argument("--at")
    p.add_argument("-q", "--query")
    p.add_argument("-n", "--limit", type=int, default=200)
    p.set_defaults(
        func=lambda a: _call(
            a,
            "notes",
            {"binary": a.binary, "tag": a.tag, "at": a.at, "query": a.query, "limit": a.limit},
        )
    )

    p = sub.add_parser("overview", parents=[common], help="one line per program in the project")
    p.set_defaults(func=lambda a: _call(a, "overview", {}))

    p = sub.add_parser("audit", parents=[common], help="re-check every stored claim")
    p.add_argument("binary", nargs="?", help="limit the audit to one program")
    p.set_defaults(func=lambda a: _call(a, "audit", {"binary": a.binary}))

    p = sub.add_parser("journal", parents=[common], help="what has been changed, and when")
    p.add_argument("--binary")
    p.add_argument("--op", help="only this operation (rename, patch, note, ...)")
    p.add_argument("--since", help="ISO date prefix, e.g. 2026-11-08")
    p.add_argument("-n", "--limit", type=int, default=50)
    p.set_defaults(
        func=lambda a: _call(
            a,
            "journal",
            {"binary": a.binary, "op": a.op, "since": a.since, "limit": a.limit},
        )
    )

    p = sub.add_parser("report", parents=[common], help="markdown report (digest + findings)")
    p.add_argument("binary")
    p.add_argument("--top", type=int, default=6, help="call-graph hubs to include")
    p.set_defaults(func=lambda a: _call(a, "report", {"binary": a.binary, "top": a.top}))

    p = sub.add_parser("types", parents=[common], help="bulk-apply a signature/type map file")
    p.add_argument("binary")
    p.add_argument(
        "--from", dest="from_", required=True, help="map file (.json or `target = decl` text)"
    )
    p.add_argument("--dry-run", action="store_true", help="parse and list, apply nothing")
    p.set_defaults(
        func=lambda a: _call(
            a, "types", {"binary": a.binary, "from": a.from_, "dry_run": a.dry_run}
        )
    )

    p = sub.add_parser("pdb", parents=[common], help="apply a matching PDB (symbols + types)")
    p.add_argument("binary")
    p.add_argument("--file", required=True, help="path to the .pdb that matches this build")
    p.add_argument("--no-untrusted", dest="untrusted", action="store_false")
    p.set_defaults(
        func=lambda a: _call(
            a, "pdb", {"binary": a.binary, "file": a.file, "untrusted": a.untrusted}
        )
    )

    p = sub.add_parser(
        "cross-xref", parents=[common], help="search a string/import across all programs"
    )
    p.add_argument("query", help="regex over string data")
    p.add_argument("--binary", help="restrict to one program")
    p.add_argument("-n", "--limit", type=int, default=20)
    p.set_defaults(
        func=lambda a: _call(
            a, "cross_xref", {"query": a.query, "binary": a.binary, "limit": a.limit}
        )
    )

    p = sub.add_parser("slice", parents=[common], help="shortest call path that reaches an import")
    p.add_argument("binary")
    p.add_argument("to", help="import or function name (regex)")
    p.add_argument(
        "--from", help="stop at a caller matching this (default entry/main/WinMain/DllMain)"
    )
    p.add_argument("-d", "--depth", type=int, default=12)
    p.add_argument("-n", "--limit", type=int, default=4)
    p.add_argument("--code", action="store_true", help="include the caller's decompiled body")
    p.add_argument(
        "--forward",
        action="store_true",
        help="reverse the question: what can `to` reach (imports, with paths)",
    )
    p.set_defaults(
        func=lambda a: _call(
            a,
            "slice",
            {
                "binary": a.binary,
                "to": a.to,
                "from": getattr(a, "from"),
                "depth": a.depth,
                "limit": a.limit,
                "code": a.code or None,
                "direction": "forward" if a.forward else None,
            },
        )
    )

    p = sub.add_parser("similar", parents=[common], help="find the same logic in other programs")
    p.add_argument("binary")
    p.add_argument("target")
    p.add_argument("--against", help="compare against one program instead of all others")
    p.add_argument("-n", "--limit", type=int, default=10)
    p.add_argument("--min-score", type=float, default=0.4)
    p.set_defaults(
        func=lambda a: _call(
            a,
            "similar",
            {
                "binary": a.binary,
                "target": a.target,
                "against": a.against,
                "limit": a.limit,
                "min_score": a.min_score,
            },
        )
    )
    p = sub.add_parser("run", parents=[common], help="replay a script of ghlab commands")
    p.add_argument("path", help=".gh script: one command per line, $VAR from --set, `>` redirects")
    p.add_argument("--set", action="append", default=[], metavar="K=V", help="variable for $K")
    p.add_argument("--keep-going", action="store_true", help="continue after a failing step")
    p.add_argument("--dry-run", action="store_true", help="parse and print the plan only")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("mcp", parents=[common], help="serve MCP over stdio (for agent clients)")
    p.set_defaults(func=cmd_mcp)

    p = sub.add_parser(
        "campaign", parents=[common], help="cluster programs by shared imports/strings"
    )
    p.add_argument("--binary", help="restrict the cluster set to one program")
    p.add_argument("--min-score", type=float, default=0.35)
    p.add_argument("-n", "--limit", type=int, default=0, help="max clusters to show")
    p.set_defaults(
        func=lambda a: _call(
            a, "campaign", {"binary": a.binary, "min_score": a.min_score, "limit": a.limit}
        )
    )

    p = sub.add_parser(
        "family", parents=[common], help="report on one family: profiles, evidence, notes"
    )
    p.add_argument("binary", nargs="?", help="report the family this program belongs to")
    p.add_argument("--min-score", type=float, default=0.35)
    p.add_argument("-n", "--limit", type=int, default=0, help="max families to show")
    p.set_defaults(
        func=lambda a: _call(
            a, "family", {"binary": a.binary, "min_score": a.min_score, "limit": a.limit}
        )
    )

    return ap


def cmd_use(args) -> int:
    if not args.binary:
        print(read_focus() or "ghlab: no focus binary set")
        return 0
    if args.binary == "-":
        print("ghlab: `use -` makes no sense", file=sys.stderr)
        return 2
    write_focus(args.binary)
    print(f"focus = {args.binary}  (pass '-' as the binary to reuse it)")
    return 0


def _call(args, cmd: str, params: dict[str, Any] | None = None) -> int:
    params = {k: v for k, v in (params or {}).items() if v is not None}
    if params.get("binary") == "-":
        focus = read_focus()
        if not focus:
            print("ghlab: no focus binary; run `ghlab use <binary>` first", file=sys.stderr)
            return 2
        params["binary"] = focus
    client = Client(args.url)
    try:
        result = client.call(cmd, **params)
    except RemoteError as ex:
        print(f"ghlab: {ex}", file=sys.stderr)
        if ex.trace and os.environ.get("GHLAB_DEBUG"):
            print(ex.trace, file=sys.stderr)
        return 1
    if getattr(args, "json", False) or cmd not in FORMATTERS:
        _print_json(result)
    else:
        print(FORMATTERS[cmd](result))
    return 0


def cmd_run(a: argparse.Namespace) -> int:
    from . import pipeline

    variables: dict[str, str] = {}
    for item in a.set or []:
        if "=" not in item:
            print(f"ghlab: --set takes K=V, got {item!r}", file=sys.stderr)
            return 2
        key, value = item.split("=", 1)
        variables[key.strip()] = value
    try:
        summary = pipeline.run_file(a.path, variables, keep_going=a.keep_going, dry_run=a.dry_run)
    except pipeline.PipelineError as ex:
        print(f"ghlab: {ex}", file=sys.stderr)
        return 2
    except OSError as ex:
        print(f"ghlab: {ex}", file=sys.stderr)
        return 2
    if a.json:
        _print_json(summary)
    elif summary["dry_run"]:
        print(f"{summary['total']} step(s) planned (dry run)")
    else:
        spent = sum(int(s.get("ms") or 0) for s in summary["steps"])
        ok = summary["ran"] - summary["failed"]
        print(f"{ok}/{summary['total']} steps ok in {spent}ms")
        for s in summary["steps"]:
            if s["status"] == "failed":
                print(f"  line {s['line']}: {s['command']} - {s['error']}")
    return 1 if summary["failed"] else 0


def cmd_mcp(_args: argparse.Namespace) -> int:
    from . import mcp

    return mcp.serve()


def main(argv: list[str] | None = None) -> int:
    # Piped output is UTF-8 (agents, editors); a real console keeps its codepage.
    if not sys.stdout.isatty():
        with contextlib.suppress(Exception):  # a StringIO in tests has no reconfigure
            sys.stdout.reconfigure(encoding="utf-8")  # ty: ignore[unresolved-attribute]
    argv = list(sys.argv[1:] if argv is None else argv)
    # `--json` is accepted before or after the subcommand.
    global_json = "--json" in argv
    if global_json:
        argv = [a for a in argv if a != "--json"]
    parser = build_parser()
    args = parser.parse_args(argv)
    if global_json:
        args.json = True
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
