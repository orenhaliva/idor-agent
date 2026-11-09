"""Benchmark with Claude subagents (e.g. Haiku) as investigator + blind judge.

  python bench/haiku_flow.py prepare <targets_dir>          # anonymised targets t01..tNN (no git history, neutral names)
  python bench/haiku_flow.py packs   <targets_dir> <tid>    # findings.json -> packs/suspect_*.md (code excerpts only)
  python bench/haiku_flow.py finalize <targets_dir> <tid>   # judge.txt -> reports/bench/<slug>-<kind>/verdict.json

Each target dir holds: code/ (git-archive export of the analysed root), index/ (FAISS copy), routes.txt, rag.sh.
The slug <-> tid mapping is kept in bench/.target_map.json, outside the targets dir, so agents can't see it.
"""
import json
import random
import re
import shutil
import subprocess
import sys
from pathlib import Path

B = Path(__file__).resolve().parent
ROOT = B.parent
sys.path.insert(0, str(B)); sys.path.insert(0, str(ROOT / "tools"))
from prepare import ANALYSIS_ROOT  # noqa: E402

MAP = B / ".target_map.json"
ESCALATE = 0.7                 # v2.4: investigator confidence that sends a judge-not-vulnerable route to the refuter
ESCALATE_VARIANTS = {"v24"}    # escalation only runs for targets mapped to these variants (older runs stay frozen)


RAG_SH = """#!/bin/sh
# usage: ./rag.sh "natural language query" [k]   (every query is logged to v2/rag_log.txt)
d="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$d/v2" && printf '%s\\t%s\\n' "$(date +%s)" "$1" >> "$d/v2/rag_log.txt"
exec "{py}" -I "{rag}" search "$d/index" "$1" -k "${{2:-8}}" 2>/dev/null
"""


def write_rag_sh(t: Path):
    (t / "rag.sh").write_text(RAG_SH.format(py=f"{ROOT}/.venv/bin/python", rag=f"{ROOT}/tools/rag.py"))
    (t / "rag.sh").chmod(0o755)


def check_rag(tdir: Path, tid: str):
    """v2.3: every finding with a caller-controlled reference must cite rag.sh queries that appear in the query log."""
    t = tdir / tid
    log = t / "v2" / "rag_log.txt"
    ran = {l.split("\t", 1)[1].strip() for l in log.read_text().splitlines() if "\t" in l} if log.exists() else set()
    bad_parts = []
    for f in sorted((t / "v2" / "findings").glob("*.json")):
        try:
            fs = json.loads(f.read_text()).get("findings", [])
        except json.JSONDecodeError:
            bad_parts.append(f.stem); continue
        need = [x for x in fs if x.get("references")]
        ok = [x for x in need if any(q.get("query", "").strip() in ran for q in x.get("rag", []) if isinstance(q, dict))]
        rate = len(ok) / len(need) if need else 1.0
        print(f"{tid} {f.stem}: {len(ok)}/{len(need)} findings with refs cite a logged search ({rate:.0%})")
        if rate < 0.8:
            bad_parts.append(f.stem)
    print(f"{tid}: {len(ran)} logged queries; rerun: {' '.join(bad_parts) or 'none'}")


def worktree(slug, kind):
    if slug == "aegra":
        return ROOT.parent / "target" / ("aegra-vuln" if kind == "vuln" else "aegra-fixed")
    return B / "work" / f"{slug}-{kind}"


def prepare(tdir: Path, cases_file: str | None = None):
    """cases_file: bench/cases.json (default) or another case file, e.g. bench/fresh_cases.json (slug/commits/root only)."""
    from prepare import load_cases
    tdir.mkdir(parents=True, exist_ok=True)
    cases = [c["slug"] for c in load_cases(Path(cases_file) if cases_file else B / "cases.json")]
    m = json.loads(MAP.read_text()) if MAP.exists() else {}
    have = {(v["slug"], v["kind"]) for v in m.values()}
    todo = [(s, k) for s in cases for k in ("vuln", "fix") if (s, k) not in have]
    random.Random(42).shuffle(todo)
    n = len(m)
    for slug, kind in todo:
        idx = ROOT / ".cache" / f"{slug}-{kind}"
        root = "." if slug == "aegra" else ANALYSIS_ROOT[slug]  # aegra index was built over the whole repo
        if not (idx / "repo.faiss").exists():
            print(f"skip {slug}-{kind}: index not built yet"); continue
        n += 1
        tid = f"t{n:02d}"
        t = tdir / tid
        if t.exists():
            shutil.rmtree(t)
        (t / "code").mkdir(parents=True)
        tree = "HEAD" if root == "." else f"HEAD:{root}"
        tar = subprocess.run(["git", "-C", str(worktree(slug, kind)), "archive", "--format=tar", tree], capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", str(t / "code")], input=tar, check=True)
        shutil.copytree(idx, t / "index")
        meta = json.loads((t / "index" / "meta.json").read_text()); meta["repo_root"] = "code"
        (t / "index" / "meta.json").write_text(json.dumps(meta))
        rj = t / "routes.json"
        subprocess.run([sys.executable, "-I", str(ROOT / "tools/find_routes.py"), str(t / "code"), "--json", str(rj)], check=True, capture_output=True)
        lines = []
        for r in json.load(open(rj))["candidates"]:
            lines.append(f"{r.get('method') or 'ANY'} {r.get('path') or '<path not extracted>'}  ({r['file']}:{r['line']}"
                         + (f" {r['handler_hint']}" if r.get("handler_hint") else "") + ")")
        if len(lines) < 15:  # routes probably not declared: add convention-routing candidates
            cj = t / "conv.json"
            subprocess.run([sys.executable, "-I", str(ROOT / "tools/convention_routes.py"), str(t / "code"), "--json", str(cj)],
                           check=True, capture_output=True)
            for r in json.load(open(cj))["candidates"]:
                lines.append(f"{r['method']} {r['path']}  ({r['file']}:{r['line']} {r['handler_hint']})")
            cj.unlink()
        (t / "routes.txt").write_text("\n".join(lines) + "\n")
        rj.unlink()
        write_rag_sh(t)
        (t / "rag.sh").chmod(0o755)
        m[tid] = {"slug": slug, "kind": kind}
        MAP.write_text(json.dumps(m, indent=1))
        print(f"{tid}: {len(lines)} routes")


def packs(tdir: Path, tid: str):
    from codetools import CodeTools
    t = tdir / tid
    data = json.loads((t / "findings.json").read_text())
    tools = CodeTools(t / "code")
    out = t / "packs"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir()
    sus = [f for f in data.get("findings", []) if f.get("verdict") in ("vulnerable", "unclear")]
    desc = data.get("codebase_description", "")
    for i, f in enumerate(sus, 1):
        parts = [f"# Route\n{f['route']}\n", f"# Codebase identity/ownership description (neutral)\n{desc}"]
        seen = set()
        for ev in sorted(f.get("evidence", []), key=lambda e: (e.get("path", ""), int(e.get("start", 0)))):
            key = (ev.get("path"), ev.get("start"))
            if key in seen or not ev.get("path"):
                continue
            seen.add(key)
            s = max(1, int(ev["start"]) - 3); e = int(ev.get("end", s)) + 3
            parts.append("# Excerpt\n" + tools.read_lines(ev["path"].removeprefix("code/"), s, min(e, s + 200)))
        (out / f"suspect_{i:02d}.md").write_text("\n\n".join(parts))
    (t / "packs_index.json").write_text(json.dumps({f"suspect_{i:02d}.md": display_route(f) for i, f in enumerate(sus, 1)}, indent=1))
    print(f"{tid}: {len(sus)} packs")


def finalize(tdir: Path, tid: str):
    t = tdir / tid
    m = json.loads(MAP.read_text())[tid]
    data = json.loads((t / "findings.json").read_text())
    idx = json.loads((t / "packs_index.json").read_text()) if (t / "packs_index.json").exists() else {}
    judge = {}
    if (t / "judge.txt").exists():
        for line in (t / "judge.txt").read_text().splitlines():
            mm = re.match(r"\s*(suspect_\d+\.md)\s*\|[^|]*\|\s*(vulnerable|safe|unclear)\b", line, re.I)
            if mm:
                judge[mm.group(1)] = mm.group(2).lower()
    confirmed = [{"route": idx[p], "judge": v} for p, v in judge.items() if v == "vulnerable" and p in idx]
    inv_vuln = [f["route"] for f in data.get("findings", []) if f.get("verdict") == "vulnerable"]
    verdict = {"target": tid, "idor_found": bool(confirmed), "confirmed": confirmed, "investigator_vulnerable": inv_vuln,
               "judge": judge, "routes_investigated": len(data.get("findings", []))}
    out = ROOT / "reports" / "bench" / f"{m['slug']}-{m['kind']}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "verdict.json").write_text(json.dumps(verdict, indent=1))
    print(f"{tid} -> {out.name}: idor_found={verdict['idor_found']} confirmed={len(confirmed)} investigator_vuln={len(inv_vuln)}")


# ---------------------------------------------------------------------------------------------
# v2: full route coverage (deterministic partitions) + refuter with code access
# ---------------------------------------------------------------------------------------------
ROUTE_RE = re.compile(r"(\S+)\s+(\S+)\s+\((\S+?):(\d+)")
VERSION_SEG = re.compile(r"^(api|rest|v\d+(\.\d+)?)$", re.I)


def resource_key(line: str) -> str:
    m = ROUTE_RE.match(line)
    if not m:
        return "~other"
    method, path, file = m.group(1), m.group(2), m.group(3)
    if path.startswith("<"):
        return "file:" + file
    segs = [s for s in path.strip("/").split("/") if s and not VERSION_SEG.match(s)]
    static = [s for s in segs if not re.match(r"^[{:<\[*]", s)]
    return "/".join(static[:2]) if static else "file:" + file


def partition(tdir: Path, tid: str, size: int = 20):
    """Split routes.txt into parts of <= size routes, keeping a resource's routes together. Every route lands in a part."""
    t = tdir / tid
    seen, lines = set(), []
    for l in (t / "routes.txt").read_text().splitlines():
        m = ROUTE_RE.match(l)
        # same METHOD+path in different files are different routes (routers mounted under different prefixes)
        key = (m.group(1), m.group(2), m.group(3)) if m and not m.group(2).startswith("<") else l
        if l.strip() and key not in seen:
            seen.add(key); lines.append(l)
    groups = {}
    for l in lines:
        groups.setdefault(resource_key(l), []).append(l)
    parts, cur = [], []
    for k in sorted(groups):
        g = groups[k]
        if cur and len(cur) + len(g) > size:
            parts.append(cur); cur = []
        while len(g) > size:
            parts.append(g[:size]); g = g[size:]
        cur += g
    if cur:
        parts.append(cur)
    v2 = t / "v2"; (v2 / "parts").mkdir(parents=True, exist_ok=True); (v2 / "findings").mkdir(exist_ok=True)
    for i, p in enumerate(parts, 1):
        (v2 / "parts" / f"p{i:02d}.txt").write_text("\n".join(p) + "\n")
    print(f"{tid}: {len(lines)} unique routes -> {len(parts)} parts")


def fill_missing(tdir: Path, tid: str):
    """Put every routes.txt line that no batch contains into one extra batch (repairs earlier partitions)."""
    t = tdir / tid
    have = set()
    for p in (t / "v2" / "parts").glob("*.txt"):
        have |= {l.strip() for l in p.read_text().splitlines() if l.strip()}
    missing = [l for l in dict.fromkeys(l.strip() for l in (t / "routes.txt").read_text().splitlines()) if l and l not in have]
    if not missing:
        print(f"{tid}: nothing missing"); return
    n = len(list((t / "v2" / "parts").glob("*.txt"))) + 1
    for i in range(0, len(missing), 20):
        (t / "v2" / "parts" / f"p{n:02d}.txt").write_text("\n".join(missing[i:i + 20]) + "\n")
        print(f"{tid}: p{n:02d} with {len(missing[i:i + 20])} missing routes"); n += 1


def handler_file(f: dict) -> str:
    ev = f.get("evidence", []) or []
    h = [e for e in ev if e.get("role") == "handler"] or ev
    return (h[0].get("path", "") if h else "").removeprefix("code/")


def display_route(f: dict) -> str:
    """Route string plus handler file, so identical router-relative strings stay distinct (scorer strips the parens)."""
    hf = handler_file(f)
    return f"{f.get('route', '')}  ({hf})" if hf else f.get("route", "")


def merged_findings(t: Path) -> dict:
    v2 = t / "v2" / "findings"
    if v2.exists() and any(v2.glob("*.json")):
        desc, fs = "", []
        for f in sorted(v2.glob("*.json")):
            try:
                d = json.loads(f.read_text())
            except json.JSONDecodeError:
                print(f"  bad json: {f.name}"); continue
            desc = desc or d.get("codebase_description", "")
            fs += [dict(x, _part=f.stem) for x in d.get("findings", [])]
        # same route string within one part: keep the most severe. Across parts the same relative
        # string ("PATCH /") can be different routes, so parts are never merged together.
        # v2.2: the handler file is part of the key, so "GET /" from two routers in one part stays two findings
        rank = {"vulnerable": 2, "unclear": 1, "safe": 0}
        best = {}
        for f in fs:
            k = (f["_part"], f.get("route", ""), handler_file(f))
            if k not in best or rank.get(f.get("verdict"), 0) > rank.get(best[k].get("verdict"), 0):
                best[k] = f
        return {"codebase_description": desc, "findings": list(best.values())}
    return json.loads((t / "findings.json").read_text())


def packs_v2(tdir: Path, tid: str):
    from codetools import CodeTools
    t = tdir / tid; v2 = t / "v2"
    data = merged_findings(t)
    tools = CodeTools(t / "code")
    out = v2 / "packs"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    sus = [f for f in data["findings"] if f.get("verdict") in ("vulnerable", "unclear")]
    for i, f in enumerate(sus, 1):
        parts = [f"# Route\n{f['route']}\n", f"# Codebase identity/ownership description (neutral)\n{data.get('codebase_description','')}"]
        seen = set()
        for ev in sorted(f.get("evidence", []), key=lambda e: (e.get("path", ""), int(e.get("start", 0) or 0))):
            key = (ev.get("path"), ev.get("start"))
            if key in seen or not ev.get("path"):
                continue
            seen.add(key)
            s = max(1, int(ev.get("start") or 1) - 3); e = int(ev.get("end") or s) + 3
            parts.append("# Excerpt\n" + tools.read_lines(ev["path"].removeprefix("code/"), s, min(e, s + 200)))
        (out / f"suspect_{i:02d}.md").write_text("\n\n".join(parts))
    (v2 / "packs_index.json").write_text(json.dumps({f"suspect_{i:02d}.md": display_route(f) for i, f in enumerate(sus, 1)}, indent=1))
    covered = len(data["findings"])
    total = sum(len(p.read_text().splitlines()) for p in (v2 / "parts").glob("*.txt"))
    print(f"{tid}: coverage {covered}/{total} routes, {len(sus)} packs")


def judge_lines(path: Path, key_re: str) -> dict:
    out = {}
    if path.exists():
        for line in path.read_text().splitlines():
            m = re.match(rf"\s*({key_re})\s*\|[^|]*\|\s*(vulnerable|safe|unclear|upheld|refuted|unsure)\b", line, re.I)
            if m:
                out[m.group(1)] = m.group(2).lower()
    return out


def claims(tdir: Path, tid: str):
    """Routes the blind judge confirmed -> claims.md for the refuter (route + reference + the claim, no excerpts)."""
    t = tdir / tid; v2 = t / "v2"
    idx = json.loads((v2 / "packs_index.json").read_text())
    judge = judge_lines(v2 / "judge.txt", r"suspect_\d+\.md")
    data = {}
    for f in merged_findings(t)["findings"]:  # prefer the vulnerable finding when a route string repeats
        for k in (display_route(f), f["route"]):
            if k not in data or f.get("verdict") == "vulnerable":
                data[k] = f
    # v2.4 disagreement escalation: the judge sees only excerpts, so it can miss context (an object's owner model,
    # a filter whose loosest branch admits other owners). When the investigator, who had the whole repo, said
    # vulnerable with confidence >= ESCALATE and the judge did not, the refuter (full code access) decides.
    variant = json.loads(MAP.read_text()).get(tid, {}).get("variant") if MAP.exists() else None
    esc_min = ESCALATE if variant in ESCALATE_VARIANTS else None
    rows, cmap, escalated = [], {}, []
    for p, verdict in sorted(judge.items()):
        if p not in idx:
            continue
        f = data.get(idx[p], {})
        if verdict != "vulnerable":
            if esc_min is None or f.get("verdict") != "vulnerable" or float(f.get("confidence") or 0) < esc_min:
                continue
            escalated.append(idx[p])
        n = len(rows) + 1
        cmap[f"claim_{n:02d}"] = idx[p]
        rows.append(f"## claim_{n:02d}\nroute: {idx[p]}\ncaller-controlled references: {', '.join(f.get('references', []))}\n"
                    f"claim: {f.get('reasoning', '')}\n")
    (v2 / "claims.md").write_text("# Claims to verify\n\n" + "\n".join(rows))
    (v2 / "claims_index.json").write_text(json.dumps(cmap, indent=1))
    (v2 / "escalated.json").write_text(json.dumps(escalated, indent=1))
    print(f"{tid}: {len(rows)} claims ({len(escalated)} escalated)")


def finalize_v2(tdir: Path, tid: str):
    t = tdir / tid; v2 = t / "v2"
    m = json.loads(MAP.read_text())[tid]
    idx = json.loads((v2 / "packs_index.json").read_text())
    judge = judge_lines(v2 / "judge.txt", r"suspect_\d+\.md")
    cidx = json.loads((v2 / "claims_index.json").read_text()) if (v2 / "claims_index.json").exists() else {}
    refute = judge_lines(v2 / "refute.txt", r"claim_\d+")
    judged_vuln = [idx[p] for p, v in judge.items() if v == "vulnerable" and p in idx]
    data = merged_findings(t)
    files_by_route = {}
    for f in data["findings"]:
        if f.get("verdict") == "vulnerable":
            for k in (f["route"], display_route(f)):
                files_by_route.setdefault(k, set()).update(
                    e.get("path", "").removeprefix("code/") for e in f.get("evidence", []) if e.get("role") in ("handler", "object_access", "missing_check_location"))
    esc = set(json.loads((v2 / "escalated.json").read_text())) if (v2 / "escalated.json").exists() else set()
    confirmed = [{"route": r, "judge": "escalated" if r in esc else "vulnerable", "refuter": refute.get(c),
                  "files": sorted(files_by_route.get(r, []))}
                 for c, r in cidx.items() if refute.get(c) == "upheld"]
    verdict = {"target": tid, "method": "v2", "idor_found": bool(confirmed), "confirmed": confirmed,
               "judge_vulnerable": judged_vuln, "refuted": [r for c, r in cidx.items() if refute.get(c) == "refuted"],
               "investigator_vulnerable": [display_route(f) for f in data["findings"] if f.get("verdict") == "vulnerable"],
               "routes_investigated": len(data["findings"])}
    out = ROOT / "reports" / (f"bench_{m['variant']}" if m.get("variant") else "bench_v2") / f"{m['slug']}-{m['kind']}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "verdict.json").write_text(json.dumps(verdict, indent=1))
    print(f"{tid}: investigated={verdict['routes_investigated']} inv_vuln={len(verdict['investigator_vulnerable'])} "
          f"judge_vuln={len(judged_vuln)} refuted={len(verdict['refuted'])} confirmed={len(confirmed)}")


if __name__ == "__main__":
    cmd, tdir = sys.argv[1], Path(sys.argv[2])
    arg = sys.argv[3] if len(sys.argv) > 3 else None
    {"prepare": lambda: prepare(tdir, arg), "packs": lambda: packs(tdir, arg), "finalize": lambda: finalize(tdir, arg),
     "partition": lambda: partition(tdir, arg), "packs2": lambda: packs_v2(tdir, arg), "claims": lambda: claims(tdir, arg),
     "finalize2": lambda: finalize_v2(tdir, arg), "fill": lambda: fill_missing(tdir, arg),
     "checkrag": lambda: check_rag(tdir, arg), "ragsh": lambda: write_rag_sh(tdir / arg)}[cmd]()
