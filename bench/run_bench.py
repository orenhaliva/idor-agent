"""Run the IDOR agent blind on every benchmark case, then score.

  python bench/run_bench.py run   [slug ...] [--kinds vuln fix] [--parallel 2]
  python bench/run_bench.py score

`run` never reads the answer fields of cases.json (routes/files/summary): it only needs slug + paths.
Routes come from the generic tools/find_routes.py, not from the advisory.
"""
import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

B = Path(__file__).resolve().parent
ROOT = B.parent
sys.path.insert(0, str(B))
from prepare import ANALYSIS_ROOT  # noqa: E402


def target(slug, kind):
    if slug == "aegra":
        return ROOT.parent / "target" / ("aegra-vuln" if kind == "vuln" else "aegra-fixed")
    return B / "work" / f"{slug}-{kind}" / ANALYSIS_ROOT[slug]


def run_one(slug, kind):
    repo = target(slug, kind)
    idx = ROOT / ".cache" / (f"aegra-{kind}" if slug == "aegra" else f"{slug}-{kind}")
    routes = ROOT / ".cache" / f"routes-{slug}-{kind}.json"
    subprocess.run([sys.executable, "-I", str(ROOT / "tools/find_routes.py"), str(repo), "--json", str(routes)],
                   check=True, capture_output=True)
    out = ROOT / "reports" / "bench" / f"{slug}-{kind}"
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "stdout.log", "a") as log:
        rc = subprocess.run([str(ROOT / ".venv/bin/python"), str(ROOT / "idor_agent.py"), str(repo), "--routes", str(routes),
                             "--index", str(idx), "--out", str(out)], stdout=log, stderr=subprocess.STDOUT).returncode
    v = out / "verdict.json"
    res = json.loads(v.read_text()) if v.exists() else {}
    print(f"{slug}-{kind}: rc={rc} idor_found={res.get('idor_found')} confirmed={[c['route'] for c in res.get('confirmed', [])]}", flush=True)


def norm(route):
    m, _, p = route.partition(" ")
    p = re.sub(r"\(.*$", "", p).strip().rstrip("/").lower()
    p = re.sub(r"\{[^}]+\}|:[a-z_]+|<[^>]+>|\[[^\]]+\]", "{}", p)
    return m.upper(), p


def matches(expected, got):
    em, ep = norm(expected)
    gm, gp = norm(got)
    # exact after param normalisation; or a prefix-registered route (e.g. PathPrefix("/api/share") + "/{hash}")
    same_path = ep == gp or (gm in ("ANY", "UNKNOWN", "") and ep.startswith(gp + "/{}"))
    # mount prefix the route finder can't see (e.g. framework adds "/api"): expected ends with the found path,
    # and the found path has at least two static segments so "/" or "/{}" never matches everything
    if not same_path and gp.count("/") >= 2 and len([s for s in gp.split("/") if s and s != "{}"]) >= 2:
        same_path = ep.endswith(gp)
    methods = set(gm.replace("|", ",").split(","))  # a route registered for "PATCH,PUT" matches either
    return same_path and (em in methods or gm in ("ANY", "UNKNOWN", ""))


def score(report_dir="bench", cases_file="cases.json"):
    cases = json.load(open(B / cases_file))
    rows, passed = [], 0
    for c in cases:
        res = {}
        for kind in ("vuln", "fix"):
            v = ROOT / "reports" / report_dir / f"{c['slug']}-{kind}" / "verdict.json"
            res[kind] = json.loads(v.read_text()) if v.exists() else None
        if not res["vuln"]:
            rows.append(f"| {c['slug']} | {c['language']} | | not run | | | | |"); continue
        conf_v = [x["route"] for x in res["vuln"].get("confirmed", [])]
        vfiles = [f for f in c.get("vulnerable_files", []) if not re.search(r"(test|spec|CHANGELOG|\.md$)", f)]

        def rel_match(e, x):
            # route finders may emit a router-relative path ("PATCH /") when the mount prefix lives in another file:
            # accept it when the method matches, the expected path ends with it, and a handler file is one the fix changed
            em, ep = norm(e); gm, gp = norm(x["route"])
            files = x.get("files", [])
            same_file = any(vf.endswith(f) or f.endswith(vf.split("/", 1)[-1]) for vf in vfiles for f in files if f)
            return same_file and (em in set(gm.split(",")) or gm in ("ANY", "")) and ep.endswith(gp.rstrip("/"))
        hit = [e for e in c["vulnerable_routes"]
               if any(matches(e, g) for g in conf_v) or any(rel_match(e, x) for x in res["vuln"].get("confirmed", []))]
        conf_f = [x["route"] for x in (res["fix"] or {}).get("confirmed", [])]
        # a fix-commit flag on the known route doesn't count against us if public history shows that route was
        # still exploitable after the fix (a later fix/advisory exists for it): see case["also_real"]
        later = c.get("also_real", {}).get("routes", [])
        still = [e for e in hit if any(matches(e, g) for g in conf_f) and not any(matches(e, l) or matches(l, e) for l in later)]
        ok = bool(hit) and res["fix"] is not None and not still
        passed += ok
        other = [g for g in conf_v if not any(matches(e, g) for e in c["vulnerable_routes"])]
        other_real = [g for g in other if any(matches(l, g) for l in c.get("also_real", {}).get("routes", []))]
        # secondary, looser signal: a confirmed route whose cited handler/object files include a file the fix changed
        def file_hit(x):
            return any(vf.endswith(f) or f.endswith(vf.split("/", 1)[-1]) for vf in vfiles for f in x.get("files", []) if f)
        fh_v = any(file_hit(x) for x in res["vuln"].get("confirmed", []))
        fh_f = any(file_hit(x) for x in (res["fix"] or {}).get("confirmed", []))
        file_col = ("yes" if fh_v else "no") + ("" if res["fix"] is None else (", fix: still" if fh_f else ", fix: clean"))
        inv_v = res["vuln"].get("investigator_vulnerable", [])
        inv_hit = [e for e in c["vulnerable_routes"] if any(matches(e, g) for g in inv_v)]
        rows.append(f"| {c['slug']} | {c['language']} | {len(inv_hit)}/{len(c['vulnerable_routes'])} | {'YES' if hit else 'no'} ({len(hit)}/{len(c['vulnerable_routes'])}) | "
                    f"{'not run' if res['fix'] is None else ('still flagged' if still else 'clean')} | {file_col} | {len(other)} ({len(other_real)} known-real) | {'PASS' if ok else 'fail'} |")
    print("| case | lang | investigator flagged | confirmed on vuln | fixed commit | fix-file confirmed | other confirmed | result |\n|---|---|---|---|---|---|---|---|")
    print("\n".join(rows))
    print(f"\npassed {passed}/{len(cases)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["run", "score"])
    ap.add_argument("slugs", nargs="*")
    ap.add_argument("--kinds", nargs="+", default=["vuln", "fix"])
    ap.add_argument("--parallel", type=int, default=2)
    ap.add_argument("--reports", default="bench")
    ap.add_argument("--cases", default="cases.json")
    a = ap.parse_args()
    if a.cmd == "score":
        score(a.reports, a.cases)
    else:
        slugs = a.slugs or [c["slug"] for c in json.load(open(B / "cases.json"))]
        jobs = [(s, k) for k in a.kinds for s in slugs]
        with ThreadPoolExecutor(a.parallel) as ex:
            list(ex.map(lambda j: run_one(*j), jobs))
