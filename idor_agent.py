#!/usr/bin/env python3
"""IDOR agent: does this repo contain an IDOR / broken object-level authorization? Which routes?

Inputs : a repo and its routes (a routes file, or tools/find_routes.py output).
Tools  : grep, read_lines, list_dir, rag_search (local FAISS). No running app, no SAST rule engine.
LLM    : Gemini free-tier pool (every key x model), investigator and judge on DIFFERENT models.

Pipeline
  1 briefing      1 call : how does THIS repo identify the caller and store ownership? (any number of styles)
  2 triage        1 call : group routes by the object a caller-controlled reference points to; drop the rest
  3 investigate   tool loop per group: trace each reference to its object access, collect proof of a check or its absence
  4 evidence pack script reads the cited line ranges itself (judge never sees the investigator's opinion)
  5 judge         blank model per suspect route; disagreement -> third model breaks the tie
  6 verdict       repo answer: IDOR found (routes + evidence) / none found

Usage:
  python idor_agent.py <repo_root> [--routes routes.json|routes.txt] [--index .cache/x] [--out reports/x]
                       [--judge gemini|none] [--max-turns 14] [--only-groups N]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "tools"))

from codetools import CodeTools  # noqa: E402
from gemini_pool import GeminiPool, PoolExhausted  # noqa: E402

NO_TOOL_MODELS = ("gemma-4-31b-it",)  # no function calling on these

# ------------------------------------------------------------------------------------------
# prompts (generic: nothing here may name a framework, a naming convention or a specific bug)
# ------------------------------------------------------------------------------------------
IDOR_DEF = """IDOR / broken object-level authorization: an authenticated (or anonymous) caller A can read, \
modify, delete, or act on an object that belongs to another user or tenant B by supplying a reference to it \
(id, slug, key, path, filename, email, ...) anywhere in the request (path, query, body, header, nested config)."""

BRIEFING_SYS = f"""You are a senior application-security engineer onboarding onto an unfamiliar codebase.
{IDOR_DEF}
From the retrieved code, describe how THIS codebase handles identity and object ownership. The code may be
legacy, mix several styles, or have changed conventions over time: list every style you see, do not assume one.
Only state what the code shows; say "unknown" otherwise."""

BRIEFING_SCHEMA = {"type": "object", "properties": {
    "languages_frameworks": {"type": "string"},
    "identity_styles": {"type": "array", "items": {"type": "string"}, "description": "how a handler learns who the caller is, with file:line examples"},
    "ownership_styles": {"type": "array", "items": {"type": "string"}, "description": "how ownership/tenancy is stored and checked, with file:line examples"},
    "authorization_layers": {"type": "array", "items": {"type": "string"}, "description": "middleware/hooks/policies/decorators and whether they enforce anything by default"},
    "data_access_styles": {"type": "array", "items": {"type": "string"}},
    "owned_object_types": {"type": "array", "items": {"type": "string"}, "description": "object types that belong to a user/tenant"},
    "shared_object_types": {"type": "array", "items": {"type": "string"}, "description": "objects intentionally global/shared"},
}, "required": ["languages_frameworks", "identity_styles", "ownership_styles", "authorization_layers",
                "data_access_styles", "owned_object_types", "shared_object_types"]}

TRIAGE_SYS = f"""You triage HTTP routes for an IDOR review. {IDOR_DEF}
Group the routes by the OBJECT TYPE that a caller-controlled reference in the route points to. A route can be in
several groups (e.g. parent and child ids, or an id in the body). Use the route path, handler hint, and the
repository briefing. Keep a route if there is any chance the caller controls an object reference, including
references hidden in the body, query or config. Drop only routes that clearly take no object reference
(health, static, login, pure listing of the caller's own data with no filter input). Use the exact route strings."""

TRIAGE_SCHEMA = {"type": "object", "properties": {
    "groups": {"type": "array", "items": {"type": "object", "properties": {
        "object_type": {"type": "string"},
        "reference_names": {"type": "array", "items": {"type": "string"}},
        "routes": {"type": "array", "items": {"type": "string"}}},
        "required": ["object_type", "reference_names", "routes"]}},
    "dropped": {"type": "array", "items": {"type": "string"}},
}, "required": ["groups", "dropped"]}

INVESTIGATE_SYS = f"""You are an application-security investigator with read-only tools over a source repository.
{IDOR_DEF}

Task: for EACH route in the group, decide whether the caller can reach another owner's object.
Method (do not skip steps):
1. Locate the handler (grep the path literal or handler name; rag_search if routing is indirect).
2. List every caller-controlled object reference the handler receives, including in body/query/config.
3. Follow each reference through EVERY function it is passed to (other files too) until the object is
   read, written, deleted, or used to start work. Read the actual code, don't guess from names.
4. Look for an ownership/tenant restriction that applies to THAT object BEFORE that access: a query constrained
   by owner/tenant, a load-then-compare-and-reject, a policy/permission call that really checks ownership, or a
   scoping helper. Hooks/policies that allow by default when nothing is configured are NOT enforcement.
   A constraint on a DIFFERENT object (e.g. the caller's own new record) does not protect this one.
5. Compare with sibling routes on the same object type: if they restrict and this one doesn't, say so.
Conventions in this repo may be inconsistent; trust code, not names.

Be economical: about {{max_turns}} tool calls for the whole group. When done, call submit_findings exactly once.
For every route give evidence as line ranges you actually read: the handler, each object access, and the
ownership check (or the place it would have to be). Verdicts: vulnerable / safe / unclear."""

SUBMIT_DECL = {"name": "submit_findings", "description": "Submit the final per-route findings for this group. Call exactly once, at the end.",
               "parameters": {"type": "object", "properties": {"findings": {"type": "array", "items": {"type": "object", "properties": {
                   "route": {"type": "string"},
                   "verdict": {"type": "string", "enum": ["vulnerable", "safe", "unclear"]},
                   "confidence": {"type": "number"},
                   "references": {"type": "array", "items": {"type": "string"}},
                   "reasoning": {"type": "string"},
                   "evidence": {"type": "array", "items": {"type": "object", "properties": {
                       "path": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"},
                       "role": {"type": "string", "description": "handler | object_access | ownership_check | missing_check_location | authz_layer | sibling"}},
                       "required": ["path", "start", "end", "role"]}}},
                   "required": ["route", "verdict", "confidence", "references", "reasoning", "evidence"]}}},
                   "required": ["findings"]}}

JUDGE_SYS = f"""You are an independent application-security reviewer. You receive one HTTP route of a codebase,
a neutral description of how the codebase handles identity/ownership, and excerpts of the code on the route's
execution path. {IDOR_DEF}
Decide from the code shown. Hooks/policies that allow by default are NOT enforcement. A restriction on a different
object does not protect this one. If the excerpts are insufficient to decide, answer "unclear"."""

JUDGE_SCHEMA = {"type": "object", "properties": {
    "verdict": {"type": "string", "enum": ["vulnerable", "safe", "unclear"]},
    "confidence": {"type": "number"},
    "object_reference": {"type": "string"},
    "missing_or_present_check": {"type": "string"},
    "evidence": {"type": "string", "description": "file:line citations from the excerpts"},
    "exploit": {"type": "string"}},
    "required": ["verdict", "confidence", "object_reference", "missing_or_present_check", "evidence", "exploit"]}


# ------------------------------------------------------------------------------------------
def load_routes(repo: Path, routes_arg: str | None) -> list[str]:
    if routes_arg:
        p = Path(routes_arg)
        if p.suffix == ".json":
            data = json.loads(p.read_text())
            if isinstance(data, dict):
                data = data.get("candidates") or data.get("routes") or []
            return [route_str(r) for r in data]
        return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]
    out = HERE / ".cache" / f"routes-{repo.name}.json"
    out.parent.mkdir(exist_ok=True)
    subprocess.run([sys.executable, str(HERE / "tools" / "find_routes.py"), str(repo), "--json", str(out)],
                   check=True, stdout=subprocess.DEVNULL)
    return load_routes(repo, str(out))


def route_str(r) -> str:
    if isinstance(r, str):
        return r
    loc = f"  ({r.get('file')}:{r.get('line')}" + (f" {r['handler_hint']}" if r.get("handler_hint") else "") + ")"
    return f"{r.get('method') or 'ANY'} {r.get('path') or '<unknown path>'}{loc}"


def briefing(pool: GeminiPool, tools: CodeTools) -> tuple[dict, str]:
    queries = ["get the current authenticated user from the request / session / token",
               "check that the object belongs to the current user or tenant, otherwise forbidden or not found",
               "authorization policy permission middleware decorator guard",
               "database model with owner user_id tenant_id organization account foreign key",
               "query filtered by user or tenant", "admin role check"]
    ctx = "\n\n".join(f"## rag_search: {q}\n{tools.rag_search(q, 5)}" for q in queries)
    ctx += "\n\n## top-level layout\n" + tools.list_dir("", 2)
    return pool.json_call(BRIEFING_SYS, ctx[:180_000], BRIEFING_SCHEMA)


def triage(pool, brief, routes) -> tuple[dict, str]:
    user = f"## Repository briefing\n{json.dumps(brief, indent=1)}\n\n## Routes ({len(routes)})\n" + "\n".join(routes)
    return pool.json_call(TRIAGE_SYS, user, TRIAGE_SCHEMA)


def investigate(pool: GeminiPool, tools: CodeTools, brief: dict, group: dict, max_turns: int, log) -> tuple[list, str, list]:
    sys_txt = INVESTIGATE_SYS.replace("{max_turns}", str(max_turns))
    user = (f"## Repository briefing\n{json.dumps(brief, indent=1)}\n\n## Group: object type `{group['object_type']}` "
            f"(references: {', '.join(group['reference_names'])})\nRoutes:\n" + "\n".join(f"- {r}" for r in group["routes"]))
    contents = [{"role": "user", "parts": [{"text": user}]}]
    decls = CodeTools.DECLS + [SUBMIT_DECL]
    model_used, trace, last_model = None, [], None
    for turn in range(max_turns + 6):
        force_submit = turn >= max_turns
        body = {"systemInstruction": {"parts": [{"text": sys_txt}]}, "contents": contents,
                "tools": [{"functionDeclarations": [SUBMIT_DECL] if force_submit else decls}],
                "generationConfig": {"temperature": 0}}
        if force_submit:
            contents.append({"role": "user", "parts": [{"text": "Tool budget reached. Call submit_findings now with what you have."}]})
        prune(contents)
        data, model = pool.generate(body, exclude_models=NO_TOOL_MODELS, prefer_model=last_model)
        if last_model and model != last_model:
            # thought signatures are bound to the model that produced them: a new model can't
            # continue the structured history, so hand it the investigation so far as plain text
            log(f"    model switch {last_model} -> {model}: continuing from a text transcript")
            contents[:] = [{"role": "user", "parts": [{"text": user + "\n\n" + flatten(contents[1:])}]}]
            body["contents"] = contents
            data, model = pool.generate(body, exclude_models=NO_TOOL_MODELS, prefer_model=model)
        last_model = model_used = model
        cand = data["candidates"][0].get("content", {"role": "model", "parts": []})
        cand.setdefault("role", "model")
        contents.append(cand)
        calls = [p["functionCall"] for p in cand.get("parts", []) if "functionCall" in p]
        if not calls:
            contents.append({"role": "user", "parts": [{"text": "Continue the investigation using tools, then call submit_findings."}]})
            continue
        responses = []
        for fc in calls:
            name, args = fc["name"], fc.get("args", {})
            if name == "submit_findings":
                log(f"    submit after {turn + 1} turns on {model}")
                return args.get("findings", []), model_used, trace
            out = tools.call(name, args)
            trace.append({"tool": name, "args": args, "chars": len(out)})
            log(f"    {model:<22} {name}({json.dumps(args)[:110]})")
            fr = {"name": name, "response": {"result": out}}
            if fc.get("id"):
                fr["id"] = fc["id"]
            responses.append({"functionResponse": fr})
        contents.append({"role": "user", "parts": responses})
    return [], model_used, trace


def prune(contents: list, keep_last: int = 4, cap: int = 1200):
    """Shrink tool results older than the last `keep_last` tool turns (the model can re-read if needed)."""
    tool_turns = [c for c in contents if any("functionResponse" in p for p in c.get("parts", []))]
    for c in tool_turns[:-keep_last]:
        for p in c["parts"]:
            r = p.get("functionResponse", {}).get("response", {})
            if isinstance(r.get("result"), str) and len(r["result"]) > cap:
                r["result"] = r["result"][:cap] + f"\n... [truncated older result; call the tool again if you need it]"


def flatten(contents: list) -> str:
    """Structured tool-call history -> plain-text transcript (for continuing on another model)."""
    out = ["## Investigation so far (tool calls you already made, with results)"]
    for c in contents:
        for p in c.get("parts", []):
            if "functionCall" in p:
                out.append(f"\n### call {p['functionCall']['name']}({json.dumps(p['functionCall'].get('args', {}))})")
            elif "functionResponse" in p:
                out.append(str(p["functionResponse"]["response"].get("result", ""))[:6000])
            elif p.get("text") and not p.get("thought"):
                out.append(p["text"][:3000])
    out.append("\nContinue from here: make further tool calls if needed, then call submit_findings.")
    return "\n".join(out)


def evidence_pack(tools: CodeTools, route: str, finding: dict, brief: dict) -> str:
    """Built by the script from cited ranges: the judge sees code, never the investigator's verdict or reasoning."""
    parts = [f"# Route\n{route}\n", "# Codebase identity/ownership description (neutral)\n" + json.dumps(
        {k: brief.get(k) for k in ("identity_styles", "ownership_styles", "authorization_layers", "shared_object_types")}, indent=1)]
    seen = set()
    for ev in sorted(finding.get("evidence", []), key=lambda e: (e.get("path", ""), e.get("start", 0))):
        key = (ev.get("path"), ev.get("start"))
        if key in seen or not ev.get("path"):
            continue
        seen.add(key)
        s = max(1, int(ev.get("start", 1)) - 3)
        e = int(ev.get("end", s)) + 3
        parts.append(f"# Excerpt\n{tools.read_lines(ev['path'], s, min(e, s + 220))}")
    return "\n\n".join(parts)


def judge(pool, pack: str, exclude: tuple) -> tuple[dict, str]:
    return pool.json_call(JUDGE_SYS, pack[:120_000], JUDGE_SCHEMA, exclude_models=exclude)


# ------------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--routes")
    ap.add_argument("--index", help="RAG index dir (default: build into .cache/)")
    ap.add_argument("--out", help="report dir (default reports/<repo>-<ts>)")
    ap.add_argument("--judge", choices=["gemini", "none"], default="gemini", help="none = write evidence packs for a Claude/Haiku judge")
    ap.add_argument("--max-turns", type=int, default=14)
    ap.add_argument("--only-groups", type=int, default=0, help="debug: investigate only the first N groups")
    a = ap.parse_args()

    repo = Path(a.repo).resolve()
    out = Path(a.out) if a.out else HERE / "reports" / f"{repo.name}-{time.strftime('%Y%m%d-%H%M%S')}"
    out.mkdir(parents=True, exist_ok=True)
    logf = open(out / "run.log", "a")

    def log(msg):
        print(msg, flush=True)
        logf.write(msg + "\n"); logf.flush()

    from rag import Searcher, build, default_out
    index = Path(a.index) if a.index else default_out(repo)
    if not (index / "repo.faiss").exists():
        log(f"building RAG index -> {index}")
        build(repo, index)
    tools = CodeTools(repo, Searcher(index))
    pool = GeminiPool(verbose=True)

    routes = load_routes(repo, a.routes)
    log(f"routes: {len(routes)}")

    # resumable: reuse saved steps so a crash / quota stop doesn't re-spend calls
    if (out / "briefing.json").exists():
        brief, m = json.loads((out / "briefing.json").read_text()), "cached"
    else:
        brief, m = briefing(pool, tools)
        (out / "briefing.json").write_text(json.dumps(brief, indent=1))
    log(f"[1 briefing] {m}")

    if (out / "triage.json").exists():
        tri, m = json.loads((out / "triage.json").read_text()), "cached"
    else:
        tri, m = triage(pool, brief, routes)
    groups = tri["groups"][: a.only_groups] if a.only_groups else tri["groups"]
    log(f"[2 triage] {m}: {len(tri['groups'])} groups, dropped {len(tri['dropped'])}")
    for g in tri["groups"]:
        log(f"    {g['object_type']}: {len(g['routes'])} routes")
    (out / "triage.json").write_text(json.dumps(tri, indent=1))

    findings = []
    gdir = out / "groups"; gdir.mkdir(exist_ok=True)
    for gi, g in enumerate(groups):
        log(f"[3 investigate] group {gi + 1}/{len(groups)}: {g['object_type']}")
        gfile = gdir / f"{gi:02d}.json"
        if gfile.exists():
            saved = json.loads(gfile.read_text())
            fs, model = saved["findings"], saved["model"]
            log("    (cached)")
        else:
            try:
                fs, model, trace = investigate(pool, tools, brief, g, a.max_turns, log)
            except PoolExhausted as e:
                log(f"    pool exhausted: {e}")
                break
            except Exception as e:  # one broken group must not kill the run
                log(f"    group failed: {type(e).__name__}: {str(e)[:200]}")
                continue
            gfile.write_text(json.dumps({"findings": fs, "model": model, "trace": trace}, indent=1))
        for f in fs:
            f.update(group=g["object_type"], investigator_model=model)
            findings.append(f)
            log(f"    -> {f['verdict']:<10} {f.get('confidence')} {f['route']}")
    (out / "findings.json").write_text(json.dumps(findings, indent=1))

    # merge duplicates (route in several groups): worst verdict wins
    rank = {"vulnerable": 2, "unclear": 1, "safe": 0}
    by_route = {}
    for f in findings:
        cur = by_route.get(f["route"])
        if not cur or rank[f["verdict"]] > rank[cur["verdict"]]:
            by_route[f["route"]] = f
        elif cur and f["route"] == cur["route"] and f is not cur:
            cur.setdefault("evidence", []).extend(f.get("evidence", []))

    suspects = [f for f in by_route.values() if f["verdict"] in ("vulnerable", "unclear")]
    packs_dir = out / "packs"; packs_dir.mkdir(exist_ok=True)
    confirmed = []
    for i, f in enumerate(suspects, 1):
        pack = evidence_pack(tools, f["route"], f, brief)
        (packs_dir / f"suspect_{i:02d}.md").write_text(pack)
        if a.judge == "none":
            continue
        try:
            j1, m1 = judge(pool, pack, exclude=(f["investigator_model"],) + NO_TOOL_MODELS)
            f["judge"] = {**j1, "model": m1}
            if j1["verdict"] != f["verdict"]:
                j2, m2 = judge(pool, pack, exclude=(f["investigator_model"], m1))
                f["tiebreak"] = {**j2, "model": m2}
            final = f["tiebreak"]["verdict"] if "tiebreak" in f else j1["verdict"]
        except PoolExhausted as e:
            log(f"    judge pool exhausted: {e}"); final = "unjudged"
        f["final"] = final
        log(f"[5 judge] {f['route']}: investigator={f['verdict']} judge={f.get('judge', {}).get('verdict')} "
            f"tiebreak={f.get('tiebreak', {}).get('verdict', '-')} => {final}")
        if final == "vulnerable":
            confirmed.append(f)

    verdict = {"repo": str(repo), "idor_found": bool(confirmed) if a.judge != "none" else None,
               "confirmed": [{"route": f["route"], "investigator": f["verdict"], "judge": f.get("judge"),
                              "tiebreak": f.get("tiebreak"), "reasoning": f.get("reasoning")} for f in confirmed],
               "suspects": [f["route"] for f in suspects], "routes_total": len(routes),
               "routes_investigated": len(by_route), "pool_calls": pool.calls}
    (out / "verdict.json").write_text(json.dumps(verdict, indent=1))
    log(f"\n[6 verdict] IDOR found: {verdict['idor_found']}  confirmed={[c['route'] for c in confirmed]}")
    log(f"report: {out}")


if __name__ == "__main__":
    main()
