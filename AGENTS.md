# IDOR agent

AI static analysis that answers one question about a repository: **does it contain an IDOR / broken
object-level authorization, and on which routes?** It uses no running app and no SAST rule engine
(no Semgrep or CodeQL). The only inputs are the route list, grep, file reads, and a local RAG (FAISS) over the repo.

It must work on unknown and legacy code: never assume a framework, a naming convention, or that
conventions are consistent. Learn them from the repo, and trust code over names.

## Layout
| path | what |
|---|---|
| `idor_agent.py` | the agent: briefing → triage → investigate (tool loop) → evidence packs → blind judge → verdict |
| `tools/find_routes.py` | grep-based route candidates for many languages/frameworks (stdlib only) |
| `tools/rag.py` | `index` / `search`: FAISS + local `jina-embeddings-v2-base-code`, language-agnostic chunking |
| `tools/codetools.py` | read-only tools given to the LLM: `grep`, `read_lines`, `list_dir`, `rag_search` |
| `tools/gemini_pool.py` | rotates across every Gemini key × model on the free tier; investigator ≠ judge model |
| `.claude/skills/idor-check/` | how to run an IDOR check on a repo (start here) |
| `.claude/skills/faiss-rag/` | how to build and query the RAG index |
| `.claude/agents/idor-judge.md` | blank Haiku judge for evidence packs (Claude Code runs) |
| `bench/cases.json` | real disclosed IDORs (vulnerable commit + fix commit) for evaluation |

## Setup
```bash
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python faiss-cpu fastembed numpy
cp .env.example .env   # add your Gemini key(s)
```

## Rules for agents working in this repo
1. **Blind judging.** A judge (Gemini call or the `idor-judge` subagent) gets only the evidence pack:
   the route, a neutral description of the codebase, and code excerpts. Never pass it the investigator's verdict
   or reasoning, the advisory, the CVE, or which route is expected.
2. **Generic prompts.** Prompts and tools must not name a specific framework, ORM, column name,
   or known bug. Repo-specific knowledge comes only from the briefing step, which reads the repo.
3. **Evidence or it didn't happen.** Every verdict cites file:line ranges that were actually read.
   Evidence packs are built by the script reading those ranges, not from the model's paraphrase.
4. **Benchmark hygiene (anti-overfitting protocol).**
   - Cases are either **dev** (results already seen) or **held-out** (never run, or run but results not looked at).
     The split is recorded in `bench/split.json`. A held-out case becomes dev the moment its result drives a change.
   - Every change to prompts, tools, or pipeline must be justified by a failure *category* measured without
     the answer key (coverage %, judge confirm rate, tool errors, cost), never by a specific missed route, file,
     framework, or product. Don't put a benchmark app's names, paths, roles, or idioms in any prompt.
   - Freeze the method (git commit), then run the held-out cases once and report that number as the headline.
   - If held-out results lead to another change, the next headline number must come from **fresh** cases
     collected after that change.
   - Measure both sides: recall (known route confirmed on the vulnerable commit) and the control (that route not
     confirmed on the fix commit). Report the other confirmed routes too, as a precision signal.
5. **Cost.** Gemini runs on the free tier through the pool. When a Claude subagent judges, use `model: haiku`
   and give it the packs folder only.
6. Read-only on target repos: never modify, run, or install anything from the repo being analysed.
