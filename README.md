# IDOR agent

AI static analysis that answers: **does this repository contain an IDOR / broken object-level
authorization, and on which routes?** It uses no running app and no SAST rule engine. The only inputs are
the route list, grep, file reads, and a local RAG index (FAISS) of the repo. Gemini (free tier) does the
reasoning, and an independent blind judge on a different model confirms each finding.

## Requirements
- macOS or Linux, Python **3.12** (3.10+ works for the stdlib tools), `git`
- [`uv`](https://docs.astral.sh/uv/) (recommended), or plain `python -m venv` + `pip`
- A Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey) (the free tier works)
- About 1 GB of disk for the embedding model and indexes. The first index build downloads the model (about 300 MB).

## Setup
```bash
git clone <this repo> idor-agent && cd idor-agent

# 1. Python environment
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements.txt
#   (without uv: python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt)

# 2. API keys
cp .env.example .env
#   edit .env:  GEMINI_API_KEYS=key1,key2
#   Keys from DIFFERENT Google accounts/projects add quota. Keys from the same project share it.

# 3. Smoke test (one tiny Gemini call)
.venv/bin/python tools/gemini_pool.py        # prints: <model> {'ok': 'ok'}
```

## Check a repository
```bash
TARGET=/path/to/repo      # or the server package inside a monorepo
NAME=myrepo

# a) routes: use the generic finder, or supply your own list (one "METHOD /path  (file:line)" per line)
python3 tools/find_routes.py "$TARGET" --json .cache/routes-$NAME.json

# b) RAG index (one per checkout; about 6 min for 3k chunks on a laptop CPU)
.venv/bin/python -I tools/rag.py index "$TARGET" --out .cache/$NAME

# c) run the agent
.venv/bin/python idor_agent.py "$TARGET" \
    --routes .cache/routes-$NAME.json --index .cache/$NAME --out reports/$NAME
```
Steps b and c are optional: without `--index` the agent builds the index itself, and without `--routes` it runs the route finder.

### Output (`reports/<name>/`)
| file | content |
|---|---|
| `verdict.json` | **`idor_found`**, confirmed routes with judge verdicts and evidence, Gemini calls used |
| `findings.json` | the investigator's per-route verdicts, reasoning and cited line ranges |
| `packs/suspect_*.md` | evidence packs the judge saw (code excerpts only, no opinions) |
| `briefing.json` / `triage.json` | how the agent understood the repo's identity/ownership model, and the route groups |
| `run.log` | full progress log |

Runs are **resumable**: rerun the same command with the same `--out`, and the saved briefing, triage and
finished groups are reused, so a quota stop doesn't waste calls.

### Search the index yourself
```bash
.venv/bin/python -I tools/rag.py search .cache/$NAME "check that the order belongs to the current user" -k 8
```

## Using Claude Haiku as the judge (optional)
Inside Claude Code (this repo ships `AGENTS.md`, skills and a judge subagent):
```bash
.venv/bin/python idor_agent.py "$TARGET" --judge none --out reports/$NAME   # writes packs only
```
Then ask Claude Code to *"judge reports/$NAME/packs with the idor-judge agent"*. It runs on Haiku and
sees only the packs folder. See `.claude/skills/idor-check/SKILL.md`.

## Benchmark (real disclosed IDORs)
`bench/cases.json` holds 9 cases (aegra dev case + 8 held-out): Go, Ruby, PHP, Java, Python, TS.
```bash
.venv/bin/python -I bench/prepare.py            # check out vuln/fix commits + build indexes (long, CPU)
.venv/bin/python bench/run_bench.py run --parallel 2
.venv/bin/python bench/run_bench.py score
```
A case passes if a known vulnerable route is confirmed on the vulnerable commit and is not confirmed on the fix commit.

## Gemini free-tier quota
- `tools/gemini_pool.py` rotates across every key × model (strongest first), moves on when a model hits 429/503,
  and remembers today's exhausted pairs in `.cache/gemini_pool.json`. Delete that file to retry all pairs.
- Free limits are per model, per project, per day, on requests **and** input tokens. One mid-size repo took about 100 calls.
  For bigger runs, add keys from other projects, or wait for the daily reset.
- Override the model order with `GEMINI_MODELS=...` in `.env`.

## Layout
```
idor_agent.py            the agent (briefing → triage → investigate → evidence packs → blind judge → verdict)
tools/find_routes.py     grep-based route finder, about 25 frameworks, stdlib only
tools/rag.py             FAISS index/search, local code embeddings, any language
tools/codetools.py       grep / read_lines / list_dir / rag_search exposed to the model
tools/gemini_pool.py     free-tier key × model rotation
bench/                   cases.json, prepare.py, run_bench.py
AGENTS.md, CLAUDE.md     rules for coding agents working here
.claude/skills/          idor-check, faiss-rag
.claude/agents/          idor-judge (Haiku, blind)
```
