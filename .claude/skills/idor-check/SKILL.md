---
name: idor-check
description: Check a source repository for IDOR / broken object-level authorization (BOLA) without running it, using routes + grep + local FAISS RAG + a blind LLM judge. Use when asked whether a repo has an IDOR, to audit authorization on routes, or to run the IDOR benchmark.
---

# Check a repo for IDOR

Answers: **IDOR found? which routes? with what evidence?** Static only: the repo is never run or modified.

## 1. Prerequisites
- `.venv` exists (see AGENTS.md → Setup) and `.env` has `GEMINI_API_KEYS=key1,key2`.
- The target repo is checked out at the commit to analyse. For a benchmark case, check out `vuln_commit` from `bench/cases.json` in its own folder.

## 2. Routes
If the user supplied the route list, save it as `routes.txt` (one `METHOD /path  (file:line)` per line) and pass `--routes`.
Otherwise:
```bash
python3 tools/find_routes.py <repo_or_src_root> --json .cache/routes-<name>.json
```
Skim the summary. If it found few or no routes (an unusual framework), look at how routing works
(`python3 tools/codetools.py` isn't a CLI, so use grep or rag search) and write `routes.txt` by hand.

## 3. RAG index (once per checkout, a few minutes on CPU)
See the `faiss-rag` skill. `idor_agent.py` builds the index itself if it's missing.

## 4. Run the agent
```bash
.venv/bin/python idor_agent.py <repo_or_src_root> --routes <routes file> --index .cache/<name> --out reports/<name>
```
Steps it runs: briefing (1 call), triage (1 call), one tool-loop investigation per object type,
evidence packs, blind Gemini judge on a different model, a tie-break if they disagree, and the verdict.
Progress goes to `reports/<name>/run.log`. Results: `verdict.json`, `findings.json`, `packs/`.

## 5. Optional: Claude Haiku as the blind judge
Run with `--judge none` to only write `reports/<name>/packs/suspect_*.md`. Then dispatch the
`idor-judge` subagent (model haiku) with ONLY the packs folder path. Don't tell it the expected
route, the advisory, or the investigator's verdicts. A route is confirmed when the judge says vulnerable.

## 6. Report back
- Repo verdict: IDOR found / not found.
- Confirmed routes: the missing check, file:line evidence, a one-line exploit.
- Routes the judge rejected (possible false positives) and `unclear` ones.
- Gemini calls used (`pool_calls` in verdict.json).

## Benchmark mode
For each case in `bench/cases.json`: run on `vuln_commit`, then on `fix_commit`. The case passes if
(a) a `vulnerable_routes` entry is confirmed on the vulnerable commit and (b) that route is not confirmed on the fix commit.
Score yourself only after both runs. Don't read the advisory before running.
