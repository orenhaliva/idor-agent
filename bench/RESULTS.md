# IDOR agent: benchmark results (2026-11-09)

**Question:** can an LLM pipeline with no running app and no rule engine find real, disclosed IDORs from the route list,
grep, file reads and a local FAISS RAG?

## Method (v2.2, frozen; hashes in `bench/split.json`)
1. **Routes:** `tools/find_routes.py` greps routes for about 25 frameworks. If it finds fewer than 15, `tools/convention_routes.py` adds convention routes.
2. **Coverage:** routes are split deterministically into batches of 20 or fewer, keeping each resource's routes together. Every route must get a verdict, and missed lines are re-queued.
3. **Investigate:** one Claude Haiku subagent per batch (`prompts/investigator.md`). It is read-only inside an anonymised copy (`tNN/code`, no git history, neutral name), with `rag.sh`.
4. **Evidence packs:** a script, not the model, cuts the cited `file:line` ranges into one pack per suspect route.
5. **Blind judge:** a separate Haiku agent sees only the packs (`prompts/judge.md`), never the investigator's verdict.
6. **Refuter:** a Haiku agent with full code access tries to disprove each judged-vulnerable route (`prompts/refuter.md`).
7. **Confirmed:** the judge said vulnerable and the refuter upheld it.

**Pass rule:** a case passes when a known route is confirmed on the vulnerable commit and is not confirmed on the fix commit.

## Anti-overfitting protocol (AGENTS.md rule 4)
- **dev:** results were seen and drove changes. **held-out:** run once on the frozen method. **fresh:** collected by an agent that reported only slugs; never seen before the run.
- Every method change was justified by a failure category measured without the answer key, and recorded with file hashes:
  - **v2.1:** partition dedup dropped routes (khoj 13, filebrowser 3).
  - **v2.2:** the merge step collapsed identical relative route strings, keeping 207/306 findings on flowise. After the fix it kept 279/306.
- A held-out case whose result drove a change moved to dev: khoj after v2.1, flowise after v2.2.
- **Contamination note:** I saw the held-out route names in the collector's summary. An object-type checklist I drafted echoed them, so I removed it before freezing.

## Results

### Dev + held-out (9 cases)
| case | split | lang | investigator flagged | confirmed on vuln | fix commit | other confirmed | result |
|---|---|---|---|---|---|---|---|
| aegra | dev | Python/FastAPI | 3/3 | 3/3 | clean | 2 (2 known-real) | PASS |
| filebrowser | dev | Go | 1/1 | 1/1 | clean | 2 | PASS |
| netmaker | dev | Go | 1/1 | 1/1 | clean | 11 | PASS |
| publify | dev | Ruby/Rails | 2/2 | 2/2 | clean | 10 (3 known-real) | PASS |
| fat_free_crm | dev | Ruby/Rails | 1/1 | 1/1 | clean | 27 | PASS |
| khoj | dev | Python | (relative path) | 1/1 | clean | 3 | PASS |
| flowise | dev | TypeScript | (relative paths) | 6/6 | clean | 75 | PASS |
| xxl-job | **held-out** | Java | 4/4 | 4/4 | clean | 5 | PASS |
| easyappointments | **held-out** | PHP (legacy) | 0/2 | 0/2 | clean | 13 | fail (label disputed, see below) |

**Dev + held-out: 8 of 9 pass.**

### Fresh cases (headline; never seen before running)
snipe-it, vikunja and wger ran on frozen v2.2. nl-portal, oqtane and spree are the clean v2.3 test (mandatory RAG, see below).

| case | method | lang | investigator flagged | confirmed on vuln | fix commit | other confirmed | result |
|---|---|---|---|---|---|---|---|
| wger | v2.2 | Python/Django | (relative path) | 1/4 | clean | 1 | PASS |
| snipe-it | v2.2 | PHP/Laravel | 3/3 | 0/3 (judge "unclear") | not run | 5 | fail |
| snipe-it (dev re-run) | v2.3 | PHP/Laravel | 3/3 | 3/3 | clean | 14 (6 later fixed upstream) | PASS (dev, not counted) |
| vikunja | v2.2 | Go | 0/1 (v2 route not extracted) | 0/1, same function confirmed on v1 sibling | clean | 2 | fail (file-level hit) |
| oqtane | v2.3 | C#/.NET | (prefix form) | 3/3 | clean | 17 | PASS |
| spree | v2.3 | Ruby/Rails | 1/1 | 0/1 (judge "safe") | not needed | 41 | fail |
| nl-portal | v2.3 | Kotlin/GraphQL | 0/1 (GraphQL mutation not a route) | 0/1 | not needed | 2 | fail |

**Fresh: 2 of 6 pass.** Investigators flagged the known route or function in 5 of 6. The rest were lost at:
- the blind judge in 2 cases (snipe-it v2.2, spree);
- the route finder in 2 cases (vikunja, nl-portal).

### v2.3: mandatory RAG (A/B on snipe-it)
- **Change:** investigators must run `rag.sh` for every referenced object type. Each query is logged, and a batch where fewer than 80% of findings cite a logged query is rerun. Packs gain an `ownership_model` excerpt.
- **Usage:**
  - Under v2.2, 20 of 174 investigators called RAG at all.
  - Under v2.3, every batch is compliant after reruns: snipe-it 263 logged queries, spree 293, oqtane 112 + 98, nl-portal 22 + 21.
- **A/B (snipe-it, same commit, same frozen judge and refuter):**
  - Under v2.2, the judge rated the 3 kit-attach routes "unclear" and none were confirmed.
  - Under v2.3, the packs carried the evidence that licenses, consumables and accessories are company-scoped while kits are global. The judge called all 15 kit routes vulnerable, and the refuters upheld the 3 known POST routes. **Confirmed 3/3.**
  - Snipe-IT is a dev case for v2.3, because its v2.2 failure motivated the change. This result is a diagnostic, not a headline.
  - **Fix-commit control (v2.3, 676 routes, 38 batches, 255 logged RAG queries):** none of the 3 known POST routes is confirmed. **Snipe-IT passes on v2.3** (dev diagnostic).
    - 9 routes are still confirmed on the fix commit. 6 of them are the `PUT .../kits/.../{accessories|consumables|licenses}/{id}` update siblings (API and web). The fix added a `view` check to the `store*` methods but not to `update*`. Upstream added those exact checks later: `0d870d540` (2026-06-08, API) and `095f79484` (2026-08-31, web). They are recorded as `also_real`, so the pipeline found an incomplete fix before upstream did.
    - The other 3 (maintenance asset reassignment, deleting unaccepted-asset acceptances, bulk user consumable cleanup) are unverified.
- **spree miss (v2.3):** the investigator was right (vulnerable, 0.8): any guest cart can be claimed by id. The judge read the lookup filter "cart user is nil OR is the caller" as an ownership check and rated it safe at 0.9. That filter is the bug, because it admits every guest cart. Failure category: **the judge treats a permissive filter as authorization.**

### Why the fresh misses happened (diagnosed after scoring; the method was not changed)
- **snipe-it (PHP/Laravel):**
  - The investigator flagged all 3 known kit-attach routes as vulnerable.
  - The blind judge rated them "unclear": the packs showed the unchecked attach, but not whether licenses, consumables and accessories are company-scoped objects.
  - The refuter never saw them, because only routes the judge calls vulnerable are refuted.
  - Failure category: **the judge lacks context.** The pack has no excerpt that shows the referenced object is tenant-owned.
- **vikunja (Go):**
  - The advisory names a `/api/v2/...` route. The route finder extracted no v2 routes, because they are registered through a different API layer.
  - The pipeline did confirm the `/api/v1` sibling, `POST /api/v1/projects/:project/views/:view/buckets/:bucket/tasks`. It calls the same vulnerable function (`updateTaskBucket` in `kanban_task_bucket.go`), and the refuter traced the same root cause the advisory describes: the request's task ID is never permission-checked.
  - On the fix commit that route is no longer confirmed.
  - Strict scoring counts this as a miss. The file-level column shows a hit that goes clean after the fix.
  - Failure category: **route-finder coverage.**

### Disputed and adjusted labels (all recorded in the case files)
- **easyappointments:** the `oauth()` ownership check the advisory adds already exists at the "vulnerable" commit (`Google.php:452`, since `c8a9e2c2`), so the agent's "safe" verdict there is defensible. Marked `label_disputed`.
- **aegra and publify:** routes still flagged on the fix commit were later fixed upstream (aegra #424/#431; publify `c2e345e1` and GHSA-v3j7-88wx-xf6h). Recorded as `also_real`, so they don't count as false positives.

## What works
- **Discovery is strong.**
  - On every dev and held-out case where the label holds, the investigator flagged the known route.
  - On the fresh cases, it flagged the known route in snipe-it (3/3) and wger, and the same vulnerable function in vikunja.
  - Full-coverage batching matters. Before v2, the single-investigator version covered only 15–57% of routes.
- **The fix-commit control works:** in every case where the known route was confirmed on the vulnerable commit (8 of 8 dev/held-out, plus wger), that route was not confirmed on its fix commit.
- **It is generic:** the same frozen prompts ran on Python, Go, Ruby, Java, TypeScript and PHP apps, including a legacy convention-routed PHP app.

## What doesn't work yet
- **Precision is unmeasured and probably low.**
  - Flowise produced 75 other confirmed routes. Some are clearly real (unscoped credential lookups, workspace deletes), but none were verified.
  - The refuter almost never refutes: 1 of 152 claims on flowise, 3 of 8 on snipe-it. It mostly confirms.
- **The judge's "unclear" is a recall leak** (snipe-it v2.2). Mandatory RAG (v2.3) fixed this case by putting ownership evidence in the packs. v2.4 escalation targets the remaining judge misses.
- **Route-finder gaps:**
  - It misses routes registered through secondary API layers (vikunja v2).
  - It emits ORM `.delete()` calls as routes (flowise: 56 of 306 lines), which multiplies one finding into about 20 packs.
  - It produces router-relative paths ("GET /") when the mount prefix lives in another file.
- **The judge is now the main bottleneck.** In both judge misses (snipe-it v2.2, spree v2.3), the investigator had the right answer. Spree's judge was confidently wrong (safe, 0.9).
- **RAG adoption was solved by enforcement (v2.3), not by suggestion.** Its value showed up as better *evidence for the judge* (ownership context), not as more discovery.
- **Repo-level yes/no is not useful on its own:** almost every commit, fixed or not, has some confirmed routes. Route-level output plus the fix-commit control is what carries signal.

### Spree: full route sweep (after scoring)
- All 544 extracted routes (466 admin, 78 store API) got an investigator verdict: 425 safe, 66 vulnerable, 53 unclear.
- Every controller in the repo maps to an extracted route. The exceptions are abstract base controllers and Devise login/password controllers, whose routes the host app's generator adds; they are out of IDOR scope.
- **Route-finder fix (generic):** Rails `resources ..., controller: 'x'` and `param: :slug` were ignored in the route label, so it read `items#create` instead of `wishlist_items#create`, and `:id` instead of `:slug`. Both are now honoured. Route counts are unchanged on every other Rails target (publify, fat_free_crm). On Spree the investigators had found the right controllers anyway from the route snippet, so no verdict changed.
- The Spree miss is therefore not coverage. The investigator flagged the route; the judge dropped it.

## v2.4 (measured on fresh set #2 below)
Each change targets a failure category seen in the judge misses (snipe-it v2.2 "unclear", spree v2.3 "safe"), not a route:
1. **Disagreement escalation** (`bench/haiku_flow.py`, `ESCALATE = 0.7`): when the investigator, who had the whole repo, says vulnerable with confidence ≥ 0.7 but the blind judge says safe or unclear, the claim still goes to the refuter, which must uphold it. It runs only for targets mapped to variant `v24`, so all scored runs above are unchanged.
   - Cost, measured without the answer key on existing runs: 0–11 extra refuter claims per target (spree 11, oqtane 7, flowise 6, snipe-it v2.3 5).
   - Confirmed routes are tagged `judge: escalated`, so their precision can be measured separately.
2. **Judge rule** (`prompts/judge_v2_4.md`): "a lookup filter is only as strict as its loosest branch". An OR, a fallback, a null/no-owner case, or a shared scope that can match objects the caller does not own does not protect them.

Snipe-IT and Spree are dev cases for v2.4. Its headline number must come from **fresh** cases.

## Fresh set #2: v2.4, frozen (headline)
Six new repos collected by an agent that reported only slugs (`bench/fresh2_cases.json`). The method was frozen before the run
(`bench/freeze_v24/SHA256SUMS`). Both commits of every repo ran the full pipeline: 12 targets, about 160 investigator batches,
all compliant with the RAG rule after reruns.

| case | lang | confirmed on vuln | fix commit | other confirmed (vuln / fix) | result |
|---|---|---|---|---|---|
| convoy | Go/chi | 2/2 | clean | 12 / 12 | **PASS** |
| identrail | Go/gin | 1/2 | clean | 1 / 0 | **PASS** |
| openremote | Java/JAX-RS | 1/1 (`DELETE /alarm`; the `/api/{realm}` mount prefix lives elsewhere) | clean | 16 / 16 | **PASS** |
| mollie-plugin | PHP/Symfony | 2/2 | clean | 3 / 2 | **PASS** |
| lemur | Python/Flask | 1/3 (`/certificates/upload`) | still flagged | 8 / 7 | fail |
| huginn | Ruby/Rails | 0/3 by route; the exact bug confirmed by handler (agents create/update accept another user's service) | clean | 4 / 0 | fail (label) |

**Fresh set #2: 4 of 6 pass** (fresh set #1 on v2.2/v2.3: 2 of 6).
- **lemur:** on the fix commit `/certificates/upload` is still confirmed, but for a different reason (roles attached without a membership check), not the replaced-certificate IDs the fix addressed. Strict scoring counts it as a fail.
- **huginn:** the collector's analysis folder was `app/`, which excludes `config/routes.rb`, so routes were labelled by controller action (`ANY /agents/create`) and do not match `POST /agents`. The confirmed handlers and the clean fix commit show the bug was found; strict scoring counts a fail.
- **v2.4 escalation:** sent 0–8 extra claims per target to the refuter (openremote fix 8). None of the 4 passes depended on it: every known route was called vulnerable by the blind judge itself. Escalated confirmations: 13 of 88 confirmed routes.
- **Method/setup changes made during this run (disclosed):**
  1. Two analysis folders chosen by the collector were too narrow (mollie `src`, openremote `manager/src/main/java`): route files lived outside them. Widened to the repo root, as for earlier cases (`analysis_root_collector` records the original).
  2. Route finder: added declarative YAML/XML route files (Symfony-style `path:` + `controller:`). Mollie went from 9 to 27 routes; counts unchanged on 6 other targets. This was made after seeing the repo's route count, before any result.
  3. Bookkeeping bug: `haiku_flow.py prepare` numbered targets by `len(map)`, which reused an id after entries were removed and overwrote the convoy vuln target mid-run. Fixed (next id = max + 1); convoy vuln was re-run from scratch.
- **Route-finder precision problem (new):** on openremote 504 of 663 extracted "routes" were Java `.put()`/`.get()` calls, which cost about 25 wasted batches per commit. Recall was unaffected.

## Next changes (each needs fresh cases to measure)
1. Done: fresh set #2 on v2.4, 4 of 6 pass (above). The next fresh set must follow the next method change.
2. Route finder: follow secondary routers and API-version groups (vikunja v2), and treat GraphQL mutations and queries as routes (nl-portal).
3. Drop ORM-call false routes (flowise `.delete()`).
4. Measure precision: sample the "other confirmed" routes and verify them by hand or against later upstream fixes, as with snipe-it's `also_real`.

## Cost
All Haiku subagents, run on the Claude Code account:
- about 300 investigator batches across the dev, held-out and fresh runs, each about 110–230k tokens (mostly cached reads). For example, the snipe-it fix commit under v2.3 took 38 batches and about 6.0M subagent tokens;
- judges and refuters about 100–200k tokens each.

Gemini (free tier) was used only in v1, and was limited to about 20 requests per day per model.

## Reproduce
- `bench/prepare.py` or `bench/index_cases.py` (indexes; the fix commit reuses the vuln commit's vectors)
- `bench/haiku_flow.py prepare|partition|fill|packs2|claims|finalize2`
- `bench/run_bench.py score --reports bench_v2 [--cases fresh_cases.json]`

The slug ↔ `tNN` map lives in `bench/.target_map.json`, outside the folder the agents can read.
