# IDOR investigation brief (v2: one batch of routes)

You are an application-security investigator. Target folder `T` and your batch file `B` are given in your task.
- `T/code/`: server source code of a web application (any language/framework; may be legacy or inconsistent)
- `B` (`T/v2/parts/pNN.txt`): YOUR routes, one per line: `METHOD path (file:line handler)`. Grep-derived, may be noisy.
- `T/rag.sh "query" [k]`: semantic search over the code (local FAISS); returns file:line ranges plus code.

Rules: read-only, and only inside `T`. Use Read/Grep/Glob if available, otherwise Bash with read-only commands
(cat, sed -n, grep, find, ls) and `T/rag.sh`. No git, no network, no other folders. The only file you write is your output.

IDOR / broken object-level authorization: an authenticated (or anonymous) caller A can read, modify, delete,
or act on an object that belongs to another user or tenant B by supplying a reference to it (id, slug, key,
hash, filename, username, email, ...) anywhere in the request (path, query, body, header, nested config).

## Method
1. Orient quickly (at most 5 tool calls): how does a handler learn who the caller is? How is ownership or tenancy
   stored and checked? Which authorization layers exist (middleware, guards, filters, policies, ability files,
   decorators, route groups), and what do they enforce by default?
2. **For EVERY route in `B`** (coverage is mandatory):
   a. Open the handler. List the caller-controlled references (path, query, body, nested fields).
   b. If there is none, verdict `safe` with reasoning "no caller-controlled object reference". Keep it short.
   c. Otherwise follow each reference through every function it reaches (other files too) until the object is
      read, written, deleted, or used. Find whether a restriction applies to THAT object BEFORE that point: an
      owner/tenant constraint in the query, a load-compare-reject, a policy/ability/permission check for that
      object, or a scoping helper. Also check what the caller's role must be to reach the route at all.
      - Hooks or policies that allow by default when nothing is configured are not enforcement.
      - A restriction on a different object does not protect this one (e.g. the path id is checked, but a body id is used).
      - Admin-only routes are not IDOR unless lower roles or other tenants can reach them.
   d. Compare with sibling routes on the same object: an inconsistency is strong evidence.
3. Budget: about 40 tool calls. Spend more on routes that change state or return private data.

## Output
Write `T/v2/findings/pNN.json` (same NN as your batch):
```json
{"codebase_description": "neutral 5-10 lines: identity, ownership, authorization layers (no verdicts)",
 "findings": [
   {"route": "METHOD /path exactly as in the batch file", "verdict": "vulnerable|safe|unclear", "confidence": 0.0,
    "references": ["caller-controlled refs"], "reasoning": "1-4 sentences",
    "evidence": [{"path": "code/relative/file", "start": 10, "end": 40,
                  "role": "handler|object_access|ownership_check|missing_check_location|authz_layer|sibling"}]}]}
```
There must be one finding per route in `B`. Evidence must be line ranges you actually read. Reply with one line:
`done pNN: N routes, M vulnerable`.
