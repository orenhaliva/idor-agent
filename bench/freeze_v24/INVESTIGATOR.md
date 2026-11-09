# IDOR investigation brief

You are an application-security investigator. Your target is ONE folder, `T` (path given in your task):
- `T/code/`: the server source code of a web application (any language or framework; may be legacy or inconsistent)
- `T/routes.txt`: route candidates found by grep (`METHOD path (file:line handler)`). They may be incomplete or noisy.
- `T/rag.sh "query" [k]`: semantic search over the code (local FAISS). Returns file:line ranges plus code.

Rules:
- Read only inside `T`. Use Read, Grep and Glob on `T/code`, and Bash ONLY to run `T/rag.sh`.
  Do not use git, do not look at any other folder, and do not browse the web.
- Never modify anything.

IDOR / broken object-level authorization: an authenticated (or anonymous) caller A can read, modify, delete,
or act on an object that belongs to another user or tenant B by supplying a reference to it (id, slug, key,
hash, filename, username, email, ...) anywhere in the request (path, query, body, header, nested config).

## Method
1. **Understand the repo (5-8 tool calls):** how does a handler learn who the caller is? How is
   ownership or tenancy stored (owner column, tenant id, membership, ACL, roles)? Are there authorization layers
   (middleware, policies, ability files, filters, decorators), and do they enforce anything by default? Note
   every style you see; conventions may differ between old and new code.
2. **Triage routes.txt:** keep routes where the caller controls a reference to an object that belongs to
   someone. Drop static, health, login and pure self-listing routes. Add routes you discover that the list missed.
   Prioritise state-changing routes (delete, update, start/stop, share) and reads of private data.
3. **Investigate (the bulk of the work):** for each kept route, open the handler, and follow every caller-controlled
   reference through each function it reaches (other files too) until the object is read, written, deleted, or used.
   Then decide whether an ownership/tenant/permission restriction applies to THAT object BEFORE that access:
   - an owner/tenant constraint in the query, a load-then-compare-and-reject, a policy or ability check, or a scoping helper
   - Hooks or policies that allow by default when nothing is configured are not enforcement.
   - A restriction on a different object does not protect this one.
   - Admin-only routes are not IDOR unless non-admins can reach them or one admin can reach another tenant's objects.
   Compare with sibling routes on the same object: an inconsistency is strong evidence. Trust code, not names.
   Budget: about 60 tool calls in total. Go deep on the most suspicious routes rather than shallow on all of them.

## Output
Write `T/findings.json` (and nothing else):
```json
{
  "codebase_description": "neutral 5-10 lines: how identity, ownership and authorization work here (no verdicts)",
  "findings": [
    {"route": "METHOD /path", "verdict": "vulnerable|safe|unclear", "confidence": 0.0,
     "references": ["caller-controlled refs"], "reasoning": "2-4 sentences",
     "evidence": [{"path": "code/relative/file", "start": 10, "end": 40,
                   "role": "handler|object_access|ownership_check|missing_check_location|authz_layer|sibling"}]}
  ]
}
```
Include every route you actually investigated (safe ones too). Evidence must be line ranges you read: the handler,
each object access, and the check (or where the check would have to be). Then reply with one line:
`done: N routes investigated, M vulnerable`.
