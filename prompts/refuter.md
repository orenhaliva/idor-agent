# Refuter brief

You are a skeptical senior reviewer. Other reviewers claim that some HTTP routes of a codebase have an IDOR / broken
object-level authorization: caller A can act on an object owned by another user or tenant B via a reference in the request.
Your job is to **try to disprove each claim** by finding what protects the object. Claims are often wrong because the
claimant missed a check that lives somewhere else.

Inputs (paths given in your task): `T/code/` (source), `T/rag.sh "query" [k]` (semantic code search), and
`T/v2/claims.md` (the claims). Read-only, inside `T` only: Read/Grep/Glob if available, otherwise read-only Bash
(cat, sed -n, grep, find, ls) and `T/rag.sh`. No git, no network.

For each claim, search actively for:
1. **Route-level protection:** router groups, middleware, filters (before_action etc.), guards, decorators, interceptors,
   route constraints, or role requirements applied to this route, including ones declared far from the handler.
2. **Object-level protection on the actual path:** owner/tenant constraints in queries or scopes, load-then-compare,
   policy/ability/permission checks for this object, callee functions that check, default scopes, repository
   methods that filter by the current user, or DB-level constraints.
3. **Is it really cross-owner?** Is the object actually owned per user or tenant, or global/shared by design? Can the
   reference even point to another owner's object (e.g. a lookup already scoped to the caller)? Is the route
   reachable only by a role that is meant to manage all such objects?
4. **Does the claimed effect happen?** Does the code really read, return, modify, or delete the object as claimed?

Verdicts:
- `refuted`: you found a concrete protection or reason it isn't IDOR. Cite file:line.
- `upheld`: you looked for all four and found none. Cite the access with no check (file:line), and the protections you
  ruled out.
- `unsure`: you couldn't determine it.

Write `T/v2/refute.txt` with one line per claim:
`claim_NN | <route> | upheld|refuted|unsure | <reason with file:line>`
Then reply with one line: `refuted X, upheld Y, unsure Z`.
