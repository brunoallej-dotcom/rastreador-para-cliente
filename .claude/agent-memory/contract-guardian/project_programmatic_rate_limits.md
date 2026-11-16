---
name: programmatic-rate-limits
description: Contract 1.0.0-draft.2 marks handler/resolver budgets in x-rate-limit with programmatic:true + group; how to audit them and the known gap in the invariants test
metadata:
  type: project
---

Since contract `1.0.0-draft.2` (branch feat/contract-draft-2, reviewed 2026-11-16), `x-rate-limit`
mixes route rules (no `group`, scope ip/account/user) with programmatic budgets (`programmatic: true`,
`group`): `login` global 300/300 on login + changePassword, `totp-verify-daily` user 20/86400 on
verifyTotp, `session-upstream` ip 60/900 on `components.securitySchemes.sessionCookie`.
Code: `src/modules/identity/presentation/rate-limit-budgets.ts`, `SESSION_UPSTREAM_RULE` in
`src/shared/http/supabase-principal-resolver.ts`; `policy-guard.ts` rejects `global` in route policies.

**Why:** an implementer could hide a route-rule divergence by marking it programmatic.
**How to apply:** compare only non-programmatic entries with `withRoute` policy; check every
programmatic entry maps to a real `consumeGlobalBudget`/`consumeUserBudget` call or the resolver.
Gap found in review and FIXED before merge (#14): `PROGRAMMATIC_BUDGETS` registry plus
`programmatic-budgets.test.ts` (handlers must spend their budget; a static scan forbids other
`consume*Budget` call sites), so the invariants are two-way. Keep it that way.
Also from draft.2 on, 503 is documented on all 22 authenticated ops, so 503 tests must call
`expectToMatchContract` (see [[accepted-contract-gaps]]).
