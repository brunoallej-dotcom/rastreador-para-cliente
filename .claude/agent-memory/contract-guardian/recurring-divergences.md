---
name: recurring-divergences
description: Known and accepted contract divergences (503 not documented, body/query ignored per ADR 0008) and recurring test gaps (Origin/429 tests without expectToMatchContract)
metadata:
  type: project
---

Accepted divergence, do not re-flag as new: infrastructure 503 (limiter or Supabase down, E-21/E-22)
is produced by every authenticated route even where the contract lists no 503 (logout, getSession,
enrollTotp, verifyTotp...). ADR 0008 (status proposed) records that the user chose NOT to change
contract 1.0.0-draft.1. Report it as informational and point to ADR 0008.

**Why:** the user decided to freeze the draft contract. A later minor version may add 503 (user's call).
**How to apply:** list it as a note, not a MÉDIO finding. Routes without a body schema don't read the
body at all, and routes without a query schema ignore unknown query params (same ADR), so 400/413/415
cannot happen there.

Recurring test gap (seen in Wave 5, auth-mfa.api.test.ts): AC-23 Origin 403 tests and secondary
assertions (a later 429, an "indistinguishable 422") check `status`/`code` without
`expectToMatchContract`. Look for `toMatchObject({ code: 'ORIGIN_NOT_ALLOWED' })` without a contract call.

Rate limit groups are named in `RATE_LIMIT_GROUPS` (rate-limiter.ts); every rule in a group must
have the same limit and window as the contract's `x-rate-limit`. Check the group name as well as the numbers.

Seen in Wave 6 (2026-11-16, admin clients): Supabase repositories map 23505 to `ConflictError`
(409 CONFLICT) by copy-paste even when the operation documents no 409 (createClient, updateClient)
and no unique constraint can fire. Grep the repository `refusalOf` for codes not in the operation's
`responses`. Also: contract `1.0.0-draft.2` (separate PR) adds 503 to every authenticated
operation; once merged, E-21 tests must call `expectToMatchContract` and the ADR 0008 skip ends.
