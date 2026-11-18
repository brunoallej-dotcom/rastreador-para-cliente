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
`responses`. (Resolved in draft.3, F-51: only P0001 `CLIENT_NAME_TAKEN` maps to 409; a raw 23505 is
500 on purpose. Keep checking other repositories for the copy-paste.) Also: contract `1.0.0-draft.2` (separate PR) adds 503 to every authenticated
operation; once merged, E-21 tests must call `expectToMatchContract` and the ADR 0008 skip ends.

Seen in draft.3 (2026-11-16, F-51): contract prose overclaims normalization. It said the name
comparison "ignora acentos combinantes", but the key is `lower(normalize(name, NFKC))`: it only folds a
decomposed accent into the composed one ("Cafe"+U+0301 = "Café"); "Cafe" and "Café" stay distinct.
When a description explains a matching or normalization rule, check it against the SQL or Zod.

Seen in Wave 8 (2026-11-16, admin processes, contract draft.3): the shared `ServiceUnavailable`
response says idempotent writes (PATCH...) are safe to retry and defers "the other writes" to the
operation description, but operation descriptions stay silent. `createProcess` duplicates on retry
(spec E-21) and a repeated cancel via `updateProcess` is 422 `PROCESS_NOT_ACTIVE` (spec E-60: cancel is
NOT idempotent), yet neither description says so. For every new write op, check its description
states what a retry after 503 returns. Also: `visibleText` (E-30) rejects `\n`/control chars, so long
free-text fields (`StageInput.description`, 2000) refuse multi-line text the contract allows; the
contract never mentions E-30. Report as BAIXO doc gap, not a code bug.

Seen again in Wave 7 (2026-11-16, client logins, draft.3 unchanged): the retry-after-503 gap recurs.
The spec documents it (E-50: a retried provision is 409 `EMAIL_ALREADY_REGISTERED`; E-51/E-53: retried
reset finishes and hands out a NEW password) but the `provisionClientUser`/`resetClientUserPassword`
descriptions are silent. Rated MÉDIO there because the 409-on-own-retry is misleading. The gap keeps
coming back each wave: suggest one contract bump that fixes every write op at once. Also new:
`provisionClientUser` and `resetClientUserPassword` share ONE 20/h counter (`client-user-admin`, spec
§3.9), but the contract lists two independent-looking 20/3600 entries, so a 429 on reset can come from
provisions. Shared counters across different operations are not stated anywhere in `info.description`
(BAIXO doc gap). `visibleText` also requires a letter or digit and refuses zero-width/filler chars,
which `DisplayName` (min 1/max 120) doesn't say.

Route-rule counters are SHARED by group (verified Wave 9): `writes` (user 60/60) = logout + client,
client-user, process writes + approveCurrentStage; `reads` (user 300/60) = getSession + client, client-user,
process reads + listProcessEvents. Numbers match the contract (accepted, ADR 0008), but the contract never
says counters are shared (60 approvals in a minute make logout 429). Report as a draft.4 doc gap, not a
divergence. `z.uuid()` (RFC variant/version bits) is used project-wide where the contract says
`format: uuid` (laxer); informational only.

Same pattern seen again in Wave 10.1 (2026-11-17): a new RPC wrapper (`beginAuthWrite` in the identity
`supabase-account-repository.ts`) reuses the shared `refusalOf`, which maps 23514/22001/INVALID_INPUT to
422. updateClientUser and resetClientUserPassword document no 422. It was unreachable there (fixed
inputs), so BAIXO. Each time a new RPC wrapper shows up, check what `refusalOf` can produce against that
operation's `responses`.
Audit-action leaks: new `audit_events` actions (Wave 10.1: `account.*_intent`, `account.provision_reverted`)
stay out of the process timeline only while `supabase-process-event-queries.ts` keeps both the
`.in('action', PROCESS_EVENT_ACTIONS)` filter and `z.enum(PROCESS_EVENT_ACTIONS)`. Check both whenever a
wave adds an audit action.

Seen in draft.4 (Wave 10.2, 2026-11-17): the new `info.description` "Entrada" section says unknown body
fields and query params are always 400 and "O servidor nunca ignora entrada que não conhece". False for
routes without a query/body schema (ADR 0008, accepted: getHealth ignores query, logout and
resetClientUserPassword ignore the body, getProcess/getMyProcess/getClient ignore query). Rated MÉDIO.
Whenever contract prose generalizes about input handling, check it against ADR 0008 and `validateInput`
(a part without a schema is skipped). Draft.4 also documents the shared `reads`/`writes`/`client-user-admin`
counters in prose (verified exact against the `*_RULE` constants), so the shared-counter doc gap is closed.
Judged documentation-only in draft.4: `deprecated: true` (annotation in JSON Schema 2020-12, Ajv knows it,
no validation effect), `$ref` wrapped in `allOf` to carry a description, declaring an already-emitted
response header. Route rules must keep having NO `group` key in `x-rate-limit` (only programmatic entries
carry `group`), so prose was the right way to document counters.
