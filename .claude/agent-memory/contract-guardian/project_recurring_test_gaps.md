---
name: recurring-test-contract-gaps
description: Recurring minor divergence - API tests assert a status/body without expectToMatchContract in secondary tests
metadata:
  type: project
---

Recurring (seen in Wave 3, `tests/api/auth-session.api.test.ts` and `auth-logging.api.test.ts`): the main AC tests validate every (operation, status) pair, but secondary tests (edge cases E-11/E-12, logging tests, "body ignored" test, `toMatchObject` on a body) assert `status` or body shape without calling `expectToMatchContract`. Classified BAIXO when the same pair is validated elsewhere; ALTO if a pair is never validated.

Also recurring: Zod for `LoginRequest` normalizes the e-mail (trim/NFC/lowercase, spec E-11) before `z.email()`, so it accepts raw strings with surrounding spaces that JSON Schema `format: email` would reject. Spec-driven leniency, not a divergence.

**Why:** keeps severity consistent between audits.
**How to apply:** in each wave audit, grep `toBe(<status>)` lines and check for a nearby `expectToMatchContract`; report pair-level coverage first, per-assertion gaps as BAIXO.

Wave 8 (admin-processes.api.test.ts) fixed the Origin/415/413/503 gap: every status goes through an
`expectContract` wrapper. Still recurring: no admin API test validates the 429 pair (only auth and
health suites hit RATE_LIMITED); rule equality is proven in `process.handlers.test.ts`. Rate as BAIXO.

Wave 7 (admin-client-users.api.test.ts) follows the same `expectContract` wrapper pattern and is the
first admin suite to validate a 429 pair (provision + reset, shared counter). The 429 pairs of list and
update are still only proven by `client-user.handlers.test.ts`. One stray assertion: a 409 in the E-23
test checks status only, but the pair is validated elsewhere (BAIXO, not worth a finding on its own).

Wave 9 (admin-approvals.api.test.ts, 2026-11-16): same pattern again. The first operation of the pair
(approveCurrentStage) has its 429 validated; the second (listProcessEvents) does not, rule equality only in
`approval.handlers.test.ts` (BAIXO, as in Wave 8). Also recurring: no admin suite asserts
`Cache-Control: no-store` (withRoute sets it, proven in `with-route.test.ts`; expectToMatchContract does
not check it); the `null` arm of a `oneOf [X, null]` problem extension (e.g. `currentStageId`) is only
checked in repository unit tests, never against the contract. 500 is never contract-validated in admin suites.

Update, contract `1.0.0-draft.4` (Wave 10.2, 2026-11-17): `Cache-Control` (enum `no-store`) is now declared
on all 204 (operation, status) pairs and the 13 component responses. The helper treats a declared header
as required unless `required: false`, so every `expectToMatchContract(..., response)` now enforces it: the
Cache-Control gap above is CLOSED. The header components still lack `required: true` (OpenAPI default is
optional), so the contract text is laxer than the helper (BAIXO doc point, not a test gap).
