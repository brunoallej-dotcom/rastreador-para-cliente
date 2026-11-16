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
