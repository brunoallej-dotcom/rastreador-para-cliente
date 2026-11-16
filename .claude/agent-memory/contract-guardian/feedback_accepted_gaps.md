---
name: accepted-contract-gaps
description: Known, accepted contract deviations not to re-report (503 infra gap, ignored body/query, rate-limit groups) per ADR 0008
metadata:
  type: feedback
---

Do not re-report these as divergences:

- **503 on infrastructure failure** (ONLY while the contract is `1.0.0-draft.1`; `1.0.0-draft.2` documents 503 on every authenticated op and ADR 0011 partly supersedes ADR 0008, so after it merges a 503 without `expectToMatchContract` is a real gap) (limiter or Supabase down, E-21/E-22) in operations whose `responses` lack 503 (e.g. `logout`, `getSession`). Accepted in `docs/adr/0008-contrato-estrito-e-entrada-nao-declarada.md`; tests intentionally do not run `expectToMatchContract` on those 503s.
- Routes without a body schema do not read the body (no 400/413/415); routes without a query schema ignore unknown params.
- Rate-limit `group` names (`login`, `writes`, `reads`, `health`...) are an implementation detail; compare only scope/limit/windowSeconds against `x-rate-limit`.

**Why:** the user decided not to change contract `1.0.0-draft.1`; the caller restated this when it asked for the Wave 3 audit (2026-11-16).
**How to apply:** check whether ADR 0008 is still `proposed`/accepted before skipping; if a later minor contract version documents 503, start validating it.
