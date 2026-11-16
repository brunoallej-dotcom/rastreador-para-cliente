---
name: wave2-audit-findings
description: Open DB audit findings to re-check (Wave 2 service_role DML, mark_password_changed; Wave 6 SQL name validation weaker than Zod)
metadata:
  type: project
---

Wave 2 audit (2026-11-15, branch feat/wave-0-foundation, migrations 20261115223622…223636 untracked).
Verdict: APROVADO COM RESSALVAS (no CRÍTICO/ALTO).

Open MÉDIO items to verify in the next audit:
1. service_role keeps full DML (incl. TRUNCATE/TRIGGER/MAINTAIN) on all business tables + INSERT
   on audit_events + default ACL for future tables. Proven: service_role can
   `UPDATE profiles SET role='ceo', client_id=NULL` and forge audit rows.
2. `public.mark_password_changed()` clears must_change_password with no proof that the password
   changed, and lets a CEO with verified TOTP at aal1 (VERIFY_MFA pending) wipe its other (aal2)
   sessions + write `account.password_changed`.

BAIXO: malformed session_id → 22P02; request_id client-controllable via direct PostgREST;
record_account_provisioned not idempotent; stage_approvals.process_id not tied to stage's process;
rate_limit PK lacks window size; Cf unicode chars pass [[:cntrl:]].

**Why:** later waves (8/9 write functions) inherit the service_role default ACL and the audit trail.
**How to apply:** first thing next audit, check whether a new migration fixed these; if Wave 8/9
adds tables and the default ACL is unchanged, escalate.
Wave 6 audit (2026-11-16, branch feat/wave-6-clients, create_client/update_client): APROVADO COM
RESSALVAS. MÉDIO: SQL name validation weaker than Zod visibleText (btrim ASCII-only, no filler, no
letter-or-number) although spec §3.7.1 claims parity; suggested a shared `private.visible_text()`
helper for Waves 8/9 (process title, stage names). BAIXO: normalize in DECLARE before guard;
`IF NOT is_ceo()` not NULL-safe (same in identity_functions). service_role DML on clients is
accepted by design (tracking_tables header comment: fixtures/manual ops).

Related: [[supabase-privilege-pitfalls]].
