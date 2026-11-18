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
   [Wave 10.1 (migration 20261117022303): REVOKE ALL on the 4 tracking tables + postgres default
   ACL in public gives service_role nothing on tables/sequences. Residual tracked as F-112:
   SELECT/REFERENCES/TRIGGER/MAINTAIN on profiles, audit_events, default_stage_template.]
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

Wave 6 name-unique audit (2026-11-16, branch feat/wave-6-client-name-unique, migration
20261116150822): functions kept every baseline guarantee (grants, guard first, FOR NO KEY UPDATE).
BAIXO: default-ignorable Mn bypass the key; crossing-rename 40P01 surfaces as 500 (app maps class
40 nowhere); hosted collation provider unverified.

Wave 6.1 audit (2026-11-16, branch feat/wave-6.1-ceo-attestation, migration 20261116145142,
static only): REPROVADO on one ALTO. Attestation functions themselves are clean (service_role-only,
search_path '', ids revalidated, refusal = RETURN so audit + session wipe commit). ALTO: a CEO
with password + one TOTP code guessed directly at Auth unenrolls the factor at Auth (aal2), which
CASCADE-erases `mfa_backend_factors`/attestations; the CEO then looks never-enrolled
(ENROLL_MFA) and the attacker re-enrolls via the BFF and gets attested. Fix proposed: durable
per-user "had backend-activated factor" marker without factor FK, refuse activation when present
(cleared only by E-25 MFA reset, Wave 11). BAIXO: `record_backend_mfa_challenge` does not require
`verified_at IS NULL`; no session<->challenge binding; hosted REFERENCES on auth.sessions /
auth.mfa_challenges and GoTrue challenge retention unverified; unattested-aal2 negatives only for
3 CEO functions. Wave 2 item 2 (mark_password_changed) is now resolved (baseline proof + attestation).
Wave 6.1 re-audit after fix round (2026-11-16, migration renamed 20261116173233, applied locally):
ALTO resolved (`private.mfa_first_activations` keyed on auth.users only, enforced in register +
attest; challenge FK dropped, verified_at copied, challenge_id UNIQUE, fresh-unverified challenge
required; consume_totp_code service_role-only 3-arg). APROVADO COM RESSALVAS. BAIXO left: first-
activation race (two pre-registered factors attested concurrently both pass the marker EXISTS; fix =
lock profile row before the check); F-63 catalog guard evadable (see pitfalls); missing positive
controls for template/require_password_change/set_account_display_name/record_account_provisioned
in 015 (covered positively in 005). Still unverified: hosted REFERENCES on auth.sessions/mfa_factors,
GoTrue challenge retention (attack-class `challenge_not_found` / activation proof rely on it).
Wave 6.1 fix commit 6013d71 (2026-11-16, static): trigger `on_mfa_factor_verified` writes mark (now
with factor_id) + activation proof; attest reads only backend tables, locks profile, deletes other
sessions on activation. APROVADO COM RESSALVAS; first-activation race resolved. BAIXO left: trigger's
column dependency on auth.mfa_factors.status can block a GoTrue migration (Wave 11 hosted check);
E-25/F-75 text omits deleting the Auth factor itself (leftover verified factor blocks re-enroll).

Wave 8 audit (2026-11-16, branch feat/wave-8-processes, migration 20261116190432, static; local DB
was on another branch so functions absent): create_process/update_process clean vs Wave 6 baseline
(guard first, nothing in DECLARE, visible_text on title/stage name/description, client FOR NO KEY
UPDATE, process FOR NO KEY UPDATE, audit only on change, no titles in metadata, no new grants/policies).
APROVADO COM RESSALVAS (BAIXO only). Forward items for Wave 9: `approve_current_stage` MUST lock the
`processes` row FOR NO KEY UPDATE *before* touching stages, else a concurrent cancel can interleave
and a stage completes on a cancelled process (I4); timeline must not fill `newTitle` from the current
`processes.title`. App repo maps 23514 CHECK_VIOLATION to 400 INVALID_INPUT, which masks integrity
bugs (e.g. a template row failing process_stages CHECK, `processes_*_at_ck`) as client errors.
No pgTAP in 013/014/016 asserts the FOR NO KEY UPDATE locks (single-session pgTAP can't race);
suggested a `prosrc ~ 'FOR NO KEY UPDATE'` catalog guard.

Wave 7 static check (2026-11-16, branch feat/wave-7-client-users, NO migration; app drives Wave 2
account functions). DB sound: all 4 write fns filter `role='client' FOR UPDATE` (CEO target ->
NOT_FOUND), no path updates profiles.role/client_id, disabled_at kills principal regardless of Auth
ban. Load-bearing order: Auth `setPassword` MUST precede `require_password_change` (baseline digests
the temp hash; reversed order = forced-change bypass); pinned by unit test. Auth Admin calls (ban,
password, delete) are guarded ONLY by app `findClientLogin` (list_client_users as CEO). BAIXO: reset
non-503 refusal after setPassword leaves Auth-side change unaudited, sessions alive; provision
compensation after record succeeded leaves `account.provisioned` for a deleted user; reset retry
duplicates the audit event.

Wave 10 static audit (2026-11-16, branch feat/wave-10-client-panel, NO migration; pgTAP 018 +
psql fixtures in tests/helpers/db.ts + user-scoped query service). APROVADO COM RESSALVAS (BAIXO
only). RLS on processes/process_stages isolates every app shape (by id, list, keyset, embedded
count). BAIXO left: 018 positive controls run as must_change_password=true logins (pins F-83 state);
keyset-tie asserts carry `client_id = A` in WHERE so they don't prove RLS; approve fixture is 4
autocommit statements, no I4 guard; stage-less fixture rows persist in dev DB (a future migration
that validates invariants over existing rows would refuse to apply without db:reset); E-34 (expired
temp password) not asserted on the panel tables (only via 015 on profiles/clients).
Forward for Wave 10.1: db.ts fixtures run as postgres (table owner) so the service_role REVOKE does
not affect them; a trigger-based "functions only" guard or commit-time invariant checks WOULD.

Wave 10.1 static audit (2026-11-17, branch feat/wave-10.1-db-hardening, migrations 20261117022303
service_role revoke, 023041 settled-password RLS, 023736 client login audit; pgTAP 019-021).
APROVADO COM RESSALVAS (BAIXO only). current_client_id()/is_ceo() now require NOT
must_change_password; callers checked (3 tenant policies; mark_password_changed/current_principal/
attest/register don't use is_ceo). BAIXO left: record_account_provision_reverted accepts ANY unused
pending login (no freshness bound) so an attested CEO can write a false "reverted" for a live login;
012 denial asserts narrowed to `WHERE id = fixture` (count(*)=0 was already robust); default-ACL
fix is FOR ROLE postgres only (no owner guard in pgTAP; supabase_admin defaults untouched);
new-migration SKILL still says REVOKE INSERT/UPDATE/DELETE/TRUNCATE from service_role, not ALL.
Wave 10.1 criterion: `db:test` runs after `test:api` WITHOUT reset, so pgTAP counts must be scoped.

Related: [[supabase-privilege-pitfalls]].

Wave 10.2 static audit (2026-11-17, branch feat/wave-10.2-product-decisions, migration 20261118020125,
pgTAP 022 + 016/017 edits). APROVADO COM RESSALVAS (BAIXO only). F-80 partial unique index
`processes_client_active_title_key` mirrors clients key + client_id; F-87 freeze in update_process and
approve_current_stage via client `FOR SHARE` -> process NKU -> stage NKU (ADR 0017). Verified deadlock-free
vs create_process/update_client/approvals (only the documented crossing-rename 40P01) and not stale
(archive NKU must wait for every SHARE holder). BAIXO left: ADR 0017 item 2 / migration comment claim a
process->client deadlock with create_process that cannot happen (rename writes its index entry only after
both locks; lock-only xmax makes `_bt_check_unique` fail fast, not wait); no `IF NOT FOUND` after the client
FOR SHARE (NULL archived_at = not archived; unreachable: FK RESTRICT, no client delete path); denial
asserts narrowed (017:712 `process_id = PX`, 022:754 client/process filters) instead of request_id scoping.
