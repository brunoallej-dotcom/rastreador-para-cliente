---
name: supabase-privilege-pitfalls
description: Supabase platform defaults that silently re-grant privileges (service_role DML via postgres default ACL, supabase_admin default ACL to anon), plus JWT claim cast and regex-class gotchas seen in this repo
metadata:
  type: project
---

Recurring traps confirmed on the local Supabase (PG 17, CLI 2.122) during the Wave 2 audit (2026-11-15):

- `ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated`
  leaves **service_role with `arwdDxtm`** on every new public table and `rwU` on sequences. Per-table
  `REVOKE ALL … FROM anon, authenticated` does the same. Always query
  `aclexplode(relacl)` for `service_role` — pgTAP in this repo only checked service_role on functions.
- `pg_default_acl` for **supabase_admin** in public grants ALL to anon/authenticated; postgres cannot
  alter it. Objects created by the dashboard/extensions into public bypass the migration hardening.
- Schema-scoped `REVOKE … FROM PUBLIC` on functions is ineffective; the global
  `ALTER DEFAULT PRIVILEGES FOR ROLE postgres REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC` is what works.
- `(auth.jwt() ->> 'session_id')::uuid` raises 22P02 on a malformed claim (fail closed, but 500
  instead of empty set). Prefer a CASE + regex guarded cast.
- `[[:cntrl:]]` (ICU en_US) catches C0/C1 but NOT Cf chars (U+202E bidi override, U+200B ZWSP).
- `btrim(x)` strips only U+0020; JS `.trim()` (Zod `visibleText`) strips all Unicode whitespace.
  SQL name checks built on `btrim` accept NBSP/U+3000-only names, Hangul filler U+3164 and
  punctuation-only names that Zod rejects (seen in Wave 6 `create_client`, 2026-11-16).
- plpgsql `DECLARE v := f(p_input)` runs **before** the `IF NOT private.is_ceo()` guard; check
  that no input processing happens in DECLARE. `IF NOT f()` is fail-open if f() ever returns NULL;
  prefer `IF f() IS NOT TRUE`.
- `DROP EXTENSION pg_graphql` leaves `graphql_public.graphql()` behind; exposure depends on
  `[api] schemas` (local) / dashboard "Exposed schemas" (hosted).

- Local DB is **ICU en-US** (`datlocprovider = i`, collversion 153.121): `lower()` is full and
  context-sensitive ("ΟΔΟΣ" -> "οδος", "İ" -> "i̇"). Hosted provider unverified; libc "C" would make
  `lower()` ASCII-only. Name-key indexes need a hosted `pg_database` check and a REINDEX after ICU or
  PG-major (Unicode table) upgrades.
- NFKC does **not** drop default-ignorable Mn chars (CGJ U+034F, VS U+FE00-FE0F, U+E0100-E01EF,
  Mongolian FVS U+180B-180D/180F) and `private.visible_text` accepts them: "Acme" vs "Ac<CGJ>me" get
  different keys in `clients_active_name_key` (probed 2026-11-16).
- Unique index + rename of two rows to each other's key (A->"b", B->"a") can deadlock (40P01) in
  `_bt_check_unique` waits; plpgsql handlers catching only `unique_violation` let it through raw.

- Security state keyed on `auth.*` rows with `ON DELETE CASCADE` (factor, session, challenge) is
  erasable by whoever can delete those rows through the Auth API: e.g. an `aal2` session obtained
  directly at Auth can unenroll a verified factor, wiping backend history and resetting the account
  to "first enrollment". Anything that must survive attacker-driven deletions needs a row keyed only
  on `auth.users` (seen in Wave 6.1, 2026-11-16).
- `tests.authenticate_as(..., 'aal2')` attests by default (Wave 6.1): old positive tests stay
  valid, but a future function checking the `aal` claim directly would pass them. Ask for an
  unattested-aal2 negative (`p_attested => false`) per new CEO object, or a `prosrc` catalog guard.
- A `prosrc ~ '''aal'''` catalog guard is evadable: `#>> '{aal}'`, `@> '{"aal":...}'`, dynamic
  `EXECUTE`, `BEGIN ATOMIC` bodies (prosrc empty, body in `pg_get_function_sqlbody`), reading
  `auth.sessions.aal` (just as unattested), and policies (not functions). Robust form, verified on
  the Wave 6.1 catalog (hits only session_is_attested + attest_mfa_session):
  `(prosrc || coalesce(pg_get_function_sqlbody(oid),'')) ~* '\maal\M|request\.jwt|\mexecute\M'`
  plus `pg_get_expr(polqual, polrelid) ~* 'aal|jwt'` on pg_policy.
- Triggers on `auth.*` tables run inside GoTrue's transaction: any raise fails the Auth call (verify,
  signup). Audit them for non-raising paths only (lock waits are OK: `supabase_auth_admin` has no
  statement/lock timeout locally, only idle_in_transaction 60 s). `UPDATE OF col` / `WHEN` record a
  pg_depend on the auth column, so a future GoTrue migration altering that column's type fails
  (hosted Auth upgrade risk). Local ACL on `auth.mfa_factors`/`mfa_challenges`/`sessions`: only
  postgres, supabase_auth_admin, dashboard_user (no authenticated/service_role), so the trigger
  can't be fired with crafted data by API roles (checked 2026-11-16).

- pgTAP audit heuristics (Wave 10): `tests.create_user` profiles keep the default
  `must_change_password = true` with a fresh baseline, so every positive RLS control in the suite runs
  as a "temporary password pending" login unless the file flips it. An isolation assert whose WHERE
  already has `client_id = <own tenant>` passes with RLS off: only filter-free or foreign-tenant-filter
  queries prove RLS. Check each "AC-09" assert for that.
  Since Wave 10.1 `tests.create_user` gives CEOs `must_change_password = false` (clients still true),
  and is_ceo()/current_client_id() refuse a pending login: a client positive control must flip it.
- Count scoping (Wave 10.1, db:test after test:api without reset): only POSITIVE counts need a
  fixture filter. A denial `count(*) = 0` is already immune to foreign rows; narrowing it to
  `WHERE id = <fixture>` weakens it. `created_at/occurred_at = now()` scoping is sound only if the
  writer stamps with `now()` (default), not `clock_timestamp()`; a matching positive count proves it.

**Why:** these pass pgTAP and `db lint` silently; they only show up in catalog queries.
**How to apply:** in every audit, run the service_role ACL query and check new CHECK regexes and
claim casts. See [[local-db-probing]] and [[wave2-audit-findings]].
