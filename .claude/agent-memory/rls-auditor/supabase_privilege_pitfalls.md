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

**Why:** these pass pgTAP and `db lint` silently; they only show up in catalog queries.
**How to apply:** in every audit, run the service_role ACL query and check new CHECK regexes and
claim casts. See [[local-db-probing]] and [[wave2-audit-findings]].
