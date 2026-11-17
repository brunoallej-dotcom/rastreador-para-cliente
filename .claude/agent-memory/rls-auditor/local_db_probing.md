---
name: local-db-probing
description: How to run read-only/rolled-back probes against this repo's local Supabase DB (container name, psql via docker exec, role limits)
metadata:
  type: reference
---

- Local DB container: `supabase_db_rastreador-para-cliente` (port 54422). No host `psql`; use
  `docker exec -i supabase_db_rastreador-para-cliente psql -U postgres -d postgres -X -q < file.sql`.
  Another project's container (`supabase_db_tracking-clientes`) also runs — don't confuse them.
- Wrap probes in `BEGIN; … ROLLBACK;` (or `BEGIN READ ONLY`). Test helpers `tests.create_user`,
  `tests.authenticate_as(id, aal)`, `tests.verify_totp`, `tests.set_request_id` persist in schema
  `tests` and can be reused inside the probe transaction.
- `postgres` **cannot** `SET ROLE supabase_auth_admin`, so the auth.users trigger can't be exercised
  under GoTrue's role from SQL; that needs an integration test via `auth.admin.createUser`.
- `pnpm db:test` and `pnpm db:lint` are allowed; never `db:reset`/`db:start` during an audit.

- Canonical memory lives in the main checkout `.claude/agent-memory/rls-auditor/`. When run from a
  worktree, the worktree copy may be deleted mid-run; read and write the main-checkout copy.
- Manager-run audits may forbid `db:test`/`db:lint` (shared DB not reset to the branch): then audit
  statically and say the gates were not run. First check
  `supabase_migrations.schema_migrations` to see whether the branch migration is even applied;
  if not, only catalog facts of the base (default ACLs, schema USAGE, auth indexes) are probeable.

Related: [[supabase-privilege-pitfalls]].
