-- Smoke test da Onda 0: o runner de pgTAP (`pnpm db:test`) está de pé.
-- Os testes de RLS, funções e invariantes entram na Onda 2.
BEGIN;
SELECT plan(1);
SELECT has_schema('public', 'schema public existe');
SELECT * FROM finish();
ROLLBACK;
