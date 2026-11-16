# ADR 0006 — Privilégios mínimos do `service_role` no banco

- **Status:** accepted
- **Data:** 2026-11-16

## Contexto

O Supabase concede, por padrão (default privileges), `ALL` em tabelas e `EXECUTE` em funções de
`public` aos papéis `anon`, `authenticated` e `service_role`. A Onda 2 revogou tudo de `anon` e
`authenticated`, mas o `rls-auditor` provou que o `service_role` (a secret key) ainda podia
promover um cliente a CEO (`UPDATE profiles SET role = 'ceo'`), gravar eventos de auditoria
forjados e executar as funções de conta. Uma secret key vazada, ou um uso indevido do admin client
no BFF, contornaria `is_ceo()`, as invariantes e a trilha de auditoria.

Ao mesmo tempo, os testes de API das Ondas 3 a 10 precisam montar fixtures (clientes, processos,
fases, aprovações) antes que os endpoints que as criam existam, e o único canal de banco
disponível para os testes em TypeScript é o PostgREST com a secret key.

## Decisão

- Defaults de privilégio em `public` (papel das migrations): nada para `anon` e `authenticated`;
  nenhum `EXECUTE` de função para `service_role`. Cada migration concede explicitamente o que
  precisa.
- O `service_role` executa só `rate_limit_hit`.
- O `service_role` não escreve em `profiles` (papel e cliente só nascem no trigger de
  `auth.users`), `audit_events` (só as funções `SECURITY DEFINER` gravam, via
  `private.record_audit_event`) e `default_stage_template` (só migration).
- O `service_role` mantém DML em `clients`, `processes`, `process_stages` e `stage_approvals`
  apenas para fixtures de teste no Supabase local e operação manual. O app nunca escreve com a
  secret key: AGENTS.md, ESLint e o hook de pós-edição restringem o admin client ao gateway de
  contas e ao rate limiter.
- Testes pgTAP provam cada item (`supabase/tests/001_privileges.test.sql`,
  `004_audit_append_only.test.sql`).

## Consequências

- **Positivas:** a secret key não forja papel nem auditoria; a superfície de escrita direta fica
  restrita a tabelas sem dado de autorização.
- **Negativas:** quem tem a secret key ainda cria usuários com `app_metadata.role = 'ceo'` pela
  Auth Admin API (é o caminho legítimo do `ceo:create`) e escreve nas tabelas de rastreamento.
  A proteção da chave em si (só servidor, rotação, Onda 11) continua sendo a barreira principal.
- Reavaliar o DML de fixtures se surgir um canal de banco só para testes (por exemplo, um driver
  Postgres na suíte), o que permitiria revogá-lo também.
