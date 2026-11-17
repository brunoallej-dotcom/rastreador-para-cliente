-- Spec: docs/specs/client-delivery-tracker.md §4.2 (matriz de acesso), SEC-04; threat model T-39,
-- T-49, F-81, F-104, F-105 (Onda 10.1) — a secret key (`service_role`) deixa de tocar as tabelas de
-- rastreamento.
--
-- Até aqui `service_role` mantinha todos os privilégios (`arwdDxtm`, o padrão do Supabase) em
-- `clients`, `processes`, `process_stages` e `stage_approvals`, só para fixtures de teste e operação
-- manual. A chave tem BYPASSRLS: com ela, uma linha feita à mão quebrava I1 a I5 sem auditoria, e uma
-- leitura enxergava todos os clientes. Agora só as funções SECURITY DEFINER escrevem (como o dono, que
-- não depende destes privilégios) e só o RLS decide quem lê.
--
-- Revoga TUDO, e não só o DML:
--   * `SELECT`: nada na aplicação lê estas tabelas com a secret key (a fachada de
--     `src/shared/db/admin-client.ts` não expõe `.from()`, e `scripts/create-ceo.ts` escreve só o Auth);
--     um SELECT com BYPASSRLS lê todos os tenants;
--   * `TRIGGER`, `REFERENCES` e `MAINTAIN`: nenhum papel de API precisa deles, e um gatilho em tabela
--     que as funções SECURITY DEFINER escrevem seria código rodando com o privilégio do dono.
-- As fixtures dos testes passam a escrever pelo `psql` do contêiner do banco (tests/helpers/db.ts).
REVOKE ALL ON public.clients FROM service_role;
REVOKE ALL ON public.processes FROM service_role;
REVOKE ALL ON public.process_stages FROM service_role;
REVOKE ALL ON public.stage_approvals FROM service_role;

-- Privilégios padrão: uma tabela ou sequência criada depois não nasce acessível à secret key ---------
-- A migration `platform_hardening` tirou `anon` e `authenticated` do padrão do dono das migrations, mas
-- deixou `service_role` (`arwdDxtm` em tabelas, `rwU` em sequências), e foi assim que as tabelas de
-- rastreamento herdaram o DML. Cada migration concede explicitamente o que a secret key precisa (hoje:
-- `SELECT` em `profiles`, `audit_events` e `default_stage_template`, concedido lá atrás).
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON TABLES FROM service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM service_role;
