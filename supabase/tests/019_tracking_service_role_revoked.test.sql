-- Onda 10.1 (F-81, T-39, T-49): a secret key (`service_role`) não tem privilégio algum nas tabelas de
-- rastreamento, e nenhuma tabela criada depois nasce acessível a ela. Antes, `service_role` mantinha o
-- padrão do Supabase (`arwdDxtm`) em `clients`, `processes`, `process_stages` e `stage_approvals`, só
-- para fixtures de teste; como a chave tem BYPASSRLS, uma linha feita à mão quebrava I1 a I5 sem
-- auditoria e uma leitura enxergava todos os clientes. Agora só as funções SECURITY DEFINER escrevem e
-- só o RLS decide quem lê.
--
-- Prova: (1) a ACL de cada tabela não tem nenhuma linha para `service_role` (não só o DML: `SELECT`,
-- `TRIGGER`, `REFERENCES` e `MAINTAIN` também); (2) cada tentativa de acesso é 42501 sob
-- `SET LOCAL ROLE service_role`; (3) nenhuma tabela de `public` é escrita pela secret key; (4) o
-- privilégio padrão do dono das migrations não concede nada a ela, e uma tabela criada agora não herda
-- privilégio; (5) as funções SECURITY DEFINER continuam escrevendo (o dono não depende destes
-- privilégios) e `authenticated` continua só lendo.
BEGIN;
SELECT plan(46);

-- arrange (como postgres) -------------------------------------------------------------------------------
INSERT INTO public.clients (id, name) VALUES ('00000000-0000-4000-8000-00000000000a', 'Cliente A');
INSERT INTO public.processes (id, client_id, title)
VALUES ('00000000-0000-4000-8000-000000000101', '00000000-0000-4000-8000-00000000000a', 'Processo A');
INSERT INTO public.process_stages (id, process_id, position, name, status, started_at)
VALUES ('00000000-0000-4000-8000-000000000201', '00000000-0000-4000-8000-000000000101', 1, 'Fase 1',
        'in_progress', now());
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
INSERT INTO public.process_stages (id, process_id, position, name)
VALUES ('00000000-0000-4000-8000-000000000202', '00000000-0000-4000-8000-000000000101', 2, 'Fase 2');

-- (1) a ACL: nenhum privilégio, de nenhum tipo --------------------------------------------------------------
SELECT table_privs_are('public', 'clients', 'service_role', ARRAY[]::text[],
  'F-81: service_role não tem privilégio algum em clients');
SELECT table_privs_are('public', 'processes', 'service_role', ARRAY[]::text[],
  'F-81: service_role não tem privilégio algum em processes');
SELECT table_privs_are('public', 'process_stages', 'service_role', ARRAY[]::text[],
  'F-81: service_role não tem privilégio algum em process_stages');
SELECT table_privs_are('public', 'stage_approvals', 'service_role', ARRAY[]::text[],
  'F-81: service_role não tem privilégio algum em stage_approvals');

SELECT is_empty(
  $$ SELECT c.relname || ':' || a.privilege_type
       FROM pg_class c
       CROSS JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
      WHERE c.oid IN ('public.clients'::regclass, 'public.processes'::regclass,
                      'public.process_stages'::regclass, 'public.stage_approvals'::regclass)
        AND a.grantee = 'service_role'::regrole $$,
  'F-81: a ACL das quatro tabelas não tem uma única linha para service_role (inclui TRIGGER, REFERENCES e MAINTAIN)'
);
SELECT is_empty(
  $$ SELECT t.name
       FROM (VALUES ('public.clients'), ('public.processes'), ('public.process_stages'),
                    ('public.stage_approvals')) t (name)
      WHERE has_any_column_privilege('service_role', t.name::regclass, 'SELECT,INSERT,UPDATE,REFERENCES') $$,
  'F-81: service_role não tem privilégio de coluna nas quatro tabelas'
);
SELECT is(
  (SELECT count(*)::int
     FROM (VALUES ('public.clients'), ('public.processes'), ('public.process_stages'),
                  ('public.stage_approvals')) t (name)),
  4,
  'F-81: o guarda olha exatamente as quatro tabelas (a lista não tem folga)'
);

-- (2) cada acesso negado, sob a secret key ----------------------------------------------------------------------
SET LOCAL ROLE service_role;
SELECT throws_ok($$ SELECT id FROM public.clients $$, '42501', NULL, 'F-81: service_role não lê clients');
SELECT throws_ok($$ SELECT id FROM public.processes $$, '42501', NULL, 'F-81: service_role não lê processes');
SELECT throws_ok($$ SELECT id FROM public.process_stages $$, '42501', NULL, 'F-81: service_role não lê process_stages');
SELECT throws_ok($$ SELECT id FROM public.stage_approvals $$, '42501', NULL, 'F-81: service_role não lê stage_approvals');

SELECT throws_ok(
  $$ INSERT INTO public.clients (name) VALUES ('Cliente de mão') $$,
  '42501', NULL, 'F-81: service_role não faz INSERT em clients'
);
SELECT throws_ok(
  $$ UPDATE public.clients SET name = 'Renomeado à mão' WHERE id = '00000000-0000-4000-8000-00000000000a' $$,
  '42501', NULL, 'F-81: service_role não faz UPDATE em clients'
);
SELECT throws_ok(
  $$ DELETE FROM public.clients WHERE id = '00000000-0000-4000-8000-00000000000a' $$,
  '42501', NULL, 'F-81: service_role não faz DELETE em clients'
);
SELECT throws_ok($$ TRUNCATE public.clients CASCADE $$, '42501', NULL, 'F-81: service_role não faz TRUNCATE em clients');

SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title) VALUES ('00000000-0000-4000-8000-00000000000a', 'Sem fase') $$,
  '42501', NULL, 'F-81: service_role não cria processo sem fase (I1) por INSERT em processes'
);
SELECT throws_ok(
  $$ UPDATE public.processes SET status = 'cancelled', cancelled_at = now()
      WHERE id = '00000000-0000-4000-8000-000000000101' $$,
  '42501', NULL, 'F-81: service_role não cancela processo por UPDATE em processes'
);
SELECT throws_ok(
  $$ DELETE FROM public.processes WHERE id = '00000000-0000-4000-8000-000000000101' $$,
  '42501', NULL, 'F-81: service_role não apaga processo'
);
SELECT throws_ok($$ TRUNCATE public.processes CASCADE $$, '42501', NULL, 'F-81: service_role não faz TRUNCATE em processes');

SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, status, started_at)
     VALUES ('00000000-0000-4000-8000-000000000101', 3, 'Fase de mão', 'in_progress', now()) $$,
  '42501', NULL, 'F-81: service_role não cria fase em andamento (I2) por INSERT em process_stages'
);
SELECT throws_ok(
  $$ UPDATE public.process_stages SET status = 'completed', completed_at = now()
      WHERE id = '00000000-0000-4000-8000-000000000201' $$,
  '42501', NULL, 'F-81: service_role não conclui fase por UPDATE em process_stages'
);
SELECT throws_ok(
  $$ DELETE FROM public.process_stages WHERE id = '00000000-0000-4000-8000-000000000202' $$,
  '42501', NULL, 'F-81: service_role não apaga fase'
);
SELECT throws_ok($$ TRUNCATE public.process_stages CASCADE $$, '42501', NULL, 'F-81: service_role não faz TRUNCATE em process_stages');

SELECT throws_ok(
  $$ INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)
     VALUES ('00000000-0000-4000-8000-000000000201', '00000000-0000-4000-8000-000000000101',
             '00000000-0000-4000-8000-0000000000c1') $$,
  '42501', NULL, 'F-81: service_role não forja aprovação (I5) por INSERT em stage_approvals'
);
SELECT throws_ok(
  $$ UPDATE public.stage_approvals SET approved_at = now() $$,
  '42501', NULL, 'F-81: service_role não altera aprovação por UPDATE em stage_approvals'
);
SELECT throws_ok($$ DELETE FROM public.stage_approvals $$, '42501', NULL, 'F-81: service_role não apaga aprovação');
SELECT throws_ok($$ TRUNCATE public.stage_approvals CASCADE $$, '42501', NULL, 'F-81: service_role não faz TRUNCATE em stage_approvals');
RESET ROLE;

SELECT is(
  (SELECT count(*)::int FROM public.clients WHERE id = '00000000-0000-4000-8000-00000000000a' AND name = 'Cliente A'),
  1,
  'F-81: nenhuma tentativa negada mexeu no cliente'
);
SELECT is(
  (SELECT count(*)::int FROM public.process_stages WHERE process_id = '00000000-0000-4000-8000-000000000101'),
  2,
  'F-81: nenhuma tentativa negada mexeu nas fases'
);

-- (3) nenhuma tabela de public é escrita pela secret key --------------------------------------------------------------------
SELECT cmp_ok(
  (SELECT count(*)::int FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')),
  '>=', 7,
  'F-81: o catálogo de public tem as 7 tabelas (a checagem abaixo não é vazia)'
);
SELECT is_empty(
  $$ SELECT c.relname
       FROM pg_class c
      WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
        AND (has_table_privilege('service_role', c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE')
             OR has_any_column_privilege('service_role', c.oid, 'INSERT,UPDATE')) $$,
  'F-81: service_role não escreve em tabela alguma de public (nem hoje, nem em tabela que alguém esqueça de proteger)'
);
SELECT is_empty(
  $$ SELECT c.relname
       FROM pg_class c
      WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
        AND c.relname NOT IN ('profiles', 'audit_events', 'default_stage_template')
        AND has_table_privilege('service_role', c.oid, 'SELECT') $$,
  'F-81: service_role só lê as três tabelas que a decisão manteve (profiles, audit_events e default_stage_template)'
);
SELECT is_empty(
  $$ SELECT c.relname
       FROM pg_class c
      WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'S'
        AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege('service_role', c.oid, 'USAGE,SELECT,UPDATE') END $$,
  'F-81: service_role não tem privilégio em sequência alguma de public'
);

-- (4) o privilégio padrão não concede nada à secret key -------------------------------------------------------------------------
SELECT is_empty(
  $$ SELECT d.defaclobjtype::text || ':' || pg_get_userbyid(a.grantee)
       FROM pg_default_acl d
       CROSS JOIN LATERAL aclexplode(d.defaclacl) a
      WHERE d.defaclrole = 'postgres'::regrole
        AND d.defaclnamespace = 'public'::regnamespace
        AND d.defaclobjtype IN ('r', 'S')
        AND a.grantee IN ('service_role'::regrole, 'anon'::regrole, 'authenticated'::regrole) $$,
  'F-81: o privilégio padrão do dono das migrations, em public, não concede nada a service_role, anon nem authenticated (tabelas e sequências)'
);
CREATE TABLE public.f81_probe (id integer PRIMARY KEY, secret text);
CREATE SEQUENCE public.f81_probe_seq;
SELECT table_privs_are('public', 'f81_probe', 'service_role', ARRAY[]::text[],
  'F-81: uma tabela criada agora não herda privilégio algum para service_role');
SELECT table_privs_are('public', 'f81_probe', 'anon', ARRAY[]::text[],
  'F-81: nem para anon (a plataforma continua endurecida)');
SELECT table_privs_are('public', 'f81_probe', 'authenticated', ARRAY[]::text[],
  'F-81: nem para authenticated: cada migration concede explicitamente o que precisa');
SELECT ok(
  NOT has_sequence_privilege('service_role', 'public.f81_probe_seq', 'USAGE,SELECT,UPDATE'),
  'F-81: uma sequência criada agora não herda privilégio para service_role'
);
SET LOCAL ROLE service_role;
SELECT throws_ok($$ INSERT INTO public.f81_probe (id) VALUES (1) $$, '42501', NULL,
  'F-81: a secret key não escreve na tabela de teste recém-criada');
SELECT throws_ok($$ SELECT id FROM public.f81_probe $$, '42501', NULL,
  'F-81: nem lê');
RESET ROLE;

-- (5) o dono segue escrevendo pelas funções; authenticated só lê --------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.create_client('Cliente da função') $$,
  'F-81: create_client (SECURITY DEFINER) segue escrevendo sem privilégio algum da secret key'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo da função') $$,
  'F-81: create_process escreve processo e fases'
);
SELECT lives_ok(
  $$ SELECT * FROM public.approve_current_stage(
       (SELECT p.id FROM public.processes p WHERE p.title = 'Processo da função'),
       (SELECT s.id FROM public.process_stages s JOIN public.processes p ON p.id = s.process_id
         WHERE p.title = 'Processo da função' AND s.status = 'in_progress')) $$,
  'F-81: approve_current_stage escreve a aprovação'
);
SELECT is(
  (SELECT count(*)::int FROM public.stage_approvals a JOIN public.processes p ON p.id = a.process_id
    WHERE p.title = 'Processo da função'),
  1,
  'F-81: a aprovação gravada pela função está lá (o CEO atestado a lê pelo RLS)'
);
SELECT tests.clear_authentication();

SELECT is_empty(
  $$ SELECT t.name
       FROM (VALUES ('public.clients'), ('public.processes'), ('public.process_stages'),
                    ('public.stage_approvals')) t (name)
      WHERE NOT has_table_privilege('authenticated', t.name::regclass, 'SELECT')
         OR has_table_privilege('authenticated', t.name::regclass, 'INSERT,UPDATE,DELETE,TRUNCATE') $$,
  'authenticated segue com SELECT (o RLS decide) e sem escrita nas quatro tabelas'
);
SELECT is_empty(
  $$ SELECT r.role
       FROM (VALUES ('anon'), ('service_role')) r (role)
       CROSS JOIN (VALUES ('public.clients'), ('public.processes'), ('public.process_stages'),
                          ('public.stage_approvals')) t (name)
      WHERE has_table_privilege(r.role, t.name::regclass, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') $$,
  'anon e service_role não têm privilégio algum nas quatro tabelas (a matriz de acesso de §4.2)'
);

SELECT * FROM finish();
ROLLBACK;
