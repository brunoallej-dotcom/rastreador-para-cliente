-- Privilégios e catálogo (Onda 2): AC-10, AC-25, RLS habilitado, policies só SELECT,
-- superfície mínima (SEC-20) e rate limit restrito ao service_role.
-- Consulta o catálogo e tenta acessos negados; só cria um CEO de teste (revertido pelo ROLLBACK).
-- Inclui a secret key (service_role): sem escrita em profiles, audit_events e template e sem
-- acesso a private.password_baselines.
BEGIN;
SELECT plan(59);

-- AC-10: anon não tem privilégio algum em public ---------------------------------------------
SELECT cmp_ok(
  (SELECT count(*)::int FROM pg_tables WHERE schemaname = 'public'), '>=', 7,
  'AC-10: o catálogo de public tem as 7 tabelas da Onda 2 (a checagem abaixo não é vazia)'
);

SELECT is_empty(
  $$ SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
        AND has_table_privilege('anon', c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') $$,
  'AC-10: anon não tem nenhum privilégio de tabela em public'
);

SELECT is_empty(
  $$ SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
        AND has_any_column_privilege('anon', c.oid, 'SELECT,INSERT,UPDATE,REFERENCES') $$,
  'AC-10: anon não tem privilégio de coluna em nenhuma tabela de public'
);

SET LOCAL ROLE anon;
SELECT throws_ok($$ SELECT id FROM public.clients $$, '42501', NULL, 'AC-10: anon não lê clients');
SELECT throws_ok($$ SELECT id FROM public.profiles $$, '42501', NULL, 'AC-10: anon não lê profiles');
SELECT throws_ok($$ SELECT id FROM public.processes $$, '42501', NULL, 'AC-10: anon não lê processes');
SELECT throws_ok($$ SELECT id FROM public.process_stages $$, '42501', NULL, 'AC-10: anon não lê process_stages');
SELECT throws_ok($$ SELECT id FROM public.stage_approvals $$, '42501', NULL, 'AC-10: anon não lê stage_approvals');
SELECT throws_ok($$ SELECT id FROM public.audit_events $$, '42501', NULL, 'AC-10: anon não lê audit_events');
SELECT throws_ok($$ SELECT position FROM public.default_stage_template $$, '42501', NULL, 'AC-10: anon não lê default_stage_template');
SELECT throws_ok($$ SELECT * FROM public.current_principal() $$, '42501', NULL, 'AC-10: anon não executa current_principal');
SELECT throws_ok($$ SELECT * FROM public.rate_limit_hit('anon-bucket', 60, 5) $$, '42501', NULL, 'AC-10: anon não executa rate_limit_hit');
RESET ROLE;

SELECT is_empty(
  $$ SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'S'
        AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege('anon', c.oid, 'USAGE,SELECT,UPDATE') END $$,
  'AC-10: anon não tem privilégio nas sequências de public'
);

SELECT cmp_ok(
  (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'),
  '>=', 8,
  'AC-10: o catálogo de public tem as 8 funções da Onda 2 (a checagem abaixo não é vazia)'
);

SELECT is_empty(
  $$ SELECT p.proname
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND has_function_privilege('anon', p.oid, 'EXECUTE') $$,
  'AC-10: anon não executa nenhuma função de public'
);

SELECT ok(
  NOT has_schema_privilege('anon', 'private', 'USAGE'),
  'AC-10: anon não tem USAGE no schema private'
);

SELECT is_empty(
  $$ SELECT p.proname
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'private' AND has_function_privilege('anon', p.oid, 'EXECUTE') $$,
  'AC-10: anon não executa nenhuma função de private'
);

-- AC-25: funções SECURITY DEFINER ---------------------------------------------------------------
SELECT cmp_ok(
  (SELECT count(*)::int
     FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname IN ('public', 'private') AND p.prosecdef),
  '>=', 18,
  'AC-25: existem 18 funções SECURITY DEFINER na Onda 2 (a checagem abaixo não é vazia)'
);

SELECT is_empty(
  $$ SELECT n.nspname || '.' || p.proname
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname IN ('public', 'private') AND p.prosecdef
        AND NOT coalesce(p.proconfig @> ARRAY['search_path=""'], false) $$,
  'AC-25: toda função SECURITY DEFINER tem search_path vazio (proconfig = search_path="")'
);

SELECT is_empty(
  $$ SELECT n.nspname || '.' || p.proname
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE n.nspname IN ('public', 'private') AND p.prosecdef
        AND a.grantee = 0 AND a.privilege_type = 'EXECUTE' $$,
  'AC-25: nenhuma função SECURITY DEFINER concede EXECUTE a PUBLIC'
);

SELECT is_empty(
  $$ SELECT n.nspname || '.' || p.proname
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname IN ('public', 'private') AND p.prosecdef
        AND has_function_privilege('anon', p.oid, 'EXECUTE') $$,
  'AC-25: anon não executa nenhuma função SECURITY DEFINER'
);

SELECT is_empty(
  $$ SELECT p.proname
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'private'
        AND p.proname NOT IN ('current_active_user_id', 'current_client_id', 'is_ceo')
        AND (has_function_privilege('authenticated', p.oid, 'EXECUTE')
             OR has_function_privilege('service_role', p.oid, 'EXECUTE')) $$,
  'AC-25: só os 3 helpers de RLS de private são executáveis pelos papéis da API'
);

SELECT is_empty(
  $$ SELECT h.name
       FROM (VALUES ('current_active_user_id'), ('current_client_id'), ('is_ceo')) h (name)
      WHERE NOT EXISTS (
        SELECT 1
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'private' AND p.proname = h.name
           AND has_function_privilege('authenticated', p.oid, 'EXECUTE')
      ) $$,
  'AC-25: authenticated executa os helpers de RLS (as policies dependem disso)'
);

SELECT is_empty(
  $$ SELECT f.name
       FROM (VALUES ('current_principal'), ('mark_password_changed'), ('record_account_provisioned'),
                    ('set_account_disabled'), ('set_account_display_name'), ('require_password_change'),
                    ('list_client_users')) f (name)
      WHERE NOT EXISTS (
        SELECT 1
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public' AND p.proname = f.name
           AND has_function_privilege('authenticated', p.oid, 'EXECUTE')
      ) $$,
  'AC-25: authenticated executa as 7 funções de identidade (que checam papel e aal por dentro)'
);

-- RLS habilitado e policies somente de leitura ---------------------------------------------------
SELECT is_empty(
  $$ SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relrowsecurity $$,
  'RLS está habilitado em toda tabela de public'
);

SELECT is_empty(
  $$ SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'private' AND c.relkind IN ('r', 'p') AND NOT c.relrowsecurity $$,
  'RLS está habilitado em toda tabela de private'
);

SELECT cmp_ok(
  (SELECT count(*)::int FROM pg_policies WHERE schemaname = 'public'), '>=', 11,
  'existem 11 policies em public na Onda 2 (a checagem abaixo não é vazia)'
);

SELECT is_empty(
  $$ SELECT tablename || '.' || policyname FROM pg_policies WHERE schemaname = 'public' AND cmd <> 'SELECT' $$,
  'toda policy de public é FOR SELECT (nenhuma de escrita, nenhuma FOR ALL)'
);

SELECT is_empty(
  $$ SELECT tablename || '.' || policyname FROM pg_policies
      WHERE schemaname = 'public' AND roles <> ARRAY['authenticated']::name[] $$,
  'toda policy de public vale só para o papel authenticated'
);

SELECT is_empty(
  $$ SELECT tablename || '.' || policyname FROM pg_policies WHERE schemaname = 'private' $$,
  'nenhuma policy em private (RLS sem policy nega tudo a quem não é dono)'
);

-- authenticated só lê ----------------------------------------------------------------------------
SELECT is_empty(
  $$ SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
        AND has_table_privilege('authenticated', c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') $$,
  'authenticated não tem INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER em tabela alguma de public'
);

SELECT is_empty(
  $$ SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
        AND has_any_column_privilege('authenticated', c.oid, 'INSERT,UPDATE,REFERENCES') $$,
  'authenticated não tem privilégio de escrita em coluna alguma de public'
);

SELECT is_empty(
  $$ SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r'
        AND NOT has_table_privilege('authenticated', c.oid, 'SELECT') $$,
  'authenticated tem SELECT em toda tabela de public (o RLS decide quais linhas)'
);

SELECT is_empty(
  $$ SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'S'
        AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege('authenticated', c.oid, 'USAGE,SELECT,UPDATE') END $$,
  'authenticated não tem privilégio nas sequências de public'
);

SELECT is_empty(
  $$ SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
      WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND a.grantee = 0 $$,
  'nenhuma tabela de public concede privilégio a PUBLIC'
);

-- Superfície mínima (SEC-20) ----------------------------------------------------------------------
SELECT is_empty(
  $$ SELECT extname FROM pg_extension WHERE extname = 'pg_graphql' $$,
  'SEC-20: a extensão pg_graphql não está instalada'
);

-- rate_limit_hit: só service_role --------------------------------------------------------------------
SELECT ok(
  has_function_privilege('service_role', 'public.rate_limit_hit(text, integer, integer)', 'EXECUTE'),
  'rate_limit_hit: service_role executa'
);

SELECT ok(
  NOT has_function_privilege('authenticated', 'public.rate_limit_hit(text, integer, integer)', 'EXECUTE'),
  'rate_limit_hit: authenticated não executa'
);

SELECT ok(
  NOT has_function_privilege('anon', 'public.rate_limit_hit(text, integer, integer)', 'EXECUTE'),
  'rate_limit_hit: anon não executa'
);

SELECT is_empty(
  $$ SELECT a.grantee
       FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE p.oid = 'public.rate_limit_hit(text, integer, integer)'::regprocedure
        AND a.privilege_type = 'EXECUTE'
        AND a.grantee NOT IN (p.proowner, 'service_role'::regrole) $$,
  'rate_limit_hit: EXECUTE concedido apenas ao dono e ao service_role (nem PUBLIC)'
);

SELECT is_empty(
  $$ SELECT p.proname
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
        AND p.proname NOT IN (
          'rate_limit_hit', 'register_backend_totp_factor', 'record_backend_mfa_challenge', 'attest_mfa_session'
        )
        AND has_function_privilege('service_role', p.oid, 'EXECUTE') $$,
  'SEC-04: service_role não executa funções de public além de rate_limit_hit e das três do atestado de CEO (Onda 6.1)'
);

SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('authenticated-bucket', 60, 5) $$,
  '42501', NULL, 'rate_limit_hit: nem um CEO aal2 autenticado executa'
);
SELECT tests.clear_authentication();

-- private.rate_limit_counters: ninguém lê direto ---------------------------------------------------------
SELECT is_empty(
  $$ SELECT r.role
       FROM (VALUES ('anon'), ('authenticated'), ('service_role')) r (role)
      WHERE has_table_privilege(r.role, 'private.rate_limit_counters',
                                'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') $$,
  'rate_limit_counters: anon, authenticated e service_role não têm privilégio algum na tabela'
);

SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT bucket FROM private.rate_limit_counters $$, '42501', NULL,
  'rate_limit_counters: anon não lê os contadores'
);
RESET ROLE;

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT bucket FROM private.rate_limit_counters $$, '42501', NULL,
  'rate_limit_counters: authenticated (CEO aal2) não lê os contadores'
);
SELECT tests.clear_authentication();

SET LOCAL ROLE service_role;
SELECT throws_ok(
  $$ SELECT bucket FROM private.rate_limit_counters $$, '42501', NULL,
  'rate_limit_counters: service_role não lê os contadores direto (só via rate_limit_hit)'
);
RESET ROLE;

-- service_role: nem a secret key escreve perfis, auditoria ou template ---------------------------------------------------
SELECT is_empty(
  $$ SELECT t.name
       FROM (VALUES ('public.profiles'), ('public.audit_events'), ('public.default_stage_template')) t (name)
      WHERE has_table_privilege('service_role', t.name::regclass, 'INSERT,UPDATE,DELETE,TRUNCATE')
         OR has_any_column_privilege('service_role', t.name::regclass, 'INSERT,UPDATE') $$,
  'AC-31: service_role não tem INSERT/UPDATE/DELETE/TRUNCATE em profiles, audit_events nem default_stage_template'
);

SELECT is_empty(
  $$ SELECT t.name
       FROM (VALUES ('public.profiles'), ('public.audit_events'), ('public.default_stage_template')) t (name)
      WHERE NOT has_table_privilege('service_role', t.name::regclass, 'SELECT') $$,
  'service_role mantém SELECT em profiles, audit_events e default_stage_template'
);

SELECT ok(
  NOT has_sequence_privilege('service_role', 'public.audit_events_id_seq', 'USAGE,SELECT,UPDATE'),
  'AC-24: service_role não tem privilégio na sequência audit_events_id_seq'
);

SET LOCAL ROLE service_role;
SELECT throws_ok(
  $$ UPDATE public.profiles SET role = 'ceo', client_id = NULL
      WHERE id = '00000000-0000-4000-8000-0000000000c1' $$,
  '42501', NULL, 'AC-31: service_role não promove perfil a CEO por UPDATE em profiles (42501)'
);
SELECT throws_ok(
  $$ INSERT INTO public.profiles (id, role, display_name)
     VALUES ('00000000-0000-4000-8000-0000000000e1', 'ceo', 'Promovido') $$,
  '42501', NULL, 'AC-31: service_role não cria perfil de CEO por INSERT em profiles (42501)'
);
SELECT throws_ok(
  $$ DELETE FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000c1' $$,
  '42501', NULL, 'AC-31: service_role não apaga perfil (42501)'
);
SELECT throws_ok(
  $$ INSERT INTO public.audit_events (action, resource_type, resource_id)
     VALUES ('client.forged', 'client', '00000000-0000-4000-8000-00000000000a') $$,
  '42501', NULL, 'AC-24: service_role não forja evento por INSERT em audit_events (42501)'
);
SELECT throws_ok(
  $$ SELECT nextval('public.audit_events_id_seq') $$,
  '42501', NULL, 'AC-24: service_role não consome a sequência de audit_events (42501)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.current_principal() $$,
  '42501', NULL, 'SEC-04: service_role não executa current_principal (42501)'
);
RESET ROLE;

-- private.password_baselines: ninguém lê nem escreve direto -------------------------------------------------------------------
SELECT is_empty(
  $$ SELECT r.role
       FROM (VALUES ('anon'), ('authenticated'), ('service_role')) r (role)
      WHERE has_table_privilege(r.role, 'private.password_baselines',
                                'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
         OR has_any_column_privilege(r.role, 'private.password_baselines', 'SELECT,INSERT,UPDATE,REFERENCES') $$,
  'password_baselines: anon, authenticated e service_role não têm privilégio algum na tabela'
);

SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT hash_digest FROM private.password_baselines $$, '42501', NULL,
  'password_baselines: anon não lê as linhas de base de senha'
);
RESET ROLE;

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT hash_digest FROM private.password_baselines $$, '42501', NULL,
  'password_baselines: authenticated (CEO aal2) não lê as linhas de base de senha'
);
SELECT tests.clear_authentication();

SET LOCAL ROLE service_role;
SELECT throws_ok(
  $$ SELECT hash_digest FROM private.password_baselines $$, '42501', NULL,
  'password_baselines: service_role não lê as linhas de base de senha'
);
RESET ROLE;

SELECT * FROM finish();
ROLLBACK;
