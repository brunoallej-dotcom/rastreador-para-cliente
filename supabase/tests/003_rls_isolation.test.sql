-- Isolamento por RLS (Onda 2): AC-09 (cliente A não vê B), AC-08 (policies: CEO aal1 não lê,
-- CEO aal2 lê tudo) e E-08 (conta desativada ou sessão apagada não lê nada, mesmo com JWT válido).
BEGIN;
SELECT plan(45);

-- Lista, como o papel atual, uma linha 'tabela:chave' por linha visível em cada tabela. SECURITY
-- INVOKER de propósito: o RLS é avaliado para quem chama. Vive só nesta transação (ROLLBACK).
CREATE FUNCTION tests.visible_rows()
RETURNS SETOF text
LANGUAGE sql
STABLE
AS $$
  SELECT 'clients:' || id::text FROM public.clients
  UNION ALL SELECT 'profiles:' || id::text FROM public.profiles
  UNION ALL SELECT 'processes:' || id::text FROM public.processes
  UNION ALL SELECT 'process_stages:' || id::text FROM public.process_stages
  UNION ALL SELECT 'stage_approvals:' || id::text FROM public.stage_approvals
  UNION ALL SELECT 'audit_events:' || id::text FROM public.audit_events
  UNION ALL SELECT 'default_stage_template:' || position::text FROM public.default_stage_template
$$;
GRANT EXECUTE ON FUNCTION tests.visible_rows() TO anon, authenticated, service_role;

-- arrange (como postgres) ----------------------------------------------------------------------------
-- Clientes A e B; a1 e a2 são logins de A, b1 é login de B, c1 é CEO com TOTP verificado.
-- a3 está desativado, a5 tem sessão expirada, c2 é CEO desativado e c3 é CEO sem sessão.
INSERT INTO public.clients (id, name) VALUES
  ('00000000-0000-4000-8000-00000000000a', 'Cliente A'),
  ('00000000-0000-4000-8000-00000000000b', 'Cliente B');

SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a2', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a3', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a5', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000b1', 'client', '00000000-0000-4000-8000-00000000000b');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c2', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c3', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');

UPDATE public.profiles SET disabled_at = now() WHERE id IN (
  '00000000-0000-4000-8000-0000000000a3', '00000000-0000-4000-8000-0000000000c2'
);
UPDATE auth.sessions SET not_after = now() - interval '1 hour' WHERE id = '00000000-0000-4000-8000-0000000000a5';
DELETE FROM auth.sessions WHERE id = '00000000-0000-4000-8000-0000000000c3';

INSERT INTO public.processes (id, client_id, title) VALUES
  ('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-00000000000a', 'Processo A1'),
  ('00000000-0000-4000-8000-0000000001a2', '00000000-0000-4000-8000-00000000000a', 'Processo A2'),
  ('00000000-0000-4000-8000-0000000001b1', '00000000-0000-4000-8000-00000000000b', 'Processo B1');

INSERT INTO public.process_stages (id, process_id, position, name, status, started_at, completed_at) VALUES
  ('00000000-0000-4000-8000-0000000002a1', '00000000-0000-4000-8000-0000000001a1', 1, 'A1 fase 1', 'completed', now() - interval '2 days', now() - interval '1 day'),
  ('00000000-0000-4000-8000-0000000002a2', '00000000-0000-4000-8000-0000000001a1', 2, 'A1 fase 2', 'in_progress', now() - interval '1 day', NULL),
  ('00000000-0000-4000-8000-0000000002a3', '00000000-0000-4000-8000-0000000001a1', 3, 'A1 fase 3', 'pending', NULL, NULL),
  ('00000000-0000-4000-8000-0000000002a4', '00000000-0000-4000-8000-0000000001a2', 1, 'A2 fase 1', 'in_progress', now(), NULL),
  ('00000000-0000-4000-8000-0000000002b1', '00000000-0000-4000-8000-0000000001b1', 1, 'B1 fase 1', 'completed', now() - interval '2 days', now() - interval '1 day'),
  ('00000000-0000-4000-8000-0000000002b2', '00000000-0000-4000-8000-0000000001b1', 2, 'B1 fase 2', 'in_progress', now() - interval '1 day', NULL);

INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by) VALUES
  ('00000000-0000-4000-8000-0000000002a1', '00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000000c1'),
  ('00000000-0000-4000-8000-0000000002b1', '00000000-0000-4000-8000-0000000001b1', '00000000-0000-4000-8000-0000000000c1');

INSERT INTO public.audit_events (actor_id, actor_role, action, resource_type, resource_id, client_id, process_id) VALUES
  ('00000000-0000-4000-8000-0000000000c1', 'ceo', 'process.created', 'process',
   '00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000001a1'),
  ('00000000-0000-4000-8000-0000000000c1', 'ceo', 'process.created', 'process',
   '00000000-0000-4000-8000-0000000001b1', '00000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-0000000001b1');

-- AC-09: cliente A (login a1) --------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');

SELECT results_eq(
  $$ SELECT id FROM public.clients ORDER BY id $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000a'::uuid) $$,
  'AC-09: cliente A lê só a própria linha de clients'
);
SELECT is_empty(
  $$ SELECT id FROM public.clients WHERE id = '00000000-0000-4000-8000-00000000000b' $$,
  'AC-09: cliente A não lê o cliente B, nem filtrando pelo id de B'
);
SELECT results_eq(
  $$ SELECT id FROM public.processes ORDER BY id $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000001a1'::uuid), ('00000000-0000-4000-8000-0000000001a2'::uuid) $$,
  'AC-09: cliente A lê só os próprios processos'
);
SELECT is_empty(
  $$ SELECT id FROM public.processes WHERE client_id = '00000000-0000-4000-8000-00000000000b' $$,
  'AC-09: cliente A não lê processos de B filtrando por client_id de B'
);
SELECT is_empty(
  $$ SELECT id FROM public.processes WHERE id = '00000000-0000-4000-8000-0000000001b1' $$,
  'AC-09: cliente A não lê o processo de B filtrando pelo id dele'
);
SELECT results_eq(
  $$ SELECT id FROM public.process_stages ORDER BY id $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000002a1'::uuid), ('00000000-0000-4000-8000-0000000002a2'::uuid),
            ('00000000-0000-4000-8000-0000000002a3'::uuid), ('00000000-0000-4000-8000-0000000002a4'::uuid) $$,
  'AC-09: cliente A lê só as fases dos próprios processos'
);
SELECT is_empty(
  $$ SELECT id FROM public.process_stages WHERE process_id = '00000000-0000-4000-8000-0000000001b1' $$,
  'AC-09: cliente A não lê fases do processo de B filtrando por process_id de B'
);
SELECT is_empty(
  $$ SELECT id FROM public.process_stages
      WHERE id IN ('00000000-0000-4000-8000-0000000002b1', '00000000-0000-4000-8000-0000000002b2') $$,
  'AC-09: cliente A não lê as fases de B filtrando pelos ids delas'
);
SELECT is_empty(
  $$ SELECT id FROM public.stage_approvals $$,
  'AC-09: cliente não lê stage_approvals'
);
SELECT is_empty(
  $$ SELECT id FROM public.audit_events $$,
  'AC-09: cliente não lê audit_events'
);
SELECT is_empty(
  $$ SELECT position FROM public.default_stage_template $$,
  'AC-09: cliente não lê default_stage_template'
);
SELECT results_eq(
  $$ SELECT id FROM public.profiles ORDER BY id $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000a1'::uuid) $$,
  'AC-09: cliente lê só o próprio perfil (nem o colega do mesmo cliente)'
);
SELECT is_empty(
  $$ SELECT id FROM public.profiles
      WHERE id IN ('00000000-0000-4000-8000-0000000000a2', '00000000-0000-4000-8000-0000000000b1',
                   '00000000-0000-4000-8000-0000000000c1') $$,
  'AC-09: cliente A não lê perfis de colega, de B nem de CEO, filtrando pelos ids'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title)
     VALUES ('00000000-0000-4000-8000-00000000000a', 'Processo forjado') $$,
  '42501', NULL, 'AC-09: cliente não escreve direto em processes'
);
SELECT throws_ok(
  $$ UPDATE public.clients SET name = 'Renomeado' WHERE id = '00000000-0000-4000-8000-00000000000a' $$,
  '42501', NULL, 'AC-09: cliente não altera clients'
);
SELECT throws_ok(
  $$ DELETE FROM public.process_stages WHERE process_id = '00000000-0000-4000-8000-0000000001a1' $$,
  '42501', NULL, 'AC-09: cliente não apaga fases'
);
SELECT tests.clear_authentication();

-- AC-09: o outro login de A vê os mesmos dados do tenant ------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a2');
SELECT results_eq(
  $$ SELECT id FROM public.processes ORDER BY id $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000001a1'::uuid), ('00000000-0000-4000-8000-0000000001a2'::uuid) $$,
  'AC-09: o tenant é do cliente, não do login: a2 lê os mesmos processos de a1'
);
SELECT tests.clear_authentication();

-- AC-09: cliente B (login b1) ------------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000b1');
SELECT set_eq(
  $$ SELECT r FROM tests.visible_rows() r $$,
  $$ VALUES ('clients:00000000-0000-4000-8000-00000000000b'),
            ('profiles:00000000-0000-4000-8000-0000000000b1'),
            ('processes:00000000-0000-4000-8000-0000000001b1'),
            ('process_stages:00000000-0000-4000-8000-0000000002b1'),
            ('process_stages:00000000-0000-4000-8000-0000000002b2') $$,
  'AC-09: cliente B vê exatamente as próprias linhas, em todas as tabelas'
);
SELECT is_empty(
  $$ SELECT id FROM public.clients WHERE id = '00000000-0000-4000-8000-00000000000a'
     UNION ALL SELECT id FROM public.processes WHERE client_id = '00000000-0000-4000-8000-00000000000a'
     UNION ALL SELECT id FROM public.process_stages WHERE process_id IN (
       '00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000001a2') $$,
  'AC-09: cliente B não lê nada de A, nem filtrando pelos ids de A'
);
SELECT tests.clear_authentication();

-- AC-08: aal2 no JWT não promove cliente a CEO ----------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1', 'aal2');
SELECT is_empty(
  $$ SELECT id FROM public.processes WHERE client_id = '00000000-0000-4000-8000-00000000000b' $$,
  'AC-08: cliente com claim aal2 continua sem ler processos de B'
);
SELECT set_eq(
  $$ SELECT id FROM public.profiles $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000a1'::uuid) $$,
  'AC-08: cliente com claim aal2 continua lendo só o próprio perfil'
);
SELECT tests.clear_authentication();

-- AC-08: CEO aal1 não lê nada além do próprio perfil ----------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT is_empty($$ SELECT id FROM public.clients $$, 'AC-08: CEO aal1 não lê clients');
SELECT results_eq(
  $$ SELECT id FROM public.profiles $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000c1'::uuid) $$,
  'AC-08: CEO aal1 lê só o próprio perfil'
);
SELECT is_empty($$ SELECT id FROM public.processes $$, 'AC-08: CEO aal1 não lê processes');
SELECT is_empty($$ SELECT id FROM public.process_stages $$, 'AC-08: CEO aal1 não lê process_stages');
SELECT is_empty($$ SELECT id FROM public.stage_approvals $$, 'AC-08: CEO aal1 não lê stage_approvals');
SELECT is_empty($$ SELECT id FROM public.audit_events $$, 'AC-08: CEO aal1 não lê audit_events');
SELECT is_empty($$ SELECT position FROM public.default_stage_template $$, 'AC-08: CEO aal1 não lê default_stage_template');
SELECT tests.clear_authentication();

-- AC-08: CEO aal2 lê tudo ----------------------------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT set_eq(
  $$ SELECT id FROM public.clients
      WHERE id IN ('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000b') $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000a'::uuid), ('00000000-0000-4000-8000-00000000000b'::uuid) $$,
  'AC-08: CEO aal2 lê os clientes A e B'
);
SELECT set_eq(
  $$ SELECT id FROM public.profiles
      WHERE id IN ('00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000a2',
                   '00000000-0000-4000-8000-0000000000a3', '00000000-0000-4000-8000-0000000000a5',
                   '00000000-0000-4000-8000-0000000000b1', '00000000-0000-4000-8000-0000000000c1',
                   '00000000-0000-4000-8000-0000000000c2', '00000000-0000-4000-8000-0000000000c3') $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000a1'::uuid), ('00000000-0000-4000-8000-0000000000a2'::uuid),
            ('00000000-0000-4000-8000-0000000000a3'::uuid), ('00000000-0000-4000-8000-0000000000a5'::uuid),
            ('00000000-0000-4000-8000-0000000000b1'::uuid), ('00000000-0000-4000-8000-0000000000c1'::uuid),
            ('00000000-0000-4000-8000-0000000000c2'::uuid), ('00000000-0000-4000-8000-0000000000c3'::uuid) $$,
  'AC-08: CEO aal2 lê os perfis de todos os usuários, inclusive desativados'
);
SELECT set_eq(
  $$ SELECT id FROM public.processes
      WHERE id IN ('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000001a2',
                   '00000000-0000-4000-8000-0000000001b1') $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000001a1'::uuid), ('00000000-0000-4000-8000-0000000001a2'::uuid),
            ('00000000-0000-4000-8000-0000000001b1'::uuid) $$,
  'AC-08: CEO aal2 lê os processos de A e de B'
);
SELECT set_eq(
  $$ SELECT id FROM public.process_stages WHERE process_id IN (
       '00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000001a2',
       '00000000-0000-4000-8000-0000000001b1') $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000002a1'::uuid), ('00000000-0000-4000-8000-0000000002a2'::uuid),
            ('00000000-0000-4000-8000-0000000002a3'::uuid), ('00000000-0000-4000-8000-0000000002a4'::uuid),
            ('00000000-0000-4000-8000-0000000002b1'::uuid), ('00000000-0000-4000-8000-0000000002b2'::uuid) $$,
  'AC-08: CEO aal2 lê as fases de todos os processos'
);
SELECT set_eq(
  $$ SELECT process_stage_id FROM public.stage_approvals WHERE approved_by = '00000000-0000-4000-8000-0000000000c1' $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000002a1'::uuid), ('00000000-0000-4000-8000-0000000002b1'::uuid) $$,
  'AC-08: CEO aal2 lê as aprovações'
);
SELECT set_eq(
  $$ SELECT client_id FROM public.audit_events WHERE actor_id = '00000000-0000-4000-8000-0000000000c1' $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000a'::uuid), ('00000000-0000-4000-8000-00000000000b'::uuid) $$,
  'AC-08: CEO aal2 lê a auditoria de todos os clientes'
);
SELECT isnt_empty(
  $$ SELECT position FROM public.default_stage_template $$,
  'AC-08: CEO aal2 lê o template padrão de fases'
);
SELECT tests.clear_authentication();

-- E-08: conta desativada, sessão apagada ou expirada, sessão de outro usuário ---------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a3');
SELECT is_empty(
  $$ SELECT r FROM tests.visible_rows() r $$,
  'E-08: cliente desativado (disabled_at) não vê nada, nem o próprio perfil'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a2');
SELECT isnt_empty(
  $$ SELECT id FROM public.processes $$,
  'E-08: antes de a sessão ser apagada, o login a2 lê os processos de A'
);
SELECT tests.clear_authentication();
DELETE FROM auth.sessions WHERE id = '00000000-0000-4000-8000-0000000000a2';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a2');
SELECT is_empty(
  $$ SELECT r FROM tests.visible_rows() r $$,
  'E-08: com a sessão apagada (JWT ainda válido), o login a2 não vê nada'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a5');
SELECT is_empty(
  $$ SELECT r FROM tests.visible_rows() r $$,
  'E-08: sessão expirada (not_after no passado) não vê nada'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2');
SELECT is_empty(
  $$ SELECT r FROM tests.visible_rows() r $$,
  'E-08: CEO desativado, mesmo com aal2, não vê nada'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT is_empty(
  $$ SELECT r FROM tests.visible_rows() r $$,
  'E-08: CEO sem sessão em auth.sessions, mesmo com aal2, não vê nada'
);
SELECT tests.clear_authentication();

SELECT set_config(
  'request.jwt.claims',
  json_build_object(
    'sub', '00000000-0000-4000-8000-0000000000a1', 'role', 'authenticated', 'aal', 'aal1',
    'session_id', '00000000-0000-4000-8000-0000000000b1'
  )::text,
  true
);
SET LOCAL ROLE authenticated;
SELECT is_empty(
  $$ SELECT r FROM tests.visible_rows() r $$,
  'E-08: session_id de outro usuário no JWT (sub = a1, sessão de b1) não vê nada'
);
RESET ROLE;

SELECT tests.clear_authentication();
SET LOCAL ROLE authenticated;
SELECT is_empty(
  $$ SELECT r FROM tests.visible_rows() r $$,
  'E-08: papel authenticated sem claims não vê nada'
);
RESET ROLE;

-- E-08: session_id ausente ou malformado no JWT é "sem sessão": nada de erro, nada de linha --------------------------
SELECT set_config(
  'request.jwt.claims',
  json_build_object(
    'sub', '00000000-0000-4000-8000-0000000000a1', 'role', 'authenticated', 'aal', 'aal1', 'session_id', 'not-a-uuid'
  )::text,
  true
);
SELECT set_config('role', 'authenticated', true);
SELECT is_empty(
  $$ SELECT r FROM tests.visible_rows() r $$,
  'E-08: session_id que não é UUID no JWT não vê nada e não gera erro'
);
RESET ROLE;

SELECT set_config(
  'request.jwt.claims',
  json_build_object('sub', '00000000-0000-4000-8000-0000000000a1', 'role', 'authenticated', 'aal', 'aal1')::text,
  true
);
SELECT set_config('role', 'authenticated', true);
SELECT is_empty(
  $$ SELECT r FROM tests.visible_rows() r $$,
  'E-08: claims sem session_id não veem nada e não geram erro'
);
RESET ROLE;
SELECT tests.clear_authentication();

SELECT * FROM finish();
ROLLBACK;
