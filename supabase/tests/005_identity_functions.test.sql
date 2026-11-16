-- Funções de identidade (Onda 2): AC-08 (funções de CEO negam cliente e CEO aal1), comportamento
-- de current_principal, mark_password_changed e das funções de conta, E-08, E-19 e a auditoria
-- (ator, papel, cliente e request_id gravados na mesma transação).
BEGIN;
SELECT plan(116);

-- arrange (como postgres) -----------------------------------------------------------------------------
-- Clientes A e B (com logins) e Z (sem logins).
-- a1..a6 são logins de A: a3 desativado, a4 sem sessão, a5 com sessão expirada.
-- b1 é login de B. c1 é o CEO que age; c2 é o CEO alvo (E-19); c3 é CEO desativado; c4 é CEO sem sessão.
INSERT INTO public.clients (id, name) VALUES
  ('00000000-0000-4000-8000-00000000000a', 'Cliente A'),
  ('00000000-0000-4000-8000-00000000000b', 'Cliente B'),
  ('00000000-0000-4000-8000-00000000000c', 'Cliente Z');

SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a', 'Ana Cliente');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a2', 'client', '00000000-0000-4000-8000-00000000000a', 'Alvo Dois');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a3', 'client', '00000000-0000-4000-8000-00000000000a', 'Desativado Três');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a4', 'client', '00000000-0000-4000-8000-00000000000a', 'Sem Sessão Quatro');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a5', 'client', '00000000-0000-4000-8000-00000000000a', 'Sessão Expirada Cinco');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a6', 'client', '00000000-0000-4000-8000-00000000000a', 'Alvo Seis');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000b1', 'client', '00000000-0000-4000-8000-00000000000b', 'Bruno de B');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo', NULL, 'Carlos CEO');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c2', 'ceo', NULL, 'Carla CEO');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c3', 'ceo', NULL, 'Cesar Desativado');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c4', 'ceo', NULL, 'Celia Sem Sessão');
-- c3 (desativado) e c4 (sem sessão) têm fator verificado: o que os nega é só o perfil e a sessão
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c3');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c4');

UPDATE public.profiles SET disabled_at = now() WHERE id IN ('00000000-0000-4000-8000-0000000000a3', '00000000-0000-4000-8000-0000000000c3');
UPDATE auth.sessions SET not_after = now() - interval '1 hour' WHERE id = '00000000-0000-4000-8000-0000000000a5';
DELETE FROM auth.sessions WHERE id IN ('00000000-0000-4000-8000-0000000000a4', '00000000-0000-4000-8000-0000000000c4');

-- Sessões extras: duas de a1 e uma de a2 (além da sessão da requisição, que tem o id do usuário).
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal) VALUES
  ('00000000-0000-4000-8000-0000000003a1', '00000000-0000-4000-8000-0000000000a1', now(), now(), 'aal1'),
  ('00000000-0000-4000-8000-0000000003a2', '00000000-0000-4000-8000-0000000000a1', now(), now(), 'aal1'),
  ('00000000-0000-4000-8000-0000000003b1', '00000000-0000-4000-8000-0000000000a2', now(), now(), 'aal1');

-- AC-08: cliente não executa nenhuma função de CEO ---------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT public.record_account_provisioned('00000000-0000-4000-8000-0000000000a2') $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não executa record_account_provisioned'
);
SELECT throws_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000a2', true) $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não executa set_account_disabled'
);
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a2', 'Renomeado pelo cliente') $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não executa set_account_display_name'
);
SELECT throws_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000a2') $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não executa require_password_change'
);
SELECT throws_ok(
  $$ SELECT * FROM public.list_client_users('00000000-0000-4000-8000-00000000000a') $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não executa list_client_users'
);
SELECT tests.clear_authentication();

-- AC-08: CEO com aal1 também não executa -------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT throws_ok(
  $$ SELECT public.record_account_provisioned('00000000-0000-4000-8000-0000000000a2') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 não executa record_account_provisioned'
);
SELECT throws_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000a2', true) $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 não executa set_account_disabled'
);
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a2', 'Renomeado sem MFA') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 não executa set_account_display_name'
);
SELECT throws_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000a2') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 não executa require_password_change'
);
SELECT throws_ok(
  $$ SELECT * FROM public.list_client_users('00000000-0000-4000-8000-00000000000a') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 não executa list_client_users'
);
SELECT tests.clear_authentication();

-- AC-08: CEO desativado ou sem sessão não executa, mesmo com aal2 ---------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT throws_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000a2', true) $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO desativado (aal2) não executa função de CEO'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c4', 'aal2');
SELECT throws_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000a2', true) $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO sem sessão em auth.sessions (aal2) não executa função de CEO'
);
SELECT tests.clear_authentication();

SELECT is_empty(
  -- fora o evento que o gatilho de criação grava para cada CEO criado (RF-14, 011_ceo_creation_audit)
  $$ SELECT id FROM public.audit_events
      WHERE resource_id::text LIKE '00000000-0000-4000-8000-0000000000__'
        AND NOT (action = 'account.provisioned' AND actor_id IS NULL
                 AND metadata @> '{"channel":"auth_admin"}'::jsonb) $$,
  'AC-08: as chamadas negadas não gravaram evento de auditoria'
);

-- current_principal() ----------------------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT results_eq(
  $$ SELECT user_id, role::text, client_id, display_name, aal, has_verified_totp, must_change_password
       FROM public.current_principal() $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000a1'::uuid, 'client', '00000000-0000-4000-8000-00000000000a'::uuid, 'Ana Cliente', 'aal1', false, true) $$,
  'current_principal: cliente devolve uma linha com papel, cliente, nome, aal1, sem TOTP e com troca de senha pendente'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT results_eq(
  $$ SELECT user_id, role::text, client_id, display_name, aal, has_verified_totp, must_change_password
       FROM public.current_principal() $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', NULL::uuid, 'Carlos CEO', 'aal1', false, true) $$,
  'current_principal: CEO sem fator TOTP devolve has_verified_totp = false e client_id nulo'
);
SELECT tests.clear_authentication();

INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
VALUES (gen_random_uuid(), '00000000-0000-4000-8000-0000000000c2', 'totp-pendente', 'totp', 'unverified', now(), now(), 'TESTSECRET');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal1');
SELECT is(
  (SELECT has_verified_totp FROM public.current_principal()),
  false,
  'current_principal: fator TOTP ainda não verificado não conta como has_verified_totp'
);
SELECT tests.clear_authentication();

SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT results_eq(
  $$ SELECT aal, has_verified_totp FROM public.current_principal() $$,
  $$ VALUES ('aal1', true) $$,
  'current_principal: depois do TOTP verificado, sessão aal1 devolve has_verified_totp = true'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT aal, has_verified_totp FROM public.current_principal() $$,
  $$ VALUES ('aal2', true) $$,
  'current_principal: sessão aal2 devolve aal = aal2'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a3');
SELECT is_empty(
  $$ SELECT * FROM public.current_principal() $$,
  'E-08: perfil desativado não tem principal, mesmo com sessão em auth.sessions'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a4');
SELECT is_empty(
  $$ SELECT * FROM public.current_principal() $$,
  'E-08: sessão apagada de auth.sessions não tem principal, mesmo com JWT válido'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a5');
SELECT is_empty(
  $$ SELECT * FROM public.current_principal() $$,
  'E-08: sessão expirada (not_after no passado) não tem principal'
);
SELECT tests.clear_authentication();

SELECT set_config(
  'request.jwt.claims',
  json_build_object('sub', '00000000-0000-4000-8000-0000000000a1', 'role', 'authenticated', 'aal', 'aal1', 'session_id', '00000000-0000-4000-8000-0000000000b1')::text,
  true
);
SET LOCAL ROLE authenticated;
SELECT is_empty(
  $$ SELECT * FROM public.current_principal() $$,
  'E-08: session_id de outro usuário no JWT não tem principal'
);
RESET ROLE;

SELECT tests.clear_authentication();
SET LOCAL ROLE authenticated;
SELECT is_empty(
  $$ SELECT * FROM public.current_principal() $$,
  'current_principal: authenticated sem claims não tem principal'
);
RESET ROLE;

-- E-08: session_id ausente ou malformado no JWT é "sem sessão", nunca um erro.
SELECT set_config(
  'request.jwt.claims',
  json_build_object('sub', '00000000-0000-4000-8000-0000000000a1', 'role', 'authenticated', 'aal', 'aal1', 'session_id', 'not-a-uuid')::text,
  true
);
SELECT set_config('role', 'authenticated', true);
SELECT is_empty(
  $$ SELECT * FROM public.current_principal() $$,
  'E-08: session_id que não é UUID no JWT devolve zero linhas, sem exceção'
);
RESET ROLE;

SELECT set_config(
  'request.jwt.claims',
  json_build_object('sub', '00000000-0000-4000-8000-0000000000a1', 'role', 'authenticated', 'aal', 'aal1')::text,
  true
);
SELECT set_config('role', 'authenticated', true);
SELECT is_empty(
  $$ SELECT * FROM public.current_principal() $$,
  'E-08: claims sem session_id devolvem zero linhas, sem exceção'
);
RESET ROLE;

SELECT set_config(
  'request.jwt.claims',
  json_build_object('sub', '00000000-0000-4000-8000-0000000000a1', 'role', 'authenticated', 'aal', 'aal1', 'session_id', '')::text,
  true
);
SELECT set_config('role', 'authenticated', true);
SELECT is_empty(
  $$ SELECT * FROM public.current_principal() $$,
  'E-08: session_id vazio no JWT devolve zero linhas, sem exceção'
);
RESET ROLE;

SELECT set_config(
  'request.jwt.claims',
  json_build_object('sub', '00000000-0000-4000-8000-0000000000a1', 'role', 'authenticated', 'aal', 'aal1', 'session_id', upper('00000000-0000-4000-8000-0000000000a1'))::text,
  true
);
SELECT set_config('role', 'authenticated', true);
SELECT isnt_empty(
  $$ SELECT * FROM public.current_principal() $$,
  'E-08: session_id em maiúsculas (UUID válido) continua identificando a sessão'
);
RESET ROLE;
SELECT tests.clear_authentication();

-- list_client_users ------------------------------------------------------------------------------------------------------
-- Datas fixas para provar a ordenação (created_at, id): a1 e a6 empatam e desempatam pelo id.
UPDATE public.profiles p
   SET created_at = v.ts
  FROM (VALUES
    ('00000000-0000-4000-8000-0000000000a2'::uuid, now() - interval '5 days'),
    ('00000000-0000-4000-8000-0000000000a1'::uuid, now() - interval '4 days'),
    ('00000000-0000-4000-8000-0000000000a6'::uuid, now() - interval '4 days'),
    ('00000000-0000-4000-8000-0000000000a3'::uuid, now() - interval '3 days'),
    ('00000000-0000-4000-8000-0000000000a4'::uuid, now() - interval '2 days'),
    ('00000000-0000-4000-8000-0000000000a5'::uuid, now() - interval '1 day')
  ) v (id, ts)
 WHERE p.id = v.id;
UPDATE auth.users SET last_sign_in_at = '2026-11-01 10:00:00+00' WHERE id = '00000000-0000-4000-8000-0000000000a1';

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT user_id FROM public.list_client_users('00000000-0000-4000-8000-00000000000a') $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000a2'::uuid), ('00000000-0000-4000-8000-0000000000a1'::uuid), ('00000000-0000-4000-8000-0000000000a6'::uuid), ('00000000-0000-4000-8000-0000000000a3'::uuid), ('00000000-0000-4000-8000-0000000000a4'::uuid), ('00000000-0000-4000-8000-0000000000a5'::uuid) $$,
  'AC-08: CEO aal2 lista só os logins do cliente, por created_at e id (sem CEO e sem logins de B)'
);
SELECT results_eq(
  $$ SELECT email, display_name, disabled_at IS NULL, must_change_password, last_sign_in_at,
            created_at = now() - interval '4 days'
       FROM public.list_client_users('00000000-0000-4000-8000-00000000000a') WHERE user_id = '00000000-0000-4000-8000-0000000000a1' $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000a1@test.local', 'Ana Cliente', true, true, '2026-11-01 10:00:00+00'::timestamptz, true) $$,
  'list_client_users: devolve e-mail, nome, pendência de senha, último acesso e criação'
);
SELECT is(
  (SELECT disabled_at IS NOT NULL FROM public.list_client_users('00000000-0000-4000-8000-00000000000a') WHERE user_id = '00000000-0000-4000-8000-0000000000a3'),
  true,
  'list_client_users: login desativado aparece com disabled_at'
);
SELECT results_eq(
  $$ SELECT user_id FROM public.list_client_users('00000000-0000-4000-8000-00000000000b') $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000b1'::uuid) $$,
  'list_client_users: o cliente B lista só o próprio login'
);
SELECT is_empty(
  $$ SELECT user_id FROM public.list_client_users('00000000-0000-4000-8000-00000000000c') $$,
  'list_client_users: cliente sem logins devolve conjunto vazio'
);
SELECT throws_ok(
  $$ SELECT * FROM public.list_client_users('00000000-0000-4000-8000-0000000000ee') $$,
  'P0001', 'NOT_FOUND', 'list_client_users: cliente inexistente falha com NOT_FOUND'
);
SELECT tests.clear_authentication();

-- mark_password_changed ----------------------------------------------------------------------------------------------------
-- A pendência só sai com prova da troca: o hash atual (auth.users.encrypted_password) tem de diferir
-- da linha de base gravada na criação. Os testes simulam a troca feita pelo Auth com um UPDATE.

-- Sem troca de senha: PASSWORD_UNCHANGED e nada muda.
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT public.mark_password_changed() $$,
  'P0001', 'PASSWORD_UNCHANGED', 'E-13: mark_password_changed sem troca de senha falha com PASSWORD_UNCHANGED'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT must_change_password FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a1'),
  true,
  'E-13: sem troca de senha, must_change_password continua true'
);
SELECT is(
  (SELECT count(*)::int FROM auth.sessions WHERE user_id = '00000000-0000-4000-8000-0000000000a1'),
  3,
  'E-13: sem troca de senha, nenhuma sessão do usuário é revogada'
);
SELECT is_empty(
  $$ SELECT id FROM public.audit_events WHERE action = 'account.password_changed' AND resource_id = '00000000-0000-4000-8000-0000000000a1' $$,
  'E-13: sem troca de senha, nenhum evento account.password_changed é gravado'
);

-- Com troca de senha (o Auth gravou um hash novo).
UPDATE auth.users SET encrypted_password = 'changed-1' WHERE id = '00000000-0000-4000-8000-0000000000a1';
SELECT tests.set_request_id('req-pwd-0001');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT lives_ok(
  $$ SELECT public.mark_password_changed() $$,
  'mark_password_changed: o próprio cliente executa depois de trocar a senha'
);
SELECT is(
  (SELECT must_change_password FROM public.current_principal()),
  false,
  'mark_password_changed: limpa a pendência e a sessão da requisição continua válida'
);
SELECT tests.clear_authentication();

SELECT results_eq(
  $$ SELECT id FROM auth.sessions WHERE user_id = '00000000-0000-4000-8000-0000000000a1' ORDER BY id $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000a1'::uuid) $$,
  'AC-06: mark_password_changed apaga as demais sessões do usuário e mantém a da requisição'
);
SELECT results_eq(
  $$ SELECT id FROM auth.sessions WHERE id = '00000000-0000-4000-8000-0000000003b1' $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000003b1'::uuid) $$,
  'mark_password_changed: a sessão de outro usuário não é tocada'
);
SELECT results_eq(
  $$ SELECT actor_id, actor_role::text, action, resource_type, resource_id, client_id, process_id IS NULL, request_id
       FROM public.audit_events WHERE action = 'account.password_changed' AND resource_id = '00000000-0000-4000-8000-0000000000a1' $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000a1'::uuid, 'client', 'account.password_changed', 'account', '00000000-0000-4000-8000-0000000000a1'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid, true, 'req-pwd-0001') $$,
  'mark_password_changed: audita account.password_changed com ator, papel, cliente e request_id'
);

-- A linha de base é renovada: chamar de novo sem outra troca volta a falhar.
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT public.mark_password_changed() $$,
  'P0001', 'PASSWORD_UNCHANGED', 'E-13: um segundo mark_password_changed sem nova troca de senha falha com PASSWORD_UNCHANGED'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT count(*)::int FROM public.audit_events WHERE action = 'account.password_changed' AND resource_id = '00000000-0000-4000-8000-0000000000a1'),
  1,
  'E-13: o segundo mark_password_changed não grava outro evento'
);

-- Primeiro acesso de um CEO sem TOTP verificado: a troca de senha acontece com aal1.
-- (c2 só tem um fator ainda não verificado, que não conta.)
UPDATE auth.users SET encrypted_password = 'changed-1' WHERE id = '00000000-0000-4000-8000-0000000000c2';
SELECT tests.set_request_id('req-pwd-0002');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal1');
SELECT lives_ok(
  $$ SELECT public.mark_password_changed() $$,
  'mark_password_changed: CEO sem fator TOTP verificado executa com aal1 (fluxo de primeiro acesso)'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT actor_id, actor_role::text, client_id, request_id
       FROM public.audit_events WHERE action = 'account.password_changed' AND resource_id = '00000000-0000-4000-8000-0000000000c2' $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000c2'::uuid, 'ceo', NULL::uuid, 'req-pwd-0002') $$,
  'mark_password_changed: evento de CEO tem actor_role ceo e client_id nulo'
);

-- CEO com TOTP verificado precisa de aal2, mesmo com a senha trocada (c1 tem fator verificado).
UPDATE auth.users SET encrypted_password = 'changed-1' WHERE id = '00000000-0000-4000-8000-0000000000c1';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT throws_ok(
  $$ SELECT public.mark_password_changed() $$,
  '42501', 'FORBIDDEN', '§3.7: CEO com TOTP verificado e sessão aal1 não executa mark_password_changed (42501)'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT must_change_password FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000c1'),
  true,
  '§3.7: a chamada negada (aal1) não limpou a pendência do CEO'
);
SELECT tests.set_request_id('req-pwd-0003');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.mark_password_changed() $$,
  '§3.7: o mesmo CEO com sessão aal2 executa mark_password_changed'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT must_change_password FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000c1' $$,
  $$ VALUES (false) $$,
  '§3.7: com aal2, o CEO tem a pendência de senha limpa'
);

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a3');
SELECT throws_ok(
  $$ SELECT public.mark_password_changed() $$,
  '42501', 'FORBIDDEN', 'mark_password_changed: perfil desativado é negado'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a4');
SELECT throws_ok(
  $$ SELECT public.mark_password_changed() $$,
  '42501', 'FORBIDDEN', 'mark_password_changed: sessão apagada é negada'
);
SELECT tests.clear_authentication();
SET LOCAL ROLE authenticated;
SELECT throws_ok(
  $$ SELECT public.mark_password_changed() $$,
  '42501', 'FORBIDDEN', 'mark_password_changed: sem claims é negado'
);
RESET ROLE;

-- set_account_disabled -----------------------------------------------------------------------------------------------------------
SELECT tests.set_request_id('req-dis-0001');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000a2', true) $$,
  'AC-08: CEO aal2 desativa a conta de um cliente'
);
SELECT tests.clear_authentication();

SELECT is(
  (SELECT disabled_at IS NOT NULL FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a2'),
  true,
  'set_account_disabled: marca disabled_at no perfil'
);
SELECT is_empty(
  $$ SELECT id FROM auth.sessions WHERE user_id = '00000000-0000-4000-8000-0000000000a2' $$,
  'set_account_disabled: apaga todas as sessões do usuário'
);
SELECT results_eq(
  $$ SELECT actor_id, actor_role::text, action, resource_type, resource_id, client_id, process_id IS NULL, request_id
       FROM public.audit_events WHERE action = 'account.disabled' AND resource_id = '00000000-0000-4000-8000-0000000000a2' $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'account.disabled', 'account', '00000000-0000-4000-8000-0000000000a2'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid, true, 'req-dis-0001') $$,
  'set_account_disabled: audita account.disabled com ator, papel, cliente e request_id'
);

INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal) VALUES ('00000000-0000-4000-8000-0000000000a2', '00000000-0000-4000-8000-0000000000a2', now(), now(), 'aal1');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a2');
SELECT is_empty(
  $$ SELECT * FROM public.current_principal() $$,
  'E-08: conta desativada com sessão viva (JWT válido) não tem principal'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000a2', true) $$,
  'set_account_disabled: desativar de novo é idempotente'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT count(*)::int FROM public.audit_events WHERE action = 'account.disabled' AND resource_id = '00000000-0000-4000-8000-0000000000a2'),
  1,
  'set_account_disabled: desativar uma conta já desativada não grava novo evento'
);

SELECT tests.set_request_id('req-ena-0001');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000a2', false) $$,
  'set_account_disabled: reativa a conta'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT disabled_at IS NULL FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a2'),
  true,
  'set_account_disabled: reativar limpa disabled_at'
);
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal) VALUES ('00000000-0000-4000-8000-0000000000a2', '00000000-0000-4000-8000-0000000000a2', now(), now(), 'aal1');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a2');
SELECT isnt_empty(
  $$ SELECT * FROM public.current_principal() $$,
  'set_account_disabled: conta reativada com sessão viva volta a ter principal'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT actor_id, actor_role::text, resource_id, client_id, request_id
       FROM public.audit_events WHERE action = 'account.enabled' AND resource_id = '00000000-0000-4000-8000-0000000000a2' $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', '00000000-0000-4000-8000-0000000000a2'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid, 'req-ena-0001') $$,
  'set_account_disabled: audita account.enabled com ator, papel, cliente e request_id'
);

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000a2', false) $$,
  'set_account_disabled: reativar de novo é idempotente'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT count(*)::int FROM public.audit_events WHERE action = 'account.enabled' AND resource_id = '00000000-0000-4000-8000-0000000000a2'),
  1,
  'set_account_disabled: reativar uma conta já ativa não grava novo evento'
);

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000c2', true) $$,
  'P0001', 'NOT_FOUND', 'E-19: alvo que é CEO falha com NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000ee', true) $$,
  'P0001', 'NOT_FOUND', 'E-19: alvo inexistente falha com NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000a2', NULL) $$,
  'P0001', 'INVALID_INPUT', 'set_account_disabled: p_disabled nulo falha com INVALID_INPUT'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT p.disabled_at IS NULL AND EXISTS (SELECT 1 FROM auth.sessions s WHERE s.id = '00000000-0000-4000-8000-0000000000c2')
     FROM public.profiles p WHERE p.id = '00000000-0000-4000-8000-0000000000c2'),
  true,
  'E-19: o CEO alvo continua ativo e com a sessão intacta'
);

-- set_account_display_name -----------------------------------------------------------------------------------------------------------
SELECT tests.set_request_id('req-name-0001');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', '  Novo Nome  ') $$,
  'AC-08: CEO aal2 renomeia o login de um cliente'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT display_name FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a6'),
  'Novo Nome',
  'set_account_display_name: grava o nome sem espaços nas pontas'
);
SELECT results_eq(
  $$ SELECT actor_id, actor_role::text, resource_type, resource_id, client_id, request_id
       FROM public.audit_events WHERE action = 'account.updated' AND resource_id = '00000000-0000-4000-8000-0000000000a6' $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'account', '00000000-0000-4000-8000-0000000000a6'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid, 'req-name-0001') $$,
  'set_account_display_name: audita account.updated com ator, papel, cliente e request_id'
);

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', '   ') $$,
  'P0001', 'INVALID_INPUT', 'set_account_display_name: nome em branco falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', '') $$,
  'P0001', 'INVALID_INPUT', 'set_account_display_name: nome vazio falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', NULL) $$,
  'P0001', 'INVALID_INPUT', 'set_account_display_name: nome nulo falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', repeat('n', 121)) $$,
  'P0001', 'INVALID_INPUT', 'set_account_display_name: nome com 121 caracteres falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', E'Linha\nQuebrada') $$,
  'P0001', 'INVALID_INPUT', 'set_account_display_name: quebra de linha falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', E'Com\tTab') $$,
  'P0001', 'INVALID_INPUT', 'set_account_display_name: tabulação falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', E'Com\x7FDEL') $$,
  'P0001', 'INVALID_INPUT', 'set_account_display_name: caractere DEL falha com INVALID_INPUT'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT display_name FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a6'),
  'Novo Nome',
  'set_account_display_name: os nomes rejeitados não alteraram o perfil'
);

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', repeat('n', 120)) $$,
  'set_account_display_name: nome com exatamente 120 caracteres é aceito'
);
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000c2', 'Renomeando CEO') $$,
  'P0001', 'NOT_FOUND', 'E-19: renomear um CEO falha com NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000ee', 'Fantasma') $$,
  'P0001', 'NOT_FOUND', 'E-19: renomear usuário inexistente falha com NOT_FOUND'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT char_length(display_name) FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a6'),
  120,
  'set_account_display_name: o nome de 120 caracteres foi gravado'
);
SELECT is(
  (SELECT count(*)::int FROM public.audit_events WHERE action = 'account.updated' AND resource_id = '00000000-0000-4000-8000-0000000000a6'),
  2,
  'set_account_display_name: só as duas chamadas bem-sucedidas foram auditadas'
);

-- E-30: caracteres de formatação Unicode são rejeitados; texto acentuado comum é aceito.
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', 'Nome' || chr(8238) || 'invertido') $$,
  'P0001', 'INVALID_INPUT', 'E-30: set_account_display_name rejeita U+202E (bidi override)'
);
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', 'Nome' || chr(8203) || 'invisível') $$,
  'P0001', 'INVALID_INPUT', 'E-30: set_account_display_name rejeita U+200B (zero-width space)'
);
SELECT lives_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', 'Ação & Cia — Produção') $$,
  'E-30: set_account_display_name aceita texto acentuado comum, com & e travessão'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT display_name FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a6'),
  'Ação & Cia — Produção',
  'E-30: o nome acentuado foi gravado como veio'
);

-- require_password_change ---------------------------------------------------------------------------------------------------------------
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal) VALUES ('00000000-0000-4000-8000-0000000003a3', '00000000-0000-4000-8000-0000000000a1', now(), now(), 'aal1');
-- O reset da senha acontece no Auth (hash novo); a RPC grava esse hash como a nova linha de base.
UPDATE auth.users SET encrypted_password = 'temp-reset-1' WHERE id = '00000000-0000-4000-8000-0000000000a1';
SELECT tests.set_request_id('req-rst-0001');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000a1') $$,
  'AC-08: CEO aal2 exige a troca de senha de um cliente'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT must_change_password FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a1'),
  true,
  'require_password_change: volta must_change_password para true'
);
SELECT is_empty(
  $$ SELECT id FROM auth.sessions WHERE user_id = '00000000-0000-4000-8000-0000000000a1' $$,
  'require_password_change: apaga todas as sessões do usuário'
);
SELECT results_eq(
  $$ SELECT actor_id, actor_role::text, resource_type, resource_id, client_id, request_id
       FROM public.audit_events WHERE action = 'account.password_reset' AND resource_id = '00000000-0000-4000-8000-0000000000a1' $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'account', '00000000-0000-4000-8000-0000000000a1'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid, 'req-rst-0001') $$,
  'require_password_change: audita account.password_reset com ator, papel, cliente e request_id'
);
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT is_empty(
  $$ SELECT * FROM public.current_principal() $$,
  'E-08: depois do reset, o JWT antigo do cliente não tem mais principal'
);
SELECT tests.clear_authentication();

-- A senha temporária é a linha de base: sem trocá-la, mark_password_changed continua falhando.
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal) VALUES ('00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000a1', now(), now(), 'aal1');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT public.mark_password_changed() $$,
  'P0001', 'PASSWORD_UNCHANGED', 'E-13: depois de require_password_change, mark_password_changed sem nova troca falha com PASSWORD_UNCHANGED'
);
SELECT is(
  (SELECT must_change_password FROM public.current_principal()),
  true,
  'E-13: depois de require_password_change e de uma chamada sem troca, a pendência continua'
);
SELECT tests.clear_authentication();
UPDATE auth.users SET encrypted_password = 'changed-2' WHERE id = '00000000-0000-4000-8000-0000000000a1';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT lives_ok(
  $$ SELECT public.mark_password_changed() $$,
  'require_password_change: trocando a senha temporária, o cliente executa mark_password_changed'
);
SELECT is(
  (SELECT must_change_password FROM public.current_principal()),
  false,
  'require_password_change: depois da troca, a pendência de senha é limpa de novo'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000c2') $$,
  'P0001', 'NOT_FOUND', 'E-19: exigir troca de senha de um CEO falha com NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000ee') $$,
  'P0001', 'NOT_FOUND', 'E-19: exigir troca de senha de usuário inexistente falha com NOT_FOUND'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT must_change_password FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000c2'),
  false,
  'E-19: o CEO alvo não ganhou must_change_password'
);

-- record_account_provisioned --------------------------------------------------------------------------------------------------------------
SELECT tests.set_request_id('req-prov-0001');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.record_account_provisioned('00000000-0000-4000-8000-0000000000b1') $$,
  'AC-08: CEO aal2 registra o provisionamento de um login'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT actor_id, actor_role::text, action, resource_type, resource_id, client_id, process_id IS NULL, request_id
       FROM public.audit_events WHERE action = 'account.provisioned' AND resource_id = '00000000-0000-4000-8000-0000000000b1' $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'account.provisioned', 'account', '00000000-0000-4000-8000-0000000000b1'::uuid, '00000000-0000-4000-8000-00000000000b'::uuid, true, 'req-prov-0001') $$,
  'record_account_provisioned: audita account.provisioned com o client_id do login'
);
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT public.record_account_provisioned('00000000-0000-4000-8000-0000000000b1') $$,
  'P0001', 'INVALID_INPUT', 'record_account_provisioned: o segundo registro do mesmo login falha com INVALID_INPUT (idempotência)'
);
SELECT lives_ok(
  $$ SELECT public.record_account_provisioned('00000000-0000-4000-8000-0000000000a6') $$,
  'record_account_provisioned: a idempotência é por login: outro login ainda pode ser registrado'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT count(*)::int FROM public.audit_events WHERE action = 'account.provisioned' AND resource_id = '00000000-0000-4000-8000-0000000000b1'),
  1,
  'record_account_provisioned: a segunda chamada não gravou outro evento'
);
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT public.record_account_provisioned('00000000-0000-4000-8000-0000000000c2') $$,
  'P0001', 'NOT_FOUND', 'E-19: registrar provisionamento de um CEO falha com NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.record_account_provisioned('00000000-0000-4000-8000-0000000000ee') $$,
  'P0001', 'NOT_FOUND', 'E-19: registrar provisionamento de usuário inexistente falha com NOT_FOUND'
);
SELECT tests.clear_authentication();
SELECT is_empty(
  -- `record_account_provisioned` não grava para CEO nem para usuário inexistente; o único evento de um
  -- CEO é o do gatilho de criação (canal auth_admin, sem ator), que não vem desta função
  $$ SELECT id FROM public.audit_events
      WHERE action = 'account.provisioned'
        AND resource_id IN ('00000000-0000-4000-8000-0000000000c2', '00000000-0000-4000-8000-0000000000ee')
        AND NOT (actor_id IS NULL AND metadata @> '{"channel":"auth_admin"}'::jsonb) $$,
  'E-19: nenhum evento account.provisioned foi gravado para CEO ou usuário inexistente'
);
SELECT is(
  (SELECT count(*)::int FROM public.audit_events
    WHERE action = 'account.provisioned' AND resource_id = '00000000-0000-4000-8000-0000000000c2'
      AND actor_id IS NULL AND metadata @> '{"channel":"auth_admin"}'::jsonb),
  1,
  'RF-14: o filtro acima exclui exatamente o evento do gatilho de criação do CEO, e ele existe'
);

-- request_id da auditoria: header ausente ou fora do formato vira NULL ------------------------------------------------------------------------
SELECT tests.set_request_id('id com espaço!');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', 'Header malformado');
SELECT tests.clear_authentication();
SELECT is(
  (SELECT request_id FROM public.audit_events
    WHERE action = 'account.updated' AND resource_id = '00000000-0000-4000-8000-0000000000a6' ORDER BY id DESC LIMIT 1),
  NULL::text,
  'request_id: header com caracteres fora de [A-Za-z0-9-] é gravado como NULL'
);

SELECT tests.set_request_id(repeat('a', 65));
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', 'Header longo');
SELECT tests.clear_authentication();
SELECT is(
  (SELECT request_id FROM public.audit_events
    WHERE action = 'account.updated' AND resource_id = '00000000-0000-4000-8000-0000000000a6' ORDER BY id DESC LIMIT 1),
  NULL::text,
  'request_id: header com 65 caracteres é gravado como NULL'
);

SELECT tests.set_request_id(repeat('b', 64));
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', 'Header no limite');
SELECT tests.clear_authentication();
SELECT is(
  (SELECT request_id FROM public.audit_events
    WHERE action = 'account.updated' AND resource_id = '00000000-0000-4000-8000-0000000000a6' ORDER BY id DESC LIMIT 1),
  repeat('b', 64),
  'request_id: header com exatamente 64 caracteres válidos é gravado'
);

SELECT set_config('request.headers', '{"user-agent":"pgtap"}', true);
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', 'Header sem request id');
SELECT tests.clear_authentication();
SELECT is(
  (SELECT request_id FROM public.audit_events
    WHERE action = 'account.updated' AND resource_id = '00000000-0000-4000-8000-0000000000a6' ORDER BY id DESC LIMIT 1),
  NULL::text,
  'request_id: headers sem x-request-id gravam NULL'
);

SELECT set_config('request.headers', '', true);
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a6', 'Sem headers');
SELECT tests.clear_authentication();
SELECT is(
  (SELECT request_id FROM public.audit_events
    WHERE action = 'account.updated' AND resource_id = '00000000-0000-4000-8000-0000000000a6' ORDER BY id DESC LIMIT 1),
  NULL::text,
  'request_id: sem headers (chamada fora do PostgREST) grava NULL'
);

SELECT * FROM finish();
ROLLBACK;
