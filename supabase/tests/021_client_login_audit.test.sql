-- Onda 10.1 (F-92 b, F-93): a auditoria do que o app escreve no Auth e as lacunas da auditoria do
-- provisionamento. Cobre `begin_client_login_admin` (a intenção gravada ANTES de cada escrita no Auth: ban,
-- unban e troca de senha), `record_account_provisioned` (agora devolve a linha do login),
-- `record_account_provision_reverted` (a compensação do provisionamento deixa rastro) e o registro tardio de
-- `account.provisioned` no reset (`require_password_change`) da conta órfã. Para cada função: anon, cliente,
-- CEO aal1, CEO aal2 sem atestado (`p_attested => false`), CEO atestado com a senha pendente, alvo de outro
-- cliente, alvo CEO, alvo inexistente, entrada inválida, o evento gravado (ator, papel, recurso, cliente,
-- request_id, metadados sem PII), nada gravado nas recusas, e o REVOKE de PUBLIC e anon.
BEGIN;
SELECT plan(96);

-- arrange (como postgres) ---------------------------------------------------------------------------------------
-- Clientes A e B. a1 e a2 são logins de A, b1 é login de B (todos com a senha temporária, como nascem). a3 é login de A
-- desativado, para provar que a intenção de desbanir é gravada para quem está desativado. c1 é CEO atestado (definitivo),
-- c2 é CEO que nunca foi atestado, c3 é CEO atestado com a senha temporária de volta.
INSERT INTO public.clients (id, name) VALUES
  ('00000000-0000-4000-8000-00000000000a', 'Cliente A'),
  ('00000000-0000-4000-8000-00000000000b', 'Cliente B');

SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a2', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a3', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000b1', 'client', '00000000-0000-4000-8000-00000000000b');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c2', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c3', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c2');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c3');
UPDATE public.profiles SET disabled_at = now() WHERE id = '00000000-0000-4000-8000-0000000000a3';

-- Os eventos que o gatilho de criação de CEO grava (011) não entram nas contagens abaixo: o alvo das funções é cliente.
CREATE FUNCTION tests.trail_of(p_user uuid)
RETURNS TABLE (action text)
LANGUAGE sql
STABLE
AS $$
  SELECT e.action FROM public.audit_events e WHERE e.resource_id = p_user ORDER BY e.id
$$;
GRANT EXECUTE ON FUNCTION tests.trail_of(uuid) TO anon, authenticated, service_role;

-- begin_client_login_admin: privilégios e forma ------------------------------------------------------------------
SELECT ok(
  (SELECT p.prosecdef AND coalesce(p.proconfig @> ARRAY['search_path=""'], false)
     FROM pg_proc p WHERE p.oid = 'public.begin_client_login_admin(uuid, uuid, text)'::regprocedure),
  'AC-25: begin_client_login_admin é SECURITY DEFINER com search_path vazio'
);
SELECT ok(
  has_function_privilege('authenticated', 'public.begin_client_login_admin(uuid, uuid, text)', 'EXECUTE'),
  'begin_client_login_admin: authenticated executa (a função confere is_ceo por dentro)'
);
SELECT is(
  has_function_privilege('anon', 'public.begin_client_login_admin(uuid, uuid, text)', 'EXECUTE')
    OR has_function_privilege('service_role', 'public.begin_client_login_admin(uuid, uuid, text)', 'EXECUTE'),
  false,
  'AC-25: anon e service_role não executam begin_client_login_admin'
);
SELECT is_empty(
  $$ SELECT a.grantee
       FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE p.oid = 'public.begin_client_login_admin(uuid, uuid, text)'::regprocedure
        AND a.privilege_type = 'EXECUTE' AND a.grantee = 0 $$,
  'AC-25: begin_client_login_admin não concede EXECUTE a PUBLIC'
);
SELECT ok(
  position('private.is_ceo() IS NOT TRUE' IN (SELECT p.prosrc FROM pg_proc p
    WHERE p.oid = 'public.begin_client_login_admin(uuid, uuid, text)'::regprocedure))
  < position('p_action' IN (SELECT p.prosrc FROM pg_proc p
    WHERE p.oid = 'public.begin_client_login_admin(uuid, uuid, text)'::regprocedure)),
  'begin_client_login_admin: a checagem de is_ceo() vem antes de qualquer uso da entrada'
);

-- begin_client_login_admin: quem não pode ------------------------------------------------------------------------
SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1', 'ban') $$,
  '42501', NULL, 'AC-10: anon não executa begin_client_login_admin'
);
RESET ROLE;

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1', 'set_password') $$,
  '42501', 'FORBIDDEN', 'AC-08: um cliente não grava a intenção, nem sobre o próprio login'
);
SELECT tests.clear_authentication();
UPDATE public.profiles SET must_change_password = false WHERE id = '00000000-0000-4000-8000-0000000000a1';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a2', 'ban') $$,
  '42501', 'FORBIDDEN', 'AC-08: nem um cliente de senha definitiva, sobre outro login do mesmo cliente'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1', 'ban') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 não grava a intenção'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2', false);
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1', 'ban') $$,
  '42501', 'FORBIDDEN', 'F-63: CEO com aal2 sem atestado (o claim obtido direto no Auth) não grava a intenção'
);
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1', 'ban-that-is-not-in-the-list') $$,
  '42501', 'FORBIDDEN', 'SEC-04: a recusa do papel vem antes da validação da entrada (uma ação inválida, sem atestado, é FORBIDDEN e não INVALID_INPUT)'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT is((SELECT private.is_ceo()), true, 'arrange: c3 atestado e com a senha definitiva é CEO');
SELECT tests.clear_authentication();
UPDATE public.profiles SET must_change_password = true WHERE id = '00000000-0000-4000-8000-0000000000c3';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1', 'ban') $$,
  '42501', 'FORBIDDEN', 'F-83: CEO atestado com a senha temporária pendente não grava a intenção'
);
SELECT tests.clear_authentication();

SELECT is_empty(
  $$ SELECT e.id FROM public.audit_events e
      WHERE e.action IN ('account.ban_intent', 'account.unban_intent', 'account.password_set_intent')
        AND e.resource_id::text LIKE '00000000-0000-4000-8000-0000000000__' $$,
  'F-92 b: nenhuma chamada recusada gravou intenção'
);

-- begin_client_login_admin: o CEO atestado ---------------------------------------------------------------------------------
SELECT tests.set_request_id('req-intent-0001');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');

SELECT lives_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1', 'ban') $$,
  'F-92 b: o CEO atestado grava a intenção de banir um login do cliente'
);
SELECT lives_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1', 'unban') $$,
  'F-92 b: e a de desbanir'
);
SELECT lives_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1', 'set_password') $$,
  'F-92 b: e a de trocar a senha'
);
SELECT lives_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a3', 'unban') $$,
  'F-92 b: a intenção de desbanir vale para um login desativado (é o que a reativação faz primeiro)'
);
SELECT lives_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1', 'ban') $$,
  'F-92 b: repetir a mesma intenção é outra tentativa e grava outro evento'
);
SELECT tests.clear_authentication();

SELECT results_eq(
  $$ SELECT e.action, e.actor_id, e.actor_role::text, e.resource_type, e.resource_id, e.client_id, e.process_id,
            e.request_id, e.metadata
       FROM public.audit_events e
      WHERE e.resource_id = '00000000-0000-4000-8000-0000000000a1' ORDER BY e.id $$,
  $$ VALUES
       ('account.ban_intent', '00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'account',
        '00000000-0000-4000-8000-0000000000a1'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid, NULL::uuid,
        'req-intent-0001', '{"action": "ban"}'::jsonb),
       ('account.unban_intent', '00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'account',
        '00000000-0000-4000-8000-0000000000a1'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid, NULL::uuid,
        'req-intent-0001', '{"action": "unban"}'::jsonb),
       ('account.password_set_intent', '00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'account',
        '00000000-0000-4000-8000-0000000000a1'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid, NULL::uuid,
        'req-intent-0001', '{"action": "set_password"}'::jsonb),
       ('account.ban_intent', '00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'account',
        '00000000-0000-4000-8000-0000000000a1'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid, NULL::uuid,
        'req-intent-0001', '{"action": "ban"}'::jsonb) $$,
  'F-92 b: cada intenção vira um evento de conta com o CEO como ator, o login como recurso, o cliente dele, o request_id e só a palavra da ação nos metadados'
);
SELECT results_eq(
  $$ SELECT action FROM tests.trail_of('00000000-0000-4000-8000-0000000000a3') $$,
  $$ VALUES ('account.unban_intent') $$,
  'F-92 b: o login desativado ganhou o evento de desbanir'
);
SELECT is_empty(
  $$ SELECT e.id FROM public.audit_events e
      WHERE e.action IN ('account.ban_intent', 'account.unban_intent', 'account.password_set_intent')
        AND e.resource_id::text LIKE '00000000-0000-4000-8000-0000000000__'
        AND (e.metadata::text ~* '(@|Cliente|Usuário)' OR e.metadata ?| ARRAY['email', 'name', 'displayName']) $$,
  'SEC-16: nenhuma intenção leva nome, e-mail ou senha nos metadados'
);
SELECT results_eq(
  $$ SELECT p.disabled_at IS NOT NULL, p.must_change_password, p.updated_at = p.created_at
       FROM public.profiles p WHERE p.id = '00000000-0000-4000-8000-0000000000a1' $$,
  $$ VALUES (false, false, true) $$,
  'F-92 b: gravar a intenção não muda o estado do login (não desativa, não mexe na senha)'
);

-- begin_client_login_admin: o que é recusado, e como ---------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000b1', 'ban') $$,
  'P0001', 'NOT_FOUND', 'E-19: o login de OUTRO cliente é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-0000000000a1', 'ban') $$,
  'P0001', 'NOT_FOUND', 'E-19: o cliente do path que não é o do login é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000c1', 'ban') $$,
  'P0001', 'NOT_FOUND', 'E-19: o id de um CEO é NOT_FOUND (nunca se age sobre CEO)'
);
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000ee', 'ban') $$,
  'P0001', 'NOT_FOUND', 'E-19: um login inexistente é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-0000000000ee', '00000000-0000-4000-8000-0000000000a1', 'ban') $$,
  'P0001', 'NOT_FOUND', 'E-19: um cliente inexistente também'
);
SELECT throws_ok(
  format('SELECT public.begin_client_login_admin(%L, %L, %L)',
         '00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1', a.value),
  'P0001', 'INVALID_INPUT', 'F-92 b: a ação ' || a.label || ' não está na lista de três'
)
FROM (VALUES ('create', 'create'), ('delete', 'delete'), ('disable', 'disable'), ('vazia', ''),
             ('em maiúsculas', 'BAN'), ('com espaço', 'ban '), ('de reset', 'password_reset'),
             ('injeção', $$ban'; DROP TABLE public.profiles; --$$)) a (label, value);
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin(NULL, '00000000-0000-4000-8000-0000000000a1', 'ban') $$,
  'P0001', 'INVALID_INPUT', 'F-92 b: cliente nulo é INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', NULL, 'ban') $$,
  'P0001', 'INVALID_INPUT', 'F-92 b: login nulo é INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.begin_client_login_admin('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1', NULL) $$,
  'P0001', 'INVALID_INPUT', 'F-92 b: ação nula é INVALID_INPUT'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT count(*)::int FROM public.audit_events e
    WHERE e.action IN ('account.ban_intent', 'account.unban_intent', 'account.password_set_intent')
      AND e.resource_id::text LIKE '00000000-0000-4000-8000-0000000000__'),
  5,
  'F-92 b: nenhuma recusa gravou evento: continuam os 5 de antes'
);

-- record_account_provisioned: devolve a linha do login ------------------------------------------------------------------------
SELECT tests.set_request_id('req-prov-0001');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT user_id, email, display_name, disabled_at, must_change_password, last_sign_in_at, created_at
       FROM public.record_account_provisioned('00000000-0000-4000-8000-0000000000a2') $$,
  $$ SELECT l.user_id, l.email, l.display_name, l.disabled_at, l.must_change_password, l.last_sign_in_at, l.created_at
       FROM public.list_client_users('00000000-0000-4000-8000-00000000000a') l
      WHERE l.user_id = '00000000-0000-4000-8000-0000000000a2' $$,
  'F-93: record_account_provisioned devolve a linha do login, igual à que list_client_users mostra'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT e.action, e.actor_id, e.actor_role::text, e.resource_type, e.client_id, e.process_id, e.request_id, e.metadata
       FROM public.audit_events e
      WHERE e.resource_id = '00000000-0000-4000-8000-0000000000a2' $$,
  $$ VALUES ('account.provisioned', '00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'account',
             '00000000-0000-4000-8000-00000000000a'::uuid, NULL::uuid, 'req-prov-0001', '{}'::jsonb) $$,
  'F-93: e grava account.provisioned na mesma transação, com o CEO, o cliente e o request_id'
);
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.record_account_provisioned('00000000-0000-4000-8000-0000000000a2') $$,
  'P0001', 'INVALID_INPUT', 'F-93: o segundo registro do mesmo login é INVALID_INPUT (um provisionamento por login), sem linha'
);
SELECT throws_ok(
  $$ SELECT * FROM public.record_account_provisioned('00000000-0000-4000-8000-0000000000c1') $$,
  'P0001', 'NOT_FOUND', 'F-93: o id de um CEO é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT * FROM public.record_account_provisioned('00000000-0000-4000-8000-0000000000ee') $$,
  'P0001', 'NOT_FOUND', 'F-93: um login inexistente é NOT_FOUND'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT count(*)::int FROM public.audit_events e
    WHERE e.resource_id = '00000000-0000-4000-8000-0000000000a2' AND e.action = 'account.provisioned'),
  1,
  'F-93: um único account.provisioned por login'
);

SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT * FROM public.record_account_provisioned('00000000-0000-4000-8000-0000000000a1') $$,
  '42501', NULL, 'AC-10: anon não executa record_account_provisioned'
);
RESET ROLE;
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT * FROM public.record_account_provisioned('00000000-0000-4000-8000-0000000000a1') $$,
  '42501', 'FORBIDDEN', 'AC-08: um cliente não registra provisionamento'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT throws_ok(
  $$ SELECT * FROM public.record_account_provisioned('00000000-0000-4000-8000-0000000000a1') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 não registra'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2', false);
SELECT throws_ok(
  $$ SELECT * FROM public.record_account_provisioned('00000000-0000-4000-8000-0000000000a1') $$,
  '42501', 'FORBIDDEN', 'F-63: CEO com aal2 sem atestado não registra'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.record_account_provisioned('00000000-0000-4000-8000-0000000000a1') $$,
  '42501', 'FORBIDDEN', 'F-83: CEO atestado com a senha pendente não registra'
);
SELECT tests.clear_authentication();
SELECT is_empty(
  $$ SELECT action FROM tests.trail_of('00000000-0000-4000-8000-0000000000a1') WHERE action = 'account.provisioned' $$,
  'F-93: nenhuma chamada recusada gravou account.provisioned'
);
SELECT is(
  has_function_privilege('anon', 'public.record_account_provisioned(uuid)', 'EXECUTE')
    OR has_function_privilege('service_role', 'public.record_account_provisioned(uuid)', 'EXECUTE')
    OR NOT has_function_privilege('authenticated', 'public.record_account_provisioned(uuid)', 'EXECUTE'),
  false,
  'AC-25: record_account_provisioned segue executável só por authenticated (a recriação refez o REVOKE e o GRANT)'
);
SELECT is(
  (SELECT p.prosecdef AND coalesce(p.proconfig @> ARRAY['search_path=""'], false)
     FROM pg_proc p WHERE p.oid = 'public.record_account_provisioned(uuid)'::regprocedure),
  true,
  'AC-25: e segue SECURITY DEFINER com search_path vazio'
);
SELECT is(
  (SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname = 'record_account_provisioned'),
  1,
  'F-93: existe uma única record_account_provisioned (a versão sem retorno foi apagada, não ficou ao lado)'
);

-- record_account_provision_reverted --------------------------------------------------------------------------------------------
SELECT ok(
  (SELECT p.prosecdef AND coalesce(p.proconfig @> ARRAY['search_path=""'], false)
     FROM pg_proc p WHERE p.oid = 'public.record_account_provision_reverted(uuid, text)'::regprocedure),
  'AC-25: record_account_provision_reverted é SECURITY DEFINER com search_path vazio'
);
SELECT is(
  has_function_privilege('anon', 'public.record_account_provision_reverted(uuid, text)', 'EXECUTE')
    OR has_function_privilege('service_role', 'public.record_account_provision_reverted(uuid, text)', 'EXECUTE')
    OR NOT has_function_privilege('authenticated', 'public.record_account_provision_reverted(uuid, text)', 'EXECUTE'),
  false,
  'AC-25: executável só por authenticated (nem anon, nem service_role)'
);
SELECT is_empty(
  $$ SELECT a.grantee
       FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE p.oid = 'public.record_account_provision_reverted(uuid, text)'::regprocedure
        AND a.privilege_type = 'EXECUTE' AND a.grantee = 0 $$,
  'AC-25: não concede EXECUTE a PUBLIC'
);

SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a1', 'record_failed') $$,
  '42501', NULL, 'AC-10: anon não executa record_account_provision_reverted'
);
RESET ROLE;
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a1', 'record_failed') $$,
  '42501', 'FORBIDDEN', 'AC-08: um cliente não registra reversão, nem do próprio login'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a1', 'record_failed') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 não registra reversão'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2', false);
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a1', 'record_failed') $$,
  '42501', 'FORBIDDEN', 'F-63: CEO com aal2 sem atestado não registra reversão'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a1', 'record_failed') $$,
  '42501', 'FORBIDDEN', 'F-83: CEO atestado com a senha pendente não registra reversão'
);
SELECT tests.clear_authentication();
SELECT is_empty(
  $$ SELECT e.id FROM public.audit_events e
      WHERE e.action = 'account.provision_reverted' AND e.resource_id::text LIKE '00000000-0000-4000-8000-0000000000__' $$,
  'F-93: nenhuma chamada recusada gravou account.provision_reverted'
);

-- a1 já trocou a senha (senha definitiva) e a2 já foi registrada; a4 é um login novo, nunca usado (o caso real)
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a4', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a5', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a6', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a7', 'client', '00000000-0000-4000-8000-00000000000a');
-- a8 foi criado há 16 minutos (fora da janela da compensação) e a9 há 14 (dentro dela)
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a8', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a9', 'client', '00000000-0000-4000-8000-00000000000a');
UPDATE public.profiles SET created_at = now() - interval '16 minutes' WHERE id = '00000000-0000-4000-8000-0000000000a8';
UPDATE public.profiles SET created_at = now() - interval '14 minutes' WHERE id = '00000000-0000-4000-8000-0000000000a9';
UPDATE auth.users SET last_sign_in_at = now() WHERE id = '00000000-0000-4000-8000-0000000000a5';

SELECT tests.set_request_id('req-rev-0001');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a4', 'because') $$,
  'P0001', 'INVALID_INPUT', 'F-93: um motivo fora das duas palavras é INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a4', NULL) $$,
  'P0001', 'INVALID_INPUT', 'F-93: motivo nulo é INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted(NULL, 'record_failed') $$,
  'P0001', 'INVALID_INPUT', 'F-93: login nulo é INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000c1', 'record_failed') $$,
  'P0001', 'NOT_FOUND', 'F-93: o id de um CEO é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000ee', 'record_failed') $$,
  'P0001', 'NOT_FOUND', 'F-93: um login inexistente é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a5', 'record_failed') $$,
  'P0001', 'NOT_FOUND', 'F-93: um login que já entrou (last_sign_in_at) não pode ser revertido: seria um registro falso'
);
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a1', 'record_failed') $$,
  'P0001', 'NOT_FOUND', 'F-93: nem um login que já trocou a senha'
);
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a8', 'record_failed') $$,
  'P0001', 'NOT_FOUND', 'F-117: um login criado há mais de 15 minutos não é da compensação (que roda na mesma requisição): NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a2', 'record_failed') $$,
  'P0001', 'INVALID_INPUT', 'F-117: um login que JÁ tem account.provisioned (a2, novo e nunca usado) não é revertido: INVALID_INPUT, o registro vale'
);
SELECT is_empty(
  $$ SELECT e.id FROM public.audit_events e
      WHERE e.action = 'account.provision_reverted'
        AND e.resource_id IN ('00000000-0000-4000-8000-0000000000a8', '00000000-0000-4000-8000-0000000000a2') $$,
  'F-117: as duas recusas não gravaram account.provision_reverted'
);

SELECT lives_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a4', 'record_failed') $$,
  'F-93: um login novo e nunca usado, sem account.provisioned (o registro falhou), pode ser revertido'
);
SELECT lives_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a4', 'record_failed') $$,
  'F-93: repetir é seguro (a compensação tenta duas vezes) e não falha'
);
SELECT lives_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a6', 'answer_lost') $$,
  'F-93: o outro motivo (answer_lost) vale também'
);
SELECT lives_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a9', 'record_failed') $$,
  'F-117: um login de 14 minutos ainda está dentro da janela de 15'
);
SELECT tests.clear_authentication();

SELECT results_eq(
  $$ SELECT e.action, e.actor_id, e.actor_role::text, e.resource_type, e.resource_id, e.client_id, e.process_id,
            e.request_id, e.metadata
       FROM public.audit_events e
      WHERE e.action = 'account.provision_reverted' AND e.resource_id::text LIKE '00000000-0000-4000-8000-0000000000__' ORDER BY e.resource_id $$,
  $$ VALUES
       ('account.provision_reverted', '00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'account',
        '00000000-0000-4000-8000-0000000000a4'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid, NULL::uuid,
        'req-rev-0001', '{"reason": "record_failed"}'::jsonb),
       ('account.provision_reverted', '00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'account',
        '00000000-0000-4000-8000-0000000000a6'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid, NULL::uuid,
        'req-rev-0001', '{"reason": "answer_lost"}'::jsonb),
       ('account.provision_reverted', '00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'account',
        '00000000-0000-4000-8000-0000000000a9'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid, NULL::uuid,
        'req-rev-0001', '{"reason": "record_failed"}'::jsonb) $$,
  'F-93: a reversão vira um evento com o CEO, o cliente, o request_id e só o motivo; a segunda chamada não gravou outro'
);
SELECT is_empty(
  $$ SELECT e.id FROM public.audit_events e
      WHERE e.action = 'account.provision_reverted' AND e.resource_id::text LIKE '00000000-0000-4000-8000-0000000000__'
        AND e.metadata::text ~* '(@|Cliente|Usuário)' $$,
  'SEC-16: a reversão não leva nome, e-mail nem senha'
);

-- o evento sobrevive à conta apagada (é o ponto: a compensação apaga a conta DEPOIS de gravar)
DELETE FROM auth.users WHERE id = '00000000-0000-4000-8000-0000000000a4';
SELECT is(
  (SELECT count(*)::int FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a4'),
  0,
  'F-93: a exclusão da conta leva o perfil junto'
);
SELECT results_eq(
  $$ SELECT action FROM tests.trail_of('00000000-0000-4000-8000-0000000000a4') $$,
  $$ VALUES ('account.provision_reverted') $$,
  'F-93: e o evento de reversão sobrevive à conta apagada (a trilha não tem FK para ela)'
);

-- require_password_change: o registro tardio de account.provisioned -------------------------------------------------------------------------
-- a7 é o órfão: nunca teve account.provisioned (o registro falhou), e o reset é o que o entrega
SELECT tests.set_request_id('req-late-0001');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000a7') $$,
  'F-93: o reset da conta órfã funciona'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT e.action, e.actor_id, e.request_id, e.metadata FROM public.audit_events e
      WHERE e.resource_id = '00000000-0000-4000-8000-0000000000a7' ORDER BY e.id $$,
  $$ VALUES ('account.provisioned', '00000000-0000-4000-8000-0000000000c1'::uuid, 'req-late-0001', '{"late": true}'::jsonb),
            ('account.password_reset', '00000000-0000-4000-8000-0000000000c1'::uuid, 'req-late-0001', '{}'::jsonb) $$,
  'F-93: o reset registra o account.provisioned que faltava, com {"late": true}, ANTES do account.password_reset, na mesma transação'
);
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal)
VALUES ('00000000-0000-4000-8000-0000000000a7', '00000000-0000-4000-8000-0000000000a7', now(), now(), 'aal1');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000a7') $$,
  'F-93: um segundo reset da mesma conta funciona'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT action FROM tests.trail_of('00000000-0000-4000-8000-0000000000a7') $$,
  $$ VALUES ('account.provisioned'), ('account.password_reset'), ('account.password_reset') $$,
  'F-93: o registro tardio acontece uma vez só: o segundo reset grava só account.password_reset'
);

-- um login que já tem account.provisioned (o caminho normal) não ganha outro
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000a2') $$,
  'F-93: o reset de um login que já foi registrado funciona'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT action FROM tests.trail_of('00000000-0000-4000-8000-0000000000a2') $$,
  $$ VALUES ('account.provisioned'), ('account.password_reset') $$,
  'F-93: um login já registrado não ganha um account.provisioned tardio'
);

-- uma conta revertida e depois entregue por reset (a exclusão falhou): a trilha conta a história
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.record_account_provision_reverted('00000000-0000-4000-8000-0000000000a6', 'answer_lost') $$,
  'F-93: arrange: a reversão da a6 foi registrada e a exclusão falhou (a conta ficou)'
);
SELECT lives_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000a6') $$,
  'F-93: o reset entrega a conta órfã'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT action FROM tests.trail_of('00000000-0000-4000-8000-0000000000a6') $$,
  $$ VALUES ('account.provision_reverted'), ('account.provisioned'), ('account.password_reset') $$,
  'F-93: a trilha da órfã: reversão, provisionamento tardio e reset, nessa ordem, cada um uma vez'
);

-- o que o reset de antes continua recusando
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000c1') $$,
  'P0001', 'NOT_FOUND', 'E-19: o id de um CEO continua NOT_FOUND no reset, e não ganha account.provisioned'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2', false);
SELECT throws_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000a1') $$,
  '42501', 'FORBIDDEN', 'F-63: CEO com aal2 sem atestado continua sem resetar'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT throws_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000a1') $$,
  '42501', 'FORBIDDEN', 'F-83: CEO atestado com a senha pendente não reseta'
);
SELECT tests.clear_authentication();
SELECT is_empty(
  $$ SELECT e.id FROM public.audit_events e
      WHERE e.resource_id = '00000000-0000-4000-8000-0000000000c1' AND e.action <> 'account.provisioned' $$,
  'E-19: o CEO alvo não ganhou evento algum de conta'
);

-- o catálogo de ações de conta: nada fora das conhecidas e todo evento obedece à forma da tabela -----------------------------------------------------
SELECT is_empty(
  $$ SELECT DISTINCT e.action FROM public.audit_events e
      WHERE e.action LIKE 'account.%' AND e.resource_id::text LIKE '00000000-0000-4000-8000-0000000000__'
        AND e.action NOT IN ('account.provisioned', 'account.provision_reverted', 'account.disabled',
                             'account.enabled', 'account.updated', 'account.password_reset',
                             'account.password_changed', 'account.ban_intent', 'account.unban_intent',
                             'account.password_set_intent') $$,
  'F-92 b: nenhum evento de conta fora do catálogo documentado na spec §3.7.4'
);

SELECT * FROM finish();
ROLLBACK;
