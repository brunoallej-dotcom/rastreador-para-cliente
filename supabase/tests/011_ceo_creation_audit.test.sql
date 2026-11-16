-- RF-14, SEC-16, AC-31: a criação de um CEO (script `ceo:create`, Auth Admin API) grava
-- `account.provisioned` na trilha de auditoria, na mesma transação do usuário, pelo mesmo gatilho que
-- cria o perfil. Um login de cliente criado pelo gatilho NÃO grava (a auditoria dele é a chamada
-- `record_account_provisioned()` de um CEO, que continua idempotente). Se a auditoria falha, o
-- COMMIT falha e o usuário não é criado.
--
-- `tests.create_user` executa o gatilho adiado na hora (SET CONSTRAINTS ALL IMMEDIATE), como o COMMIT faria.
BEGIN;
SELECT plan(21);

INSERT INTO public.clients (id, name) VALUES ('00000000-0000-4000-8000-0000000000c1', 'Cliente Auditoria');

SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'ceo', NULL, 'CEO Auditado');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a2', 'ceo', NULL, 'CEO Que Opera');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000b1', 'client', '00000000-0000-4000-8000-0000000000c1', 'Cliente Um');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000a2');

-- RF-14: um CEO criado grava exatamente um evento ----------------------------------------------------------
SELECT is(
  (SELECT count(*)::int FROM public.audit_events WHERE resource_id = '00000000-0000-4000-8000-0000000000a1'),
  1,
  'RF-14: criar um CEO grava exatamente 1 evento de auditoria'
);
SELECT results_eq(
  $$ SELECT action, resource_type, actor_id, actor_role::text, client_id, process_id, request_id, metadata - 'db_user'
       FROM public.audit_events WHERE resource_id = '00000000-0000-4000-8000-0000000000a1' $$,
  $$ VALUES ('account.provisioned', 'account', NULL::uuid, NULL::text, NULL::uuid, NULL::uuid, NULL::text,
             '{"role":"ceo","channel":"auth_admin"}'::jsonb) $$,
  'RF-14: o evento é account.provisioned sobre a conta, sem ator, cliente, processo nem request_id, com role e canal nos metadados'
);

SELECT is(
  (SELECT metadata ->> 'db_user' FROM public.audit_events WHERE resource_id = '00000000-0000-4000-8000-0000000000a1'),
  session_user::text,
  'T-13: o evento guarda o papel da conexão que criou o CEO (separa o Auth de SQL direto)'
);

-- T-13: papel em user_metadata não conta; só app_metadata decide ------------------------------------------------
SELECT tests.insert_auth_user(
  '00000000-0000-4000-8000-0000000000b2',
  '{"role":"client","client_id":"00000000-0000-4000-8000-0000000000c1","display_name":"Cliente Forjado"}'::jsonb,
  '{"role":"ceo"}'::jsonb
);
SELECT is(
  (SELECT count(*)::int FROM public.audit_events WHERE resource_id = '00000000-0000-4000-8000-0000000000b2'),
  0,
  'T-13: role ceo só em user_metadata (app_metadata client) não grava o evento de CEO'
);

-- Login de cliente: o gatilho não grava ----------------------------------------------------------------------
SELECT is(
  (SELECT count(*)::int FROM public.audit_events WHERE resource_id = '00000000-0000-4000-8000-0000000000b1'),
  0,
  'criar um login de cliente pelo gatilho não grava evento'
);
SELECT is(
  (SELECT count(*)::int FROM public.audit_events
    WHERE resource_id IN ('00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000a2', '00000000-0000-4000-8000-0000000000b1')),
  2,
  'um evento por CEO criado (a1 e a2), nenhum pelo cliente (b1)'
);

-- Sem colisão com a idempotência de record_account_provisioned (alvo cliente) ---------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a2', 'aal2');
SELECT lives_ok(
  $$ SELECT public.record_account_provisioned('00000000-0000-4000-8000-0000000000b1') $$,
  'o CEO aal2 audita o provisionamento do login de cliente normalmente'
);
SELECT throws_ok(
  $$ SELECT public.record_account_provisioned('00000000-0000-4000-8000-0000000000b1') $$,
  'P0001', 'INVALID_INPUT', 'a segunda chamada para o mesmo login continua recusada (idempotência)'
);
SELECT throws_ok(
  $$ SELECT public.record_account_provisioned('00000000-0000-4000-8000-0000000000a1') $$,
  'P0001', 'NOT_FOUND', 'E-19: a função de conta continua sem enxergar CEO como alvo, com o evento do gatilho no lugar'
);
-- o CEO aal2 lê a trilha (RLS), inclusive o evento de criação de CEO
SELECT is(
  (SELECT count(*)::int FROM public.audit_events WHERE action = 'account.provisioned' AND resource_id = '00000000-0000-4000-8000-0000000000a1'),
  1,
  'o CEO aal2 lê o evento de criação de CEO'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT count(*)::int FROM public.audit_events WHERE resource_id = '00000000-0000-4000-8000-0000000000b1'),
  1,
  'o login de cliente tem exatamente o evento da função de CEO'
);
SELECT is(
  (SELECT count(*)::int FROM public.audit_events WHERE resource_id = '00000000-0000-4000-8000-0000000000a1'),
  1,
  'o CEO a1 continua com um único evento depois das chamadas acima'
);

-- RLS: o cliente não lê a trilha -----------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000b1');
SELECT is_empty(
  $$ SELECT id FROM public.audit_events WHERE resource_id = '00000000-0000-4000-8000-0000000000a1' $$,
  'AC-09: o cliente não lê o evento de criação de CEO'
);
SELECT tests.clear_authentication();

-- Fail closed: se a auditoria falha, o usuário não nasce ---------------------------------------------------------
CREATE FUNCTION tests.fail_audit_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'AUDIT_DOWN';
END;
$$;
CREATE TRIGGER zz_fail_audit_insert
  BEFORE INSERT ON public.audit_events
  FOR EACH ROW EXECUTE FUNCTION tests.fail_audit_insert();

SELECT throws_ok(
  $$ SELECT tests.create_user('00000000-0000-4000-8000-0000000000e1', 'ceo', NULL, 'CEO Sem Auditoria') $$,
  'P0001', 'AUDIT_DOWN', 'fail closed: sem poder auditar, a criação do CEO falha no COMMIT'
);
SELECT is_empty(
  $$ SELECT id FROM auth.users WHERE id = '00000000-0000-4000-8000-0000000000e1' $$,
  'fail closed: o CEO cuja auditoria falhou não existe em auth.users'
);
SELECT is_empty(
  $$ SELECT id FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000e1' $$,
  'fail closed: nem o perfil'
);
SELECT lives_ok(
  $$ SELECT tests.create_user('00000000-0000-4000-8000-0000000000e2', 'client', '00000000-0000-4000-8000-0000000000c1', 'Cliente Sem Evento') $$,
  'um login de cliente é criado mesmo com a auditoria indisponível: o gatilho não grava para ele'
);
DROP TRIGGER zz_fail_audit_insert ON public.audit_events;

-- A função continua endurecida ------------------------------------------------------------------------------
SELECT ok(
  (SELECT p.prosecdef AND p.proconfig = ARRAY['search_path=""']
     FROM pg_proc p WHERE p.oid = 'private.handle_new_auth_user()'::regprocedure),
  'private.handle_new_auth_user() segue SECURITY DEFINER com search_path vazio'
);
SELECT ok(
  NOT has_function_privilege('anon', 'private.handle_new_auth_user()', 'EXECUTE')
  AND NOT has_function_privilege('authenticated', 'private.handle_new_auth_user()', 'EXECUTE')
  AND NOT has_function_privilege('service_role', 'private.handle_new_auth_user()', 'EXECUTE'),
  'private.handle_new_auth_user() não é executável por anon, authenticated nem service_role'
);
SELECT ok(
  (SELECT t.tgdeferrable AND t.tginitdeferred
     FROM pg_trigger t
    WHERE t.tgrelid = 'auth.users'::regclass AND t.tgname = 'on_auth_user_created'),
  'o gatilho de perfil e de auditoria segue DEFERRABLE INITIALLY DEFERRED (roda no COMMIT)'
);
SELECT ok(
  (SELECT count(*) = 1 FROM pg_trigger t
    WHERE t.tgrelid = 'auth.users'::regclass AND t.tgfoid = 'private.handle_new_auth_user()'::regprocedure),
  'há um único gatilho em auth.users que executa a função: a auditoria não roda duas vezes'
);

SELECT * FROM finish();
ROLLBACK;
