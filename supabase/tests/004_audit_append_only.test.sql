-- audit_events é append-only (Onda 2): AC-24. UPDATE, DELETE e TRUNCATE falham para CEO aal2,
-- service_role e até o dono (postgres, por trigger); INSERT direto só existe dentro das funções.
BEGIN;
SELECT plan(19);

-- arrange (como postgres) --------------------------------------------------------------------------
INSERT INTO public.clients (id, name) VALUES ('00000000-0000-4000-8000-00000000000a', 'Cliente A');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');

INSERT INTO public.audit_events (actor_id, actor_role, action, resource_type, resource_id, client_id) VALUES
  ('00000000-0000-4000-8000-0000000000c1', 'ceo', 'client.created', 'client',
   '00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000a'),
  ('00000000-0000-4000-8000-0000000000c1', 'ceo', 'client.updated', 'client',
   '00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000a');

SELECT has_trigger('public', 'audit_events', 'audit_events_reject_update_delete', 'AC-24: trigger BEFORE UPDATE OR DELETE existe');
SELECT has_trigger('public', 'audit_events', 'audit_events_reject_truncate', 'AC-24: trigger BEFORE TRUNCATE existe');

-- AC-24: nem o dono (postgres) altera ou apaga ----------------------------------------------------------
SELECT throws_ok(
  $$ UPDATE public.audit_events SET action = 'client.forged' WHERE resource_id = '00000000-0000-4000-8000-00000000000a' $$,
  '42501', 'FORBIDDEN', 'AC-24: UPDATE em audit_events falha até para postgres (trigger)'
);
SELECT throws_ok(
  $$ DELETE FROM public.audit_events WHERE resource_id = '00000000-0000-4000-8000-00000000000a' $$,
  '42501', 'FORBIDDEN', 'AC-24: DELETE em audit_events falha até para postgres (trigger)'
);
SELECT throws_ok(
  $$ TRUNCATE public.audit_events $$,
  '42501', 'FORBIDDEN', 'AC-24: TRUNCATE em audit_events falha até para postgres (trigger)'
);

-- AC-24: CEO aal2 lê, mas não escreve ----------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT is(
  (SELECT count(*)::int FROM public.audit_events WHERE resource_id = '00000000-0000-4000-8000-00000000000a'),
  2,
  'AC-24: CEO aal2 lê a auditoria'
);
SELECT throws_ok(
  $$ UPDATE public.audit_events SET action = 'client.forged' WHERE resource_id = '00000000-0000-4000-8000-00000000000a' $$,
  '42501', NULL, 'AC-24: CEO aal2 não faz UPDATE em audit_events'
);
SELECT throws_ok(
  $$ DELETE FROM public.audit_events WHERE resource_id = '00000000-0000-4000-8000-00000000000a' $$,
  '42501', NULL, 'AC-24: CEO aal2 não faz DELETE em audit_events'
);
SELECT throws_ok(
  $$ TRUNCATE public.audit_events $$,
  '42501', NULL, 'AC-24: CEO aal2 não faz TRUNCATE em audit_events'
);
SELECT throws_ok(
  $$ INSERT INTO public.audit_events (action, resource_type, resource_id)
     VALUES ('client.forged', 'client', '00000000-0000-4000-8000-00000000000a') $$,
  '42501', NULL, 'AC-24: CEO aal2 não faz INSERT direto em audit_events (só as funções gravam)'
);
SELECT tests.clear_authentication();

-- AC-24: cliente não escreve nem lê ------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ INSERT INTO public.audit_events (action, resource_type, resource_id)
     VALUES ('client.forged', 'client', '00000000-0000-4000-8000-00000000000a') $$,
  '42501', NULL, 'AC-24: cliente não faz INSERT em audit_events'
);
SELECT throws_ok(
  $$ DELETE FROM public.audit_events $$,
  '42501', NULL, 'AC-24: cliente não faz DELETE em audit_events'
);
SELECT tests.clear_authentication();

-- AC-24: service_role (a secret key) também não -------------------------------------------------------------------------
SET LOCAL ROLE service_role;
SELECT throws_ok(
  $$ UPDATE public.audit_events SET action = 'client.forged' WHERE resource_id = '00000000-0000-4000-8000-00000000000a' $$,
  '42501', NULL, 'AC-24: service_role não faz UPDATE em audit_events (privilégio revogado)'
);
SELECT throws_ok(
  $$ DELETE FROM public.audit_events WHERE resource_id = '00000000-0000-4000-8000-00000000000a' $$,
  '42501', NULL, 'AC-24: service_role não faz DELETE em audit_events (privilégio revogado)'
);
SELECT throws_ok(
  $$ TRUNCATE public.audit_events $$,
  '42501', NULL, 'AC-24: service_role não faz TRUNCATE em audit_events (privilégio revogado)'
);
SELECT throws_ok(
  $$ INSERT INTO public.audit_events (action, resource_type, resource_id)
     VALUES ('client.forged', 'client', '00000000-0000-4000-8000-00000000000a') $$,
  '42501', NULL, 'AC-24: service_role não faz INSERT em audit_events (só as funções SECURITY DEFINER gravam)'
);
RESET ROLE;

-- anon -----------------------------------------------------------------------------------------------------------------------
SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ INSERT INTO public.audit_events (action, resource_type, resource_id)
     VALUES ('client.forged', 'client', '00000000-0000-4000-8000-00000000000a') $$,
  '42501', NULL, 'AC-24: anon não faz INSERT em audit_events'
);
RESET ROLE;

-- O histórico continua intacto ---------------------------------------------------------------------------------------------------
SELECT results_eq(
  $$ SELECT action FROM public.audit_events WHERE resource_id = '00000000-0000-4000-8000-00000000000a' ORDER BY id $$,
  $$ VALUES ('client.created'), ('client.updated') $$,
  'AC-24: depois de todas as tentativas, os dois eventos continuam como foram gravados'
);

-- A identidade é GENERATED ALWAYS: ninguém escolhe o id de um evento ----------------------------------------------------------------
SELECT throws_ok(
  $$ INSERT INTO public.audit_events (id, action, resource_type, resource_id)
     VALUES (1, 'client.forged', 'client', '00000000-0000-4000-8000-00000000000a') $$,
  '428C9', NULL, 'AC-24: o id do evento é GENERATED ALWAYS (nem o dono escolhe o id)'
);

SELECT * FROM finish();
ROLLBACK;
