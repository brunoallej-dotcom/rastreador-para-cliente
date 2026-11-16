-- private.session_is_alive (SEC-07, ADR 0009): a sessão vale no máximo 12 h desde a criação e 4 h
-- desde a última atividade, e o banco aplica os dois limites mesmo que o Auth não os aplique.
-- Os limites são testados pelo efeito que importa: `current_principal()` devolve ou não o principal.
-- Dentro da transação now() é fixo, então as idades abaixo são determinísticas.
BEGIN;
SELECT plan(27);

INSERT INTO public.clients (id, name) VALUES ('00000000-0000-4000-8000-00000000000a', 'Cliente A');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');

-- Posiciona a sessão do cliente (id = id do usuário) e diz se o banco ainda lhe dá um principal.
CREATE FUNCTION pg_temp.has_principal(p_created interval, p_refreshed interval)
RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
  v_found boolean;
BEGIN
  UPDATE auth.sessions
     SET created_at   = CASE WHEN p_created IS NULL THEN NULL ELSE now() - p_created END,
         -- refreshed_at é `timestamp` SEM fuso, em UTC (como o GoTrue grava)
         refreshed_at = CASE WHEN p_refreshed IS NULL THEN NULL ELSE (now() AT TIME ZONE 'UTC') - p_refreshed END
   WHERE id = '00000000-0000-4000-8000-0000000000a1';
  PERFORM tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
  SELECT EXISTS (SELECT 1 FROM public.current_principal()) INTO v_found;
  PERFORM tests.clear_authentication();
  RETURN v_found;
END;
$$;

-- Marca de atividade do refresh token: o GoTrue nem sempre grava `refreshed_at` ---------------------------------
CREATE FUNCTION pg_temp.add_refresh_token(p_session uuid, p_age interval)
RETURNS void
LANGUAGE sql
AS $$
  INSERT INTO auth.refresh_tokens (instance_id, token, user_id, revoked, created_at, updated_at, session_id)
  VALUES ('00000000-0000-0000-0000-000000000000', 'rt-' || gen_random_uuid(), p_session::text, false,
          now() - p_age, now() - p_age, p_session);
$$;

-- Dentro dos dois limites: tem principal --------------------------------------------------------------------
SELECT is(pg_temp.has_principal(interval '1 minute', NULL), true,
  'SEC-07: sessão recém-criada (nunca renovada) tem principal');
SELECT is(pg_temp.has_principal(interval '11 hours 59 minutes', interval '1 hour'), true,
  'SEC-07: sessão de 11 h 59 min, renovada há 1 h, tem principal');
SELECT is(pg_temp.has_principal(interval '3 hours', NULL), true,
  'SEC-07: sessão de 3 h que nunca foi renovada ainda está dentro das 4 h de inatividade');
SELECT is(pg_temp.has_principal(interval '6 hours', interval '3 hours 59 minutes'), true,
  'SEC-07: renovada há 3 h 59 min está dentro das 4 h de inatividade');

-- timebox: 12 h desde a criação, mesmo em uso --------------------------------------------------------------
SELECT is(pg_temp.has_principal(interval '12 hours 1 minute', interval '1 minute'), false,
  'SEC-07: sessão criada há 12 h 1 min NÃO tem principal, mesmo renovada agora (timebox)');
SELECT is(pg_temp.has_principal(interval '13 hours', NULL), false,
  'SEC-07: sessão criada há 13 h não tem principal');
SELECT is(pg_temp.has_principal(interval '3 days', interval '1 minute'), false,
  'SEC-07: sessão de 3 dias, em uso, não tem principal (um refresh token roubado não vive para sempre)');

-- inatividade: 4 h desde a última atividade -------------------------------------------------------------------
SELECT is(pg_temp.has_principal(interval '6 hours', interval '4 hours 1 minute'), false,
  'SEC-07: sem renovação há 4 h 1 min NÃO tem principal (inatividade)');
SELECT is(pg_temp.has_principal(interval '5 hours', NULL), false,
  'SEC-07: sessão de 5 h que nunca foi renovada: a inatividade conta desde a criação');
SELECT is(pg_temp.has_principal(interval '8 hours', interval '7 hours'), false,
  'SEC-07: renovada há 7 h não tem principal');

-- Renovação registrada só pelo refresh token (refreshed_at nulo ou antigo) -----------------------------------
SELECT pg_temp.add_refresh_token('00000000-0000-4000-8000-0000000000a1', interval '1 hour');
SELECT is(pg_temp.has_principal(interval '6 hours', NULL), true,
  'SEC-07: refreshed_at nulo, mas refresh token novo há 1 h: a atividade conta, tem principal');
SELECT is(pg_temp.has_principal(interval '8 hours', interval '7 hours'), true,
  'SEC-07: refreshed_at antigo (7 h) e refresh token novo (1 h): vale o mais recente');
DELETE FROM auth.refresh_tokens WHERE session_id = '00000000-0000-4000-8000-0000000000a1';

SELECT pg_temp.add_refresh_token('00000000-0000-4000-8000-0000000000a1', interval '5 hours');
SELECT is(pg_temp.has_principal(interval '8 hours', NULL), false,
  'SEC-07: o refresh token mais novo tem 5 h: inatividade, sem principal');
DELETE FROM auth.refresh_tokens WHERE session_id = '00000000-0000-4000-8000-0000000000a1';

-- o refresh token de OUTRA sessão não mantém esta viva
SELECT pg_temp.add_refresh_token('00000000-0000-4000-8000-0000000000c1', interval '1 hour');
SELECT is(pg_temp.has_principal(interval '8 hours', NULL), false,
  'SEC-07: refresh token recente de outra sessão não mantém a sessão do cliente viva');
DELETE FROM auth.refresh_tokens WHERE session_id = '00000000-0000-4000-8000-0000000000c1';

-- created_at nulo: sem prova de idade, nega (fail closed) ------------------------------------------------------
SELECT is(pg_temp.has_principal(NULL, interval '1 minute'), false,
  'SEC-07: sessão sem created_at não tem principal (sem prova de idade, nega)');
SELECT is(pg_temp.has_principal(NULL, NULL), false,
  'SEC-07: sessão sem created_at e sem renovação não tem principal');

-- refreshed_at é UTC sem fuso: o fuso da sessão do Postgres não pode deslocar o limite ---------------------------
SELECT set_config('timezone', 'America/Sao_Paulo', true);
SELECT is(pg_temp.has_principal(interval '6 hours', interval '3 hours'), true,
  'SEC-07: com timezone America/Sao_Paulo (UTC-3), renovada há 3 h tem principal');
SELECT is(pg_temp.has_principal(interval '8 hours', interval '5 hours'), false,
  'SEC-07: com timezone America/Sao_Paulo, renovada há 5 h NÃO tem principal');
SELECT set_config('timezone', 'Pacific/Kiritimati', true);
SELECT is(pg_temp.has_principal(interval '6 hours', interval '3 hours'), true,
  'SEC-07: com timezone Pacific/Kiritimati (UTC+14), renovada há 3 h tem principal');
SELECT is(pg_temp.has_principal(interval '8 hours', interval '5 hours'), false,
  'SEC-07: com timezone Pacific/Kiritimati, renovada há 5 h NÃO tem principal');
SELECT set_config('timezone', 'Pacific/Pago_Pago', true);
SELECT is(pg_temp.has_principal(interval '6 hours', interval '3 hours'), true,
  'SEC-07: com timezone Pacific/Pago_Pago (UTC-11), renovada há 3 h tem principal');
SELECT is(pg_temp.has_principal(interval '8 hours', interval '5 hours'), false,
  'SEC-07: com timezone Pacific/Pago_Pago, renovada há 5 h NÃO tem principal');
SELECT set_config('timezone', 'UTC', true);

-- Sessão vencida não vale para função de CEO nem para a RLS -----------------------------------------------------
UPDATE auth.sessions
   SET created_at = now() - interval '13 hours', refreshed_at = NULL
 WHERE id = '00000000-0000-4000-8000-0000000000c1';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT is_empty(
  $$ SELECT user_id FROM public.current_principal() $$,
  'SEC-07: CEO aal2 com sessão de 13 h não tem principal'
);
SELECT throws_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000a1', true) $$,
  '42501', 'FORBIDDEN', 'SEC-07: função de CEO nega a sessão vencida (is_ceo() exige sessão viva)'
);
SELECT is_empty(
  $$ SELECT id FROM public.clients $$,
  'SEC-07: a RLS não mostra nada a um CEO com sessão vencida'
);
SELECT tests.clear_authentication();

-- A função continua fechada --------------------------------------------------------------------------------------
SELECT is(
  has_function_privilege('anon', 'private.session_is_alive()', 'EXECUTE')
    OR has_function_privilege('authenticated', 'private.session_is_alive()', 'EXECUTE'),
  false,
  'AC-25: private.session_is_alive() continua sem EXECUTE para anon e authenticated'
);
SELECT is(
  (SELECT p.prosecdef AND coalesce(p.proconfig @> ARRAY['search_path=""'], false)
     FROM pg_proc p WHERE p.oid = 'private.session_is_alive()'::regprocedure),
  true,
  'AC-25: private.session_is_alive() continua SECURITY DEFINER com search_path vazio'
);

SELECT * FROM finish();
ROLLBACK;
