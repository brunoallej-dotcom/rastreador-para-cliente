-- Onda 6.1: elevação de CEO atestada pelo backend (F-50 b, F-60, F-61, F-63) e validade de 72 h da
-- senha temporária (F-41). Cobre: privilégios dos registros e das funções (só o service_role atesta),
-- `aal2` sem atestado negado em toda função e leitura de CEO, atestado de outra sessão, de outro
-- usuário, de fator removido ou não verificado, cada recusa do atestado (o motivo, as sessões apagadas
-- e a auditoria), o oráculo (janela de 120 s), a ativação pelo backend, o registro de fatores e de
-- challenges e a validade da senha temporária (vencida, dentro do prazo, renovada pelo reset).
BEGIN;
SELECT plan(99);

-- ids determinísticos por cenário n: usuário, fator, challenge e sessão extra ---------------------------
CREATE FUNCTION pg_temp.uid(n integer) RETURNS uuid LANGUAGE sql IMMUTABLE AS
  $$ SELECT ('00000000-0000-4000-8000-0000e' || lpad(n::text, 7, '0'))::uuid $$;
CREATE FUNCTION pg_temp.fid(n integer) RETURNS uuid LANGUAGE sql IMMUTABLE AS
  $$ SELECT ('00000000-0000-4000-8000-0000f' || lpad(n::text, 7, '0'))::uuid $$;
CREATE FUNCTION pg_temp.cid(n integer) RETURNS uuid LANGUAGE sql IMMUTABLE AS
  $$ SELECT ('00000000-0000-4000-8000-0000c' || lpad(n::text, 7, '0'))::uuid $$;
CREATE FUNCTION pg_temp.sid(n integer) RETURNS uuid LANGUAGE sql IMMUTABLE AS
  $$ SELECT ('00000000-0000-4000-8000-0000a' || lpad(n::text, 7, '0'))::uuid $$;
-- os testes chamam os geradores de id também com o papel da API (SET LOCAL ROLE / authenticate_as)
GRANT EXECUTE ON FUNCTION pg_temp.uid(integer), pg_temp.fid(integer), pg_temp.cid(integer), pg_temp.sid(integer)
  TO anon, authenticated, service_role;

-- Um CEO com sessão aal2 (id = id do usuário), um fator TOTP e um challenge, nas condições pedidas:
--   p_factor_status    estado do fator no Auth;
--   p_in_registry      o backend cadastrou o fator (private.mfa_backend_factors);
--   p_activated        o registro já tem a ativação gravada;
--   p_verified_ago     há quanto tempo o Auth verificou o challenge (NULL = nunca verificado);
--   p_in_backend       o backend registrou o challenge (private.mfa_backend_challenges);
--   p_was_verified     o fator já estava verificado quando o backend registrou o challenge.
CREATE FUNCTION pg_temp.arrange(
  n               integer,
  p_factor_status text DEFAULT 'verified',
  p_in_registry   boolean DEFAULT true,
  p_activated     boolean DEFAULT false,
  p_verified_ago  interval DEFAULT interval '0 seconds',
  p_in_backend    boolean DEFAULT true,
  p_was_verified  boolean DEFAULT false
)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM tests.create_user(pg_temp.uid(n), 'ceo');
  UPDATE auth.sessions SET aal = 'aal2' WHERE id = pg_temp.uid(n);
  INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
  VALUES (pg_temp.fid(n), pg_temp.uid(n), 'cenario', 'totp', p_factor_status::auth.factor_status, now(), now(), 'TESTSECRET');
  IF p_in_registry THEN
    INSERT INTO private.mfa_backend_factors (factor_id, user_id, activated_at, activation_challenge_id)
    VALUES (pg_temp.fid(n), pg_temp.uid(n),
            CASE WHEN p_activated THEN now() END,
            CASE WHEN p_activated THEN pg_temp.cid(n) END);
  END IF;
  INSERT INTO auth.mfa_challenges (id, factor_id, created_at, verified_at, ip_address)
  VALUES (pg_temp.cid(n), pg_temp.fid(n), now(),
          CASE WHEN p_verified_ago IS NULL THEN NULL ELSE now() - p_verified_ago END, '127.0.0.1');
  IF p_in_backend THEN
    INSERT INTO private.mfa_backend_challenges (challenge_id, factor_id, user_id, factor_was_verified)
    VALUES (pg_temp.cid(n), pg_temp.fid(n), pg_temp.uid(n), p_was_verified);
  END IF;
END;
$$;

-- Um challenge a mais no fator do cenário n: o `id` é o do cenário m (sufixo de outro cenário);
-- p_in_backend diz se o backend o registrou.
CREATE FUNCTION pg_temp.extra_challenge(n integer, m integer, p_verified_ago interval, p_in_backend boolean, p_was_verified boolean DEFAULT true)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO auth.mfa_challenges (id, factor_id, created_at, verified_at, ip_address)
  VALUES (pg_temp.cid(m), pg_temp.fid(n), now(),
          CASE WHEN p_verified_ago IS NULL THEN NULL ELSE now() - p_verified_ago END, '127.0.0.1');
  IF p_in_backend THEN
    INSERT INTO private.mfa_backend_challenges (challenge_id, factor_id, user_id, factor_was_verified)
    VALUES (pg_temp.cid(m), pg_temp.fid(n), pg_temp.uid(n), p_was_verified);
  END IF;
END;
$$;

-- Chama a função de atestado e resume: [resultado, sessões que o usuário ainda tem, eventos de recusa]
CREATE FUNCTION pg_temp.attest_with(p_user uuid, p_session uuid, p_factor uuid, p_challenge uuid)
RETURNS text[]
LANGUAGE plpgsql
AS $$
DECLARE
  v_result text := public.attest_mfa_session(p_user, p_session, p_factor, p_challenge);
BEGIN
  RETURN ARRAY[
    v_result,
    (SELECT count(*) FROM auth.sessions s WHERE s.user_id = p_user)::text,
    (SELECT count(*) FROM public.audit_events e
      WHERE e.action = 'auth.mfa_attestation_refused' AND e.resource_id = p_user)::text
  ];
END;
$$;
CREATE FUNCTION pg_temp.attest(n integer) RETURNS text[] LANGUAGE sql AS
  $$ SELECT pg_temp.attest_with(pg_temp.uid(n), pg_temp.uid(n), pg_temp.fid(n), pg_temp.cid(n)) $$;

-- arrange (como postgres) --------------------------------------------------------------------------
INSERT INTO public.clients (id, name) VALUES ('00000000-0000-4000-8000-00000000000a', 'Cliente A');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');
-- c1: o CEO que age (fator verificado; atestado quando o teste pede); c2: outro CEO
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c2', 'ceo');
-- c3: o CEO atestado dos testes de privilégio (c1 só é atestado depois do bloco E-32)
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c3', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c2');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c3');

-- privilégios: tabelas privadas --------------------------------------------------------------------------
SELECT is(
  (SELECT count(*)::integer FROM pg_class c
    WHERE c.oid IN ('private.mfa_backend_factors'::regclass, 'private.mfa_backend_challenges'::regclass,
                    'private.mfa_session_attestations'::regclass)
      AND c.relrowsecurity),
  3,
  'F-63: as três tabelas de atestado têm RLS habilitado'
);
SELECT is_empty(
  $$ SELECT t.name, r.role
       FROM (VALUES ('private.mfa_backend_factors'), ('private.mfa_backend_challenges'),
                    ('private.mfa_session_attestations')) t (name)
      CROSS JOIN (VALUES ('anon'), ('authenticated'), ('service_role')) r (role)
      WHERE has_table_privilege(r.role, t.name,
                                'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') $$,
  'F-63: anon, authenticated e service_role não têm privilégio algum nas tabelas de atestado'
);
SELECT is_empty(
  $$ SELECT policyname FROM pg_policies
      WHERE schemaname = 'private'
        AND tablename IN ('mfa_backend_factors', 'mfa_backend_challenges', 'mfa_session_attestations') $$,
  'F-63: nenhuma policy nas tabelas de atestado (RLS sem policy nega a quem não é dono)'
);

-- privilégios: funções ---------------------------------------------------------------------------------
SELECT is(
  (SELECT count(*)::integer FROM pg_proc p
    WHERE p.oid IN ('public.attest_mfa_session(uuid, uuid, uuid, uuid)'::regprocedure,
                    'public.register_backend_totp_factor(uuid, uuid, uuid)'::regprocedure,
                    'public.record_backend_mfa_challenge(uuid, uuid, uuid)'::regprocedure,
                    'public.list_backend_totp_factors()'::regprocedure,
                    'private.session_is_attested()'::regprocedure,
                    'private.refuse_mfa_attestation(uuid, uuid, text)'::regprocedure)
      AND p.prosecdef
      AND 'search_path=""' = ANY (p.proconfig)),
  6,
  'AC-25: as funções do atestado são SECURITY DEFINER com search_path vazio'
);
SELECT is_empty(
  $$ SELECT p.proname, a.grantee::regrole
       FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE p.oid IN ('public.attest_mfa_session(uuid, uuid, uuid, uuid)'::regprocedure,
                      'public.register_backend_totp_factor(uuid, uuid, uuid)'::regprocedure,
                      'public.record_backend_mfa_challenge(uuid, uuid, uuid)'::regprocedure)
        AND a.privilege_type = 'EXECUTE'
        AND a.grantee NOT IN (p.proowner, 'service_role'::regrole) $$,
  'F-63: attest_mfa_session e as funções de registro: EXECUTE só para o dono e o service_role (nem PUBLIC, nem anon, nem authenticated)'
);
SELECT is_empty(
  $$ SELECT p.proname, r.role
       FROM pg_proc p
      CROSS JOIN (VALUES ('anon'), ('authenticated')) r (role)
      WHERE p.oid IN ('private.session_is_attested()'::regprocedure,
                      'private.refuse_mfa_attestation(uuid, uuid, text)'::regprocedure,
                      'private.temporary_password_validity()'::regprocedure)
        AND has_function_privilege(r.role, p.oid, 'EXECUTE') $$,
  'F-63: os helpers privados do atestado e da validade não são executáveis por anon nem authenticated'
);
SELECT ok(
  has_function_privilege('authenticated', 'public.list_backend_totp_factors()', 'EXECUTE')
  AND NOT has_function_privilege('anon', 'public.list_backend_totp_factors()', 'EXECUTE')
  AND NOT has_function_privilege('service_role', 'public.list_backend_totp_factors()', 'EXECUTE'),
  'F-60: list_backend_totp_factors é do usuário autenticado (nem anon, nem service_role)'
);

-- ninguém além do service_role chama a função de atestado ------------------------------------------------
SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT public.attest_mfa_session('00000000-0000-4000-8000-0000000000c1',
       '00000000-0000-4000-8000-0000000000c1', gen_random_uuid(), gen_random_uuid()) $$,
  '42501', NULL, 'F-63: anon não chama attest_mfa_session (42501)'
);
RESET ROLE;
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT throws_ok(
  $$ SELECT public.attest_mfa_session('00000000-0000-4000-8000-0000000000c3',
       '00000000-0000-4000-8000-0000000000c3', gen_random_uuid(), gen_random_uuid()) $$,
  '42501', NULL, 'F-63: nem o CEO atestado (authenticated) chama attest_mfa_session: não atesta a própria sessão (42501)'
);
SELECT throws_ok(
  $$ SELECT public.register_backend_totp_factor('00000000-0000-4000-8000-0000000000c3',
       gen_random_uuid(), '00000000-0000-4000-8000-0000000000c3') $$,
  '42501', NULL, 'F-60: authenticated não chama register_backend_totp_factor (42501)'
);
SELECT throws_ok(
  $$ SELECT public.record_backend_mfa_challenge('00000000-0000-4000-8000-0000000000c3',
       gen_random_uuid(), gen_random_uuid()) $$,
  '42501', NULL, 'F-63: authenticated não chama record_backend_mfa_challenge (42501)'
);
SELECT tests.clear_authentication();
SET LOCAL ROLE service_role;
SELECT throws_ok(
  $$ SELECT public.attest_mfa_session(NULL, gen_random_uuid(), gen_random_uuid(), gen_random_uuid()) $$,
  'P0001', 'INVALID_INPUT', 'F-63: o service_role chama attest_mfa_session; entrada nula é INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.attest_mfa_session(gen_random_uuid(), gen_random_uuid(), NULL, gen_random_uuid()) $$,
  'P0001', 'INVALID_INPUT', 'F-63: fator nulo é INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT private.session_is_attested() $$, '42501', NULL,
  'F-63: o service_role não chama o helper privado'
);
RESET ROLE;

-- aal2 SEM atestado não é CEO (E-32 no banco) -----------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2', false);
SELECT is(
  (SELECT count(*)::integer FROM public.clients),
  0,
  'E-32: CEO com fator verificado e claim aal2 SEM atestado não lê os clientes'
);
SELECT throws_ok(
  $$ SELECT public.create_client('Cliente de quem não é CEO') $$,
  '42501', 'FORBIDDEN', 'E-32: aal2 sem atestado não executa create_client'
);
SELECT throws_ok(
  $$ SELECT * FROM public.list_client_users('00000000-0000-4000-8000-00000000000a') $$,
  '42501', 'FORBIDDEN', 'E-32: aal2 sem atestado não executa list_client_users'
);
SELECT throws_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000a1', true) $$,
  '42501', 'FORBIDDEN', 'E-32: aal2 sem atestado não executa set_account_disabled'
);
SELECT is(
  (SELECT p.aal FROM public.current_principal() p),
  'aal1',
  'E-32: o principal de uma aal2 sem atestado é aal1 (o app calcula VERIFY_MFA)'
);
SELECT is(
  (SELECT p.has_verified_totp FROM public.current_principal() p),
  true,
  'E-32: o fator continua verificado, então a pendência é VERIFY_MFA e não ENROLL_MFA'
);
SELECT tests.clear_authentication();

-- com o atestado, o mesmo CEO age ----------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT is(
  (SELECT p.aal FROM public.current_principal() p),
  'aal2',
  'F-63: a sessão atestada tem principal aal2'
);
SELECT lives_ok(
  $$ SELECT public.create_client('Cliente do CEO atestado') $$,
  'F-63: a sessão atestada executa create_client'
);
SELECT tests.clear_authentication();

-- o claim aal1 não vale, mesmo com atestado gravado para a sessão
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT is(
  (SELECT count(*)::integer FROM public.clients),
  0,
  'F-63: um JWT aal1 de uma sessão atestada não é CEO'
);
SELECT tests.clear_authentication();

-- atestado de OUTRA sessão não conta ------------------------------------------------------------------------
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal)
VALUES (pg_temp.sid(1), '00000000-0000-4000-8000-0000000000c1', now(), now(), 'aal2');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2', false, pg_temp.sid(1));
SELECT is(
  (SELECT count(*)::integer FROM public.clients),
  0,
  'F-63: outra sessão aal2 do mesmo CEO, sem atestado próprio, não é CEO (o atestado é por session_id)'
);
SELECT tests.clear_authentication();

-- atestado de OUTRO usuário não conta (linha plantada, fora da função) --------------------------------------
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal)
VALUES (pg_temp.sid(2), '00000000-0000-4000-8000-0000000000c2', now(), now(), 'aal2');
INSERT INTO private.mfa_session_attestations (session_id, user_id, factor_id, challenge_id)
SELECT pg_temp.sid(2), '00000000-0000-4000-8000-0000000000c1', f.id, gen_random_uuid()
  FROM auth.mfa_factors f WHERE f.user_id = '00000000-0000-4000-8000-0000000000c1';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2', false, pg_temp.sid(2));
SELECT is(
  (SELECT count(*)::integer FROM public.clients),
  0,
  'F-63: um atestado em nome de outro usuário, na sessão do c2, não faz do c2 um CEO'
);
SELECT tests.clear_authentication();

-- fator removido, não verificado ou trocado: o atestado não conta mais -----------------------------------------
SELECT pg_temp.arrange(30);
SELECT pg_temp.attest(30);
SELECT tests.authenticate_as(pg_temp.uid(30), 'aal2', false);
SELECT cmp_ok(
  (SELECT count(*)::integer FROM public.clients), '>', 0,
  'F-24: o atestado de um fator verificado vale (o CEO atestado lê os clientes)'
);
SELECT tests.clear_authentication();

UPDATE auth.mfa_factors SET status = 'unverified' WHERE id = pg_temp.fid(30);
SELECT tests.authenticate_as(pg_temp.uid(30), 'aal2', false);
SELECT is(
  (SELECT count(*)::integer FROM public.clients),
  0,
  'F-63: com o fator atestado de volta a não verificado, o mesmo JWT já não é CEO'
);
SELECT tests.clear_authentication();
UPDATE auth.mfa_factors SET status = 'verified' WHERE id = pg_temp.fid(30);
SELECT tests.authenticate_as(pg_temp.uid(30), 'aal2', false);
SELECT cmp_ok(
  (SELECT count(*)::integer FROM public.clients), '>', 0,
  'F-63: a checagem do fator é viva: verificado de novo, o atestado volta a valer'
);
SELECT tests.clear_authentication();

DELETE FROM auth.mfa_factors WHERE id = pg_temp.fid(30);
SELECT is(
  (SELECT count(*)::integer FROM private.mfa_session_attestations WHERE user_id = pg_temp.uid(30)),
  0,
  'F-24: remover o fator apaga o atestado dele (ON DELETE CASCADE)'
);
SELECT tests.authenticate_as(pg_temp.uid(30), 'aal2', false);
SELECT is(
  (SELECT count(*)::integer FROM public.clients),
  0,
  'F-24: sem o fator, o JWT aal2 atestado antes não lê mais os clientes'
);
SELECT tests.clear_authentication();

-- sessão apagada leva o atestado --------------------------------------------------------------------------------
SELECT pg_temp.arrange(31);
SELECT pg_temp.attest(31);
DELETE FROM auth.sessions WHERE id = pg_temp.uid(31);
SELECT is(
  (SELECT count(*)::integer FROM private.mfa_session_attestations WHERE user_id = pg_temp.uid(31)),
  0,
  'F-63: apagar a sessão apaga o atestado (ON DELETE CASCADE)'
);

-- mark_password_changed: aal2 sem atestado não troca a senha de um CEO com TOTP verificado ---------------------
UPDATE auth.users SET encrypted_password = 'changed-1' WHERE id = '00000000-0000-4000-8000-0000000000c2';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2', false);
SELECT throws_ok(
  $$ SELECT public.mark_password_changed() $$,
  '42501', 'FORBIDDEN', 'E-32: um CEO com TOTP verificado e aal2 sem atestado não executa mark_password_changed'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2');
SELECT lives_ok(
  $$ SELECT public.mark_password_changed() $$,
  'F-63: o mesmo CEO com a sessão atestada executa mark_password_changed'
);
SELECT tests.clear_authentication();

-- attest_mfa_session: o caminho feliz e a ativação pelo backend ------------------------------------------------
SELECT pg_temp.arrange(1);
SELECT is(
  pg_temp.attest(1),
  ARRAY['attested', '1', '0'],
  'F-63: com tudo certo o atestado é gravado, as sessões ficam e nada é auditado'
);
SELECT is(
  (SELECT row(a.user_id, a.factor_id, a.challenge_id)::text
     FROM private.mfa_session_attestations a WHERE a.session_id = pg_temp.uid(1)),
  row(pg_temp.uid(1), pg_temp.fid(1), pg_temp.cid(1))::text,
  'F-63: o atestado amarra sessão, usuário, fator e challenge do backend'
);
SELECT is(
  (SELECT row(bf.activated_at IS NOT NULL, bf.activation_challenge_id)::text
     FROM private.mfa_backend_factors bf WHERE bf.factor_id = pg_temp.fid(1)),
  row(true, pg_temp.cid(1))::text,
  'F-61: a primeira ativação pelo backend grava a ativação e o challenge dela'
);
SELECT is(
  pg_temp.attest(1),
  ARRAY['attested', '1', '0'],
  'F-63: atestar de novo a mesma sessão é idempotente'
);
SELECT is(
  (SELECT count(*)::integer FROM private.mfa_session_attestations WHERE session_id = pg_temp.uid(1)),
  1,
  'F-63: continua um atestado por sessão'
);

-- recusas: cada uma devolve o motivo, apaga TODAS as sessões do usuário e audita ------------------------------
SELECT tests.create_user(pg_temp.uid(2), 'client', '00000000-0000-4000-8000-00000000000a');
SELECT is(
  pg_temp.attest_with(pg_temp.uid(2), pg_temp.uid(2), gen_random_uuid(), gen_random_uuid()),
  ARRAY['not_ceo', '0', '1'],
  'F-63: quem não é CEO é recusado (not_ceo)'
);

SELECT pg_temp.arrange(3);
SELECT is(
  pg_temp.attest_with(pg_temp.uid(3), gen_random_uuid(), pg_temp.fid(3), pg_temp.cid(3)),
  ARRAY['session_not_found', '0', '1'],
  'F-63: uma sessão que não existe é recusada (session_not_found)'
);

SELECT pg_temp.arrange(4);
UPDATE auth.sessions SET aal = 'aal1' WHERE id = pg_temp.uid(4);
SELECT is(
  pg_temp.attest(4),
  ARRAY['session_not_aal2', '0', '1'],
  'F-63: uma sessão que o Auth não elevou a aal2 é recusada (session_not_aal2)'
);

SELECT pg_temp.arrange(5);
SELECT pg_temp.arrange(6);
SELECT is(
  pg_temp.attest_with(pg_temp.uid(5), pg_temp.uid(5), pg_temp.fid(6), pg_temp.cid(5)),
  ARRAY['factor_not_found', '0', '1'],
  'F-63: o fator de OUTRO usuário é recusado (factor_not_found)'
);
SELECT is(
  (SELECT count(*)::integer FROM auth.sessions WHERE user_id = pg_temp.uid(6)),
  1,
  'F-63: a recusa do usuário 5 não toca as sessões de outro usuário'
);

SELECT pg_temp.arrange(7);
UPDATE auth.mfa_factors SET factor_type = 'phone', phone = '+5511999990007' WHERE id = pg_temp.fid(7);
SELECT is(
  pg_temp.attest(7),
  ARRAY['factor_not_totp', '0', '1'],
  'F-63: um fator que não é TOTP é recusado (factor_not_totp)'
);

SELECT pg_temp.arrange(8, p_factor_status => 'unverified');
SELECT is(
  pg_temp.attest(8),
  ARRAY['factor_not_verified', '0', '1'],
  'F-63: um fator não verificado é recusado (factor_not_verified)'
);

SELECT pg_temp.arrange(9, p_in_registry => false);
SELECT is(
  pg_temp.attest(9),
  ARRAY['factor_not_backend', '0', '1'],
  'F-61: um fator verificado que o backend nunca cadastrou (plantado direto no Auth) é recusado (factor_not_backend)'
);

SELECT pg_temp.arrange(10);
SELECT is(
  pg_temp.attest_with(pg_temp.uid(10), pg_temp.uid(10), pg_temp.fid(10), gen_random_uuid()),
  ARRAY['challenge_not_found', '0', '1'],
  'F-63: um challenge que não existe é recusado (challenge_not_found)'
);

SELECT pg_temp.arrange(11);
SELECT pg_temp.arrange(12);
SELECT is(
  pg_temp.attest_with(pg_temp.uid(11), pg_temp.uid(11), pg_temp.fid(11), pg_temp.cid(12)),
  ARRAY['challenge_not_found', '0', '1'],
  'F-63: o challenge de OUTRO fator é recusado (challenge_not_found)'
);

SELECT pg_temp.arrange(13, p_verified_ago => NULL);
SELECT is(
  pg_temp.attest(13),
  ARRAY['challenge_not_verified', '0', '1'],
  'F-63: um challenge que o Auth não verificou é recusado (challenge_not_verified)'
);

SELECT pg_temp.arrange(14, p_verified_ago => interval '121 seconds');
SELECT is(
  pg_temp.attest(14),
  ARRAY['challenge_stale', '0', '1'],
  'F-63: um challenge verificado há mais de 120 s é recusado (challenge_stale)'
);

SELECT pg_temp.arrange(15, p_in_backend => false);
SELECT is(
  pg_temp.attest(15),
  ARRAY['challenge_not_backend', '0', '1'],
  'F-63: um challenge verificado que o backend não registrou é recusado (challenge_not_backend)'
);

-- oráculo: um código aceito direto no Auth, na janela, impede o atestado ------------------------------------------
SELECT pg_temp.arrange(16, p_activated => true, p_was_verified => true);
SELECT pg_temp.extra_challenge(16, 116, interval '30 seconds', false);
SELECT is(
  pg_temp.attest(16),
  ARRAY['oracle', '0', '1'],
  'E-33: um challenge verificado direto no Auth (fora do backend) há 30 s recusa o atestado (oracle)'
);
SELECT is(
  (SELECT row(e.actor_id, e.actor_role, e.resource_type, e.client_id, e.process_id, e.metadata)::text
     FROM public.audit_events e
    WHERE e.action = 'auth.mfa_attestation_refused' AND e.resource_id = pg_temp.uid(16)),
  row(NULL::uuid, NULL::public.app_role, 'account', NULL::uuid, NULL::uuid,
      jsonb_build_object('reason', 'oracle', 'factor_id', pg_temp.fid(16)))::text,
  'E-33: a auditoria da recusa leva só o motivo e o id do fator (sem PII), em nome de ninguém'
);
SELECT is(
  (SELECT count(*)::integer FROM private.mfa_session_attestations WHERE user_id = pg_temp.uid(16)),
  0,
  'E-33: depois da recusa não há atestado algum do usuário'
);

SELECT pg_temp.arrange(18, p_activated => true, p_was_verified => true);
SELECT pg_temp.extra_challenge(18, 118, interval '119 seconds', false);
SELECT is(
  pg_temp.attest(18),
  ARRAY['oracle', '0', '1'],
  'E-33: com 119 s a janela do oráculo ainda pega o challenge de fora'
);

SELECT pg_temp.arrange(17, p_activated => true, p_was_verified => true);
SELECT pg_temp.extra_challenge(17, 117, interval '121 seconds', false);       -- fora da janela
SELECT pg_temp.extra_challenge(17, 217, NULL, false);                          -- chute errado: nunca verificado
SELECT pg_temp.extra_challenge(17, 317, interval '10 seconds', true, true);    -- outro dispositivo do CEO, pelo backend
SELECT is(
  pg_temp.attest(17),
  ARRAY['attested', '1', '0'],
  'E-33: com 121 s, um challenge só criado ou um do próprio backend (login legítimo concorrente) não recusam o atestado'
);

-- ativação pelo backend (F-61) -----------------------------------------------------------------------------------
SELECT pg_temp.arrange(19);
SELECT pg_temp.extra_challenge(19, 119, interval '1 day', false);
SELECT is(
  pg_temp.attest(19),
  ARRAY['factor_not_activated_by_backend', '0', '1'],
  'F-61: um fator ativado direto no Auth (challenge verificado de fora, mesmo antigo) nunca é atestado'
);

SELECT pg_temp.arrange(20, p_was_verified => true);
SELECT is(
  pg_temp.attest(20),
  ARRAY['factor_not_activated_by_backend', '0', '1'],
  'F-61: um fator já verificado quando o backend registrou o challenge não tem ativação do backend'
);

-- a ativação é derivada: depois de uma falha entre o verify e o atestado, o próximo verify se recupera
SELECT pg_temp.arrange(21);                                                     -- cid(21): o challenge que ativou
SELECT pg_temp.extra_challenge(21, 221, interval '5 seconds', true, true);     -- o verify seguinte
SELECT is(
  pg_temp.attest_with(pg_temp.uid(21), pg_temp.uid(21), pg_temp.fid(21), pg_temp.cid(221)),
  ARRAY['attested', '1', '0'],
  'F-61: o verify depois de uma falha do atestado ativa o fator pelo challenge que o ativou (recupera, não tranca o CEO)'
);
SELECT is(
  (SELECT bf.activation_challenge_id FROM private.mfa_backend_factors bf WHERE bf.factor_id = pg_temp.fid(21)),
  pg_temp.cid(21),
  'F-61: a ativação gravada é a do challenge que ativou, não a do atual'
);

-- o resto das entradas ---------------------------------------------------------------------------------------------
SELECT throws_ok(
  $$ SELECT public.attest_mfa_session(pg_temp.uid(1), NULL, pg_temp.fid(1), pg_temp.cid(1)) $$,
  'P0001', 'INVALID_INPUT', 'F-63: sessão nula é INVALID_INPUT (e nada é recusado nem apagado)'
);
SELECT is(
  (SELECT count(*)::integer FROM auth.sessions WHERE user_id = pg_temp.uid(1)),
  1,
  'F-63: a entrada inválida não apagou sessão alguma'
);

-- register_backend_totp_factor ----------------------------------------------------------------------------------------
SELECT tests.create_user(pg_temp.uid(40), 'ceo');
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
VALUES (pg_temp.fid(40), pg_temp.uid(40), 'candidato', 'totp', 'unverified', now(), now(), 'TESTSECRET');
SET LOCAL ROLE service_role;
SELECT lives_ok(
  $$ SELECT public.register_backend_totp_factor(pg_temp.uid(40), pg_temp.fid(40), pg_temp.uid(40)) $$,
  'F-60: o service_role registra o fator que o enroll acabou de criar'
);
RESET ROLE;
SELECT is(
  (SELECT row(bf.user_id, bf.enrolled_session_id, bf.activated_at)::text
     FROM private.mfa_backend_factors bf WHERE bf.factor_id = pg_temp.fid(40)),
  row(pg_temp.uid(40), pg_temp.uid(40), NULL::timestamptz)::text,
  'F-60: o registro leva o usuário, a sessão que cadastrou e nenhuma ativação'
);
SELECT lives_ok(
  $$ SELECT public.register_backend_totp_factor(pg_temp.uid(40), pg_temp.fid(40), pg_temp.uid(40)) $$,
  'F-60: registrar duas vezes é idempotente'
);
SELECT throws_ok(
  $$ SELECT public.register_backend_totp_factor(pg_temp.uid(41), pg_temp.fid(40), pg_temp.uid(40)) $$,
  'P0001', 'NOT_FOUND', 'F-60: o fator de outro usuário (ou usuário que não existe) é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.register_backend_totp_factor(pg_temp.uid(40), pg_temp.fid(40), pg_temp.uid(1)) $$,
  'P0001', 'NOT_FOUND', 'F-60: a sessão de outro usuário é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.register_backend_totp_factor(pg_temp.uid(40), gen_random_uuid(), pg_temp.uid(40)) $$,
  'P0001', 'NOT_FOUND', 'F-60: um fator que não existe é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.register_backend_totp_factor(pg_temp.uid(1), pg_temp.fid(1), pg_temp.uid(1)) $$,
  'P0001', 'NOT_FOUND', 'F-60: um fator já verificado não se cadastra (NOT_FOUND)'
);
SELECT throws_ok(
  $$ SELECT public.register_backend_totp_factor(pg_temp.uid(2), pg_temp.fid(1), pg_temp.uid(2)) $$,
  'P0001', 'NOT_FOUND', 'F-60: quem não é CEO não cadastra fator (NOT_FOUND)'
);
SELECT throws_ok(
  $$ SELECT public.register_backend_totp_factor(NULL, pg_temp.fid(40), pg_temp.uid(40)) $$,
  'P0001', 'INVALID_INPUT', 'F-60: usuário nulo é INVALID_INPUT'
);

-- list_backend_totp_factors: só os fatores do próprio usuário que o backend cadastrou -----------------------------
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
VALUES (pg_temp.fid(42), pg_temp.uid(40), 'plantado', 'totp', 'unverified', now(), now(), 'TESTSECRET');
SELECT tests.authenticate_as(pg_temp.uid(40));
SELECT is(
  (SELECT array_agg(l.factor_id) FROM public.list_backend_totp_factors() l),
  ARRAY[pg_temp.fid(40)],
  'F-60: a lista traz só o fator cadastrado pelo backend; o candidato plantado direto no Auth não aparece'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2');
SELECT is(
  (SELECT count(*)::integer FROM public.list_backend_totp_factors()),
  1,
  'F-60: cada usuário vê só os próprios (o c2 vê o dele, não o do usuário 40)'
);
SELECT tests.clear_authentication();
SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT * FROM public.list_backend_totp_factors() $$, '42501', NULL,
  'F-60: anon não lista os fatores'
);
RESET ROLE;

-- record_backend_mfa_challenge ---------------------------------------------------------------------------------------
INSERT INTO auth.mfa_challenges (id, factor_id, created_at, ip_address)
VALUES (pg_temp.cid(50), pg_temp.fid(40), now(), '127.0.0.1'),
       (pg_temp.cid(51), pg_temp.fid(1), now(), '127.0.0.1');
SET LOCAL ROLE service_role;
SELECT lives_ok(
  $$ SELECT public.record_backend_mfa_challenge(pg_temp.uid(40), pg_temp.fid(40), pg_temp.cid(50)) $$,
  'F-63: o service_role registra o challenge que o backend criou'
);
SELECT lives_ok(
  $$ SELECT public.record_backend_mfa_challenge(pg_temp.uid(1), pg_temp.fid(1), pg_temp.cid(51)) $$,
  'F-63: registra também o challenge de um fator já verificado'
);
SELECT lives_ok(
  $$ SELECT public.record_backend_mfa_challenge(pg_temp.uid(40), pg_temp.fid(40), pg_temp.cid(50)) $$,
  'F-63: registrar duas vezes é idempotente'
);
RESET ROLE;
SELECT is(
  (SELECT array_agg(b.factor_was_verified ORDER BY b.challenge_id)
     FROM private.mfa_backend_challenges b WHERE b.challenge_id IN (pg_temp.cid(50), pg_temp.cid(51))),
  ARRAY[false, true],
  'F-61: o registro guarda se o fator já estava verificado quando o backend criou o challenge'
);
SELECT throws_ok(
  $$ SELECT public.record_backend_mfa_challenge(pg_temp.uid(1), pg_temp.fid(40), pg_temp.cid(50)) $$,
  'P0001', 'NOT_FOUND', 'F-63: o fator de outro usuário é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.record_backend_mfa_challenge(pg_temp.uid(40), pg_temp.fid(40), pg_temp.cid(51)) $$,
  'P0001', 'NOT_FOUND', 'F-63: o challenge de outro fator é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.record_backend_mfa_challenge(pg_temp.uid(40), pg_temp.fid(40), gen_random_uuid()) $$,
  'P0001', 'NOT_FOUND', 'F-63: um challenge que não existe é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT public.record_backend_mfa_challenge(pg_temp.uid(40), NULL, pg_temp.cid(50)) $$,
  'P0001', 'INVALID_INPUT', 'F-63: fator nulo é INVALID_INPUT'
);

-- limpeza oportunista: só de fator já ativado, só de challenge de fator já verificado, só antigo
SELECT pg_temp.arrange(60, p_activated => true, p_was_verified => true);
SELECT pg_temp.extra_challenge(60, 160, interval '0 seconds', true, true);
SELECT pg_temp.extra_challenge(60, 260, interval '0 seconds', true, false);
UPDATE private.mfa_backend_challenges SET recorded_at = now() - interval '8 days'
 WHERE challenge_id IN (pg_temp.cid(60), pg_temp.cid(160), pg_temp.cid(260));
INSERT INTO auth.mfa_challenges (id, factor_id, created_at, ip_address) VALUES (pg_temp.cid(360), pg_temp.fid(60), now(), '127.0.0.1');
SET LOCAL ROLE service_role;
SELECT public.record_backend_mfa_challenge(pg_temp.uid(60), pg_temp.fid(60), pg_temp.cid(360));
RESET ROLE;
SELECT is(
  (SELECT array_agg(b.challenge_id ORDER BY b.challenge_id)
     FROM private.mfa_backend_challenges b WHERE b.factor_id = pg_temp.fid(60)),
  ARRAY[pg_temp.cid(260), pg_temp.cid(360)],
  'F-63: a limpeza apaga os registros antigos de challenge de fator verificado (cid 60 e 160) e guarda a prova da ativação (260) e o novo'
);
SELECT pg_temp.arrange(61, p_activated => false);
UPDATE private.mfa_backend_challenges SET recorded_at = now() - interval '8 days' WHERE challenge_id = pg_temp.cid(61);
UPDATE private.mfa_backend_challenges SET factor_was_verified = true WHERE challenge_id = pg_temp.cid(61);
INSERT INTO auth.mfa_challenges (id, factor_id, created_at, ip_address) VALUES (pg_temp.cid(361), pg_temp.fid(61), now(), '127.0.0.1');
SET LOCAL ROLE service_role;
SELECT public.record_backend_mfa_challenge(pg_temp.uid(61), pg_temp.fid(61), pg_temp.cid(361));
RESET ROLE;
SELECT is(
  (SELECT count(*)::integer FROM private.mfa_backend_challenges b WHERE b.factor_id = pg_temp.fid(61)),
  2,
  'F-63: a limpeza não mexe em fator que ainda não foi ativado (a prova da ativação pode estar ali)'
);

-- F-41: a senha temporária vale 72 h ---------------------------------------------------------------------------------------
SELECT is(
  private.temporary_password_validity(),
  interval '72 hours',
  'F-41: o prazo da senha temporária é 72 h (constante nomeada)'
);
SELECT tests.create_user(pg_temp.uid(70), 'client', '00000000-0000-4000-8000-00000000000a');
SELECT is(
  (SELECT p.must_change_password FROM public.profiles p WHERE p.id = pg_temp.uid(70)),
  true,
  'F-41: o perfil nasce com a senha temporária'
);
SELECT tests.authenticate_as(pg_temp.uid(70));
SELECT is(
  (SELECT count(*)::integer FROM public.current_principal()),
  1,
  'F-41: recém-criada, a senha temporária tem principal'
);
SELECT tests.clear_authentication();

UPDATE private.password_baselines SET recorded_at = now() - interval '71 hours 59 minutes' WHERE user_id = pg_temp.uid(70);
SELECT tests.authenticate_as(pg_temp.uid(70));
SELECT is(
  (SELECT count(*)::integer FROM public.current_principal()),
  1,
  'F-41: com 71 h 59 min a senha temporária ainda vale'
);
SELECT tests.clear_authentication();

UPDATE private.password_baselines SET recorded_at = now() - interval '72 hours' WHERE user_id = pg_temp.uid(70);
SELECT tests.authenticate_as(pg_temp.uid(70));
SELECT is(
  (SELECT count(*)::integer FROM public.current_principal()),
  0,
  'E-34: com 72 h exatas a senha temporária venceu: sem principal'
);
SELECT is(
  (SELECT count(*)::integer FROM public.profiles),
  0,
  'E-34: vencida, a conta não lê nem o próprio perfil (RLS)'
);
SELECT throws_ok(
  $$ SELECT public.mark_password_changed() $$,
  '42501', 'FORBIDDEN', 'E-34: vencida, a conta não troca a senha (só o reset do CEO reabre)'
);
SELECT tests.clear_authentication();

-- o reset de um CEO (função da Onda 2) renova o prazo
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.require_password_change(pg_temp.uid(70)) $$,
  'E-35: o CEO reseta o login com a senha temporária vencida'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT b.recorded_at = now() FROM private.password_baselines b WHERE b.user_id = pg_temp.uid(70)),
  true,
  'E-35: o reset grava uma linha de base nova (o prazo de 72 h recomeça)'
);
-- o reset apaga as sessões do alvo (Onda 2): ele entra de novo, com a senha temporária nova
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal)
VALUES (pg_temp.uid(70), pg_temp.uid(70), now(), now(), 'aal1');
SELECT tests.authenticate_as(pg_temp.uid(70));
SELECT is(
  (SELECT count(*)::integer FROM public.current_principal()),
  1,
  'E-35: depois do reset (e de um novo login) a conta volta a ter principal'
);
SELECT tests.clear_authentication();

-- trocar a senha encerra o estado temporário: nada mais vence
UPDATE auth.users SET encrypted_password = 'changed-2' WHERE id = pg_temp.uid(70);
SELECT tests.authenticate_as(pg_temp.uid(70));
SELECT lives_ok(
  $$ SELECT public.mark_password_changed() $$,
  'F-41: dentro do prazo a conta troca a senha'
);
SELECT tests.clear_authentication();
UPDATE private.password_baselines SET recorded_at = now() - interval '400 days' WHERE user_id = pg_temp.uid(70);
SELECT tests.authenticate_as(pg_temp.uid(70));
SELECT is(
  (SELECT count(*)::integer FROM public.current_principal()),
  1,
  'F-41: com a senha definitiva (must_change_password = false) a linha de base antiga não vence nada'
);
SELECT tests.clear_authentication();

-- sem linha de base e com senha temporária: fail closed
SELECT tests.create_user(pg_temp.uid(71), 'client', '00000000-0000-4000-8000-00000000000a');
DELETE FROM private.password_baselines WHERE user_id = pg_temp.uid(71);
SELECT tests.authenticate_as(pg_temp.uid(71));
SELECT is(
  (SELECT count(*)::integer FROM public.current_principal()),
  0,
  'F-41: senha temporária sem linha de base não tem principal (fail closed)'
);
SELECT tests.clear_authentication();

-- o CEO com a senha temporária vencida perde o poder, mesmo com a sessão atestada
SELECT pg_temp.arrange(72);
SELECT pg_temp.attest(72);
UPDATE private.password_baselines SET recorded_at = now() - interval '73 hours' WHERE user_id = pg_temp.uid(72);
SELECT tests.authenticate_as(pg_temp.uid(72), 'aal2', false);
SELECT is(
  (SELECT count(*)::integer FROM public.clients),
  0,
  'F-41: um CEO atestado com a senha temporária vencida não lê os clientes'
);
SELECT throws_ok(
  $$ SELECT public.create_client('Cliente de CEO vencido') $$,
  '42501', 'FORBIDDEN', 'F-41: nem executa função de CEO'
);
SELECT tests.clear_authentication();

SELECT * FROM finish();
ROLLBACK;
