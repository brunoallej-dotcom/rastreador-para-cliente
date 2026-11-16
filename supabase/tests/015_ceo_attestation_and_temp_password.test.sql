-- Onda 6.1 (e a revisão dela, F-64 a F-72): elevação de CEO atestada pelo backend (F-50 b, F-60, F-61, F-63) e validade de 72 h da
-- senha temporária (F-41). Cobre: privilégios dos registros e das funções (só o service_role atesta),
-- `aal2` sem atestado negado em toda função e leitura de CEO, atestado de outra sessão, de outro
-- usuário, de fator removido ou não verificado, cada recusa do atestado (o motivo, as sessões apagadas
-- e a auditoria), o oráculo (janela de 120 s), a ativação pelo backend, o registro de fatores e de
-- challenges e a validade da senha temporária (vencida, dentro do prazo, renovada pelo reset).
BEGIN;
SELECT plan(157);

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
--   p_was_verified     o fator já estava verificado quando o backend registrou o challenge;
--   p_proof            o que o gatilho on_mfa_factor_verified concluiu na ativação: true = foi do backend,
--                      false = não foi (um challenge verificado de fora, ou o fator já verificado antes).
CREATE FUNCTION pg_temp.arrange(
  n               integer,
  p_factor_status text DEFAULT 'verified',
  p_in_registry   boolean DEFAULT true,
  p_activated     boolean DEFAULT false,
  p_verified_ago  interval DEFAULT interval '0 seconds',
  p_in_backend    boolean DEFAULT true,
  p_was_verified  boolean DEFAULT false,
  p_proof         boolean DEFAULT true
)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM tests.create_user(pg_temp.uid(n), 'ceo');
  INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
  VALUES (pg_temp.fid(n), pg_temp.uid(n), 'cenario', 'totp', p_factor_status::auth.factor_status, now(), now(), 'TESTSECRET');
  UPDATE auth.sessions SET aal = 'aal2', factor_id = pg_temp.fid(n) WHERE id = pg_temp.uid(n);
  IF p_in_registry THEN
    INSERT INTO private.mfa_backend_factors (
      factor_id, user_id, activated_at, activation_challenge_id,
      proof_challenge_id, proof_verified_at, proof_by_backend
    )
    VALUES (pg_temp.fid(n), pg_temp.uid(n),
            CASE WHEN p_activated THEN now() END,
            CASE WHEN p_activated THEN pg_temp.cid(n) END,
            pg_temp.cid(n), now(), p_proof);
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
                    'private.mfa_session_attestations'::regclass, 'private.mfa_first_activations'::regclass)
      AND c.relrowsecurity),
  4,
  'F-63: as quatro tabelas de atestado têm RLS habilitado'
);
SELECT is_empty(
  $$ SELECT t.name, r.role
       FROM (VALUES ('private.mfa_backend_factors'), ('private.mfa_backend_challenges'),
                    ('private.mfa_session_attestations'), ('private.mfa_first_activations')) t (name)
      CROSS JOIN (VALUES ('anon'), ('authenticated'), ('service_role')) r (role)
      WHERE has_table_privilege(r.role, t.name,
                                'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') $$,
  'F-63: anon, authenticated e service_role não têm privilégio algum nas tabelas de atestado'
);
SELECT is_empty(
  $$ SELECT policyname FROM pg_policies
      WHERE schemaname = 'private'
        AND tablename IN ('mfa_backend_factors', 'mfa_backend_challenges', 'mfa_session_attestations',
                          'mfa_first_activations') $$,
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
                    'private.refuse_mfa_attestation(uuid, uuid, text)'::regprocedure,
                    'private.snapshot_mfa_activation()'::regprocedure)
      AND p.prosecdef
      AND 'search_path=""' = ANY (p.proconfig)),
  7,
  'AC-25: as funções do atestado são SECURITY DEFINER com search_path vazio'
);
SELECT is_empty(
  $$ SELECT p.proname, a.grantee::regrole
       FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE p.oid IN ('public.attest_mfa_session(uuid, uuid, uuid, uuid)'::regprocedure,
                      'public.register_backend_totp_factor(uuid, uuid, uuid)'::regprocedure,
                      'public.record_backend_mfa_challenge(uuid, uuid, uuid)'::regprocedure,
                      'public.consume_totp_code(uuid, uuid, bytea)'::regprocedure)
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
                      'private.snapshot_mfa_activation()'::regprocedure,
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
  ARRAY['attested_activated', '1', '0'],
  'F-63, F-72: com tudo certo o atestado é gravado e diz que ATIVOU o fator; as sessões ficam e nada é auditado'
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
  'F-63: atestar de novo a mesma sessão é idempotente, e já não diz que ativou (a ativação é uma vez só)'
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
  ARRAY['not_ceo', '1', '1'],
  'F-63, F-66: quem não é CEO é recusado (not_ceo) e as sessões ficam (não é sinal de ataque)'
);

SELECT pg_temp.arrange(3);
SELECT is(
  pg_temp.attest_with(pg_temp.uid(3), gen_random_uuid(), pg_temp.fid(3), pg_temp.cid(3)),
  ARRAY['session_not_found', '1', '1'],
  'F-63, F-66: uma sessão que não existe é recusada (session_not_found) sem derrubar as outras'
);

SELECT pg_temp.arrange(4);
UPDATE auth.sessions SET aal = 'aal1' WHERE id = pg_temp.uid(4);
SELECT is(
  pg_temp.attest(4),
  ARRAY['session_not_aal2', '1', '1'],
  'F-63, F-66: uma sessão que o Auth não elevou a aal2 é recusada (session_not_aal2) sem revogar'
);

SELECT pg_temp.arrange(5);
SELECT pg_temp.arrange(6);
UPDATE auth.sessions SET factor_id = pg_temp.fid(6) WHERE id = pg_temp.uid(5);
SELECT is(
  pg_temp.attest_with(pg_temp.uid(5), pg_temp.uid(5), pg_temp.fid(6), pg_temp.cid(5)),
  ARRAY['factor_not_found', '1', '1'],
  'F-63, F-66: o fator de OUTRO usuário é recusado (factor_not_found), sem revogar'
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
  ARRAY['factor_not_totp', '1', '1'],
  'F-63, F-66: um fator que não é TOTP é recusado (factor_not_totp), sem revogar'
);

SELECT pg_temp.arrange(8, p_factor_status => 'unverified');
SELECT is(
  pg_temp.attest(8),
  ARRAY['factor_not_verified', '1', '1'],
  'F-63, F-66: um fator não verificado é recusado (factor_not_verified), sem revogar'
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
  ARRAY['challenge_not_verified', '1', '1'],
  'F-63, F-66: um challenge que o Auth não verificou é recusado (challenge_not_verified), sem revogar'
);

SELECT pg_temp.arrange(14, p_verified_ago => interval '121 seconds');
SELECT is(
  pg_temp.attest(14),
  ARRAY['challenge_stale', '1', '1'],
  'F-63, F-66: um challenge verificado há mais de 120 s é recusado (challenge_stale), sem revogar'
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
      jsonb_build_object('reason', 'oracle', 'factor_id', pg_temp.fid(16),
                         'severity', 'alert', 'revoked', true))::text,
  'E-33, F-66, F-68: a auditoria da recusa leva o motivo, o id do fator, a severidade e se revogou (sem PII), em nome de ninguém'
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
SELECT pg_temp.arrange(19, p_proof => false);
SELECT pg_temp.extra_challenge(19, 119, interval '1 day', false);
SELECT is(
  pg_temp.attest(19),
  ARRAY['factor_not_activated_by_backend', '0', '1'],
  'F-61: um fator ativado direto no Auth (challenge verificado de fora, mesmo antigo) nunca é atestado'
);

SELECT pg_temp.arrange(20, p_was_verified => true, p_proof => false);
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
  ARRAY['attested_activated', '1', '0'],
  'F-61, F-72: o verify depois de uma falha do atestado ativa o fator pelo challenge que o ativou e DIZ que ativou (o app derruba as outras sessões)'
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

-- F-67: só um challenge novo e ainda não verificado se registra (ninguém "adota" um challenge que foi
-- verificado direto no Auth, nem um velho)
INSERT INTO auth.mfa_challenges (id, factor_id, created_at, verified_at, ip_address)
VALUES (pg_temp.cid(52), pg_temp.fid(40), now(), now(), '127.0.0.1'),
       (pg_temp.cid(53), pg_temp.fid(40), now() - interval '61 seconds', NULL, '127.0.0.1'),
       (pg_temp.cid(54), pg_temp.fid(40), now() - interval '59 seconds', NULL, '127.0.0.1');
SET LOCAL ROLE service_role;
SELECT throws_ok(
  $$ SELECT public.record_backend_mfa_challenge(pg_temp.uid(40), pg_temp.fid(40), pg_temp.cid(52)) $$,
  'P0001', 'NOT_FOUND', 'F-67: um challenge que já foi verificado não se registra'
);
SELECT throws_ok(
  $$ SELECT public.record_backend_mfa_challenge(pg_temp.uid(40), pg_temp.fid(40), pg_temp.cid(53)) $$,
  'P0001', 'NOT_FOUND', 'F-67: um challenge criado há 61 s não se registra'
);
SELECT lives_ok(
  $$ SELECT public.record_backend_mfa_challenge(pg_temp.uid(40), pg_temp.fid(40), pg_temp.cid(54)) $$,
  'F-67: um challenge criado há 59 s e não verificado se registra'
);
RESET ROLE;
SELECT is(
  (SELECT count(*)::integer FROM private.mfa_backend_challenges
    WHERE challenge_id IN (pg_temp.cid(52), pg_temp.cid(53))),
  0,
  'F-67: os dois recusados não ficaram no registro'
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

-- severidade da auditoria: só os sinais de ataque são `alert` e revogam (F-66, F-68) -----------------------
SELECT is(
  (SELECT e.metadata ->> 'severity' || '/' || (e.metadata ->> 'revoked')
     FROM public.audit_events e
    WHERE e.action = 'auth.mfa_attestation_refused' AND e.resource_id = pg_temp.uid(3)),
  'warning/false',
  'F-66, F-68: uma recusa de corrida é auditada como warning e não revoga'
);

-- F-64: apagar o fator do CEO direto no Auth não reabre o cadastro -----------------------------------------
SELECT pg_temp.arrange(80);
SELECT pg_temp.attest(80);
SELECT is(
  (SELECT count(*)::integer FROM private.mfa_first_activations WHERE user_id = pg_temp.uid(80)),
  1,
  'F-64: a primeira ativação pelo backend grava a marca do usuário'
);
SELECT is(
  (SELECT count(*)::integer FROM pg_constraint
    WHERE conrelid = 'private.mfa_first_activations'::regclass AND contype = 'f'),
  1,
  'F-64: a marca tem uma só FK (auth.users): nenhuma para o fator, para o CASCADE não a apagar'
);
-- o ataque: com uma aal2 obtida direto no Auth, DELETE /factors/{id}
DELETE FROM auth.mfa_factors WHERE id = pg_temp.fid(80);
SELECT is(
  (SELECT (SELECT count(*) FROM private.mfa_backend_factors WHERE user_id = pg_temp.uid(80))::text
          || '/' || (SELECT count(*) FROM private.mfa_session_attestations WHERE user_id = pg_temp.uid(80))::text
          || '/' || (SELECT count(*) FROM private.mfa_first_activations WHERE user_id = pg_temp.uid(80))::text),
  '0/0/1',
  'F-64: apagar o fator leva o registro e os atestados, mas NÃO a marca de primeira ativação'
);
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
VALUES (pg_temp.fid(81), pg_temp.uid(80), 'do atacante', 'totp', 'unverified', now(), now(), 'TESTSECRET');
SET LOCAL ROLE service_role;
SELECT is(
  public.register_backend_totp_factor(pg_temp.uid(80), pg_temp.fid(81), pg_temp.uid(80)),
  'factor_reenrolled',
  'F-64: o enroll pelo backend depois do fator apagado é recusado (factor_reenrolled)'
);
RESET ROLE;
SELECT is(
  (SELECT count(*)::integer FROM private.mfa_backend_factors WHERE factor_id = pg_temp.fid(81)),
  0,
  'F-64: o fator do atacante não foi cadastrado'
);
SELECT is(
  (SELECT count(*)::integer FROM auth.sessions WHERE user_id = pg_temp.uid(80)),
  0,
  'F-64: a recusa apagou todas as sessões do usuário'
);
SELECT is(
  (SELECT e.metadata
     FROM public.audit_events e
    WHERE e.action = 'auth.mfa_attestation_refused' AND e.resource_id = pg_temp.uid(80)),
  jsonb_build_object('reason', 'factor_reenrolled', 'factor_id', pg_temp.fid(81),
                     'severity', 'alert', 'revoked', true),
  'F-64: a recusa é auditada como alerta'
);
-- só o reset do operador reabre o cadastro
SELECT tests.reset_first_activation(pg_temp.uid(80));
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal)
VALUES (pg_temp.uid(80), pg_temp.uid(80), now(), now(), 'aal1');
SET LOCAL ROLE service_role;
SELECT is(
  public.register_backend_totp_factor(pg_temp.uid(80), pg_temp.fid(81), pg_temp.uid(80)),
  'registered',
  'F-64: depois do reset do operador (a marca apagada) o cadastro volta a funcionar'
);
RESET ROLE;

-- F-64 no atestado: um fator cadastrado ANTES da marca, mas ativado depois dela, também é recusado
SELECT pg_temp.arrange(82);
INSERT INTO private.mfa_first_activations (user_id, factor_id)
VALUES (pg_temp.uid(82), gen_random_uuid());
SELECT is(
  pg_temp.attest(82),
  ARRAY['factor_reenrolled', '0', '1'],
  'F-64: a ativação de um fator novo, com a marca do usuário gravada, é recusada no atestado (factor_reenrolled) e revoga'
);

-- F-71: a prova da ativação não depende de o Auth guardar as linhas de challenge -------------------------------
SELECT ok(
  (SELECT bf.proof_verified_at IS NOT NULL AND bf.proof_by_backend
     FROM private.mfa_backend_factors bf WHERE bf.factor_id = pg_temp.fid(1)),
  'F-71, F-73: o registro do fator guarda a prova da ativação (instante e origem), não o Auth'
);
DELETE FROM auth.mfa_challenges WHERE id = pg_temp.cid(1);
SELECT is(
  (SELECT count(*)::integer FROM private.mfa_backend_challenges WHERE challenge_id = pg_temp.cid(1)),
  1,
  'F-71: o Auth apagar o challenge não apaga o registro do backend (sem CASCADE)'
);
SELECT ok(
  (SELECT bf.activated_at IS NOT NULL FROM private.mfa_backend_factors bf WHERE bf.factor_id = pg_temp.fid(1)),
  'F-71: nem a ativação do fator'
);
-- a derivação da ativação usa a cópia quando o Auth já não tem o challenge que ativou
SELECT pg_temp.arrange(83);                                                    -- cid(83): o que ativou
SELECT pg_temp.extra_challenge(83, 283, interval '5 seconds', true, true);    -- o verify seguinte
DELETE FROM auth.mfa_challenges WHERE id = pg_temp.cid(83);
SELECT is(
  pg_temp.attest_with(pg_temp.uid(83), pg_temp.uid(83), pg_temp.fid(83), pg_temp.cid(283)),
  ARRAY['attested_activated', '1', '0'],
  'F-71, F-73: a ativação vem da prova do registro quando o Auth já apagou o challenge que ativou'
);

-- F-67: um challenge atesta uma sessão só; a sessão tem de ter sido elevada pelo fator ---------------------------
SELECT pg_temp.arrange(84);
SELECT pg_temp.attest(84);
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal, factor_id)
VALUES (pg_temp.sid(84), pg_temp.uid(84), now(), now(), 'aal2', pg_temp.fid(84));
SELECT is(
  pg_temp.attest_with(pg_temp.uid(84), pg_temp.sid(84), pg_temp.fid(84), pg_temp.cid(84)),
  ARRAY['challenge_reused', '0', '1'],
  'F-67: o challenge que já atestou uma sessão não atesta outra (challenge_reused) e revoga'
);
SELECT pg_temp.arrange(85);
SELECT pg_temp.attest(85);
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal, factor_id)
VALUES (pg_temp.sid(85), pg_temp.uid(85), now(), now(), 'aal2', pg_temp.fid(85));
SELECT throws_ok(
  $$ INSERT INTO private.mfa_session_attestations (session_id, user_id, factor_id, challenge_id)
     VALUES (pg_temp.sid(85), pg_temp.uid(85), pg_temp.fid(85), pg_temp.cid(85)) $$,
  '23505', NULL, 'F-67: challenge_id é UNIQUE na tabela de atestados'
);
SELECT pg_temp.arrange(86);
UPDATE auth.sessions SET factor_id = NULL WHERE id = pg_temp.uid(86);
SELECT is(
  pg_temp.attest(86),
  ARRAY['session_factor_mismatch', '0', '1'],
  'F-67: uma sessão que o Auth não elevou por este fator é recusada (session_factor_mismatch) e revoga'
);

-- um CEO desativado ---------------------------------------------------------------------------------------------
SELECT pg_temp.arrange(87);
UPDATE public.profiles SET disabled_at = now() WHERE id = pg_temp.uid(87);
SELECT is(
  pg_temp.attest(87),
  ARRAY['not_ceo', '1', '1'],
  'F-67: um CEO desativado não recebe atestado (not_ceo)'
);
SELECT tests.create_user(pg_temp.uid(88), 'ceo');
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
VALUES (pg_temp.fid(88), pg_temp.uid(88), 'candidato', 'totp', 'unverified', now(), now(), 'TESTSECRET');
UPDATE public.profiles SET disabled_at = now() WHERE id = pg_temp.uid(88);
SET LOCAL ROLE service_role;
SELECT throws_ok(
  $$ SELECT public.register_backend_totp_factor(pg_temp.uid(88), pg_temp.fid(88), pg_temp.uid(88)) $$,
  'P0001', 'NOT_FOUND', 'F-67: um CEO desativado não cadastra fator (NOT_FOUND)'
);
RESET ROLE;

-- todo objeto de CEO nega a aal2 SEM atestado (p_attested => false) ---------------------------------------------------
-- c9: CEO com fator verificado que NUNCA é atestado; o resto do que se lê vem de dados de outros usuários
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c9', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c9');
INSERT INTO public.processes (id, client_id, title)
VALUES ('00000000-0000-4000-8000-0000000d0001', '00000000-0000-4000-8000-00000000000a', 'Processo do teste F-63');
INSERT INTO public.process_stages (id, process_id, position, name, status, started_at, completed_at) VALUES
  ('00000000-0000-4000-8000-0000000d0002', '00000000-0000-4000-8000-0000000d0001', 1, 'Fase 1', 'completed', now() - interval '2 days', now() - interval '1 day'),
  ('00000000-0000-4000-8000-0000000d0003', '00000000-0000-4000-8000-0000000d0001', 2, 'Fase 2', 'in_progress', now() - interval '1 day', NULL);
INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)
VALUES ('00000000-0000-4000-8000-0000000d0002', '00000000-0000-4000-8000-0000000d0001',
        '00000000-0000-4000-8000-0000000000c1');
INSERT INTO public.audit_events (actor_id, actor_role, action, resource_type, resource_id)
VALUES ('00000000-0000-4000-8000-0000000000c1', 'ceo', 'client.created', 'client',
        '00000000-0000-4000-8000-00000000000a');

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c9', 'aal2', false);
SELECT throws_ok(
  $$ SELECT public.update_client('00000000-0000-4000-8000-00000000000a', 'Renomeado sem atestado') $$,
  '42501', 'FORBIDDEN', 'F-63: aal2 sem atestado não executa update_client'
);
SELECT throws_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000a1') $$,
  '42501', 'FORBIDDEN', 'F-63: aal2 sem atestado não executa require_password_change'
);
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a1', 'Renomeado sem atestado') $$,
  '42501', 'FORBIDDEN', 'F-63: aal2 sem atestado não executa set_account_display_name'
);
SELECT throws_ok(
  $$ SELECT public.record_account_provisioned('00000000-0000-4000-8000-0000000000a1') $$,
  '42501', 'FORBIDDEN', 'F-63: aal2 sem atestado não executa record_account_provisioned'
);
SELECT is(
  (SELECT count(*)::integer FROM public.profiles WHERE id <> '00000000-0000-4000-8000-0000000000c9'),
  0,
  'F-63: a policy de CEO de profiles não entrega os perfis de outros a uma aal2 sem atestado'
);
SELECT is((SELECT count(*)::integer FROM public.audit_events), 0, 'F-63: a policy de CEO de audit_events nega');
SELECT is((SELECT count(*)::integer FROM public.processes), 0, 'F-63: a policy de CEO de processes nega');
SELECT is((SELECT count(*)::integer FROM public.process_stages), 0, 'F-63: a policy de CEO de process_stages nega');
SELECT is((SELECT count(*)::integer FROM public.stage_approvals), 0, 'F-63: a policy de CEO de stage_approvals nega');
SELECT is(
  (SELECT count(*)::integer FROM public.default_stage_template), 0,
  'F-63: a policy de CEO de default_stage_template nega'
);
SELECT tests.clear_authentication();

-- o controle positivo: a mesma sessão, atestada, lê tudo isso
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c9', 'aal2');
SELECT ok((SELECT count(*) FROM public.profiles WHERE id <> '00000000-0000-4000-8000-0000000000c9') > 0,
          'F-63 (controle): atestado, o CEO lê os perfis de outros');
SELECT ok((SELECT count(*) FROM public.audit_events) > 0, 'F-63 (controle): atestado, o CEO lê a auditoria');
SELECT ok((SELECT count(*) FROM public.processes) > 0, 'F-63 (controle): atestado, o CEO lê os processos');
SELECT ok((SELECT count(*) FROM public.process_stages) > 0, 'F-63 (controle): atestado, o CEO lê as fases');
SELECT ok((SELECT count(*) FROM public.stage_approvals) > 0, 'F-63 (controle): atestado, o CEO lê as aprovações');
SELECT lives_ok(
  $$ SELECT public.update_client('00000000-0000-4000-8000-00000000000a', 'Renomeado com atestado') $$,
  'F-63 (controle): atestado, o CEO executa update_client'
);
SELECT lives_ok(
  $$ SELECT public.record_account_provisioned('00000000-0000-4000-8000-0000000000a1') $$,
  'F-63 (controle): atestado, o CEO executa record_account_provisioned'
);
SELECT lives_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a1', 'Renomeado com atestado') $$,
  'F-63 (controle): atestado, o CEO executa set_account_display_name'
);
SELECT ok(
  (SELECT count(*) FROM public.default_stage_template) > 0,
  'F-63 (controle): atestado, o CEO lê o template de fases'
);
-- por último: apaga as sessões do alvo
SELECT lives_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000a1') $$,
  'F-63 (controle): atestado, o CEO executa require_password_change'
);
SELECT tests.clear_authentication();

-- F-73: o gatilho de ativação grava a marca e a prova NA TRANSAÇÃO em que o Auth ativa o fator --------------
SELECT is(
  (SELECT t.tgenabled::text FROM pg_trigger t
    WHERE t.tgrelid = 'auth.mfa_factors'::regclass AND t.tgname = 'on_mfa_factor_verified'),
  'O',
  'F-73: o gatilho on_mfa_factor_verified existe em auth.mfa_factors e está habilitado'
);
-- como o Auth faz: o challenge vira verificado e, na mesma transação, o fator
SELECT tests.create_user(pg_temp.uid(100), 'ceo');
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
VALUES (pg_temp.fid(100), pg_temp.uid(100), 'candidato', 'totp', 'unverified', now(), now(), 'TESTSECRET');
INSERT INTO private.mfa_backend_factors (factor_id, user_id) VALUES (pg_temp.fid(100), pg_temp.uid(100));
INSERT INTO auth.mfa_challenges (id, factor_id, created_at, ip_address)
VALUES (pg_temp.cid(100), pg_temp.fid(100), now(), '127.0.0.1');
INSERT INTO private.mfa_backend_challenges (challenge_id, factor_id, user_id, factor_was_verified)
VALUES (pg_temp.cid(100), pg_temp.fid(100), pg_temp.uid(100), false);
SELECT is(
  (SELECT count(*)::integer FROM private.mfa_first_activations WHERE user_id = pg_temp.uid(100)),
  0,
  'F-73: antes da ativação não há marca'
);
UPDATE auth.mfa_challenges SET verified_at = now() WHERE id = pg_temp.cid(100);
UPDATE auth.mfa_factors SET status = 'verified' WHERE id = pg_temp.fid(100);
SELECT is(
  (SELECT row(bf.proof_challenge_id, bf.proof_by_backend, bf.proof_verified_at IS NOT NULL)::text
     FROM private.mfa_backend_factors bf WHERE bf.factor_id = pg_temp.fid(100)),
  row(pg_temp.cid(100), true, true)::text,
  'F-73: o gatilho grava a prova no registro do fator: o challenge do backend que ativou, o instante e a origem'
);
SELECT is(
  (SELECT m.factor_id FROM private.mfa_first_activations m WHERE m.user_id = pg_temp.uid(100)),
  pg_temp.fid(100),
  'F-73, F-64: e a marca da primeira ativação do usuário, com o fator que a criou, ANTES de qualquer atestado'
);
SELECT ok(
  (SELECT bf.activated_at IS NULL FROM private.mfa_backend_factors bf WHERE bf.factor_id = pg_temp.fid(100)),
  'F-73: o gatilho não ativa: o `activated_at` só o atestado grava'
);
-- o Auth apaga o challenge que ativou (limpeza do hospedado): a ativação vem da prova do registro
DELETE FROM auth.mfa_challenges WHERE id = pg_temp.cid(100);
INSERT INTO auth.mfa_challenges (id, factor_id, created_at, verified_at, ip_address)
VALUES (pg_temp.cid(101), pg_temp.fid(100), now(), now(), '127.0.0.1');
INSERT INTO private.mfa_backend_challenges (challenge_id, factor_id, user_id, factor_was_verified)
VALUES (pg_temp.cid(101), pg_temp.fid(100), pg_temp.uid(100), true);
UPDATE auth.sessions SET aal = 'aal2', factor_id = pg_temp.fid(100) WHERE id = pg_temp.uid(100);
SELECT is(
  pg_temp.attest_with(pg_temp.uid(100), pg_temp.uid(100), pg_temp.fid(100), pg_temp.cid(101)),
  ARRAY['attested_activated', '1', '0'],
  'F-73, F-71: o atestado ativa só com as tabelas do backend: o Auth já não tem o challenge que ativou'
);

-- a janela do F-64 fica fechada mesmo que o atestado nunca aconteça: o fator é apagado e outro cadastrado
SELECT tests.create_user(pg_temp.uid(102), 'ceo');
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
VALUES (pg_temp.fid(102), pg_temp.uid(102), 'candidato', 'totp', 'unverified', now(), now(), 'TESTSECRET');
INSERT INTO private.mfa_backend_factors (factor_id, user_id) VALUES (pg_temp.fid(102), pg_temp.uid(102));
INSERT INTO auth.mfa_challenges (id, factor_id, created_at, ip_address)
VALUES (pg_temp.cid(102), pg_temp.fid(102), now(), '127.0.0.1');
INSERT INTO private.mfa_backend_challenges (challenge_id, factor_id, user_id, factor_was_verified)
VALUES (pg_temp.cid(102), pg_temp.fid(102), pg_temp.uid(102), false);
UPDATE auth.mfa_challenges SET verified_at = now() WHERE id = pg_temp.cid(102);
UPDATE auth.mfa_factors SET status = 'verified' WHERE id = pg_temp.fid(102);
-- (o atestado falhou: 503, session_not_found forçado... nada foi atestado) e o atacante, com uma aal2,
-- apaga o fator e tenta cadastrar o dele
DELETE FROM auth.mfa_factors WHERE id = pg_temp.fid(102);
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
VALUES (pg_temp.fid(103), pg_temp.uid(102), 'do atacante', 'totp', 'unverified', now(), now(), 'TESTSECRET');
SET LOCAL ROLE service_role;
SELECT is(
  public.register_backend_totp_factor(pg_temp.uid(102), pg_temp.fid(103), pg_temp.uid(102)),
  'factor_reenrolled',
  'F-73, F-64: sem nenhum atestado, só pelo gatilho, o cadastro de um fator novo depois do apagado é recusado'
);
RESET ROLE;

-- um fator que o backend NÃO cadastrou (plantado) não passa pelo gatilho
SELECT tests.create_user(pg_temp.uid(104), 'ceo');
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
VALUES (pg_temp.fid(104), pg_temp.uid(104), 'plantado', 'totp', 'unverified', now(), now(), 'TESTSECRET');
UPDATE auth.mfa_factors SET status = 'verified' WHERE id = pg_temp.fid(104);
SELECT is(
  (SELECT count(*)::integer FROM private.mfa_first_activations WHERE user_id = pg_temp.uid(104)),
  0,
  'F-73: um fator plantado direto no Auth não grava a marca (ele nunca é atestado, F-61)'
);

-- ativação por outro caminho (um chute certo direto no Auth no candidato do backend): marca sim, prova não
SELECT tests.create_user(pg_temp.uid(105), 'ceo');
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
VALUES (pg_temp.fid(105), pg_temp.uid(105), 'candidato', 'totp', 'unverified', now(), now(), 'TESTSECRET');
INSERT INTO private.mfa_backend_factors (factor_id, user_id) VALUES (pg_temp.fid(105), pg_temp.uid(105));
INSERT INTO auth.mfa_challenges (id, factor_id, created_at, verified_at, ip_address)
VALUES (pg_temp.cid(105), pg_temp.fid(105), now(), now(), '127.0.0.1'),       -- do backend
       (pg_temp.cid(205), pg_temp.fid(105), now(), now() - interval '1 second', '127.0.0.1'); -- direto no Auth
INSERT INTO private.mfa_backend_challenges (challenge_id, factor_id, user_id, factor_was_verified)
VALUES (pg_temp.cid(105), pg_temp.fid(105), pg_temp.uid(105), false);
UPDATE auth.mfa_factors SET status = 'verified' WHERE id = pg_temp.fid(105);
SELECT is(
  (SELECT row(bf.proof_by_backend, m.factor_id)::text
     FROM private.mfa_backend_factors bf
     JOIN private.mfa_first_activations m ON m.user_id = bf.user_id
    WHERE bf.factor_id = pg_temp.fid(105)),
  row(false, pg_temp.fid(105))::text,
  'F-73: com um challenge verificado de fora do backend, a prova diz que NÃO foi do backend, e a marca é gravada mesmo assim (só bloqueia)'
);
UPDATE auth.sessions SET aal = 'aal2', factor_id = pg_temp.fid(105) WHERE id = pg_temp.uid(105);
SELECT is(
  pg_temp.attest(105),
  ARRAY['oracle', '0', '1'],
  'F-73: o challenge de fora, dentro da janela, também é o oráculo'
);

-- a prova é gravada uma vez só: virar `verified` de novo não a troca
SELECT tests.create_user(pg_temp.uid(106), 'ceo');
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
VALUES (pg_temp.fid(106), pg_temp.uid(106), 'candidato', 'totp', 'unverified', now(), now(), 'TESTSECRET');
INSERT INTO private.mfa_backend_factors (factor_id, user_id) VALUES (pg_temp.fid(106), pg_temp.uid(106));
INSERT INTO auth.mfa_challenges (id, factor_id, created_at, verified_at, ip_address)
VALUES (pg_temp.cid(106), pg_temp.fid(106), now(), now(), '127.0.0.1');
INSERT INTO private.mfa_backend_challenges (challenge_id, factor_id, user_id, factor_was_verified)
VALUES (pg_temp.cid(106), pg_temp.fid(106), pg_temp.uid(106), false);
UPDATE auth.mfa_factors SET status = 'verified' WHERE id = pg_temp.fid(106);
INSERT INTO auth.mfa_challenges (id, factor_id, created_at, verified_at, ip_address)
VALUES (pg_temp.cid(206), pg_temp.fid(106), now(), now() + interval '1 second', '127.0.0.1');
UPDATE auth.mfa_factors SET status = 'unverified' WHERE id = pg_temp.fid(106);
UPDATE auth.mfa_factors SET status = 'verified' WHERE id = pg_temp.fid(106);
SELECT is(
  (SELECT row(bf.proof_challenge_id, bf.proof_by_backend)::text
     FROM private.mfa_backend_factors bf WHERE bf.factor_id = pg_temp.fid(106)),
  row(pg_temp.cid(106), true)::text,
  'F-73: a prova é gravada na primeira ativação e não muda quando o fator vira verified de novo'
);

-- F-74: o atestado que ativa apaga as outras sessões do usuário, dentro da transação ---------------------------------
SELECT pg_temp.arrange(110);
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal, factor_id) VALUES
  (pg_temp.sid(110), pg_temp.uid(110), now(), now(), 'aal1', NULL),
  (pg_temp.sid(210), pg_temp.uid(110), now(), now(), 'aal2', pg_temp.fid(110));
SELECT tests.create_user(pg_temp.uid(111), 'ceo');
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal)
VALUES (pg_temp.sid(111), pg_temp.uid(111), now(), now(), 'aal1');
SELECT is(
  pg_temp.attest(110),
  ARRAY['attested_activated', '1', '0'],
  'F-74: o atestado que ATIVA o fator apaga as outras sessões do usuário (a aal1 e a aal2) e mantém a atestada'
);
SELECT is(
  (SELECT array_agg(s.id) FROM auth.sessions s WHERE s.user_id = pg_temp.uid(110)),
  ARRAY[pg_temp.uid(110)],
  'F-74: sobra só a sessão atestada'
);
SELECT is(
  (SELECT count(*)::integer FROM auth.sessions WHERE user_id = pg_temp.uid(111)),
  2,
  'F-74: as duas sessões de outro usuário não são tocadas'
);
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal, factor_id)
VALUES (pg_temp.sid(310), pg_temp.uid(110), now(), now(), 'aal2', pg_temp.fid(110));
SELECT is(
  pg_temp.attest(110),
  ARRAY['attested', '2', '0'],
  'F-74: um atestado que NÃO ativa (o fator já estava ativado) não derruba as outras sessões'
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
