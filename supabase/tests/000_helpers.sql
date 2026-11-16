-- Helpers dos testes pgTAP (só banco local e CI; nunca vai para migration).
-- Roda primeiro (prefixo 000) e SEM rollback, para o schema `tests` ficar disponível aos demais
-- arquivos. Cada arquivo *.test.sql roda em BEGIN … ROLLBACK e usa UUIDs fixos.
--
--   tests.create_user(id, role, client_id DEFAULT NULL, display_name DEFAULT NULL)
--       cria o usuário em auth.users com raw_app_meta_data (o trigger cria o perfil) e uma
--       sessão em auth.sessions cujo id é o próprio id do usuário; devolve o id.
--   tests.insert_auth_user(id, app_meta jsonb, user_meta jsonb DEFAULT '{}')
--       só o INSERT em auth.users, para testar o trigger com metadados arbitrários.
--   tests.verify_totp(user_id)      cria um fator TOTP verificado (has_verified_totp = true).
--   tests.attest_session(user_id, session_id DEFAULT NULL) devolve boolean
--       atesta a sessão (session_id; por padrão a do próprio usuário) como o backend faria: eleva a
--       sessão a aal2, registra o fator TOTP verificado do CEO como cadastrado e ativado pelo
--       backend, registra e verifica um challenge do backend e chama a função REAL
--       public.attest_mfa_session (levanta erro se ela recusar). false, sem fazer nada, quando não há
--       o que atestar: usuário que não é CEO ou está desativado, sem fator TOTP verificado ou sem a sessão.
--   tests.reset_first_activation(user_id)
--       apaga a marca de primeira ativação (o reset de MFA do operador, E-25): reabre o cadastro de fator.
--   tests.authenticate_as(user_id, aal DEFAULT 'aal1', attested DEFAULT true, session_id DEFAULT NULL)
--       role = authenticated e request.jwt.claims com sub, aal e session_id (por padrão = user_id). Com aal2 e
--       attested, atesta a sessão antes (tests.attest_session): é o CEO que o backend elevou. Com
--       attested = false, o claim aal2 fica sem atestado: é o que se obtém direto no Auth.
--   tests.set_request_id(id)       simula o header x-request-id enviado pelo PostgREST.
--   tests.clear_authentication()   volta ao papel da sessão (postgres) e limpa os claims.

SELECT plan(1);

CREATE SCHEMA IF NOT EXISTS tests;
GRANT USAGE ON SCHEMA tests TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION tests.insert_auth_user(
  p_id        uuid,
  p_app_meta  jsonb,
  p_user_meta jsonb DEFAULT '{}'::jsonb
)
RETURNS uuid
LANGUAGE plpgsql
AS $$
BEGIN
  -- O trigger de perfil é um CONSTRAINT TRIGGER adiado até o COMMIT (migration
  -- profile_trigger_commit_time_check); como cada teste roda em BEGIN … ROLLBACK, o INSERT
  -- precisa executá-lo na hora para o perfil existir e os dados inválidos falharem aqui.
  SET CONSTRAINTS ALL IMMEDIATE;
  INSERT INTO auth.users (
    id, instance_id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at
  )
  VALUES (
    p_id, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated',
    p_id::text || '@test.local', '', now(), p_app_meta, p_user_meta, now(), now()
  );
  RETURN p_id;
END;
$$;

CREATE OR REPLACE FUNCTION tests.create_user(
  p_id           uuid,
  p_role         text,
  p_client_id    uuid DEFAULT NULL,
  p_display_name text DEFAULT NULL
)
RETURNS uuid
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM tests.insert_auth_user(
    p_id,
    jsonb_strip_nulls(jsonb_build_object(
      'role', p_role,
      'client_id', p_client_id,
      'display_name', coalesce(p_display_name, 'Usuário ' || left(p_id::text, 8))
    ))
  );
  INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal)
  VALUES (p_id, p_id, now(), now(), 'aal1');
  RETURN p_id;
END;
$$;

CREATE OR REPLACE FUNCTION tests.verify_totp(p_user_id uuid)
RETURNS void
LANGUAGE sql
AS $$
  INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
  VALUES (gen_random_uuid(), p_user_id, 'test-totp', 'totp', 'verified', now(), now(), 'TESTSECRET');
$$;

-- Atesta uma sessão pelo caminho REAL (public.attest_mfa_session). SECURITY DEFINER: roda como o dono
-- dos helpers qualquer que seja o papel da sessão de teste no momento da chamada.
CREATE OR REPLACE FUNCTION tests.attest_session(p_user_id uuid, p_session_id uuid DEFAULT NULL)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_session_id   uuid := coalesce(p_session_id, p_user_id);
  v_factor_id    uuid;
  v_activated    boolean;
  v_challenge_id uuid := gen_random_uuid();
  v_result       text;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.profiles p
     WHERE p.id = p_user_id AND p.role = 'ceo' AND p.disabled_at IS NULL
  ) THEN
    RETURN false;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM auth.sessions s WHERE s.id = v_session_id AND s.user_id = p_user_id) THEN
    RETURN false;
  END IF;
  SELECT f.id
    INTO v_factor_id
    FROM auth.mfa_factors f
   WHERE f.user_id = p_user_id
     AND f.factor_type = 'totp'
     AND f.status = 'verified'
   ORDER BY f.created_at, f.id
   LIMIT 1;
  IF NOT FOUND THEN
    RETURN false;
  END IF;

  UPDATE auth.sessions SET aal = 'aal2', factor_id = v_factor_id WHERE id = v_session_id;

  INSERT INTO private.mfa_backend_factors (factor_id, user_id, enrolled_session_id)
  VALUES (v_factor_id, p_user_id, v_session_id)
  ON CONFLICT (factor_id) DO NOTHING;
  SELECT bf.activated_at IS NOT NULL
    INTO v_activated
    FROM private.mfa_backend_factors bf
   WHERE bf.factor_id = v_factor_id;

  INSERT INTO auth.mfa_challenges (id, factor_id, created_at, verified_at, ip_address)
  VALUES (v_challenge_id, v_factor_id, now(), now(), '127.0.0.1');
  INSERT INTO private.mfa_backend_challenges (challenge_id, factor_id, user_id, factor_was_verified)
  VALUES (v_challenge_id, v_factor_id, p_user_id, v_activated);

  v_result := public.attest_mfa_session(p_user_id, v_session_id, v_factor_id, v_challenge_id);
  IF v_result NOT IN ('attested', 'attested_activated') THEN
    RAISE EXCEPTION 'tests.attest_session: a função recusou o atestado (%)', v_result;
  END IF;
  RETURN true;
END;
$$;

-- Simula o reset de MFA do operador (E-25, Onda 11): apaga a marca de primeira ativação, a única coisa
-- que reabre o cadastro e a ativação de um fator novo depois que o primeiro foi ativado (F-64).
CREATE OR REPLACE FUNCTION tests.reset_first_activation(p_user_id uuid)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
  DELETE FROM private.mfa_first_activations WHERE user_id = p_user_id;
$$;

CREATE OR REPLACE FUNCTION tests.authenticate_as(
  p_user_id    uuid,
  p_aal        text DEFAULT 'aal1',
  p_attested   boolean DEFAULT true,
  p_session_id uuid DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  IF p_aal = 'aal2' AND p_attested THEN
    PERFORM tests.attest_session(p_user_id, p_session_id);
  END IF;
  PERFORM set_config(
    'request.jwt.claims',
    json_build_object(
      'sub', p_user_id, 'role', 'authenticated', 'aal', p_aal,
      'session_id', coalesce(p_session_id, p_user_id)
    )::text,
    true
  );
  PERFORM set_config('role', 'authenticated', true);
END;
$$;

CREATE OR REPLACE FUNCTION tests.set_request_id(p_request_id text)
RETURNS void
LANGUAGE sql
AS $$
  SELECT set_config('request.headers', json_build_object('x-request-id', p_request_id)::text, true);
$$;

CREATE OR REPLACE FUNCTION tests.clear_authentication()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM set_config('request.jwt.claims', '', true);
  RESET ROLE;
END;
$$;

GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA tests TO anon, authenticated, service_role;

SELECT ok(true, 'helpers de teste carregados');
SELECT * FROM finish();
