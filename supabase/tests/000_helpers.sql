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
--   tests.authenticate_as(user_id, aal DEFAULT 'aal1')
--       role = authenticated e request.jwt.claims com sub, aal e session_id (= user_id).
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

CREATE OR REPLACE FUNCTION tests.authenticate_as(p_user_id uuid, p_aal text DEFAULT 'aal1')
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM set_config(
    'request.jwt.claims',
    json_build_object('sub', p_user_id, 'role', 'authenticated', 'aal', p_aal, 'session_id', p_user_id)::text,
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
