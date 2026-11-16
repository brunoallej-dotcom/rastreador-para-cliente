-- Trigger private.handle_new_auth_user como CONSTRAINT TRIGGER adiado (correção da Onda 2 feita na
-- Onda 3): o GoTrue faz INSERT em auth.users com app_metadata sem papel e grava o app_metadata
-- recebido por UPDATE, na mesma transação (`auth.admin.createUser`). O perfil tem de nascer do
-- estado FINAL da linha, no COMMIT, e continuar fail closed (AC-31, E-18).
--
-- `tests.create_gotrue_user` reproduz a sequência do GoTrue e termina com SET CONSTRAINTS ALL IMMEDIATE,
-- que executa o trigger como o COMMIT faria.
BEGIN;
SELECT plan(15);

INSERT INTO public.clients (id, name, archived_at) VALUES
  ('00000000-0000-4000-8000-00000000000a', 'Cliente A', NULL),
  ('00000000-0000-4000-8000-00000000000f', 'Cliente Arquivado', now());

CREATE FUNCTION pg_temp.create_gotrue_user(p_id uuid, p_final_app_meta jsonb, p_user_meta jsonb DEFAULT '{}')
RETURNS uuid
LANGUAGE plpgsql
AS $$
BEGIN
  SET CONSTRAINTS ALL DEFERRED;
  -- 1. INSERT como o GoTrue faz: só provider/providers, senha já definida
  INSERT INTO auth.users (
    id, instance_id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at
  )
  VALUES (
    p_id, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated',
    p_id::text || '@test.local', 'temporary-hash-1', now(),
    '{"provider":"email","providers":["email"]}', p_user_meta, now(), now()
  );
  -- 2. UPDATE com o app_metadata recebido
  IF p_final_app_meta IS NOT NULL THEN
    UPDATE auth.users
       SET raw_app_meta_data = raw_app_meta_data || p_final_app_meta
     WHERE id = p_id;
  END IF;
  -- 3. COMMIT: os triggers adiados rodam
  SET CONSTRAINTS ALL IMMEDIATE;
  RETURN p_id;
END;
$$;

-- AC-31: o perfil nasce do app_metadata gravado DEPOIS do INSERT ---------------------------------------
SELECT lives_ok(
  $$ SELECT pg_temp.create_gotrue_user(
       '00000000-0000-4000-8000-0000000000b1',
       '{"role":"client","client_id":"00000000-0000-4000-8000-00000000000a","display_name":"Maria Admin API"}'
     ) $$,
  'AC-31: createUser do GoTrue (INSERT e depois UPDATE do app_metadata) cria o usuário'
);
SELECT results_eq(
  $$ SELECT role::text, client_id, display_name, must_change_password
       FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000b1' $$,
  $$ VALUES ('client', '00000000-0000-4000-8000-00000000000a'::uuid, 'Maria Admin API', true) $$,
  'AC-31: o perfil sai do estado final de raw_app_meta_data, com must_change_password = true'
);
SELECT is(
  (SELECT b.hash_digest = extensions.digest('temporary-hash-1', 'sha256')
     FROM private.password_baselines b WHERE b.user_id = '00000000-0000-4000-8000-0000000000b1'),
  true,
  'SEC-10: a linha de base da senha é gravada com o hash que o usuário tinha no COMMIT'
);

SELECT lives_ok(
  $$ SELECT pg_temp.create_gotrue_user(
       '00000000-0000-4000-8000-0000000000b2', '{"role":"ceo","display_name":"CEO Admin API"}'
     ) $$,
  'AC-31: o mesmo vale para um CEO'
);
SELECT results_eq(
  $$ SELECT role::text, client_id FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000b2' $$,
  $$ VALUES ('ceo', NULL::uuid) $$,
  'AC-31: o perfil do CEO nasce sem client_id'
);

-- AC-31: fail closed no COMMIT ---------------------------------------------------------------------------
SELECT throws_ok(
  $$ SELECT pg_temp.create_gotrue_user('00000000-0000-4000-8000-0000000000e1', NULL) $$,
  'P0001', 'INVALID_INPUT', 'AC-31: sem app_metadata.role nenhum UPDATE vem e o COMMIT falha'
);
SELECT throws_ok(
  $$ SELECT pg_temp.create_gotrue_user('00000000-0000-4000-8000-0000000000e2', '{"role":"admin","display_name":"X"}') $$,
  'P0001', 'INVALID_INPUT', 'AC-31: papel desconhecido no UPDATE derruba o COMMIT'
);
SELECT throws_ok(
  $$ SELECT pg_temp.create_gotrue_user(
       '00000000-0000-4000-8000-0000000000e3', '{"display_name":"X"}', '{"role":"ceo","display_name":"Só no User"}'
     ) $$,
  'P0001', 'INVALID_INPUT', 'AC-31: user_metadata.role = ceo continua ignorado: sem app_metadata.role o COMMIT falha'
);
SELECT throws_ok(
  $$ SELECT pg_temp.create_gotrue_user(
       '00000000-0000-4000-8000-0000000000e4',
       '{"role":"client","client_id":"00000000-0000-4000-8000-00000000000f","display_name":"X"}'
     ) $$,
  'P0001', 'CLIENT_ARCHIVED', 'AC-31: cliente arquivado derruba o COMMIT'
);
SELECT is_empty(
  $$ SELECT id FROM auth.users WHERE id::text LIKE '00000000-0000-4000-8000-0000000000e%' $$,
  'AC-31: nenhum dos COMMITs que falharam deixou usuário em auth.users'
);
SELECT is_empty(
  $$ SELECT id FROM public.profiles WHERE id::text LIKE '00000000-0000-4000-8000-0000000000e%' $$,
  'AC-31: nenhum dos COMMITs que falharam deixou perfil'
);

-- Usuário apagado antes do COMMIT: nada a provisionar ---------------------------------------------------
SELECT lives_ok(
  $$ DO $body$
     BEGIN
       SET CONSTRAINTS ALL DEFERRED;
       INSERT INTO auth.users (id, instance_id, aud, role, email, encrypted_password, raw_app_meta_data, created_at, updated_at)
       VALUES ('00000000-0000-4000-8000-0000000000f1', '00000000-0000-0000-0000-000000000000', 'authenticated',
               'authenticated', 'f1@test.local', 'x', '{"provider":"email"}', now(), now());
       DELETE FROM auth.users WHERE id = '00000000-0000-4000-8000-0000000000f1';
       SET CONSTRAINTS ALL IMMEDIATE;
     END
     $body$ $$,
  'um usuário criado e apagado na mesma transação não derruba o COMMIT'
);

-- E-18: o limite de 10 logins vale no COMMIT (a conta inclui o login b1 criado acima) ---------------------
SELECT throws_ok(
  $$ SELECT pg_temp.create_gotrue_user(
       ('00000000-0000-4000-8000-0000000002' || lpad(g::text, 2, '0'))::uuid,
       '{"role":"client","client_id":"00000000-0000-4000-8000-00000000000a","display_name":"Lote"}'
     )
       FROM generate_series(1, 11) g $$,
  'P0001', 'USER_LIMIT_REACHED', 'E-18: o 10º novo usuário do cliente (11º no total) falha no COMMIT com USER_LIMIT_REACHED'
);

-- O trigger é só AFTER INSERT, adiado -------------------------------------------------------------------------
SELECT ok(
  (SELECT t.tgdeferrable AND t.tginitdeferred AND (t.tgtype & 4) <> 0 AND (t.tgtype & 58) = 0
     FROM pg_trigger t
    WHERE t.tgrelid = 'auth.users'::regclass AND t.tgname = 'on_auth_user_created'),
  'AC-31: o trigger de perfil é só AFTER INSERT (sem UPDATE, DELETE nem TRUNCATE), DEFERRABLE INITIALLY DEFERRED'
);

-- Só no INSERT: app_metadata mudado depois da criação não promove ninguém ---------------------------------
UPDATE auth.users
   SET raw_app_meta_data = '{"role":"ceo","display_name":"Promovido"}'
 WHERE id = '00000000-0000-4000-8000-0000000000b1';
SET CONSTRAINTS ALL IMMEDIATE;
SELECT results_eq(
  $$ SELECT role::text FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000b1' $$,
  $$ VALUES ('client') $$,
  'AC-31: mudar app_metadata depois da criação não promove o perfil'
);

SELECT * FROM finish();
ROLLBACK;
