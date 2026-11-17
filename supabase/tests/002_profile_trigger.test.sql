-- Trigger private.handle_new_auth_user (Onda 2): AC-31 (parte do banco), E-18, E-30 e a linha de
-- base da senha. O perfil nasce de raw_app_meta_data; raw_user_meta_data nunca é lido; qualquer dado inválido
-- derruba o INSERT em auth.users (fail closed); nenhum caminho promove alguém a CEO.
BEGIN;
SELECT plan(42);

-- arrange (como postgres) -------------------------------------------------------------------------
INSERT INTO public.clients (id, name, archived_at) VALUES
  ('00000000-0000-4000-8000-00000000000a', 'Cliente A', NULL),
  ('00000000-0000-4000-8000-00000000000b', 'Cliente B', NULL),
  ('00000000-0000-4000-8000-00000000000f', 'Cliente Arquivado', now()),
  ('00000000-0000-4000-8000-00000000001f', 'Cliente Lotado', NULL);

-- AC-31: metadados válidos criam o perfil certo -----------------------------------------------------
SELECT tests.create_user(
  '00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a', 'Maria Cliente'
);
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo', NULL, 'Carlos CEO');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
-- `tests.create_user` já entrega o CEO com a senha definitiva (000_helpers); o perfil como o TRIGGER o cria
-- (com a senha temporária) é o de um CEO inserido direto em auth.users
SELECT tests.insert_auth_user(
  '00000000-0000-4000-8000-0000000000c9',
  '{"role":"ceo","display_name":"Carlos CEO"}'
);

SELECT results_eq(
  $$ SELECT role::text, client_id, display_name, must_change_password, disabled_at IS NULL
       FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a1' $$,
  $$ VALUES ('client', '00000000-0000-4000-8000-00000000000a'::uuid, 'Maria Cliente', true, true) $$,
  'AC-31: app_metadata de cliente cria perfil client com client_id, nome e must_change_password = true'
);

SELECT results_eq(
  $$ SELECT role::text, client_id, display_name, must_change_password, disabled_at IS NULL
       FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000c9' $$,
  $$ VALUES ('ceo', NULL::uuid, 'Carlos CEO', true, true) $$,
  'AC-31: app_metadata de CEO cria perfil ceo sem client_id e com must_change_password = true'
);

SELECT tests.insert_auth_user(
  '00000000-0000-4000-8000-0000000000a2',
  '{"role":"client","client_id":"00000000-0000-4000-8000-00000000000A","display_name":"  Com Espaços  "}'
);
SELECT results_eq(
  $$ SELECT client_id, display_name FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a2' $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000a'::uuid, 'Com Espaços') $$,
  'AC-31: o nome de exibição é gravado sem espaços nas pontas e client_id aceita hex maiúsculo'
);

-- SEC-10: o trigger grava a linha de base da senha (digest sha256 do hash em auth.users) ------------------
SELECT is(
  (SELECT b.hash_digest = extensions.digest(coalesce(u.encrypted_password, ''), 'sha256')
     FROM private.password_baselines b JOIN auth.users u ON u.id = b.user_id
    WHERE b.user_id = '00000000-0000-4000-8000-0000000000a1'),
  true,
  'SEC-10: o trigger grava a linha de base da senha do cliente (sha256 do hash atual)'
);
SELECT is(
  (SELECT b.hash_digest = extensions.digest(coalesce(u.encrypted_password, ''), 'sha256')
     FROM private.password_baselines b JOIN auth.users u ON u.id = b.user_id
    WHERE b.user_id = '00000000-0000-4000-8000-0000000000c1'),
  true,
  'SEC-10: o trigger grava a linha de base da senha do CEO (sha256 do hash atual)'
);

-- AC-31: papel ausente ou inválido derruba o INSERT -----------------------------------------------------
SELECT throws_ok(
  $$ SELECT tests.insert_auth_user('00000000-0000-4000-8000-0000000000d1', '{"display_name":"Sem Papel"}') $$,
  'P0001', 'INVALID_INPUT', 'AC-31: sem app_metadata.role o INSERT em auth.users falha'
);
SELECT is_empty(
  $$ SELECT id FROM auth.users WHERE id = '00000000-0000-4000-8000-0000000000d1' $$,
  'AC-31: sem papel, o usuário não é criado (fail closed)'
);
SELECT is_empty(
  $$ SELECT id FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000d1' $$,
  'AC-31: sem papel, nenhum perfil é criado'
);

SELECT throws_ok(
  $$ SELECT tests.insert_auth_user('00000000-0000-4000-8000-0000000000d2', '{}') $$,
  'P0001', 'INVALID_INPUT', 'AC-31: app_metadata vazio falha'
);

SELECT throws_ok(
  $$ SELECT tests.insert_auth_user('00000000-0000-4000-8000-0000000000d3', '{"role":"admin","display_name":"X"}') $$,
  'P0001', 'INVALID_INPUT', 'AC-31: papel desconhecido (admin) falha'
);

-- AC-31: user_metadata é ignorado -----------------------------------------------------------------------
SELECT throws_ok(
  $$ SELECT tests.insert_auth_user(
       '00000000-0000-4000-8000-0000000000d4',
       '{"display_name":"X"}',
       '{"role":"ceo"}'
     ) $$,
  'P0001', 'INVALID_INPUT', 'AC-31: user_metadata.role = ceo sem app_metadata.role falha (user_metadata é ignorado)'
);
SELECT is_empty(
  $$ SELECT id FROM auth.users WHERE id = '00000000-0000-4000-8000-0000000000d4' $$,
  'AC-31: com user_metadata.role = ceo e sem app_metadata.role, o usuário não é criado'
);

SELECT tests.insert_auth_user(
  '00000000-0000-4000-8000-0000000000a3',
  '{"role":"client","client_id":"00000000-0000-4000-8000-00000000000a","display_name":"App Nome"}',
  '{"role":"ceo","client_id":"00000000-0000-4000-8000-00000000000b","display_name":"User Nome"}'
);
SELECT results_eq(
  $$ SELECT role::text, client_id, display_name FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a3' $$,
  $$ VALUES ('client', '00000000-0000-4000-8000-00000000000a'::uuid, 'App Nome') $$,
  'AC-31: user_metadata com role ceo, outro client_id e outro nome não muda nada: vale o app_metadata'
);

SELECT throws_ok(
  $$ SELECT tests.insert_auth_user(
       '00000000-0000-4000-8000-0000000000d5', '{"role":"ceo"}', '{"display_name":"Só no User"}'
     ) $$,
  'P0001', 'INVALID_INPUT', 'AC-31: display_name só em user_metadata falha (o nome vem do app_metadata)'
);

-- Nome de exibição inválido -------------------------------------------------------------------------------
SELECT throws_ok(
  $$ SELECT tests.insert_auth_user('00000000-0000-4000-8000-0000000000d6', '{"role":"ceo","display_name":"   "}') $$,
  'P0001', 'INVALID_INPUT', 'AC-31: nome em branco falha'
);
SELECT throws_ok(
  $$ SELECT tests.insert_auth_user(
       '00000000-0000-4000-8000-0000000000d7', jsonb_build_object('role', 'ceo', 'display_name', repeat('n', 121))
     ) $$,
  'P0001', 'INVALID_INPUT', 'AC-31: nome com 121 caracteres falha'
);
SELECT throws_ok(
  $$ SELECT tests.insert_auth_user(
       '00000000-0000-4000-8000-0000000000d8', jsonb_build_object('role', 'ceo', 'display_name', E'Nome\nQuebrado')
     ) $$,
  'P0001', 'INVALID_INPUT', 'AC-31: nome com caractere de controle falha'
);

SELECT throws_ok(
  $$ SELECT tests.insert_auth_user(
       '00000000-0000-4000-8000-0000000000de',
       jsonb_build_object('role', 'ceo', 'display_name', 'Nome' || chr(8238) || 'invertido')
     ) $$,
  'P0001', 'INVALID_INPUT', 'E-30: nome com U+202E (bidi override) falha'
);
SELECT throws_ok(
  $$ SELECT tests.insert_auth_user(
       '00000000-0000-4000-8000-0000000000df',
       jsonb_build_object('role', 'ceo', 'display_name', 'Nome' || chr(8203) || 'invisível')
     ) $$,
  'P0001', 'INVALID_INPUT', 'E-30: nome com U+200B (zero-width space) falha'
);
SELECT tests.insert_auth_user(
  '00000000-0000-4000-8000-0000000000a6',
  jsonb_build_object('role', 'ceo', 'display_name', 'Ação & Cia — Produção')
);
SELECT results_eq(
  $$ SELECT display_name FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a6' $$,
  $$ VALUES ('Ação & Cia — Produção') $$,
  'E-30: nome acentuado comum, com & e travessão, é aceito e gravado como veio'
);

-- Vínculo com o cliente ------------------------------------------------------------------------------------------
SELECT throws_ok(
  $$ SELECT tests.insert_auth_user('00000000-0000-4000-8000-0000000000d9', '{"role":"client","display_name":"X"}') $$,
  'P0001', 'INVALID_INPUT', 'AC-31: cliente sem client_id falha'
);
SELECT throws_ok(
  $$ SELECT tests.insert_auth_user(
       '00000000-0000-4000-8000-0000000000da', '{"role":"client","client_id":"not-a-uuid","display_name":"X"}'
     ) $$,
  'P0001', 'INVALID_INPUT', 'AC-31: cliente com client_id malformado falha'
);
SELECT throws_ok(
  $$ SELECT tests.insert_auth_user(
       '00000000-0000-4000-8000-0000000000db',
       '{"role":"ceo","client_id":"00000000-0000-4000-8000-00000000000a","display_name":"X"}'
     ) $$,
  'P0001', 'INVALID_INPUT', 'AC-31: CEO com client_id falha'
);
SELECT throws_ok(
  $$ SELECT tests.insert_auth_user(
       '00000000-0000-4000-8000-0000000000dc',
       '{"role":"client","client_id":"00000000-0000-4000-8000-0000000000ee","display_name":"X"}'
     ) $$,
  'P0001', 'NOT_FOUND', 'AC-31: cliente inexistente falha com NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT tests.insert_auth_user(
       '00000000-0000-4000-8000-0000000000dd',
       '{"role":"client","client_id":"00000000-0000-4000-8000-00000000000f","display_name":"X"}'
     ) $$,
  'P0001', 'CLIENT_ARCHIVED', 'AC-31: cliente arquivado falha com CLIENT_ARCHIVED'
);
SELECT is_empty(
  $$ SELECT id FROM auth.users WHERE id::text LIKE '00000000-0000-4000-8000-0000000000d%' $$,
  'AC-31: nenhuma das tentativas inválidas deixou usuário em auth.users'
);
SELECT is_empty(
  $$ SELECT user_id FROM private.password_baselines WHERE user_id::text LIKE '00000000-0000-4000-8000-0000000000d%' $$,
  'SEC-10: nenhuma das tentativas inválidas deixou linha de base de senha'
);

-- E-18: limite de 10 logins por cliente --------------------------------------------------------------------------------
SELECT tests.insert_auth_user(
  ('00000000-0000-4000-8000-0000000001' || lpad(g::text, 2, '0'))::uuid,
  jsonb_build_object('role', 'client', 'client_id', '00000000-0000-4000-8000-00000000001f', 'display_name', 'Login ' || g)
)
  FROM generate_series(1, 10) g;

SELECT is(
  (SELECT count(*)::int FROM public.profiles WHERE client_id = '00000000-0000-4000-8000-00000000001f'),
  10,
  'E-18: o cliente chega a 10 logins'
);
SELECT throws_ok(
  $$ SELECT tests.insert_auth_user(
       '00000000-0000-4000-8000-0000000001ff',
       '{"role":"client","client_id":"00000000-0000-4000-8000-00000000001f","display_name":"Décimo primeiro"}'
     ) $$,
  'P0001', 'USER_LIMIT_REACHED', 'E-18: o 11º login do mesmo cliente falha com USER_LIMIT_REACHED'
);
SELECT is_empty(
  $$ SELECT id FROM auth.users WHERE id = '00000000-0000-4000-8000-0000000001ff' $$,
  'E-18: o 11º usuário não é criado em auth.users'
);
SELECT lives_ok(
  $$ SELECT tests.insert_auth_user(
       '00000000-0000-4000-8000-0000000000a4',
       '{"role":"client","client_id":"00000000-0000-4000-8000-00000000000b","display_name":"Login de B"}'
     ) $$,
  'E-18: o limite é por cliente: outro cliente continua aceitando logins'
);

-- Nenhum caminho promove a CEO -----------------------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ UPDATE public.profiles SET role = 'ceo', client_id = NULL WHERE id = '00000000-0000-4000-8000-0000000000a1' $$,
  '42501', NULL, 'AC-31: nem CEO aal2 faz UPDATE em profiles.role (42501)'
);
SELECT throws_ok(
  $$ INSERT INTO public.profiles (id, role, display_name)
     VALUES ('00000000-0000-4000-8000-0000000000e1', 'ceo', 'Promovido') $$,
  '42501', NULL, 'AC-31: nem CEO aal2 faz INSERT em profiles (42501)'
);
SELECT throws_ok(
  $$ DELETE FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a1' $$,
  '42501', NULL, 'AC-31: nem CEO aal2 faz DELETE em profiles (42501)'
);
SELECT throws_ok(
  $$ UPDATE auth.users SET raw_app_meta_data = '{"role":"ceo","display_name":"X"}'
      WHERE id = '00000000-0000-4000-8000-0000000000a1' $$,
  '42501', NULL, 'AC-31: authenticated não altera app_metadata em auth.users (42501)'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1', 'aal1');
SELECT throws_ok(
  $$ UPDATE public.profiles SET role = 'ceo', client_id = NULL WHERE id = '00000000-0000-4000-8000-0000000000a1' $$,
  '42501', NULL, 'AC-31: cliente não promove o próprio perfil a CEO (42501)'
);
SELECT tests.clear_authentication();

UPDATE auth.users
   SET raw_app_meta_data = '{"role":"ceo","display_name":"Promovido"}'
 WHERE id = '00000000-0000-4000-8000-0000000000a1';
SELECT results_eq(
  $$ SELECT role::text, client_id FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000a1' $$,
  $$ VALUES ('client', '00000000-0000-4000-8000-00000000000a'::uuid) $$,
  'AC-31: mudar app_metadata depois do INSERT não promove o perfil (o trigger só roda na criação)'
);

SELECT throws_ok(
  $$ UPDATE public.profiles SET role = 'ceo' WHERE id = '00000000-0000-4000-8000-0000000000a1' $$,
  '23514', NULL, 'AC-31: nem como dono (postgres) dá para promover a CEO sem tirar o client_id (profiles_role_client_ck)'
);
SELECT throws_ok(
  $$ UPDATE public.profiles SET client_id = '00000000-0000-4000-8000-00000000000a' WHERE id = '00000000-0000-4000-8000-0000000000c1' $$,
  '23514', NULL, 'AC-31: CEO não ganha client_id (profiles_role_client_ck)'
);

-- CHECK de profiles.display_name vale mesmo para o dono (postgres) e a linha de base some com o usuário ---------
SELECT throws_ok(
  $$ UPDATE public.profiles SET display_name = 'Nome' || chr(8238) || 'invertido'
      WHERE id = '00000000-0000-4000-8000-0000000000a1' $$,
  '23514', NULL, 'E-30: o CHECK de profiles.display_name rejeita U+202E (bidi override)'
);
SELECT throws_ok(
  $$ UPDATE public.profiles SET display_name = 'Nome' || chr(8203) || 'invisível'
      WHERE id = '00000000-0000-4000-8000-0000000000a1' $$,
  '23514', NULL, 'E-30: o CHECK de profiles.display_name rejeita U+200B (zero-width space)'
);

DELETE FROM auth.users WHERE id = '00000000-0000-4000-8000-0000000000a4';
SELECT is_empty(
  $$ SELECT user_id FROM private.password_baselines WHERE user_id = '00000000-0000-4000-8000-0000000000a4' $$,
  'SEC-10: apagar o usuário em auth.users apaga a linha de base da senha (ON DELETE CASCADE)'
);

SELECT * FROM finish();
ROLLBACK;
