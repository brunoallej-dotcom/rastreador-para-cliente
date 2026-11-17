-- Onda 10.1 (F-83, T-42): só um usuário com a senha definitiva lê dados de negócio pelo RLS, e só um CEO
-- com a senha definitiva é `is_ceo()`. Um login de cliente com a senha temporária ainda por trocar
-- (`must_change_password = true`, dentro das 72 h) tem principal (o `GET /auth/session`, a troca de senha e
-- o logout dependem disso), mas não lê nada de `clients`, `processes`, `process_stages` nem
-- `stage_approvals` pelo PostgREST: o BFF já recusa `/me/*` a ele (403 `PASSWORD_CHANGE_REQUIRED`, E-81), e
-- agora o banco diz o mesmo para quem chama direto com o próprio JWT.
--
-- Prova: (1) o login pendente não lê tabela de negócio alguma, e o mesmo login lê assim que troca a senha
-- (a pendência é a única diferença); (2) o que continua funcionando para ele: `current_principal()`, o
-- próprio perfil, o nome do próprio cliente por `current_client_summary()` (o login e o `GET /auth/session`
-- o mostram), `mark_password_changed()` e o logout; (3) o controle positivo: o login de senha definitiva
-- lê só o próprio tenant; (4) `is_ceo()`: um CEO atestado com a senha pendente não é CEO (nem lê, nem
-- escreve), mas troca a senha, e depois da troca volta a ser CEO; sem atestado nada muda; (5) a função nova
-- e o inventário das policies.
BEGIN;
SELECT plan(67);

-- arrange (como postgres) ---------------------------------------------------------------------------------------
-- Clientes A e B, cada um com um processo de duas fases. a1: login de A com a senha definitiva (controle
-- positivo). a2: login de A com a senha temporária dentro das 72 h (o alvo). a3: login de A com a senha
-- temporária de 73 h (E-34). a4: login de A com a senha definitiva e desativado. b1: login de B com a senha
-- definitiva. c1: CEO com a senha definitiva e fator verificado (atestado). c2: CEO com fator verificado que
-- volta a ter a senha temporária depois de atestado. Todo cliente nasce com a senha temporária (tests.create_user).
INSERT INTO public.clients (id, name) VALUES
  ('00000000-0000-4000-8000-00000000000a', 'Cliente A'),
  ('00000000-0000-4000-8000-00000000000b', 'Cliente B');
INSERT INTO public.processes (id, client_id, title) VALUES
  ('00000000-0000-4000-8000-000000000101', '00000000-0000-4000-8000-00000000000a', 'Processo de A'),
  ('00000000-0000-4000-8000-000000000102', '00000000-0000-4000-8000-00000000000b', 'Processo de B');
INSERT INTO public.process_stages (id, process_id, position, name, status, started_at) VALUES
  ('00000000-0000-4000-8000-000000000201', '00000000-0000-4000-8000-000000000101', 1, 'A fase 1', 'in_progress', now()),
  ('00000000-0000-4000-8000-000000000203', '00000000-0000-4000-8000-000000000102', 1, 'B fase 1', 'in_progress', now());
INSERT INTO public.process_stages (id, process_id, position, name) VALUES
  ('00000000-0000-4000-8000-000000000202', '00000000-0000-4000-8000-000000000101', 2, 'A fase 2');

SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a2', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a3', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a4', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000b1', 'client', '00000000-0000-4000-8000-00000000000b');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c2', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c4', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c2');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c4');
UPDATE public.profiles SET must_change_password = false WHERE id IN (
  '00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000a4',
  '00000000-0000-4000-8000-0000000000b1'
);
UPDATE public.profiles SET disabled_at = now() WHERE id = '00000000-0000-4000-8000-0000000000a4';
UPDATE private.password_baselines SET recorded_at = now() - interval '73 hours'
 WHERE user_id = '00000000-0000-4000-8000-0000000000a3';

-- a2 troca a senha mais adiante: o hash do Auth muda (o que `mark_password_changed` compara com a linha de base)
SELECT is(
  (SELECT array_agg(p.id::text ORDER BY p.id)
     FROM public.profiles p
    WHERE p.must_change_password
      AND p.id IN ('00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000a2',
                   '00000000-0000-4000-8000-0000000000a3', '00000000-0000-4000-8000-0000000000a4',
                   '00000000-0000-4000-8000-0000000000b1', '00000000-0000-4000-8000-0000000000c1',
                   '00000000-0000-4000-8000-0000000000c2')),
  ARRAY['00000000-0000-4000-8000-0000000000a2', '00000000-0000-4000-8000-0000000000a3'],
  'arrange: só a2 e a3 têm a senha temporária pendente (o CEO nasce com a definitiva, os outros clientes também)'
);

-- (1) o login com a senha temporária pendente (a2) não lê tabela de negócio alguma ------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a2');
SELECT is(
  (SELECT count(*)::int FROM public.processes), 0,
  'F-83: o login a2 (senha temporária pendente) não lê processo algum, nem os do próprio cliente'
);
SELECT is_empty(
  $$ SELECT id FROM public.processes WHERE id = '00000000-0000-4000-8000-000000000101' $$,
  'F-83: nem o processo do próprio cliente, pelo id'
);
SELECT is_empty(
  $$ SELECT id FROM public.processes WHERE client_id = '00000000-0000-4000-8000-00000000000a' $$,
  'F-83: nem a lista do próprio cliente (a forma que GET /me/processes usa)'
);
SELECT is(
  (SELECT count(*)::int FROM public.process_stages), 0,
  'F-83: o login a2 não lê fase alguma'
);
SELECT is_empty(
  $$ SELECT id FROM public.process_stages WHERE process_id = '00000000-0000-4000-8000-000000000101' $$,
  'F-83: nem as fases do processo do próprio cliente'
);
SELECT is(
  (SELECT count(*)::int FROM public.clients), 0,
  'F-83: o login a2 não lê linha alguma de clients, nem a do próprio cliente'
);
SELECT is(
  (SELECT count(*)::int FROM public.stage_approvals), 0,
  'F-83: o login a2 não lê aprovação alguma'
);
SELECT is_empty(
  $$ SELECT position FROM public.default_stage_template $$,
  'F-83: o login a2 não lê o template padrão de fases (policy só de CEO)'
);
SELECT is(
  (SELECT private.current_client_id()), NULL::uuid,
  'F-83: current_client_id() é nulo para quem ainda tem a senha temporária (o tenant só vale para o login definitivo)'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title) VALUES ('00000000-0000-4000-8000-00000000000a', 'Direto') $$,
  '42501', NULL, 'F-83: e a escrita direta continua negada (nenhum GRANT de escrita para authenticated)'
);
SELECT tests.clear_authentication();

-- (2) o que continua funcionando para o login pendente ---------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a2');
SELECT results_eq(
  $$ SELECT user_id, role::text, client_id, aal, has_verified_totp, must_change_password
       FROM public.current_principal() $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000a2'::uuid, 'client', '00000000-0000-4000-8000-00000000000a'::uuid,
             'aal1', false, true) $$,
  'F-83: o principal do login pendente continua existindo (o GET /auth/session e a troca de senha dependem dele)'
);
SELECT results_eq(
  $$ SELECT id, name FROM public.current_client_summary() $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000a'::uuid, 'Cliente A') $$,
  'F-83: o nome do próprio cliente continua disponível ao login pendente (SessionClient do login e do GET /auth/session)'
);
SELECT results_eq(
  $$ SELECT id FROM public.profiles $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000000a2'::uuid) $$,
  'F-83: o login pendente lê o próprio perfil e só ele'
);
SELECT tests.clear_authentication();

-- a2 troca a senha: o hash do Auth muda e `mark_password_changed` limpa a pendência
UPDATE auth.users SET encrypted_password = 'changed-1' WHERE id = '00000000-0000-4000-8000-0000000000a2';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a2');
SELECT lives_ok(
  $$ SELECT public.mark_password_changed() $$,
  'F-83: o login pendente troca a senha (mark_password_changed não depende da leitura de negócio)'
);
SELECT tests.clear_authentication();

-- a única diferença é a pendência: o MESMO login, agora com a senha definitiva, lê o que é do tenant dele
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a2');
SELECT results_eq(
  $$ SELECT id FROM public.processes $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000101'::uuid) $$,
  'F-83: depois de trocar a senha, o mesmo login lê o processo do próprio cliente (e só ele)'
);
SELECT results_eq(
  $$ SELECT position::int FROM public.process_stages ORDER BY position $$,
  $$ VALUES (1), (2) $$,
  'F-83: depois da troca, lê as duas fases do próprio processo'
);
SELECT results_eq(
  $$ SELECT id FROM public.clients $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000a'::uuid) $$,
  'F-83: depois da troca, lê a linha do próprio cliente'
);
SELECT is(
  (SELECT private.current_client_id()), '00000000-0000-4000-8000-00000000000a'::uuid,
  'F-83: depois da troca, current_client_id() devolve o tenant'
);
SELECT tests.clear_authentication();

-- a senha temporária volta (o reset do CEO): o login volta a não ler nada
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000a2') $$,
  'F-83: o CEO reseta o login a2 (a senha temporária volta)'
);
SELECT tests.clear_authentication();
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, aal)
VALUES ('00000000-0000-4000-8000-0000000000a2', '00000000-0000-4000-8000-0000000000a2', now(), now(), 'aal1');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a2');
SELECT is(
  (SELECT count(*)::int FROM public.processes), 0,
  'F-83: depois do reset do CEO, o login a2 volta a não ler processo algum'
);
SELECT is(
  (SELECT count(*)::int FROM public.current_principal()), 1,
  'F-83: e volta a ter principal com a pendência (o fluxo de troca recomeça)'
);
SELECT tests.clear_authentication();

-- E-34: a senha temporária vencida (a3) não tem principal e não lê nada --------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a3');
SELECT is((SELECT count(*)::int FROM public.processes), 0, 'E-34: a3 (73 h) não lê processo algum');
SELECT is((SELECT count(*)::int FROM public.clients), 0, 'E-34: nem cliente algum');
SELECT is((SELECT count(*)::int FROM public.current_client_summary()), 0, 'E-34: nem o resumo do cliente');
SELECT is((SELECT count(*)::int FROM public.current_principal()), 0, 'E-34: e não tem principal');
SELECT tests.clear_authentication();

-- (3) o controle positivo: o login de senha definitiva lê só o próprio tenant -------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT results_eq(
  $$ SELECT id FROM public.processes ORDER BY id $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000101'::uuid) $$,
  'F-83: controle positivo: a1 (senha definitiva) lê o processo de A e só ele (as linhas existem; os vazios acima valem)'
);
SELECT is((SELECT count(*)::int FROM public.process_stages), 2, 'F-83: a1 lê as duas fases de A, e nenhuma de B');
SELECT results_eq(
  $$ SELECT id FROM public.clients $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000a'::uuid) $$,
  'F-83: a1 lê a própria linha de clients e só ela'
);
SELECT results_eq(
  $$ SELECT id, name FROM public.current_client_summary() $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000a'::uuid, 'Cliente A') $$,
  'F-83: current_client_summary() devolve o cliente do próprio perfil'
);
SELECT is((SELECT count(*)::int FROM public.stage_approvals), 0, 'F-83: a1 não lê aprovação (policy só de CEO)');
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000b1');
SELECT results_eq(
  $$ SELECT id FROM public.processes $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000102'::uuid) $$,
  'F-83: b1 lê só o processo de B'
);
SELECT results_eq(
  $$ SELECT id, name FROM public.current_client_summary() $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000b'::uuid, 'Cliente B') $$,
  'F-83: o resumo de b1 é o cliente B, nunca o de A (a função não tem parâmetro)'
);
SELECT tests.clear_authentication();

-- login desativado (a4, senha definitiva) e sessão morta: nada
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a4');
SELECT is((SELECT count(*)::int FROM public.processes), 0, 'E-08: o login desativado não lê processo algum');
SELECT is((SELECT count(*)::int FROM public.current_client_summary()), 0, 'E-08: nem o resumo do cliente');
SELECT tests.clear_authentication();

-- anon
SET LOCAL ROLE anon;
SELECT throws_ok($$ SELECT * FROM public.current_client_summary() $$, '42501', NULL, 'AC-10: anon não executa current_client_summary');
RESET ROLE;

-- (4) is_ceo(): a senha definitiva é parte do que faz um CEO --------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT is((SELECT private.is_ceo()), true, 'F-83: controle positivo: o CEO atestado com a senha definitiva é CEO');
SELECT is(
  (SELECT count(*)::int FROM public.clients WHERE id IN ('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000b')),
  2, 'F-83: e lê os clientes (de todos os tenants)'
);
SELECT lives_ok($$ SELECT public.create_client('Cliente do CEO definitivo') $$, 'F-83: e executa funções de CEO');
SELECT is(
  (SELECT count(*)::int FROM public.current_client_summary()), 0,
  'F-83: um CEO não tem cliente: current_client_summary() não devolve linha'
);
SELECT tests.clear_authentication();

-- c2 foi atestado com a senha definitiva e a perdeu depois (o reset de um operador, F-41)
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2');
SELECT is((SELECT private.is_ceo()), true, 'F-83: arrange: c2 atestado, ainda com a senha definitiva, é CEO');
SELECT tests.clear_authentication();
UPDATE public.profiles SET must_change_password = true WHERE id = '00000000-0000-4000-8000-0000000000c2';

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2');
SELECT is((SELECT private.is_ceo()), false, 'F-83: o CEO atestado que voltou a ter a senha temporária NÃO é CEO');
SELECT is((SELECT count(*)::int FROM public.clients), 0, 'F-83: não lê os clientes');
SELECT is((SELECT count(*)::int FROM public.processes), 0, 'F-83: não lê os processos');
SELECT is((SELECT count(*)::int FROM public.profiles), 1, 'F-83: lê só o próprio perfil, não os de outros');
SELECT is((SELECT count(*)::int FROM public.audit_events), 0, 'F-83: não lê a auditoria');
SELECT throws_ok(
  $$ SELECT public.create_client('Cliente de CEO pendente') $$,
  '42501', 'FORBIDDEN', 'F-83: não executa função de CEO (create_client)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.list_client_users('00000000-0000-4000-8000-00000000000a') $$,
  '42501', 'FORBIDDEN', 'F-83: nem list_client_users'
);
SELECT throws_ok(
  $$ SELECT public.approve_current_stage('00000000-0000-4000-8000-000000000101',
                                         '00000000-0000-4000-8000-000000000201') $$,
  '42501', 'FORBIDDEN', 'F-83: nem a aprovação de uma fase'
);
-- o atestado e o principal não dependem de is_ceo(): a sessão segue atestada, e a troca de senha funciona
SELECT results_eq(
  $$ SELECT role::text, aal, has_verified_totp, must_change_password FROM public.current_principal() $$,
  $$ VALUES ('ceo', 'aal2', true, true) $$,
  'F-83: o principal do CEO pendente segue atestado (aal2) e mostra a pendência: o atestado não é tocado'
);
SELECT tests.clear_authentication();

UPDATE auth.users SET encrypted_password = 'changed-2' WHERE id = '00000000-0000-4000-8000-0000000000c2';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2');
SELECT lives_ok(
  $$ SELECT public.mark_password_changed() $$,
  'F-83: o CEO pendente e atestado troca a senha (mark_password_changed usa o atestado, não is_ceo())'
);
SELECT is((SELECT private.is_ceo()), true, 'F-83: depois da troca o mesmo CEO volta a ser CEO');
SELECT is(
  (SELECT count(*)::int FROM public.clients
    WHERE id IN ('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000b')
       OR name = 'Cliente do CEO definitivo'),
  3, 'F-83: e volta a ler os clientes (as duas fixtures e o que o CEO criou)'
);
SELECT tests.clear_authentication();

-- sem atestado, com ou sem a pendência: nada muda (o claim aal2 obtido direto no Auth não vale nada). c4 nunca foi
-- atestado (uma sessão atestada continua atestada na mesma transação, então o controle é outro CEO)
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c4', 'aal2', false);
SELECT is((SELECT private.is_ceo()), false, 'F-83: aal2 sem atestado, com a senha definitiva, não é CEO');
SELECT is(
  (SELECT count(*)::int FROM public.clients
    WHERE id IN ('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000b')),
  0, 'F-83: e não lê os clientes'
);
SELECT tests.clear_authentication();
UPDATE public.profiles SET must_change_password = true WHERE id = '00000000-0000-4000-8000-0000000000c4';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c4', 'aal2', false);
SELECT is((SELECT private.is_ceo()), false, 'F-83: aal2 sem atestado e com a senha pendente continua não sendo CEO');
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c4', 'aal1');
SELECT is((SELECT private.is_ceo()), false, 'F-83: aal1 com a senha pendente não é CEO');
SELECT tests.clear_authentication();

-- o atestado de um CEO com a senha pendente é possível NO BANCO (a função do backend não olha a pendência): o
-- que o impede é o BFF (enroll e verify não aceitam CHANGE_PASSWORD) e, agora, is_ceo(), que não o reconhece
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c3', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c3');
UPDATE public.profiles SET must_change_password = true WHERE id = '00000000-0000-4000-8000-0000000000c3';
SELECT is(
  tests.attest_session('00000000-0000-4000-8000-0000000000c3'), true,
  'F-83: o banco atesta a sessão de um CEO com a senha pendente (a camada que impede é o BFF)'
);
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT is((SELECT private.is_ceo()), false, 'F-83: mas a sessão atestada dele não dá acesso de CEO enquanto a senha for temporária');
SELECT tests.clear_authentication();

-- (5) a função nova e o inventário das policies ---------------------------------------------------------------------------------------------
SELECT policies_are(
  'public', 'clients',
  ARRAY['clients_select_own_tenant', 'clients_select_ceo'],
  'F-97: clients tem exatamente as duas policies de leitura (o tenant da sessão e o CEO atestado)'
);
SELECT policies_are(
  'public', 'processes',
  ARRAY['processes_select_own_tenant', 'processes_select_ceo'],
  'F-97: processes continua com as duas policies de leitura'
);
SELECT policies_are(
  'public', 'process_stages',
  ARRAY['process_stages_select_own_tenant', 'process_stages_select_ceo'],
  'F-97: process_stages continua com as duas policies de leitura'
);
SELECT is(
  (SELECT p.prosecdef AND coalesce(p.proconfig @> ARRAY['search_path=""'], false)
     FROM pg_proc p WHERE p.oid = 'public.current_client_summary()'::regprocedure),
  true,
  'AC-25: current_client_summary é SECURITY DEFINER com search_path vazio'
);
SELECT is(
  has_function_privilege('authenticated', 'public.current_client_summary()', 'EXECUTE'),
  true,
  'current_client_summary: authenticated executa'
);
SELECT is(
  has_function_privilege('anon', 'public.current_client_summary()', 'EXECUTE')
    OR has_function_privilege('service_role', 'public.current_client_summary()', 'EXECUTE'),
  false,
  'current_client_summary: nem anon nem service_role executam'
);
SELECT is_empty(
  $$ SELECT a.grantee
       FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE p.oid = 'public.current_client_summary()'::regprocedure
        AND a.privilege_type = 'EXECUTE' AND a.grantee = 0 $$,
  'current_client_summary: EXECUTE não é concedido a PUBLIC'
);
SELECT is(
  (SELECT count(*)::int FROM pg_attribute a
    WHERE a.attrelid = 'public.clients'::regclass AND a.attnum > 0 AND NOT a.attisdropped),
  5,
  'F-83: clients tem 5 colunas (id, name, archived_at, created_at, updated_at): a função devolve só id e name, o mínimo da sessão'
);

SELECT * FROM finish();
ROLLBACK;
