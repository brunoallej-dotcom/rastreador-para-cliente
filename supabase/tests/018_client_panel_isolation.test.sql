-- Onda 10: isolamento do painel do cliente (AC-09, AC-20, E-08), no banco. O app lê `processes` e
-- `process_stages` com o client do usuário (RLS) e com as MESMAS formas de consulta que `GET /me/processes`
-- usa: a lista com contagens de fases por processo (o `count` embutido do PostgREST), a fase atual, o keyset
-- por (created_at DESC, id) e a leitura de um processo pelo id. Este arquivo roda essas formas como cada
-- papel e prova que o cliente A lê só o que é dele, que B e um cliente sem processos não leem nada de A, que
-- um empate de `created_at` entre tenants não vaza, que contagem e junção não revelam linha de outro tenant,
-- que o cliente nunca lê aprovações e que nenhum caminho de escrita direta lhe sobra. Complementa 003 (que
-- prova o RLS linha a linha) sem repetir a matriz inteira; não há objeto novo de banco nesta onda.
--
-- Também fixa o INVENTÁRIO das policies das três tabelas que o painel toca (F-97: uma policy permissiva nova,
-- ou uma frouxa, quebra aqui até alguém revisar), prova com logins de senha definitiva (os positivos não
-- dependem de `must_change_password`, que nasce verdadeiro) e registra os dois estados da senha temporária: o
-- login com a senha ainda por trocar LÊ pelo RLS (resíduo F-83, que a Onda 10.1 inverte) e o de senha
-- temporária vencida (72 h, E-34) não lê nada.
BEGIN;
SELECT plan(54);

-- A forma da lista do painel: por processo do tenant, quantas fases tem, quantas estão concluídas e a posição
-- da fase em andamento. SECURITY INVOKER de propósito: o RLS é avaliado para quem chama. Vive só nesta
-- transação (ROLLBACK).
CREATE FUNCTION tests.panel_list(p_tenant uuid)
RETURNS TABLE (id uuid, total_stages bigint, completed_stages bigint, current_position smallint)
LANGUAGE sql
STABLE
AS $$
  SELECT p.id,
         (SELECT count(*) FROM public.process_stages s WHERE s.process_id = p.id),
         (SELECT count(*) FROM public.process_stages s WHERE s.process_id = p.id AND s.status = 'completed'),
         (SELECT s.position FROM public.process_stages s WHERE s.process_id = p.id AND s.status = 'in_progress')
    FROM public.processes p
   WHERE p.client_id = p_tenant
   ORDER BY p.created_at DESC, p.id
$$;
GRANT EXECUTE ON FUNCTION tests.panel_list(uuid) TO anon, authenticated, service_role;

-- arrange (como postgres) ----------------------------------------------------------------------------
-- Clientes A, B e D (D não tem processo). a1 e a2 são logins de A (o tenant é do cliente, não do login), a3 é
-- login desativado de A, a5 tem sessão expirada, b1 é login de B e d1 é login de D: todos com a senha
-- DEFINITIVA (must_change_password = false), para que cada um teste só a condição que o nome dele diz. a4 ainda
-- tem a senha temporária, dentro das 72 h (o resíduo F-83), e a6 tem a senha temporária de mais de 72 h (E-34).
-- c1 é CEO com fator verificado (controle positivo, atestado) e c2 é CEO com fator que NUNCA é atestado (só o
-- claim aal2 aparece).
INSERT INTO public.clients (id, name) VALUES
  ('00000000-0000-4000-8000-00000000000a', 'Cliente A'),
  ('00000000-0000-4000-8000-00000000000b', 'Cliente B'),
  ('00000000-0000-4000-8000-00000000000d', 'Cliente D');

SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a2', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a3', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a4', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a5', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a6', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000b1', 'client', '00000000-0000-4000-8000-00000000000b');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000d1', 'client', '00000000-0000-4000-8000-00000000000d');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c2', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c2');
-- Todo login nasce com a senha temporária (must_change_password = true); os que representam um cliente
-- "plenamente ativo", ou que testam OUTRA condição, passam à senha definitiva. a4 e a6 ficam como nasceram.
UPDATE public.profiles SET must_change_password = false WHERE id IN (
  '00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000a2',
  '00000000-0000-4000-8000-0000000000a3', '00000000-0000-4000-8000-0000000000a5',
  '00000000-0000-4000-8000-0000000000b1', '00000000-0000-4000-8000-0000000000d1'
);
-- a6: a senha temporária tem mais de 72 h (o prazo corre de private.password_baselines.recorded_at, F-41)
UPDATE private.password_baselines SET recorded_at = now() - interval '73 hours'
 WHERE user_id = '00000000-0000-4000-8000-0000000000a6';
UPDATE public.profiles SET disabled_at = now() WHERE id = '00000000-0000-4000-8000-0000000000a3';
UPDATE auth.sessions SET not_after = now() - interval '1 hour' WHERE id = '00000000-0000-4000-8000-0000000000a5';

-- Três processos nascem no MESMO instante (o empate do keyset): 101 e 103 são de A, e o 102, de B, tem um id que
-- cai entre os dois. 104 é de A, mais antigo e concluído (as duas fases com aprovação).
INSERT INTO public.processes (id, client_id, title, status, completed_at, created_at, updated_at) VALUES
  ('00000000-0000-4000-8000-000000000101', '00000000-0000-4000-8000-00000000000a', 'A ativo', 'active', NULL,
   '2026-03-03 10:00:00+00', '2026-03-03 10:00:00+00'),
  ('00000000-0000-4000-8000-000000000102', '00000000-0000-4000-8000-00000000000b', 'B ativo', 'active', NULL,
   '2026-03-03 10:00:00+00', '2026-03-03 10:00:00+00'),
  ('00000000-0000-4000-8000-000000000103', '00000000-0000-4000-8000-00000000000a', 'A de uma fase', 'active', NULL,
   '2026-03-03 10:00:00+00', '2026-03-03 10:00:00+00'),
  ('00000000-0000-4000-8000-000000000104', '00000000-0000-4000-8000-00000000000a', 'A concluido', 'completed',
   '2026-03-02 12:00:00+00', '2026-03-02 10:00:00+00', '2026-03-02 12:00:00+00');

INSERT INTO public.process_stages (id, process_id, position, name, status, started_at, completed_at) VALUES
  ('00000000-0000-4000-8000-000000000201', '00000000-0000-4000-8000-000000000101', 1, 'A1 fase 1', 'completed',
   '2026-03-03 10:00:00+00', '2026-03-03 11:00:00+00'),
  ('00000000-0000-4000-8000-000000000202', '00000000-0000-4000-8000-000000000101', 2, 'A1 fase 2', 'in_progress',
   '2026-03-03 11:00:00+00', NULL),
  ('00000000-0000-4000-8000-000000000203', '00000000-0000-4000-8000-000000000101', 3, 'A1 fase 3', 'pending', NULL, NULL),
  ('00000000-0000-4000-8000-000000000204', '00000000-0000-4000-8000-000000000102', 1, 'B1 fase 1', 'in_progress',
   '2026-03-03 10:00:00+00', NULL),
  ('00000000-0000-4000-8000-000000000205', '00000000-0000-4000-8000-000000000102', 2, 'B1 fase 2', 'pending', NULL, NULL),
  ('00000000-0000-4000-8000-000000000206', '00000000-0000-4000-8000-000000000103', 1, 'A3 fase 1', 'in_progress',
   '2026-03-03 10:00:00+00', NULL),
  ('00000000-0000-4000-8000-000000000207', '00000000-0000-4000-8000-000000000104', 1, 'A4 fase 1', 'completed',
   '2026-03-02 10:00:00+00', '2026-03-02 11:00:00+00'),
  ('00000000-0000-4000-8000-000000000208', '00000000-0000-4000-8000-000000000104', 2, 'A4 fase 2', 'completed',
   '2026-03-02 11:00:00+00', '2026-03-02 12:00:00+00');

INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by) VALUES
  ('00000000-0000-4000-8000-000000000201', '00000000-0000-4000-8000-000000000101', '00000000-0000-4000-8000-0000000000c1'),
  ('00000000-0000-4000-8000-000000000207', '00000000-0000-4000-8000-000000000104', '00000000-0000-4000-8000-0000000000c1'),
  ('00000000-0000-4000-8000-000000000208', '00000000-0000-4000-8000-000000000104', '00000000-0000-4000-8000-0000000000c1');

-- O ponto de partida: quem está plenamente ativo e quem ainda tem a senha temporária --------------------------------
SELECT is(
  (SELECT count(*) FROM public.profiles
    WHERE must_change_password AND id IN (
      '00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000a2',
      '00000000-0000-4000-8000-0000000000a3', '00000000-0000-4000-8000-0000000000a5',
      '00000000-0000-4000-8000-0000000000b1', '00000000-0000-4000-8000-0000000000d1')),
  0::bigint,
  'arrange: a1, a2, a3, a5, b1 e d1 têm a senha definitiva (os testes deles não dependem da pendência)'
);
SELECT is(
  (SELECT count(*) FROM public.profiles
    WHERE must_change_password AND id IN (
      '00000000-0000-4000-8000-0000000000a4', '00000000-0000-4000-8000-0000000000a6')),
  2::bigint,
  'arrange: a4 e a6 ainda têm a senha temporária'
);

-- F-97: o inventário das policies, para uma permissiva nova (ou frouxa) quebrar aqui até ser revista ------------------
SELECT policies_are(
  'public', 'processes',
  ARRAY['processes_select_own_tenant', 'processes_select_ceo'],
  'F-97: processes tem exatamente as duas policies de leitura (o próprio tenant e o CEO atestado)'
);
SELECT policies_are(
  'public', 'process_stages',
  ARRAY['process_stages_select_own_tenant', 'process_stages_select_ceo'],
  'F-97: process_stages tem exatamente as duas policies de leitura (o próprio tenant e o CEO atestado)'
);
SELECT policies_are(
  'public', 'stage_approvals',
  ARRAY['stage_approvals_select_ceo'],
  'F-97: stage_approvals tem só a policy do CEO atestado: o cliente não tem policy, então não lê'
);

-- AC-20: cliente A (login a1), a lista do painel -------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');

SELECT results_eq(
  $$ SELECT id, total_stages, completed_stages, current_position
       FROM tests.panel_list('00000000-0000-4000-8000-00000000000a') $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000101'::uuid, 3::bigint, 1::bigint, 2::smallint),
            ('00000000-0000-4000-8000-000000000103'::uuid, 1::bigint, 0::bigint, 1::smallint),
            ('00000000-0000-4000-8000-000000000104'::uuid, 2::bigint, 2::bigint, NULL::smallint) $$,
  'AC-20: a lista do painel de A traz os 3 processos dele, em ordem, com as contagens e a fase atual certas'
);
SELECT results_eq(
  $$ SELECT id FROM public.processes WHERE client_id = '00000000-0000-4000-8000-00000000000a'
      ORDER BY created_at DESC, id $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000101'::uuid), ('00000000-0000-4000-8000-000000000103'::uuid),
            ('00000000-0000-4000-8000-000000000104'::uuid) $$,
  'AC-20: o filtro por tenant da consulta e o RLS dão o mesmo conjunto'
);
SELECT results_eq(
  $$ SELECT id FROM public.processes ORDER BY created_at DESC, id $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000101'::uuid), ('00000000-0000-4000-8000-000000000103'::uuid),
            ('00000000-0000-4000-8000-000000000104'::uuid) $$,
  'AC-09: sem nenhum filtro, o RLS sozinho já entrega só os processos de A (o filtro por tenant é um cinto a mais)'
);
SELECT results_eq(
  $$ SELECT position, name, status FROM public.process_stages
      WHERE process_id = '00000000-0000-4000-8000-000000000101' ORDER BY position $$,
  $$ VALUES (1::smallint, 'A1 fase 1', 'completed'::public.stage_status),
            (2::smallint, 'A1 fase 2', 'in_progress'::public.stage_status),
            (3::smallint, 'A1 fase 3', 'pending'::public.stage_status) $$,
  'AC-20: o detalhe de um processo de A traz as fases dele, em ordem de posição'
);

-- AC-09: o que A tenta de B ----------------------------------------------------------------------------------------
SELECT is_empty(
  $$ SELECT id FROM tests.panel_list('00000000-0000-4000-8000-00000000000b') $$,
  'AC-09: a lista do painel com o id de B no filtro de tenant é vazia para A'
);
SELECT is_empty(
  $$ SELECT id FROM public.processes WHERE id = '00000000-0000-4000-8000-000000000102' $$,
  'AC-09, E-05: o processo de B, pelo id, não existe para A'
);
SELECT is(
  (SELECT count(*) FROM public.process_stages WHERE process_id = '00000000-0000-4000-8000-000000000102'),
  0::bigint,
  'AC-09: a contagem das fases do processo de B dá 0 para A (a contagem embutida não revela a existência)'
);
SELECT is(
  (SELECT count(*) FROM public.processes WHERE client_id = '00000000-0000-4000-8000-00000000000b'),
  0::bigint,
  'AC-09: a contagem dos processos de B dá 0 para A'
);
SELECT is_empty(
  $$ SELECT s.id FROM public.processes p JOIN public.process_stages s ON s.process_id = p.id
      WHERE p.client_id = '00000000-0000-4000-8000-00000000000b' $$,
  'AC-09: a junção processo-fase de B é vazia para A'
);
SELECT is_empty(
  $$ SELECT id FROM public.process_stages WHERE id IN (
       '00000000-0000-4000-8000-000000000204', '00000000-0000-4000-8000-000000000205') $$,
  'AC-09: as fases de B, pelos ids, não existem para A'
);
SELECT is_empty(
  $$ SELECT id FROM public.processes WHERE client_id <> '00000000-0000-4000-8000-00000000000a' $$,
  'AC-09: "tudo que não é de A" é vazio para A'
);
SELECT is_empty(
  $$ SELECT id FROM public.processes p WHERE EXISTS (
       SELECT 1 FROM public.process_stages s
        WHERE s.process_id = p.id AND s.name LIKE 'B1%') $$,
  'AC-09: procurar o processo de B pelo nome de uma fase dele é vazio para A'
);

-- AC-09: o empate de created_at entre tenants ----------------------------------------------------------------------
SELECT results_eq(
  $$ SELECT id FROM public.processes
      WHERE client_id = '00000000-0000-4000-8000-00000000000a'
        AND created_at = '2026-03-03 10:00:00+00' AND id > '00000000-0000-4000-8000-000000000101'
      ORDER BY id LIMIT 5 $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000103'::uuid) $$,
  'AC-09: o keyset do mesmo instante depois do 101 traz o 103 e NÃO o 102, que é de B e cai entre os dois'
);
SELECT results_eq(
  $$ SELECT id FROM public.processes
      WHERE created_at = '2026-03-03 10:00:00+00' AND id > '00000000-0000-4000-8000-000000000101'
      ORDER BY id LIMIT 5 $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000103'::uuid) $$,
  'AC-09: o mesmo keyset SEM o filtro de tenant (só o RLS) traz o 103 e não o 102: o RLS sozinho já separa o empate'
);
SELECT results_eq(
  $$ SELECT id FROM public.processes
      WHERE client_id = '00000000-0000-4000-8000-00000000000a'
        AND created_at < '2026-03-03 10:00:00+00'
      ORDER BY created_at DESC, id LIMIT 5 $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000104'::uuid) $$,
  'AC-09: o keyset dos mais antigos traz só o processo de A'
);
SELECT is_empty(
  $$ SELECT id FROM public.processes
      WHERE created_at = '2026-03-03 10:00:00+00' AND id = '00000000-0000-4000-8000-000000000102' $$,
  'AC-09: uma posição (cursor) forjada no instante e no id de B não faz o processo de B aparecer'
);

-- AC-20: o cliente não lê quem aprovou ------------------------------------------------------------------------------
SELECT is_empty(
  $$ SELECT id FROM public.stage_approvals $$,
  'AC-20: o cliente não lê stage_approvals, nem as aprovações das fases concluídas dele'
);
SELECT is_empty(
  $$ SELECT approved_by FROM public.stage_approvals WHERE process_id = '00000000-0000-4000-8000-000000000104' $$,
  'AC-20: nem filtrando pelo próprio processo concluído, o cliente descobre quem aprovou'
);
SELECT is_empty($$ SELECT id FROM public.audit_events $$, 'AC-20: o cliente não lê a linha do tempo (audit_events)');
SELECT is_empty(
  $$ SELECT id FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000c1' $$,
  'AC-20: o cliente não lê o perfil do CEO que aprovou'
);

-- AC-09: o cliente não escreve, nem no que é dele -------------------------------------------------------------------
SELECT throws_ok(
  $$ UPDATE public.processes SET status = 'completed', completed_at = now()
      WHERE id = '00000000-0000-4000-8000-000000000101' $$,
  '42501', NULL, 'AC-09: o cliente não conclui o próprio processo por UPDATE direto'
);
SELECT throws_ok(
  $$ UPDATE public.process_stages SET status = 'completed', completed_at = now()
      WHERE id = '00000000-0000-4000-8000-000000000202' $$,
  '42501', NULL, 'AC-09: o cliente não avança a própria fase por UPDATE direto'
);
SELECT throws_ok(
  $$ INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)
     VALUES ('00000000-0000-4000-8000-000000000202', '00000000-0000-4000-8000-000000000101',
             '00000000-0000-4000-8000-0000000000a1') $$,
  '42501', NULL, 'AC-09: o cliente não se autoaprova por INSERT em stage_approvals'
);
SELECT throws_ok(
  $$ DELETE FROM public.processes WHERE id = '00000000-0000-4000-8000-000000000101' $$,
  '42501', NULL, 'AC-09: o cliente não apaga o próprio processo'
);
SELECT tests.clear_authentication();

-- AC-09: o outro login de A vê os mesmos dados do tenant -------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a2');
SELECT results_eq(
  $$ SELECT id FROM tests.panel_list('00000000-0000-4000-8000-00000000000a') $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000101'::uuid), ('00000000-0000-4000-8000-000000000103'::uuid),
            ('00000000-0000-4000-8000-000000000104'::uuid) $$,
  'AC-09: o tenant é do cliente, não do login: a2 lê a mesma lista de a1'
);
SELECT tests.clear_authentication();

-- F-83 residual (Onda 10.1 inverte): a senha temporária ainda por trocar, dentro das 72 h --------------------------------
-- O BFF recusa `/me/*` a este login (403 PASSWORD_CHANGE_REQUIRED, E-81), mas o RLS de leitura é pelo tenant da
-- sessão, não pela pendência: quem chama o PostgREST direto com o próprio JWT LÊ os processos do próprio cliente.
-- Estes dois asserts descrevem o estado de hoje, de propósito. A Onda 10.1 decide se a policy passa a exigir
-- `must_change_password = false`; quando passar, só estes dois viram `is_empty`.
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a4');
SELECT results_eq(
  $$ SELECT id FROM tests.panel_list('00000000-0000-4000-8000-00000000000a') $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000101'::uuid), ('00000000-0000-4000-8000-000000000103'::uuid),
            ('00000000-0000-4000-8000-000000000104'::uuid) $$,
  'F-83 residual (Onda 10.1 inverte): o login a4, com a senha temporária por trocar, lê a lista do próprio tenant pelo RLS'
);
SELECT isnt_empty(
  $$ SELECT id FROM public.process_stages WHERE process_id = '00000000-0000-4000-8000-000000000101' $$,
  'F-83 residual (Onda 10.1 inverte): o login a4 lê também as fases de um processo do próprio tenant'
);
SELECT is_empty(
  $$ SELECT id FROM tests.panel_list('00000000-0000-4000-8000-00000000000b') $$,
  'AC-09: e o login a4, mesmo lendo o que é do próprio tenant, não lê nada de B'
);
SELECT tests.clear_authentication();

-- E-34: a senha temporária com mais de 72 h não dá principal, então não lê nada ---------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a6');
SELECT is_empty(
  $$ SELECT id FROM tests.panel_list('00000000-0000-4000-8000-00000000000a') $$,
  'E-34: o login a6, com a senha temporária vencida (73 h), lê lista vazia no painel'
);
SELECT is_empty(
  $$ SELECT id FROM public.processes WHERE id = '00000000-0000-4000-8000-000000000101' $$,
  'E-34: o login a6 não lê o processo do próprio tenant pelo id'
);
SELECT is_empty(
  $$ SELECT id FROM public.process_stages $$,
  'E-34: o login a6 não lê fase alguma'
);
SELECT is(
  (SELECT count(*) FROM public.processes), 0::bigint,
  'E-34: o login a6 conta 0 processos (a contagem também é vazia)'
);
SELECT tests.clear_authentication();

-- AC-09: cliente B (login b1) ----------------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000b1');
SELECT results_eq(
  $$ SELECT id, total_stages, completed_stages, current_position
       FROM tests.panel_list('00000000-0000-4000-8000-00000000000b') $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000102'::uuid, 2::bigint, 0::bigint, 1::smallint) $$,
  'AC-20: a lista do painel de B traz só o processo de B'
);
SELECT is_empty(
  $$ SELECT id FROM tests.panel_list('00000000-0000-4000-8000-00000000000a') $$,
  'AC-09: a lista do painel com o id de A no filtro de tenant é vazia para B'
);
SELECT is_empty(
  $$ SELECT id FROM public.processes WHERE id IN (
       '00000000-0000-4000-8000-000000000101', '00000000-0000-4000-8000-000000000103',
       '00000000-0000-4000-8000-000000000104') $$,
  'AC-09, E-05: os processos de A, pelos ids, não existem para B'
);
SELECT is(
  (SELECT count(*) FROM public.process_stages WHERE process_id = '00000000-0000-4000-8000-000000000101'),
  0::bigint,
  'AC-09: a contagem das fases de um processo de A dá 0 para B'
);
SELECT results_eq(
  $$ SELECT id FROM public.processes
      WHERE created_at = '2026-03-03 10:00:00+00' AND id >= '00000000-0000-4000-8000-000000000101'
      ORDER BY id LIMIT 5 $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000102'::uuid) $$,
  'AC-09: o espelho do keyset sem filtro de tenant: B lê só o 102, e o RLS tira o 101 e o 103, que são de A'
);
SELECT tests.clear_authentication();

-- AC-09: cliente sem nenhum processo (login d1) ------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000d1');
SELECT is_empty(
  $$ SELECT id FROM tests.panel_list('00000000-0000-4000-8000-00000000000d') $$,
  'AC-20: um cliente sem processos tem a lista do painel vazia (e não um erro)'
);
SELECT is(
  (SELECT count(*) FROM public.processes), 0::bigint,
  'AC-09: o cliente D, sem processos, não lê nem os dos outros clientes'
);
SELECT is(
  (SELECT count(*) FROM public.process_stages), 0::bigint,
  'AC-09: o cliente D não lê fase alguma'
);
SELECT tests.clear_authentication();

-- E-08: login desativado e sessão expirada leem lista vazia, sem erro --------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a3');
SELECT is_empty(
  $$ SELECT id FROM tests.panel_list('00000000-0000-4000-8000-00000000000a') $$,
  'E-08: o login desativado de A, com JWT ainda válido, lê lista vazia no painel'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a5');
SELECT is_empty(
  $$ SELECT id FROM tests.panel_list('00000000-0000-4000-8000-00000000000a') $$,
  'E-08: a sessão expirada de A lê lista vazia no painel'
);
SELECT tests.clear_authentication();

-- AC-21: um CEO sem atestado não lê pelas formas do painel; o atestado é o controle positivo --------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2', false);
SELECT is_empty(
  $$ SELECT id FROM tests.panel_list('00000000-0000-4000-8000-00000000000a') $$,
  'AC-21: CEO com aal2 sem atestado (o claim obtido direto no Auth) lê lista vazia, mesmo com o id de A'
);
SELECT is_empty(
  $$ SELECT id FROM public.process_stages $$,
  'AC-21: CEO com aal2 sem atestado não lê fase alguma'
);
SELECT is(
  (SELECT private.current_client_id()), NULL::uuid,
  'AC-21: um CEO não tem tenant: current_client_id() é nulo'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT is_empty(
  $$ SELECT id FROM tests.panel_list('00000000-0000-4000-8000-00000000000a') $$,
  'AC-21: CEO aal1 lê lista vazia, mesmo com o id de A'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT id FROM tests.panel_list('00000000-0000-4000-8000-00000000000a') $$,
  $$ VALUES ('00000000-0000-4000-8000-000000000101'::uuid), ('00000000-0000-4000-8000-000000000103'::uuid),
            ('00000000-0000-4000-8000-000000000104'::uuid) $$,
  'AC-21: controle positivo: o CEO atestado lê a lista de A pelo RLS de CEO (as linhas existem; os vazios acima valem)'
);
SELECT tests.clear_authentication();

-- AC-10: anon não lê as duas tabelas do painel ----------------------------------------------------------------------------
SET LOCAL ROLE anon;
SELECT throws_ok($$ SELECT id FROM public.processes $$, '42501', NULL, 'AC-10: anon não lê processes');
SELECT throws_ok($$ SELECT id FROM public.process_stages $$, '42501', NULL, 'AC-10: anon não lê process_stages');
RESET ROLE;

SELECT * FROM finish();
ROLLBACK;
