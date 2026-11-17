-- Onda 8: create_process e update_process (spec §3.6, §3.7). Cobre: privilégios e search_path das funções
-- (AC-25), anon (AC-10), cliente com aal1 e com aal2 no JWT (AC-08, AC-09: não executa nem lê outro
-- cliente), CEO aal1, CEO aal2 sem fator TOTP verificado (F-24), CEO com sessão morta ou desativado, CEO
-- com `aal2` SEM atestado (Onda 6.1: o claim obtido direto no Auth não vale) com o controle positivo logo
-- depois, escrita direta negada, a autorização antes de qualquer trabalho com a entrada (F-55), o caminho
-- feliz (AC-15: template ou fases informadas, a fase 1 in_progress), I1 (de 1 a 30 fases, posições
-- contíguas), as regras de texto iguais às do Zod no título, no nome e na descrição da fase, na criação E
-- na atualização (E-30, F-52: espaços Unicode, fillers, só pontuação), cliente inexistente ou arquivado
-- (E-16), a máquina de estados do update_process (AC-19, I3, I4), a idempotência das mudanças, a auditoria
-- gravada na mesma transação (ator, papel, recurso, cliente, processo, request_id, sem título nem nome) e o
-- isolamento por tenant das linhas que as funções criam (AC-09).
BEGIN;
SELECT plan(389);

-- arrange (como postgres) --------------------------------------------------------------------------
-- A e B são clientes ativos; X é arquivado. a1 é login de A e b1, de B. c1 é CEO com fator verificado; c2,
-- CEO sem fator; c3, CEO com fator e sessão apagada; c4, CEO com fator e perfil desativado; c5, CEO com fator
-- que NUNCA é atestado pelos helpers (só o claim aal2 aparece): o que se obtém direto no Auth. O c5 é atestado
-- no controle positivo, então c6 faz o mesmo papel no fim, quando já existem linhas para ele não ver.
INSERT INTO public.clients (id, name, archived_at) VALUES
  ('00000000-0000-4000-8000-00000000000a', 'Cliente A', NULL),
  ('00000000-0000-4000-8000-00000000000b', 'Cliente B', NULL),
  ('00000000-0000-4000-8000-00000000000c', 'Cliente X', now() - interval '3 days');

SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000b1', 'client', '00000000-0000-4000-8000-00000000000b');
-- os logins de A e de B são clientes plenamente ativos (senha definitiva): com a senha temporária o RLS não lê
-- processo nem fase (F-83, arquivo 020), e aqui o que se prova é o isolamento entre clientes
UPDATE public.profiles SET must_change_password = false WHERE id IN (
  '00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000b1'
);
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c2', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c3', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c4', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c5', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c6', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c3');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c4');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c5');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c6');
DELETE FROM auth.sessions WHERE id = '00000000-0000-4000-8000-0000000000c3';
UPDATE public.profiles SET disabled_at = now() WHERE id = '00000000-0000-4000-8000-0000000000c4';

-- Dois processos que já terminaram, para provar que só o processo ativo muda (I3, I4): um concluído (com a
-- aprovação da única fase, I5) e um cancelado no meio (a fase 1 concluída, a 2 ainda em andamento: congelada).
INSERT INTO public.processes (id, client_id, title, status, version, completed_at, created_at, updated_at) VALUES
  ('00000000-0000-4000-8000-0000000001c1', '00000000-0000-4000-8000-00000000000a', 'Processo concluido', 'completed', 2,
   now() - interval '1 day', now() - interval '3 days', now() - interval '1 day');
INSERT INTO public.process_stages (id, process_id, position, name, status, started_at, completed_at) VALUES
  ('00000000-0000-4000-8000-0000000002c1', '00000000-0000-4000-8000-0000000001c1', 1, 'Unica', 'completed',
   now() - interval '3 days', now() - interval '1 day');
INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by) VALUES
  ('00000000-0000-4000-8000-0000000002c1', '00000000-0000-4000-8000-0000000001c1', '00000000-0000-4000-8000-0000000000c1');
INSERT INTO public.processes (id, client_id, title, status, version, cancelled_at, created_at, updated_at) VALUES
  ('00000000-0000-4000-8000-0000000001c2', '00000000-0000-4000-8000-00000000000a', 'Processo cancelado', 'cancelled', 3,
   now() - interval '1 day', now() - interval '3 days', now() - interval '1 day');
INSERT INTO public.process_stages (id, process_id, position, name, status, started_at, completed_at) VALUES
  ('00000000-0000-4000-8000-0000000002c2', '00000000-0000-4000-8000-0000000001c2', 1, 'Feita', 'completed',
   now() - interval '3 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000002c3', '00000000-0000-4000-8000-0000000001c2', 2, 'Parada', 'in_progress',
   now() - interval '2 days', NULL);
INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by) VALUES
  ('00000000-0000-4000-8000-0000000002c2', '00000000-0000-4000-8000-0000000001c2', '00000000-0000-4000-8000-0000000000c1');

-- Textos que o Zod (`visibleText`) recusa e que o banco também tem de recusar: no título, no nome e na
-- descrição da fase, na criação e na atualização (um por linha; o NULL só vale onde NULL é "não mexe").
CREATE TEMP TABLE bad_texts (label text PRIMARY KEY, value text);
INSERT INTO bad_texts (label, value) VALUES
  ('nulo', NULL),
  ('vazio', ''),
  ('so espacos', '   '),
  ('so NBSP', chr(160)),
  ('so U+3000', chr(12288)),
  ('so BOM', chr(65279)),
  ('so filler Hangul U+3164', chr(12644)),
  ('filler Hangul no meio', 'a' || chr(12644) || 'b'),
  ('filler U+115F', chr(4447) || 'a'),
  ('filler U+1160', 'a' || chr(4448)),
  ('filler U+FFA0', 'a' || chr(65440)),
  ('filler Khmer U+17B4', 'a' || chr(6068)),
  ('braille em branco U+2800', 'a' || chr(10240)),
  ('so pontuacao', '***'),
  ('so travessoes e ponto medio', chr(8212) || ' ' || chr(183) || ' ' || chr(8212)),
  ('so espacos e pontuacao', ' . , '),
  ('so emoji', chr(128512)),
  ('161 caracteres', repeat('a', 161)),
  ('acima de 16 KiB', repeat('a', 20000)),
  ('quebra de linha', 'Linha' || chr(10) || 'dupla'),
  ('tabulacao interna', 'a' || chr(9) || 'b'),
  ('NEL interno U+0085', 'a' || chr(133) || 'b'),
  ('separador de linha U+2028', 'a' || chr(8232) || 'b'),
  ('largura zero U+200B', 'Zero' || chr(8203) || 'width'),
  ('override bidi U+202E', 'Bidi' || chr(8238) || 'override'),
  ('BOM no meio', 'Bom' || chr(65279) || 'marca'),
  ('hifen suave U+00AD', 'a' || chr(173) || 'b');
GRANT SELECT ON bad_texts TO authenticated;

-- Textos que o Zod aceita (e como ficam guardados).
CREATE TEMP TABLE good_texts (label text PRIMARY KEY, value text NOT NULL, expected text NOT NULL);
INSERT INTO good_texts (label, value, expected) VALUES
  ('espacos nas pontas', '  Processo Novo  ', 'Processo Novo'),
  ('NBSP e U+3000 nas pontas', chr(160) || 'Acme' || chr(12288), 'Acme'),
  ('BOM nas pontas', chr(65279) || 'Acme BOM' || chr(65279), 'Acme BOM'),
  ('NFC (e + acento combinante)', 'Cafe' || chr(769), 'Caf' || chr(233)),
  ('japones', chr(26085) || chr(26412), chr(26085) || chr(26412)),
  ('grego', chr(913) || chr(946) || chr(947), chr(913) || chr(946) || chr(947)),
  ('pontuacao com letras', 'A&B - Consultoria (S/A)', 'A&B - Consultoria (S/A)'),
  ('so numeros', '2026', '2026'),
  ('160 caracteres', repeat('a', 160), repeat('a', 160));
GRANT SELECT ON good_texts TO authenticated;

-- Os processos que o teste cria, por apelido: o título muda nas atualizações, o id não.
CREATE TEMP TABLE proc (label text PRIMARY KEY, id uuid NOT NULL);
GRANT SELECT ON proc TO authenticated;

-- Como o PostgREST faz: o app manda o id da requisição, e a auditoria o guarda.
SELECT tests.set_request_id('req-procs-0001');

-- AC-25: privilégios e configuração das funções ------------------------------------------------------
SELECT ok(
  (SELECT p.prosecdef FROM pg_proc p WHERE p.oid = 'public.create_process(uuid, text, jsonb)'::regprocedure),
  'create_process: SECURITY DEFINER'
);
SELECT ok(
  (SELECT p.prosecdef FROM pg_proc p WHERE p.oid = 'public.update_process(uuid, text, boolean)'::regprocedure),
  'update_process: SECURITY DEFINER'
);
SELECT ok(
  (SELECT 'search_path=""' = ANY (p.proconfig) FROM pg_proc p WHERE p.oid = 'public.create_process(uuid, text, jsonb)'::regprocedure),
  'AC-25: create_process tem search_path vazio'
);
SELECT ok(
  (SELECT 'search_path=""' = ANY (p.proconfig) FROM pg_proc p WHERE p.oid = 'public.update_process(uuid, text, boolean)'::regprocedure),
  'AC-25: update_process tem search_path vazio'
);
SELECT ok(
  NOT has_function_privilege('anon', 'public.create_process(uuid, text, jsonb)', 'EXECUTE'),
  'AC-10: anon não executa create_process'
);
SELECT ok(
  NOT has_function_privilege('anon', 'public.update_process(uuid, text, boolean)', 'EXECUTE'),
  'AC-10: anon não executa update_process'
);
SELECT ok(
  has_function_privilege('authenticated', 'public.create_process(uuid, text, jsonb)', 'EXECUTE'),
  'create_process: authenticated executa (a checagem de CEO aal2 atestado é por dentro)'
);
SELECT ok(
  has_function_privilege('authenticated', 'public.update_process(uuid, text, boolean)', 'EXECUTE'),
  'update_process: authenticated executa (a checagem de CEO aal2 atestado é por dentro)'
);
SELECT ok(
  NOT has_function_privilege('service_role', 'public.create_process(uuid, text, jsonb)', 'EXECUTE'),
  'SEC-04: service_role não executa create_process (nem a secret key escreve processo de negócio)'
);
SELECT ok(
  NOT has_function_privilege('service_role', 'public.update_process(uuid, text, boolean)', 'EXECUTE'),
  'SEC-04: service_role não executa update_process'
);
SELECT is_empty(
  $$ SELECT p.proname
       FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE p.oid IN ('public.create_process(uuid, text, jsonb)'::regprocedure,
                      'public.update_process(uuid, text, boolean)'::regprocedure)
        AND a.grantee = 0 AND a.privilege_type = 'EXECUTE' $$,
  'AC-25: create_process e update_process não concedem EXECUTE a PUBLIC'
);
SELECT is(
  (SELECT p.prorettype::regtype::text FROM pg_proc p WHERE p.oid = 'public.create_process(uuid, text, jsonb)'::regprocedure),
  'processes',
  'create_process devolve a linha de processes (sem título em metadados nem texto de erro)'
);

-- Os travamentos, no catálogo (a concorrência em si não se prova num teste de uma sessão só): o cliente é
-- travado com FOR NO KEY UPDATE em create_process (criar e arquivar se serializam, E-16) e o processo, em
-- update_process (as escritas do mesmo processo se serializam, a aprovação da Onda 9 inclusive). Nenhuma das
-- duas usa FOR UPDATE, que bloquearia quem só referencia a linha por chave estrangeira.
SELECT ok(
  (SELECT p.prosrc ~ 'FROM public\.clients c\s+WHERE c\.id = p_client_id\s+FOR NO KEY UPDATE'
     FROM pg_proc p WHERE p.oid = 'public.create_process(uuid, text, jsonb)'::regprocedure),
  'E-16: create_process trava a linha de public.clients com FOR NO KEY UPDATE'
);
SELECT ok(
  (SELECT p.prosrc ~ 'FROM public\.processes p\s+WHERE p\.id = p_process_id\s+FOR NO KEY UPDATE'
     FROM pg_proc p WHERE p.oid = 'public.update_process(uuid, text, boolean)'::regprocedure),
  'AC-19: update_process trava a linha de public.processes com FOR NO KEY UPDATE'
);
SELECT ok(
  (SELECT position('FOR NO KEY UPDATE' IN p.prosrc) < position('INSERT INTO public.processes' IN p.prosrc)
          AND position('FOR NO KEY UPDATE' IN p.prosrc) > 0
     FROM pg_proc p WHERE p.oid = 'public.create_process(uuid, text, jsonb)'::regprocedure),
  'E-16: create_process trava o cliente ANTES de inserir o processo'
);
SELECT ok(
  (SELECT position('FOR NO KEY UPDATE' IN p.prosrc) < position('UPDATE public.processes p' IN p.prosrc)
          AND position('FOR NO KEY UPDATE' IN p.prosrc) > 0
     FROM pg_proc p WHERE p.oid = 'public.update_process(uuid, text, boolean)'::regprocedure),
  'AC-19: update_process trava o processo ANTES de mudá-lo'
);
SELECT is_empty(
  $$ SELECT p.proname FROM pg_proc p
      WHERE p.oid IN ('public.create_process(uuid, text, jsonb)'::regprocedure,
                      'public.update_process(uuid, text, boolean)'::regprocedure)
        AND p.prosrc ~ 'FOR\s+UPDATE\M' $$,
  'create_process e update_process não usam FOR UPDATE (só FOR NO KEY UPDATE)'
);
SELECT ok(
  (SELECT p.prosrc ~ 'IF private\.is_ceo\(\) IS NOT TRUE THEN' FROM pg_proc p WHERE p.oid = 'public.create_process(uuid, text, jsonb)'::regprocedure)
  AND (SELECT p.prosrc ~ 'IF private\.is_ceo\(\) IS NOT TRUE THEN' FROM pg_proc p WHERE p.oid = 'public.update_process(uuid, text, boolean)'::regprocedure),
  'F-55: as duas funções abrem com IF private.is_ceo() IS NOT TRUE'
);

-- AC-10: anon ------------------------------------------------------------------------------------------
SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo do anon') $$,
  '42501', NULL, 'AC-10: anon não executa create_process'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c1', 'Renomeado pelo anon', NULL) $$,
  '42501', NULL, 'AC-10: anon não executa update_process'
);
SELECT throws_ok(
  $$ SELECT id FROM public.processes $$,
  '42501', NULL, 'AC-10: anon não lê processes'
);
SELECT throws_ok(
  $$ SELECT id FROM public.process_stages $$,
  '42501', NULL, 'AC-10: anon não lê process_stages'
);
RESET ROLE;

-- AC-08, AC-09: cliente A ----------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo do cliente') $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não executa create_process nem no próprio tenant'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000b', 'Processo no outro cliente') $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não executa create_process no tenant de outro cliente'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c1', 'Renomeado pelo cliente', NULL) $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não executa update_process nem no processo do próprio tenant'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c2', NULL, true) $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não cancela processo'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title) VALUES ('00000000-0000-4000-8000-00000000000a', 'Escrita direta') $$,
  '42501', NULL, 'SEC-04: cliente não faz INSERT direto em processes'
);
SELECT throws_ok(
  $$ UPDATE public.processes SET title = 'Escrita direta' WHERE id = '00000000-0000-4000-8000-0000000001c1' $$,
  '42501', NULL, 'SEC-04: cliente não faz UPDATE direto em processes'
);
SELECT throws_ok(
  $$ DELETE FROM public.processes WHERE id = '00000000-0000-4000-8000-0000000001c1' $$,
  '42501', NULL, 'SEC-04: cliente não faz DELETE direto em processes'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name) VALUES ('00000000-0000-4000-8000-0000000001c1', 2, 'Direta') $$,
  '42501', NULL, 'SEC-04: cliente não faz INSERT direto em process_stages'
);
SELECT tests.clear_authentication();

-- AC-08: cliente com `aal2` no JWT (um claim que ele mesmo não deveria conseguir; vale a checagem de papel) ---
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo com aal2') $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente com aal2 no JWT não executa create_process'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c1', 'Renomeado com aal2', NULL) $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente com aal2 no JWT não executa update_process'
);
SELECT tests.clear_authentication();

-- AC-08: CEO com aal1 (fator verificado, mas sessão só com a senha) --------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo do CEO aal1') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 não executa create_process'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c1', 'Renomeado aal1', NULL) $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 não executa update_process'
);
SELECT is_empty($$ SELECT id FROM public.processes $$, 'AC-08: CEO aal1 não lê nenhum processo');
SELECT is_empty($$ SELECT id FROM public.process_stages $$, 'AC-08: CEO aal1 não lê nenhuma fase');
SELECT tests.clear_authentication();

-- F-24: CEO com aal2 no JWT, mas sem fator TOTP verificado --------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo sem fator') $$,
  '42501', 'FORBIDDEN', 'F-24: CEO aal2 sem fator verificado não executa create_process'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c1', 'Renomeado sem fator', NULL) $$,
  '42501', 'FORBIDDEN', 'F-24: CEO aal2 sem fator verificado não executa update_process'
);
SELECT is_empty($$ SELECT id FROM public.processes $$, 'F-24: CEO aal2 sem fator não lê nenhum processo');
SELECT tests.clear_authentication();

-- E-08: CEO aal2 com fator, mas sessão apagada, ou com perfil desativado -----------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo da sessão morta') $$,
  '42501', 'FORBIDDEN', 'E-08: CEO com a sessão apagada não executa create_process'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c1', 'Renomeado sem sessão', NULL) $$,
  '42501', 'FORBIDDEN', 'E-08: CEO com a sessão apagada não executa update_process'
);
SELECT is_empty($$ SELECT id FROM public.processes $$, 'E-08: CEO com a sessão apagada não lê nenhum processo');
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c4', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo do CEO desativado') $$,
  '42501', 'FORBIDDEN', 'E-08: CEO desativado não executa create_process'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c1', 'Renomeado desativado', NULL) $$,
  '42501', 'FORBIDDEN', 'E-08: CEO desativado não executa update_process'
);
SELECT is_empty($$ SELECT id FROM public.processes $$, 'E-08: CEO desativado não lê nenhum processo');
SELECT tests.clear_authentication();

-- AC-08, F-50 b: CEO com `aal2` no JWT e SEM atestado do backend (o que se obtém direto no Auth) ---------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c5', 'aal2', false);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo sem atestado') $$,
  '42501', 'FORBIDDEN', 'F-50 b: CEO com aal2 sem atestado não executa create_process'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c1', 'Renomeado sem atestado', NULL) $$,
  '42501', 'FORBIDDEN', 'F-50 b: CEO com aal2 sem atestado não executa update_process'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c1', NULL, true) $$,
  '42501', 'FORBIDDEN', 'F-50 b: CEO com aal2 sem atestado não cancela processo'
);
SELECT is_empty($$ SELECT id FROM public.processes $$, 'F-50 b: CEO com aal2 sem atestado não lê nenhum processo');
SELECT is_empty($$ SELECT id FROM public.process_stages $$, 'F-50 b: CEO com aal2 sem atestado não lê nenhuma fase');
SELECT is_empty($$ SELECT process_id FROM public.stage_approvals $$, 'F-50 b: CEO com aal2 sem atestado não lê nenhuma aprovação');
SELECT is_empty($$ SELECT position FROM public.default_stage_template $$, 'F-50 b: CEO com aal2 sem atestado não lê o template');
SELECT tests.clear_authentication();
-- controle positivo: a MESMA sessão, agora atestada pelo caminho real, passa (o que negou foi a falta do atestado)
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c5', 'aal2');
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo depois do atestado') $$,
  'F-50 b: a mesma sessão, depois de atestada, executa create_process'
);
SELECT lives_ok(
  $$ SELECT * FROM public.update_process((SELECT id FROM public.processes WHERE title = 'Processo depois do atestado'), 'Processo atestado') $$,
  'F-50 b: a mesma sessão, depois de atestada, executa update_process'
);
SELECT tests.clear_authentication();

-- F-55: a autorização vem antes de qualquer trabalho com a entrada (uma entrada inválida não muda a resposta) ---
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', repeat('a', 20000)) $$,
  '42501', 'FORBIDDEN', 'F-55: cliente com um título enorme recebe FORBIDDEN, não INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '"nao e lista"'::jsonb) $$,
  '42501', 'FORBIDDEN', 'F-55: cliente com fases que não são uma lista recebe FORBIDDEN, não INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000dead', 'Titulo') $$,
  '42501', 'FORBIDDEN', 'F-55: cliente com um cliente inexistente recebe FORBIDDEN, não NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c1', chr(10), NULL) $$,
  '42501', 'FORBIDDEN', 'F-55: cliente com um título inválido recebe FORBIDDEN, não INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-00000000dead', NULL, NULL) $$,
  '42501', 'FORBIDDEN', 'F-55: cliente com um processo inexistente recebe FORBIDDEN, não NOT_FOUND'
);
SELECT tests.clear_authentication();

SELECT results_eq(
  $$ SELECT count(*)::int FROM public.processes $$,
  $$ VALUES (3) $$,
  'AC-08: nenhuma chamada negada criou processo (os 2 de fixture e o do controle positivo)'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.audit_events WHERE action LIKE 'process.%' $$,
  $$ VALUES (2) $$,
  'AC-08: nenhuma chamada negada gravou auditoria (só o controle positivo: criou e renomeou)'
);

-- AC-15: CEO aal2 atestado, criação com o template -----------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');

SELECT results_eq(
  $$ SELECT title, status::text, version, client_id, completed_at IS NULL, cancelled_at IS NULL
       FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo Um') $$,
  $$ VALUES ('Processo Um', 'active', 1, '00000000-0000-4000-8000-00000000000a'::uuid, true, true) $$,
  'AC-15: create_process devolve o processo ativo, versão 1, do cliente'
);
SELECT results_eq(
  $$ SELECT s.name, s.description
       FROM public.process_stages s
       JOIN public.processes p ON p.id = s.process_id AND p.title = 'Processo Um'
      ORDER BY s.position $$,
  $$ SELECT t.name, t.description FROM public.default_stage_template t ORDER BY t.position $$,
  'AC-15: sem fases, o processo copia o template padrão, com nomes e descrições, na ordem'
);
SELECT results_eq(
  $$ SELECT s.position::int, s.status::text
       FROM public.process_stages s
       JOIN public.processes p ON p.id = s.process_id AND p.title = 'Processo Um'
      ORDER BY s.position $$,
  $$ SELECT t.position::int, CASE WHEN t.position = (SELECT min(position) FROM public.default_stage_template)
                                  THEN 'in_progress' ELSE 'pending' END
       FROM public.default_stage_template t ORDER BY t.position $$,
  'AC-15, I1, I2: as posições são de 1 a n e só a fase 1 começa in_progress, as outras pending'
);
SELECT results_eq(
  $$ SELECT s.started_at = p.created_at, s.completed_at IS NULL
       FROM public.process_stages s
       JOIN public.processes p ON p.id = s.process_id AND p.title = 'Processo Um'
      WHERE s.position = 1 $$,
  $$ VALUES (true, true) $$,
  'AC-15: a fase 1 começa no instante em que o processo nasce e não tem conclusão'
);
SELECT results_eq(
  $$ SELECT count(*)::int
       FROM public.process_stages s
       JOIN public.processes p ON p.id = s.process_id AND p.title = 'Processo Um'
      WHERE s.status = 'pending' AND (s.started_at IS NOT NULL OR s.completed_at IS NOT NULL) $$,
  $$ VALUES (0) $$,
  'AC-15: as fases pending não têm início nem conclusão'
);
SELECT is_empty(
  $$ SELECT a.id FROM public.stage_approvals a JOIN public.processes p ON p.id = a.process_id AND p.title = 'Processo Um' $$,
  'AC-15, I5: um processo novo não tem aprovação nenhuma'
);

-- AC-15: com as fases informadas ---------------------------------------------------------------------------------
-- (Cada criação e a leitura das fases são dois comandos: um comando que chama create_process e junta as
-- fases no mesmo SELECT não enxerga as linhas que a função acabou de gravar, que é o snapshot dele.)
SELECT lives_ok(
  $$ SELECT * FROM public.create_process(
       '00000000-0000-4000-8000-00000000000a', 'Processo Dois',
       '[{"name":"  Desenho  ","description":"Telas e fluxo"},{"name":"Entrega"},{"name":"Revisao","description":null}]'::jsonb) $$,
  'AC-15: create_process aceita fases informadas'
);
SELECT results_eq(
  $$ SELECT s.position::int, s.name, s.description, s.status::text
       FROM public.process_stages s
       JOIN public.processes p ON p.id = s.process_id AND p.title = 'Processo Dois'
      ORDER BY s.position $$,
  $$ VALUES (1, 'Desenho', 'Telas e fluxo', 'in_progress'),
            (2, 'Entrega', NULL, 'pending'),
            (3, 'Revisao', NULL, 'pending') $$,
  'AC-15, I1, I2: com fases informadas, vale a ordem do array, o nome é aparado, a descrição ausente ou null vira NULL'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.process_stages s
       JOIN public.processes p ON p.id = s.process_id AND p.title = 'Processo Dois' $$,
  $$ VALUES (3) $$,
  'AC-15: o template não é copiado quando as fases vêm informadas'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process(
       '00000000-0000-4000-8000-00000000000a', 'Processo de 30 fases',
       (SELECT jsonb_agg(jsonb_build_object('name', 'Fase ' || g) ORDER BY g) FROM generate_series(1, 30) g)) $$,
  'I1: create_process aceita 30 fases (o limite)'
);
SELECT results_eq(
  $$ SELECT count(*)::int, min(s.position)::int, max(s.position)::int, count(*) FILTER (WHERE s.status = 'in_progress')::int
       FROM public.process_stages s
       JOIN public.processes p ON p.id = s.process_id AND p.title = 'Processo de 30 fases' $$,
  $$ VALUES (30, 1, 30, 1) $$,
  'I1: 30 fases são guardadas, de 1 a 30, e só uma começa in_progress'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.process_stages s
       JOIN public.processes p ON p.id = s.process_id AND p.title = 'Processo de 30 fases'
      WHERE s.name <> 'Fase ' || s.position $$,
  $$ VALUES (0) $$,
  'I1: as 30 fases ficam na ordem do array'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process(
       '00000000-0000-4000-8000-00000000000a', 'Processo de 1 fase', '[{"name":"Unica"}]'::jsonb) $$,
  'I1, E-04: create_process aceita uma fase só (o mínimo)'
);
SELECT results_eq(
  $$ SELECT count(*)::int, count(*) FILTER (WHERE s.status = 'in_progress')::int
       FROM public.process_stages s
       JOIN public.processes p ON p.id = s.process_id AND p.title = 'Processo de 1 fase' $$,
  $$ VALUES (1, 1) $$,
  'I1, E-04: a fase única começa in_progress'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process(
       '00000000-0000-4000-8000-00000000000a', 'Processo com descricao longa',
       jsonb_build_array(jsonb_build_object('name', 'A', 'description', repeat('d', 2000)))) $$,
  'AC-15: create_process aceita uma descrição de 2000 caracteres (o limite)'
);
SELECT results_eq(
  $$ SELECT s.description
       FROM public.process_stages s
       JOIN public.processes p ON p.id = s.process_id AND p.title = 'Processo com descricao longa' $$,
  $$ VALUES (repeat('d', 2000)) $$,
  'AC-15: a descrição de 2000 caracteres é guardada inteira'
);

-- E-20, I1: listas que não valem ----------------------------------------------------------------------------------
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '[]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-20, I1: lista de fases vazia é recusada'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process(
       '00000000-0000-4000-8000-00000000000a', 'Titulo',
       (SELECT jsonb_agg(jsonb_build_object('name', 'Fase ' || g) ORDER BY g) FROM generate_series(1, 31) g)) $$,
  'P0001', 'INVALID_INPUT', 'E-20, I1: 31 fases são recusadas'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '{"name":"A"}'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-20: fases que são um objeto, e não uma lista, são recusadas'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '"A"'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-20: fases que são um texto são recusadas'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', 'null'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-20: o JSON null não é "sem fases" (sem fases é o parâmetro ausente)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '["A"]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-20: uma fase que não é objeto é recusada'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '[{"name":"A"},null]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-20: uma fase null é recusada'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '[{}]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-20: uma fase sem nome é recusada'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '[{"name":null}]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-20: uma fase com nome null é recusada'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '[{"name":42}]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-20: um nome que é número, e não texto, é recusado'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '[{"name":["A"]}]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-20: um nome que é lista é recusado'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '[{"name":"A","description":42}]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-20: uma descrição que é número é recusada'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '[{"name":"A","description":""}]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-63, E-20: o banco é mais estrito que a API e recusa a descrição vazia (a API a transforma em "sem descrição")'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '[{"name":"A","extra":1}]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-63, SEC-06: uma chave desconhecida na fase é recusada (como o .strict() do Zod)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '[{"name":"A","position":3}]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'SEC-06: a posição não vem do cliente (mass assignment)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '[{"name":"A","status":"completed"}]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'SEC-06: o status da fase não vem do cliente (mass assignment)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '[{"name":"A","id":"00000000-0000-4000-8000-0000000002ff"}]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'SEC-06: o id da fase não vem do cliente (mass assignment)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Titulo', '[{"name":"Boa"},{"name":"   "}]'::jsonb) $$,
  'P0001', 'INVALID_INPUT', 'E-20: um nome só de espaços na segunda fase recusa o processo inteiro'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process(
       '00000000-0000-4000-8000-00000000000a', 'Titulo',
       jsonb_build_array(jsonb_build_object('name', repeat('n', 121)))) $$,
  'P0001', 'INVALID_INPUT', 'E-20: um nome com 121 caracteres é recusado'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process(
       '00000000-0000-4000-8000-00000000000a', 'Titulo',
       jsonb_build_array(jsonb_build_object('name', 'A', 'description', repeat('d', 2001)))) $$,
  'P0001', 'INVALID_INPUT', 'E-20: uma descrição com 2001 caracteres é recusada'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process(
       '00000000-0000-4000-8000-00000000000a', 'Processo com nome de 120',
       jsonb_build_array(jsonb_build_object('name', repeat('n', 120)))) $$,
  'E-20: um nome com 120 caracteres (o limite) é aceito'
);

-- E-30, F-52: o título e as fases com as MESMAS regras do Zod, na criação -----------------------------------------
SELECT is(
  (SELECT c.title FROM public.create_process('00000000-0000-4000-8000-00000000000a', g.value) c), g.expected,
  'E-30: create_process aceita e guarda o título "' || g.label || '"'
) FROM good_texts g ORDER BY g.label;
SELECT throws_ok(
  format('SELECT * FROM public.create_process(%L, %L)', '00000000-0000-4000-8000-00000000000a', b.value),
  'P0001', 'INVALID_INPUT',
  'E-30: create_process recusa o título: ' || b.label
) FROM bad_texts b ORDER BY b.label;
SELECT lives_ok(
  format('SELECT * FROM public.create_process(%L, %L, %L::jsonb)', '00000000-0000-4000-8000-00000000000a',
         'Nome de fase ' || g.label, jsonb_build_array(jsonb_build_object('name', g.value))::text),
  'E-30: create_process aceita o nome de fase "' || g.label || '"'
) FROM good_texts g WHERE g.label <> '160 caracteres' ORDER BY g.label;
SELECT is(
  (SELECT s.name FROM public.process_stages s
     JOIN public.processes p ON p.id = s.process_id AND p.title = 'Nome de fase ' || g.label),
  g.expected,
  'E-30: create_process guarda o nome de fase "' || g.label || '" como o Zod o guarda'
) FROM good_texts g WHERE g.label <> '160 caracteres' ORDER BY g.label;
SELECT throws_ok(
  format('SELECT * FROM public.create_process(%L, %L, %L::jsonb)', '00000000-0000-4000-8000-00000000000a', 'Titulo',
         jsonb_build_array(jsonb_build_object('name', b.value))::text),
  'P0001', 'INVALID_INPUT',
  'E-30: create_process recusa o nome de fase: ' || b.label
) FROM bad_texts b ORDER BY b.label;
SELECT throws_ok(
  format('SELECT * FROM public.create_process(%L, %L, %L::jsonb)', '00000000-0000-4000-8000-00000000000a', 'Titulo',
         jsonb_build_array(jsonb_build_object('name', 'Boa', 'description', b.value))::text),
  'P0001', 'INVALID_INPUT',
  'E-30: create_process recusa a descrição de fase: ' || b.label
) FROM bad_texts b WHERE b.label NOT IN ('nulo', '161 caracteres') ORDER BY b.label;
SELECT lives_ok(
  format('SELECT * FROM public.create_process(%L, %L, %L::jsonb)', '00000000-0000-4000-8000-00000000000a',
         'Descricao de fase ' || g.label,
         jsonb_build_array(jsonb_build_object('name', 'Boa', 'description', g.value))::text),
  'E-30: create_process aceita a descrição de fase "' || g.label || '"'
) FROM good_texts g ORDER BY g.label;
SELECT is(
  (SELECT s.description FROM public.process_stages s
     JOIN public.processes p ON p.id = s.process_id AND p.title = 'Descricao de fase ' || g.label),
  g.expected,
  'E-30: create_process guarda a descrição de fase "' || g.label || '" como o Zod a guarda'
) FROM good_texts g ORDER BY g.label;

-- E-16: cliente inexistente ou arquivado ----------------------------------------------------------------------------
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000dead', 'Processo sem cliente') $$,
  'P0001', 'NOT_FOUND', 'create_process: cliente inexistente é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000c', 'Processo no arquivado') $$,
  'P0001', 'CLIENT_ARCHIVED', 'E-16: cliente arquivado é CLIENT_ARCHIVED'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000c', 'Processo no arquivado', '[{"name":"A"}]'::jsonb) $$,
  'P0001', 'CLIENT_ARCHIVED', 'E-16: cliente arquivado é CLIENT_ARCHIVED também com fases informadas'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process(NULL, 'Processo sem id') $$,
  'P0001', 'NOT_FOUND', 'create_process: o id de cliente nulo é NOT_FOUND'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo no ativo depois do arquivado') $$,
  'E-16: o cliente ativo continua aceitando processo'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo dos titulos') $$,
  'AC-15: um processo só para as atualizações de título (arrange)'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.processes WHERE title IN ('Processo no arquivado', 'Processo sem cliente') $$,
  $$ VALUES (0) $$,
  'E-16: cliente arquivado ou inexistente não ganhou processo'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.processes WHERE client_id = '00000000-0000-4000-8000-00000000000c' $$,
  $$ VALUES (0) $$,
  'E-16: o cliente arquivado segue sem nenhum processo'
);
SELECT tests.clear_authentication();

-- E-16: arquivar depois de ter processos não apaga nem muda os processos (só impede os novos) --------------------
UPDATE public.clients SET archived_at = now() WHERE id = '00000000-0000-4000-8000-00000000000b';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000b', 'Processo no recém arquivado') $$,
  'P0001', 'CLIENT_ARCHIVED', 'E-16: um cliente arquivado há um instante também recusa'
);
SELECT tests.clear_authentication();
UPDATE public.clients SET archived_at = NULL WHERE id = '00000000-0000-4000-8000-00000000000b';

INSERT INTO proc (label, id)
SELECT v.label, p.id
  FROM (VALUES ('um', 'Processo Um'), ('dois', 'Processo Dois'), ('trinta', 'Processo de 30 fases'),
               ('uma', 'Processo de 1 fase'), ('titulos', 'Processo dos titulos')) v (label, title)
  JOIN public.processes p ON p.title = v.title;
-- 'um' nasceu há dois dias, para provar quando `updated_at` mexe (dentro de uma transação o now() é um só).
UPDATE public.processes SET created_at = now() - interval '2 days', updated_at = now() - interval '2 days'
  WHERE id = (SELECT p.id FROM proc p WHERE p.label = 'um');

-- SEC-16: a auditoria de create_process, na mesma transação, sem título nem nome ------------------------------------
SELECT results_eq(
  $$ SELECT e.action, e.actor_id, e.actor_role::text, e.resource_type, e.resource_id = p.id,
            e.client_id = p.client_id, e.process_id = p.id, e.request_id, e.metadata
       FROM public.audit_events e
       JOIN public.processes p ON p.id = e.resource_id
      WHERE p.title = 'Processo Um' $$,
  $$ VALUES ('process.created', '00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'process',
             true, true, true, 'req-procs-0001', '{}'::jsonb) $$,
  'SEC-16: create_process grava process.created com ator, papel, recurso, cliente, processo e request_id'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.audit_events e JOIN public.processes p ON p.id = e.resource_id
      WHERE p.title = 'Processo Dois' $$,
  $$ VALUES (1) $$,
  'SEC-16: uma linha de auditoria por processo criado (e nenhuma por fase)'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.audit_events WHERE action = 'process.created' $$,
  $$ SELECT count(*)::int FROM public.processes WHERE id NOT IN ('00000000-0000-4000-8000-0000000001c1', '00000000-0000-4000-8000-0000000001c2') $$,
  'SEC-16: cada processo criado pelas funções tem o seu process.created, e os recusados não deixaram nenhum'
);
SELECT is_empty(
  $$ SELECT e.id FROM public.audit_events e JOIN public.processes p ON p.id = e.resource_id
      WHERE e.metadata::text LIKE '%' || p.title || '%' $$,
  'SEC-16: nenhum título de processo vai para os metadados da auditoria'
);
SELECT is_empty(
  $$ SELECT e.id FROM public.audit_events e WHERE e.resource_type = 'stage' AND e.action LIKE 'process.%' $$,
  'SEC-16: criar fases não grava evento de fase (a aprovação, na Onda 9, é que grava stage.approved)'
);

-- AC-19: update_process, renomear ----------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT tests.set_request_id('req-procs-0002');
SELECT results_eq(
  $$ SELECT title, status::text, version, updated_at = now(), created_at = now() - interval '2 days'
       FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'um'), '  Processo Um Renomeado ') $$,
  $$ VALUES ('Processo Um Renomeado', 'active', 2, true, true) $$,
  'AC-19: update_process renomeia (título aparado), mantém ativo, soma 1 à versão e move updated_at'
);
SELECT results_eq(
  $$ SELECT count(*)::int, count(*) FILTER (WHERE s.status = 'in_progress')::int
       FROM public.process_stages s JOIN public.processes p ON p.id = s.process_id AND p.id = (SELECT p.id FROM proc p WHERE p.label = 'um') $$,
  $$ SELECT count(*)::int, 1 FROM public.default_stage_template $$,
  'AC-19: renomear não mexe nas fases'
);
SELECT results_eq(
  $$ SELECT title, version, updated_at = now() FROM public.update_process(
       (SELECT p.id FROM proc p WHERE p.label = 'um'),
       chr(160) || 'Processo Um Renomeado' || chr(12288)) $$,
  $$ VALUES ('Processo Um Renomeado', 2, true) $$,
  'E-61, AC-19: renomear para o mesmo título (depois da normalização) não muda nada nem soma versão'
);
SELECT results_eq(
  $$ SELECT title, version FROM public.update_process(
       (SELECT p.id FROM proc p WHERE p.label = 'um'),
       'Processo Um Renomeado', NULL) $$,
  $$ VALUES ('Processo Um Renomeado', 2) $$,
  'AC-19: repetir o mesmo PATCH devolve o processo como está (o retry é seguro)'
);
SELECT results_eq(
  $$ SELECT title FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'um'), 'Cafe' || chr(769)) $$,
  $$ VALUES ('Caf' || chr(233)) $$,
  'E-30: update_process guarda o título em NFC'
);
SELECT is(
  (SELECT u.title FROM public.update_process(
     (SELECT p.id FROM proc p WHERE p.label = 'titulos'), g.value) u),
  g.expected,
  'E-30: update_process aceita e guarda o título "' || g.label || '"'
) FROM good_texts g ORDER BY g.label;

-- AC-19: cancelar ------------------------------------------------------------------------------------------------------
SELECT results_eq(
  $$ SELECT status::text, version, cancelled_at IS NOT NULL, completed_at IS NULL, title
       FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'dois'), NULL, true) $$,
  $$ VALUES ('cancelled', 2, true, true, 'Processo Dois') $$,
  'AC-19: update_process cancela: status cancelled, cancelled_at preenchido, versão +1, título intacto'
);
SELECT results_eq(
  $$ SELECT s.position::int, s.status::text, s.started_at IS NOT NULL, s.completed_at IS NULL
       FROM public.process_stages s JOIN public.processes p ON p.id = s.process_id AND p.id = (SELECT p.id FROM proc p WHERE p.label = 'dois')
      ORDER BY s.position $$,
  $$ VALUES (1, 'in_progress', true, true), (2, 'pending', false, true), (3, 'pending', false, true) $$,
  'I4: cancelar congela as fases como estavam (a fase em andamento continua em andamento)'
);
SELECT is_empty(
  $$ SELECT a.id FROM public.stage_approvals a JOIN public.processes p ON p.id = a.process_id AND p.id = (SELECT p.id FROM proc p WHERE p.label = 'dois') $$,
  'I4: cancelar não cria aprovação'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'dois'), NULL, true) $$,
  'P0001', 'PROCESS_NOT_ACTIVE', 'E-60, AC-19, I4: cancelar um processo já cancelado é PROCESS_NOT_ACTIVE (não é idempotente)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'dois'), 'Renomeado depois de cancelado') $$,
  'P0001', 'PROCESS_NOT_ACTIVE', 'AC-19, I4: renomear um processo cancelado é PROCESS_NOT_ACTIVE'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'dois'), 'Processo Dois') $$,
  'P0001', 'PROCESS_NOT_ACTIVE', 'E-60, I4: até um renome para o mesmo título é PROCESS_NOT_ACTIVE num processo cancelado'
);

-- renomear e cancelar na mesma chamada
SELECT results_eq(
  $$ SELECT title, status::text, version
       FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'uma'), 'Processo de 1 fase encerrado', true) $$,
  $$ VALUES ('Processo de 1 fase encerrado', 'cancelled', 2) $$,
  'E-61, AC-19: renomear e cancelar na mesma chamada soma 1 à versão, uma vez só'
);

-- I3, I4: processos que já terminaram (fixtures)
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c1', 'Renomeado concluido') $$,
  'P0001', 'PROCESS_NOT_ACTIVE', 'I3: renomear um processo concluído é PROCESS_NOT_ACTIVE'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c1', NULL, true) $$,
  'P0001', 'PROCESS_NOT_ACTIVE', 'I3: cancelar um processo concluído é PROCESS_NOT_ACTIVE'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001c2', 'Renomeado cancelado') $$,
  'P0001', 'PROCESS_NOT_ACTIVE', 'I4: renomear um processo cancelado (fixture) é PROCESS_NOT_ACTIVE'
);
SELECT results_eq(
  $$ SELECT p.title, p.status::text, p.version,
            (SELECT string_agg(s.status::text, ',' ORDER BY s.position) FROM public.process_stages s WHERE s.process_id = p.id)
       FROM public.processes p WHERE p.id IN ('00000000-0000-4000-8000-0000000001c1', '00000000-0000-4000-8000-0000000001c2')
      ORDER BY p.id $$,
  $$ VALUES ('Processo concluido', 'completed', 2, 'completed'),
            ('Processo cancelado', 'cancelled', 3, 'completed,in_progress') $$,
  'I3, I4: as recusas não mudaram nem o processo concluído nem o cancelado, nem as fases deles'
);

-- entrada inválida e processo inexistente
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'trinta'), NULL, NULL) $$,
  'P0001', 'INVALID_INPUT', 'update_process sem título e sem cancelamento é INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'trinta'), NULL, false) $$,
  'P0001', 'INVALID_INPUT', 'I4: p_cancel = false é INVALID_INPUT (não há caminho de volta)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'trinta'), 'Titulo', false) $$,
  'P0001', 'INVALID_INPUT', 'I4: renomear com p_cancel = false também é INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-00000000dead', 'Titulo') $$,
  'P0001', 'NOT_FOUND', 'update_process: processo inexistente é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process(NULL, 'Titulo') $$,
  'P0001', 'NOT_FOUND', 'update_process: o id nulo é NOT_FOUND'
);
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, NULL)',
         (SELECT p.id FROM proc p WHERE p.label = 'trinta'), b.value),
  'P0001', 'INVALID_INPUT',
  'E-30: update_process recusa o título: ' || b.label
) FROM bad_texts b ORDER BY b.label;
SELECT is(
  (SELECT p.title FROM public.processes p WHERE p.title = 'Processo de 30 fases'), 'Processo de 30 fases',
  'E-30: as atualizações recusadas deixaram o título como estava'
);
SELECT tests.clear_authentication();

-- SEC-16: a auditoria de update_process -----------------------------------------------------------------------------------
SELECT results_eq(
  $$ SELECT e.action, e.actor_id, e.actor_role::text, e.resource_type, e.resource_id = p.id,
            e.client_id = p.client_id, e.process_id = p.id, e.request_id, e.metadata
       FROM public.audit_events e JOIN public.processes p ON p.id = e.resource_id
      WHERE p.id = (SELECT p.id FROM proc p WHERE p.label = 'dois') AND e.action <> 'process.created' $$,
  $$ VALUES ('process.cancelled', '00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'process',
             true, true, true, 'req-procs-0002', '{}'::jsonb) $$,
  'SEC-16: cancelar grava process.cancelled com ator, papel, recurso, cliente, processo e request_id, sem metadados'
);
SELECT results_eq(
  $$ SELECT e.action, e.metadata
       FROM public.audit_events e JOIN public.processes p ON p.id = e.resource_id
      WHERE p.id = (SELECT p.id FROM proc p WHERE p.label = 'uma') AND e.action <> 'process.created'
      ORDER BY e.id $$,
  $$ VALUES ('process.updated', '{"fields":["title"]}'::jsonb), ('process.cancelled', '{}'::jsonb) $$,
  'SEC-16: renomear e cancelar na mesma chamada grava dois eventos, nessa ordem; renomear só diz que o título mudou'
);
SELECT results_eq(
  $$ SELECT e.action FROM public.audit_events e
      WHERE e.resource_id = (SELECT p.id FROM proc p WHERE p.label = 'um') ORDER BY e.id $$,
  $$ VALUES ('process.created'), ('process.updated'), ('process.updated') $$,
  'SEC-16: só as mudanças reais foram auditadas: os renomes para o mesmo título e o PATCH repetido não gravam nada'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.audit_events e
      WHERE e.resource_id = (SELECT p.id FROM proc p WHERE p.label = 'titulos') $$,
  $$ SELECT (1 + count(*))::int FROM good_texts $$,
  'SEC-16: o processo dos títulos tem o process.created e um process.updated por título aceito, e nenhum das recusas'
);
SELECT is_empty(
  $$ SELECT e.id FROM public.audit_events e
      WHERE e.resource_id IN ('00000000-0000-4000-8000-0000000001c1', '00000000-0000-4000-8000-0000000001c2') $$,
  'SEC-16: as recusas de PROCESS_NOT_ACTIVE não gravaram auditoria'
);
SELECT is_empty(
  $$ SELECT e.id FROM public.audit_events e
      WHERE e.action LIKE 'process.%' AND e.metadata::text <> '{}' AND e.metadata::text <> '{"fields": ["title"]}' $$,
  'SEC-16: os metadados dos eventos de processo são vazios ou só dizem que o título mudou'
);

-- SEC-04: escrita direta negada, também para o CEO aal2 atestado --------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title) VALUES ('00000000-0000-4000-8000-00000000000a', 'Direto') $$,
  '42501', NULL, 'SEC-04: nem o CEO aal2 faz INSERT direto em processes'
);
SELECT throws_ok(
  $$ UPDATE public.processes SET title = 'Direto' WHERE id = '00000000-0000-4000-8000-0000000001c1' $$,
  '42501', NULL, 'SEC-04: nem o CEO aal2 faz UPDATE direto em processes'
);
SELECT throws_ok(
  $$ DELETE FROM public.processes WHERE id = '00000000-0000-4000-8000-0000000001c1' $$,
  '42501', NULL, 'SEC-04: nem o CEO aal2 faz DELETE direto em processes'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name) VALUES ('00000000-0000-4000-8000-0000000001c1', 2, 'Direta') $$,
  '42501', NULL, 'SEC-04: nem o CEO aal2 faz INSERT direto em process_stages'
);
SELECT throws_ok(
  $$ UPDATE public.process_stages SET status = 'completed' WHERE id = '00000000-0000-4000-8000-0000000002c3' $$,
  '42501', NULL, 'SEC-04: nem o CEO aal2 faz UPDATE direto em process_stages'
);
SELECT throws_ok(
  $$ INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)
     VALUES ('00000000-0000-4000-8000-0000000002c3', '00000000-0000-4000-8000-0000000001c2', '00000000-0000-4000-8000-0000000000c1') $$,
  '42501', NULL, 'SEC-04: nem o CEO aal2 faz INSERT direto em stage_approvals (a aprovação, na Onda 9, é função)'
);
SELECT throws_ok(
  $$ INSERT INTO public.default_stage_template (position, name) VALUES (20, 'Direta') $$,
  '42501', NULL, 'SEC-04: nem o CEO aal2 altera o template (só migration)'
);
SELECT tests.clear_authentication();

-- AC-09: isolamento por tenant das linhas que as funções criam ------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000b', 'Processo do B', '[{"name":"Fase do B 1"},{"name":"Fase do B 2"}]'::jsonb) $$,
  'AC-09: o CEO cria um processo para o cliente B (arrange do isolamento)'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT results_eq(
  $$ SELECT DISTINCT client_id FROM public.processes $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000a'::uuid) $$,
  'AC-09: o cliente A lê processos só do próprio tenant, os que o CEO criou inclusive'
);
SELECT is_empty(
  $$ SELECT id FROM public.processes WHERE title = 'Processo do B' $$,
  'AC-09: o cliente A não vê o processo que o CEO criou para B'
);
SELECT is_empty(
  $$ SELECT s.id FROM public.process_stages s JOIN public.processes p ON p.id = s.process_id WHERE p.client_id = '00000000-0000-4000-8000-00000000000b' $$,
  'AC-09: o cliente A não vê as fases do processo de B'
);
SELECT is_empty(
  $$ SELECT id FROM public.process_stages WHERE name LIKE 'Fase do B%' $$,
  'AC-09: o cliente A não acha as fases de B nem pelo nome'
);
SELECT results_eq(
  $$ SELECT count(*)::int > 0 FROM public.process_stages WHERE process_id = (SELECT p.id FROM proc p WHERE p.label = 'dois') $$,
  $$ VALUES (true) $$,
  'AC-09: o cliente A lê as fases dos processos do próprio tenant'
);
SELECT is_empty($$ SELECT id FROM public.stage_approvals $$, 'AC-09: o cliente A não lê nenhuma aprovação, nem a do próprio processo');
SELECT is_empty($$ SELECT position FROM public.default_stage_template $$, 'AC-09: o cliente A não lê o template');
SELECT is_empty($$ SELECT id FROM public.audit_events $$, 'AC-09: o cliente A não lê a auditoria dos processos');
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000b1');
SELECT results_eq(
  $$ SELECT title FROM public.processes ORDER BY title $$,
  $$ VALUES ('Processo do B') $$,
  'AC-09: o cliente B lê só o próprio processo'
);
SELECT results_eq(
  $$ SELECT name FROM public.process_stages ORDER BY position $$,
  $$ VALUES ('Fase do B 1'), ('Fase do B 2') $$,
  'AC-09: o cliente B lê só as fases do próprio processo, em ordem'
);
SELECT is_empty(
  $$ SELECT id FROM public.processes WHERE client_id = '00000000-0000-4000-8000-00000000000a' $$,
  'AC-09: o cliente B não vê os processos de A'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT count(DISTINCT client_id)::int FROM public.processes $$,
  $$ VALUES (2) $$,
  'AC-09: o CEO aal2 atestado lê os processos de todos os clientes'
);
SELECT results_eq(
  $$ SELECT count(*)::int > 0 FROM public.default_stage_template $$,
  $$ VALUES (true) $$,
  'o CEO aal2 atestado lê o template'
);
SELECT tests.clear_authentication();

-- F-50 b: depois de tudo, o CEO sem atestado continua sem ver as linhas que as funções criaram --------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c6', 'aal2', false);
SELECT is_empty($$ SELECT id FROM public.processes $$, 'F-50 b: o CEO com aal2 sem atestado não lê nenhum dos processos que as funções criaram');
SELECT is_empty($$ SELECT id FROM public.process_stages $$, 'F-50 b: o CEO com aal2 sem atestado não lê nenhuma das fases que as funções criaram');
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'trinta'), 'Renomeado sem atestado') $$,
  '42501', 'FORBIDDEN', 'F-50 b: o CEO com aal2 sem atestado não renomeia um processo que existe'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'trinta'), NULL, true) $$,
  '42501', 'FORBIDDEN', 'F-50 b: o CEO com aal2 sem atestado não cancela um processo que existe'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2');
SELECT is_empty($$ SELECT id FROM public.processes $$, 'F-24: o CEO aal2 sem fator verificado continua sem ver processo nenhum');
SELECT tests.clear_authentication();

-- F-86: o template aceita só o texto que a API aceita, já normalizado (como postgres: nenhum papel da API escreve nele) -----------------
SELECT ok(
  (SELECT bool_and(c.convalidated) AND count(*) = 2
     FROM pg_constraint c
    WHERE c.conrelid = 'public.default_stage_template'::regclass
      AND c.conname IN ('default_stage_template_name_visible_ck', 'default_stage_template_description_visible_ck')),
  'F-86: os dois CHECKs de texto do template existem e foram validados contra as linhas do seed'
);
SELECT is_empty(
  $$ SELECT t.position FROM public.default_stage_template t
      WHERE private.visible_text(t.name, 120) IS DISTINCT FROM t.name
         OR (t.description IS NOT NULL AND private.visible_text(t.description, 2000) IS DISTINCT FROM t.description) $$,
  'F-86: o seed do template (Q-01) passa pelas mesmas regras do Zod e já está normalizado'
);
SELECT throws_ok(
  format('INSERT INTO public.default_stage_template (position, name) VALUES (20, %L)', b.value),
  '23514', NULL,
  'F-86: o template recusa o nome: ' || b.label
) FROM bad_texts b WHERE b.label <> 'nulo' ORDER BY b.label;
SELECT throws_ok(
  format('INSERT INTO public.default_stage_template (position, name, description) VALUES (20, %L, %L)', 'Boa', b.value),
  '23514', NULL,
  'F-86: o template recusa a descrição: ' || b.label
) FROM bad_texts b WHERE b.label NOT IN ('nulo', '161 caracteres') ORDER BY b.label;
SELECT throws_ok(
  $$ INSERT INTO public.default_stage_template (position, name) VALUES (20, '  Com espacos nas pontas  ') $$,
  '23514', NULL, 'F-86: o template recusa um nome que o Zod apararia (o que entra no template é copiado como está)'
);
SELECT throws_ok(
  $$ INSERT INTO public.default_stage_template (position, name) VALUES (20, 'Cafe' || chr(769)) $$,
  '23514', NULL, 'F-86: o template recusa um nome fora do NFC'
);
SELECT throws_ok(
  $$ INSERT INTO public.default_stage_template (position, name, description) VALUES (20, 'Boa', '  Descricao com espacos  ') $$,
  '23514', NULL, 'F-86: o template recusa uma descrição com espaços nas pontas'
);
SELECT lives_ok(
  $$ INSERT INTO public.default_stage_template (position, name, description)
     VALUES (20, 'Etapa extra', 'Descricao ok'), (21, chr(26085) || chr(26412), NULL) $$,
  'F-86: o template aceita nome e descrição que a API aceita (japonês incluso)'
);
DELETE FROM public.default_stage_template WHERE position IN (20, 21);

-- Template com buracos nas posições: as fases do processo continuam de 1 a n (I1) ----------------------------------------------------------
DELETE FROM public.default_stage_template WHERE position IN (2, 4);
UPDATE public.default_stage_template SET position = 9 WHERE position = 6;
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo do template com buracos') $$,
  'I1: create_process aceita um template com buracos nas posições'
);
SELECT results_eq(
  $$ SELECT s.position::int, s.name, s.status::text
       FROM public.process_stages s
       JOIN public.processes p ON p.id = s.process_id AND p.title = 'Processo do template com buracos'
      ORDER BY s.position $$,
  $$ VALUES (1, 'Contrato assinado', 'in_progress'), (2, 'Planejamento', 'pending'),
            (3, 'Revisão', 'pending'), (4, 'Entrega final', 'pending') $$,
  'E-62, I1: um template com buracos nas posições (1, 3, 5, 9) gera um processo de posições 1 a 4, na ordem do template'
);
SELECT tests.clear_authentication();

-- Template vazio é defeito de migration: erro sem código do catálogo (o app responde 500) e nada é criado ---------------------------------
DELETE FROM public.default_stage_template;
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo do template vazio') $$,
  'P0001', 'TEMPLATE_EMPTY', 'E-62: um template vazio é TEMPLATE_EMPTY, nunca um processo sem fases (I1)'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000000a', 'Processo com fases e template vazio', '[{"name":"A"}]'::jsonb) $$,
  'fases informadas não dependem do template'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.processes WHERE title = 'Processo do template vazio' $$,
  $$ VALUES (0) $$,
  'I1: o template vazio não deixou processo sem fases'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.processes p
      WHERE NOT EXISTS (SELECT 1 FROM public.process_stages s WHERE s.process_id = p.id)
        AND p.id NOT IN ('00000000-0000-4000-8000-0000000001c1', '00000000-0000-4000-8000-0000000001c2') $$,
  $$ VALUES (0) $$,
  'I1: nenhum processo criado pelas funções ficou sem fase'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.processes p
      WHERE p.id NOT IN ('00000000-0000-4000-8000-0000000001c1', '00000000-0000-4000-8000-0000000001c2')
        AND (SELECT count(*) FILTER (WHERE s.status = 'in_progress') FROM public.process_stages s WHERE s.process_id = p.id) <> 1
        AND p.status = 'active' $$,
  $$ VALUES (0) $$,
  'I2: todo processo ativo criado pelas funções tem exatamente uma fase in_progress'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.processes p
      WHERE p.id NOT IN ('00000000-0000-4000-8000-0000000001c1', '00000000-0000-4000-8000-0000000001c2')
        AND (SELECT max(s.position) <> count(*) OR min(s.position) <> 1 FROM public.process_stages s WHERE s.process_id = p.id) $$,
  $$ VALUES (0) $$,
  'I1: toda lista de fases criada pelas funções tem posições contíguas de 1 a n'
);

SELECT * FROM finish();
ROLLBACK;
