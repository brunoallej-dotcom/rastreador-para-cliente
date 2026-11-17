-- Onda 9: approve_current_stage, o "Ok" do CEO (spec §3.6, §3.7, §3.7.3). Cobre: privilégios e search_path da
-- função (AC-25), a ORDEM DE TRAVA no catálogo (F-82, T-41: o processo primeiro, FOR NO KEY UPDATE, igual ao
-- update_process; só depois o status e a fase), anon (AC-10), cliente com aal1 e com aal2 no JWT (AC-08, AC-09),
-- CEO aal1, CEO aal2 sem fator, CEO com sessão morta ou desativado, CEO com `aal2` SEM atestado (Onda 6.1) com o
-- controle positivo logo depois, a autorização antes de qualquer trabalho com a entrada (F-55), o caminho feliz
-- (AC-16: a fase vira completed com a aprovação e o CEO, a próxima in_progress, version +1 uma vez, auditoria na
-- mesma transação, qualquer CEO aprova), a última fase (AC-18, E-04), processo concluído ou cancelado (E-03, I3,
-- I4, AC-19), a fase esperada velha, futura, de outro processo ou inexistente (E-01, E-02: STALE_STAGE), a
-- precedência dos erros (papel, entrada, processo, status, fase), erros sem DETAIL nem HINT, as invariantes
-- depois de cada passo (I2, I5, I6), escrita direta negada, o isolamento por tenant, o cliente arquivado (F-87:
-- hoje vale o atual, e o teste o registra), o instante da aprovação depois de uma espera de trava com o teto de
-- 1 minuto (F-104), a função que confere o que escreve (F-105, T-49: posições com buraco, fase anterior aberta,
-- nenhuma fase atual, sempre sem escrever nada), o índice da linha do tempo (F-106) e as invariantes e contagens
-- escopadas aos processos desta fixture (o arquivo não depende do que `pnpm test:api` deixou no banco).
BEGIN;
SELECT plan(123);

-- arrange (como postgres) --------------------------------------------------------------------------
-- A e B são clientes ativos; X é arquivado. a1 é login de A e b1, de B. c1 e c7 são CEOs com fator verificado;
-- c2, CEO sem fator; c3, CEO com fator e sessão apagada; c4, CEO com fator e perfil desativado; c5, CEO com fator
-- que NUNCA é atestado pelos helpers (só o claim aal2 aparece): o que se obtém direto no Auth. O c5 é atestado
-- no controle positivo, então c6 faz o mesmo papel no fim, quando já existem aprovações para ele não ver.
INSERT INTO public.clients (id, name, archived_at) VALUES
  ('00000000-0000-4000-8000-00000000000a', 'Cliente A', NULL),
  ('00000000-0000-4000-8000-00000000000b', 'Cliente B', NULL),
  ('00000000-0000-4000-8000-00000000000c', 'Cliente X', now() - interval '3 days');

SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000b1', 'client', '00000000-0000-4000-8000-00000000000b');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo', NULL, 'CEO Um');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c2', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c3', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c4', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c5', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c6', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c7', 'ceo', NULL, 'CEO Sete');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c3');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c4');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c5');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c6');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c7');
DELETE FROM auth.sessions WHERE id = '00000000-0000-4000-8000-0000000000c3';
UPDATE public.profiles SET disabled_at = now() WHERE id = '00000000-0000-4000-8000-0000000000c4';
-- Nenhum usuário deste arquivo está com a troca de senha pendente: o que nega ou deixa passar é só o que cada caso
-- diz (uma mudança futura de RLS que olhe `must_change_password`, F-83, não quebra os controles positivos por
-- outro motivo).
UPDATE public.profiles SET must_change_password = false
 WHERE id IN ('00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000b1',
              '00000000-0000-4000-8000-0000000000c1', '00000000-0000-4000-8000-0000000000c2',
              '00000000-0000-4000-8000-0000000000c3', '00000000-0000-4000-8000-0000000000c4',
              '00000000-0000-4000-8000-0000000000c5', '00000000-0000-4000-8000-0000000000c6',
              '00000000-0000-4000-8000-0000000000c7');

-- Os processos (montados como postgres, com as fases já no estado que a função de criação deixaria):
--   P3 (1a1): cliente A, 3 fases (2a1 em andamento, 2a2 e 2a3 pendentes): o caminho feliz inteiro.
--   P1 (1a2): cliente A, 1 fase (2b1): a primeira aprovação conclui o processo (E-04).
--   PB (1b1): cliente B, 2 fases (2c1, 2c2): cancelado antes de aprovar (AC-19).
--   PX (1d1): cliente X (arquivado), 2 fases (2d1, 2d2): aprovar e depois cancelar (F-87, I4).
--   PD (1e1): concluído, com a aprovação da única fase (2e1).   PC (1e2): cancelado no meio (2e2 feita, 2e3 parada).
--   PF (1f1): 2 fases; a fase 2f1 começou DAQUI A UM SEGUNDO (o `started_at` que uma aprovação que esperou a trava
--             grava na fase seguinte, com um `now()` mais antigo que ele: dentro da tolerância de 1 minuto, F-104).
--   PG (1a3): 2 fases (2f3 em andamento, 2f4 pendente); a fase 2f3 começou DAQUI A UMA HORA, além da tolerância:
--             linha quebrada (F-104).
-- Os que nascem quebrados de propósito (a função precisa recusá-los e não escrever nada: F-105, T-49):
--   PH (1a4): posições 1 e 3 (buraco; 2f5 em andamento, 2f6 pendente): a fase seguinte à atual não existe.
--   PI (1a5): a fase 1 (2f7) ainda `pending` e a 2 (2f8), a última, em andamento: concluiria o processo com uma
--             fase aberta.
--   PN (1a6): processo ativo sem nenhuma fase em andamento (2f9 pendente: o ramo NOT FOUND da busca da fase atual).
INSERT INTO public.processes (id, client_id, title, version, created_at, updated_at) VALUES
  ('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-00000000000a', 'Processo A3', 1, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000001a2', '00000000-0000-4000-8000-00000000000a', 'Processo A1', 1, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000001b1', '00000000-0000-4000-8000-00000000000b', 'Processo B', 1, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000001d1', '00000000-0000-4000-8000-00000000000c', 'Processo X', 1, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000001f1', '00000000-0000-4000-8000-00000000000a', 'Processo F', 1, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000001a3', '00000000-0000-4000-8000-00000000000a', 'Processo G', 1, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000001a4', '00000000-0000-4000-8000-00000000000a', 'Processo H', 1, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000001a5', '00000000-0000-4000-8000-00000000000a', 'Processo I', 1, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000001a6', '00000000-0000-4000-8000-00000000000a', 'Processo N', 1, now() - interval '2 days', now() - interval '2 days');
INSERT INTO public.process_stages (id, process_id, position, name, status, started_at) VALUES
  ('00000000-0000-4000-8000-0000000002a1', '00000000-0000-4000-8000-0000000001a1', 1, 'Fase 1', 'in_progress', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000002a2', '00000000-0000-4000-8000-0000000001a1', 2, 'Fase 2', 'pending', NULL),
  ('00000000-0000-4000-8000-0000000002a3', '00000000-0000-4000-8000-0000000001a1', 3, 'Fase 3', 'pending', NULL),
  ('00000000-0000-4000-8000-0000000002b1', '00000000-0000-4000-8000-0000000001a2', 1, 'Unica', 'in_progress', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000002c1', '00000000-0000-4000-8000-0000000001b1', 1, 'Fase do B 1', 'in_progress', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000002c2', '00000000-0000-4000-8000-0000000001b1', 2, 'Fase do B 2', 'pending', NULL),
  ('00000000-0000-4000-8000-0000000002d1', '00000000-0000-4000-8000-0000000001d1', 1, 'Fase do X 1', 'in_progress', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000002d2', '00000000-0000-4000-8000-0000000001d1', 2, 'Fase do X 2', 'pending', NULL),
  ('00000000-0000-4000-8000-0000000002f1', '00000000-0000-4000-8000-0000000001f1', 1, 'Fase F 1', 'in_progress', now() + interval '1 second'),
  ('00000000-0000-4000-8000-0000000002f2', '00000000-0000-4000-8000-0000000001f1', 2, 'Fase F 2', 'pending', NULL),
  ('00000000-0000-4000-8000-0000000002f3', '00000000-0000-4000-8000-0000000001a3', 1, 'Fase G 1', 'in_progress', now() + interval '1 hour'),
  ('00000000-0000-4000-8000-0000000002f4', '00000000-0000-4000-8000-0000000001a3', 2, 'Fase G 2', 'pending', NULL),
  ('00000000-0000-4000-8000-0000000002f5', '00000000-0000-4000-8000-0000000001a4', 1, 'Fase H 1', 'in_progress', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000002f6', '00000000-0000-4000-8000-0000000001a4', 3, 'Fase H 3', 'pending', NULL),
  ('00000000-0000-4000-8000-0000000002f7', '00000000-0000-4000-8000-0000000001a5', 1, 'Fase I 1', 'pending', NULL),
  ('00000000-0000-4000-8000-0000000002f8', '00000000-0000-4000-8000-0000000001a5', 2, 'Fase I 2', 'in_progress', now() - interval '1 day'),
  ('00000000-0000-4000-8000-0000000002f9', '00000000-0000-4000-8000-0000000001a6', 1, 'Fase N 1', 'pending', NULL);

INSERT INTO public.processes (id, client_id, title, status, version, completed_at, created_at, updated_at) VALUES
  ('00000000-0000-4000-8000-0000000001e1', '00000000-0000-4000-8000-00000000000a', 'Processo concluido', 'completed', 2,
   now() - interval '1 day', now() - interval '3 days', now() - interval '1 day');
INSERT INTO public.process_stages (id, process_id, position, name, status, started_at, completed_at) VALUES
  ('00000000-0000-4000-8000-0000000002e1', '00000000-0000-4000-8000-0000000001e1', 1, 'Unica', 'completed',
   now() - interval '3 days', now() - interval '1 day');
INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by) VALUES
  ('00000000-0000-4000-8000-0000000002e1', '00000000-0000-4000-8000-0000000001e1', '00000000-0000-4000-8000-0000000000c1');
INSERT INTO public.processes (id, client_id, title, status, version, cancelled_at, created_at, updated_at) VALUES
  ('00000000-0000-4000-8000-0000000001e2', '00000000-0000-4000-8000-00000000000a', 'Processo cancelado', 'cancelled', 3,
   now() - interval '1 day', now() - interval '3 days', now() - interval '1 day');
INSERT INTO public.process_stages (id, process_id, position, name, status, started_at, completed_at) VALUES
  ('00000000-0000-4000-8000-0000000002e2', '00000000-0000-4000-8000-0000000001e2', 1, 'Feita', 'completed',
   now() - interval '3 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-0000000002e3', '00000000-0000-4000-8000-0000000001e2', 2, 'Parada', 'in_progress',
   now() - interval '2 days', NULL);
INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by) VALUES
  ('00000000-0000-4000-8000-0000000002e2', '00000000-0000-4000-8000-0000000001e2', '00000000-0000-4000-8000-0000000000c1');

-- Os processos desta fixture: toda contagem e toda invariante de tabela inteira olha só para eles, para não
-- depender de linhas que outro teste deixou no banco (as de `pnpm test:api`, por exemplo: processos sem fase e
-- auditoria sem `request_id`). `fixture_processes` são os saudáveis; `broken_processes`, os que nascem
-- quebrados de propósito (F-105) e que ficam de fora das invariantes.
CREATE TEMP TABLE fixture_processes (id uuid PRIMARY KEY);
INSERT INTO fixture_processes (id) VALUES
  ('00000000-0000-4000-8000-0000000001a1'), ('00000000-0000-4000-8000-0000000001a2'),
  ('00000000-0000-4000-8000-0000000001b1'), ('00000000-0000-4000-8000-0000000001d1'),
  ('00000000-0000-4000-8000-0000000001f1'), ('00000000-0000-4000-8000-0000000001e1'),
  ('00000000-0000-4000-8000-0000000001e2'), ('00000000-0000-4000-8000-0000000001a3');
GRANT SELECT ON fixture_processes TO authenticated;
CREATE TEMP TABLE broken_processes (id uuid PRIMARY KEY);
INSERT INTO broken_processes (id) VALUES
  ('00000000-0000-4000-8000-0000000001a4'), ('00000000-0000-4000-8000-0000000001a5'),
  ('00000000-0000-4000-8000-0000000001a6');
GRANT SELECT ON broken_processes TO authenticated;

-- Captura o erro de um comando, com o que ele leva (código, mensagem, DETAIL, HINT): as funções de escrita só
-- podem levantar o código fixo, sem texto que vaze linha. Roda como quem chama (a sessão autenticada).
CREATE FUNCTION pg_temp.try(p_sql text)
RETURNS TABLE (sqlstate text, message text, detail text, hint text)
LANGUAGE plpgsql
AS $$
DECLARE
  v_sqlstate text;
  v_message  text;
  v_detail   text;
  v_hint     text;
BEGIN
  EXECUTE p_sql;
  RETURN;
EXCEPTION WHEN OTHERS THEN
  GET STACKED DIAGNOSTICS v_sqlstate = RETURNED_SQLSTATE, v_message = MESSAGE_TEXT,
                          v_detail = PG_EXCEPTION_DETAIL, v_hint = PG_EXCEPTION_HINT;
  RETURN QUERY SELECT v_sqlstate, v_message, nullif(v_detail, ''), nullif(v_hint, '');
END;
$$;
GRANT EXECUTE ON FUNCTION pg_temp.try(text) TO authenticated;

-- O corpo de uma função sem os comentários (`/* ... */` e `--` até o fim da linha): os asserts de ordem de trava
-- olham o SQL que executa, e não o que os comentários dizem dele. Sobra `/*` ou `*/` (um comentário aninhado ou
-- mal fechado)? Um assert abaixo falha: o guarda falha fechado em vez de mascarar código.
CREATE FUNCTION pg_temp.code(p_oid oid)
RETURNS text
LANGUAGE sql
AS $$
  SELECT regexp_replace(regexp_replace(p.prosrc, '/\*.*?\*/', '', 'g'), '--[^\n]*', '', 'g')
    FROM pg_proc p WHERE p.oid = p_oid
$$;

-- O que o banco guarda de um processo, numa linha: status, versão, fases, aprovações e auditoria. Um caso que
-- precisa provar "não escreveu nada" compara esta linha antes e depois, como postgres.
CREATE FUNCTION pg_temp.state_of(p_id uuid)
RETURNS text
LANGUAGE sql
AS $$
  SELECT p.status::text || '/v' || p.version || '/'
         || (SELECT string_agg(s.position || ':' || s.status::text, ',' ORDER BY s.position)
               FROM public.process_stages s WHERE s.process_id = p.id)
         || '/approvals=' || (SELECT count(*) FROM public.stage_approvals a WHERE a.process_id = p.id)
         || '/audit=' || (SELECT count(*) FROM public.audit_events e WHERE e.process_id = p.id)
    FROM public.processes p WHERE p.id = p_id
$$;

-- Como o PostgREST faz: o app manda o id da requisição, e a auditoria o guarda.
SELECT tests.set_request_id('req-approve-0001');

-- AC-25: privilégios e configuração da função --------------------------------------------------------------
SELECT ok(
  (SELECT p.prosecdef FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'approve_current_stage: SECURITY DEFINER'
);
SELECT ok(
  (SELECT 'search_path=""' = ANY (p.proconfig) FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'AC-25: approve_current_stage tem search_path vazio'
);
SELECT ok(
  NOT has_function_privilege('anon', 'public.approve_current_stage(uuid, uuid)', 'EXECUTE'),
  'AC-10: anon não executa approve_current_stage'
);
SELECT ok(
  has_function_privilege('authenticated', 'public.approve_current_stage(uuid, uuid)', 'EXECUTE'),
  'approve_current_stage: authenticated executa (a checagem de CEO aal2 atestado é por dentro)'
);
SELECT ok(
  NOT has_function_privilege('service_role', 'public.approve_current_stage(uuid, uuid)', 'EXECUTE'),
  'SEC-04: service_role não executa approve_current_stage (nem a secret key aprova)'
);
SELECT is_empty(
  $$ SELECT p.proname
       FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure
        AND a.grantee = 0 AND a.privilege_type = 'EXECUTE' $$,
  'AC-25: approve_current_stage não concede EXECUTE a PUBLIC'
);
SELECT is(
  (SELECT p.prorettype::regtype::text FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'processes',
  'approve_current_stage devolve a linha de processes (sem título em metadados nem texto de erro)'
);
SELECT has_index(
  'public', 'audit_events', 'audit_events_process_id_id_idx', ARRAY['process_id', 'id'],
  'F-106: a linha do tempo tem o índice (process_id, id) para o keyset por id'
);
SELECT ok(
  (SELECT pg_get_indexdef(i.indexrelid) ~ 'WHERE \(process_id IS NOT NULL\)'
     FROM pg_index i WHERE i.indexrelid = 'public.audit_events_process_id_id_idx'::regclass),
  'F-106: o índice é parcial (process_id IS NOT NULL), como os outros da trilha'
);

-- F-82, T-41: a ORDEM DE TRAVA, no catálogo (a concorrência em si está nos testes de API, que seguram a trava
-- numa segunda sessão: um teste de uma sessão só não prova a espera). O processo é a primeira linha travada, com
-- FOR NO KEY UPDATE, a mesma consulta e o mesmo modo de update_process; o status é lido depois da trava; a fase
-- em andamento só é travada depois disso, também com FOR NO KEY UPDATE; nenhuma escrita vem antes das duas
-- travas; e nada trava public.clients (create_process trava o cliente e depois insere o processo: uma aprovação
-- que travasse o cliente depois do processo cruzaria com ela).
SELECT ok(
  (SELECT pg_temp.code(p.oid) ~ 'FROM public\.processes p\s+WHERE p\.id = p_process_id\s+FOR NO KEY UPDATE'
     FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'F-82: approve_current_stage trava a linha de public.processes com FOR NO KEY UPDATE'
);
SELECT ok(
  (SELECT pg_temp.code(p.oid) ~ 'FROM public\.processes p\s+WHERE p\.id = p_process_id\s+FOR NO KEY UPDATE'
     FROM pg_proc p WHERE p.oid = 'public.update_process(uuid, text, boolean)'::regprocedure),
  'F-82: update_process trava a mesma linha, com o mesmo modo (as duas se serializam)'
);
SELECT ok(
  (SELECT pg_temp.code(p.oid) ~ 'FROM public\.process_stages s\s+WHERE s\.process_id = p_process_id\s+AND s\.status = ''in_progress''\s+FOR NO KEY UPDATE'
     FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'F-82: a fase em andamento é travada com FOR NO KEY UPDATE'
);
SELECT ok(
  (SELECT position('FROM public.processes p' IN pg_temp.code(p.oid)) > 0
          AND position('FROM public.processes p' IN pg_temp.code(p.oid)) < position('FROM public.process_stages s' IN pg_temp.code(p.oid))
     FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'F-82: o processo é lido (e travado) ANTES de qualquer leitura das fases'
);
SELECT ok(
  (SELECT pg_temp.code(p.oid) !~ '/\*|\*/'
     FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'F-82: nenhum comentário aninhado ou mal fechado sobra no corpo (o guarda de ordem olha código, não comentário)'
);
SELECT ok(
  (SELECT regexp_count(pg_temp.code(p.oid), 'FOR NO KEY UPDATE', 1, 'i') = 2
     FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'F-82: duas travas, a do processo e a da fase, nessa ordem, e mais nenhuma'
);
SELECT ok(
  (SELECT position('FOR NO KEY UPDATE' IN pg_temp.code(p.oid)) < position('v_row.status <> ''active''' IN pg_temp.code(p.oid))
          AND position('v_row.status <> ''active''' IN pg_temp.code(p.oid)) > 0
          AND position('v_row.status <> ''active''' IN pg_temp.code(p.oid)) < position('v_stage_id <> p_expected_stage_id' IN pg_temp.code(p.oid))
          AND position('v_stage_id <> p_expected_stage_id' IN pg_temp.code(p.oid)) > 0
     FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'F-82, I4: o status é conferido DEPOIS da trava do processo e ANTES da fase esperada'
);
SELECT ok(
  (SELECT position('FROM public.process_stages s' IN pg_temp.code(p.oid)) < position('UPDATE public.process_stages s' IN pg_temp.code(p.oid))
          AND position('UPDATE public.process_stages s' IN pg_temp.code(p.oid)) > 0
          AND position('FOR NO KEY UPDATE' IN pg_temp.code(p.oid)) < position('INSERT INTO public.stage_approvals' IN pg_temp.code(p.oid))
          AND position('INSERT INTO public.stage_approvals' IN pg_temp.code(p.oid)) < position('UPDATE public.processes p' IN pg_temp.code(p.oid))
          AND position('UPDATE public.processes p' IN pg_temp.code(p.oid)) > 0
     FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'F-82: as duas travas vêm antes de qualquer escrita (fase, aprovação, processo)'
);
SELECT ok(
  (SELECT pg_temp.code(p.oid) !~* 'FOR\s+UPDATE\M' AND pg_temp.code(p.oid) !~* 'FOR\s+(KEY\s+)?SHARE\M' AND pg_temp.code(p.oid) !~* 'public\.clients'
     FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'F-82: approve_current_stage não usa FOR UPDATE nem FOR SHARE e não toca public.clients'
);
SELECT ok(
  (SELECT pg_temp.code(p.oid) ~ 'IF private\.is_ceo\(\) IS NOT TRUE THEN'
          AND position('is_ceo()' IN pg_temp.code(p.oid)) < position('FOR NO KEY UPDATE' IN pg_temp.code(p.oid))
     FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'F-55: approve_current_stage abre com IF private.is_ceo() IS NOT TRUE, antes de qualquer trava'
);
SELECT ok(
  (SELECT (regexp_match(pg_temp.code(p.oid), 'DECLARE(.*?)BEGIN', 'is'))[1] !~* '(=|\mDEFAULT\M)'
     FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'F-55: o DECLARE não inicializa nada, nem com :=, nem com =, nem com DEFAULT (nenhum trabalho com a entrada antes da checagem de CEO)'
);

-- AC-10: anon ------------------------------------------------------------------------------------------
SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a1') $$,
  '42501', NULL, 'AC-10: anon não executa approve_current_stage'
);
SELECT throws_ok(
  $$ SELECT process_id FROM public.stage_approvals $$,
  '42501', NULL, 'AC-10: anon não lê stage_approvals'
);
RESET ROLE;

-- AC-08, AC-09: cliente A ----------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a1') $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não aprova nem o processo do próprio tenant'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001b1', '00000000-0000-4000-8000-0000000002c1') $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não aprova o processo de outro cliente'
);
SELECT throws_ok(
  $$ INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)
     VALUES ('00000000-0000-4000-8000-0000000002a1', '00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000000a1') $$,
  '42501', NULL, 'SEC-04: cliente não faz INSERT direto em stage_approvals'
);
SELECT throws_ok(
  $$ UPDATE public.process_stages SET status = 'completed', completed_at = now() WHERE id = '00000000-0000-4000-8000-0000000002a1' $$,
  '42501', NULL, 'SEC-04: cliente não conclui uma fase com UPDATE direto'
);
SELECT tests.clear_authentication();

-- AC-08: cliente com `aal2` no JWT (um claim que ele mesmo não deveria conseguir; vale a checagem de papel) ---
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a1') $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente com aal2 no JWT não executa approve_current_stage'
);
SELECT tests.clear_authentication();

-- AC-08: CEO com aal1 (fator verificado, mas sessão só com a senha) ----------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a1') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 não executa approve_current_stage'
);
SELECT is_empty($$ SELECT id FROM public.process_stages $$, 'AC-08: CEO aal1 não lê nenhuma fase');
SELECT tests.clear_authentication();

-- F-24: CEO com aal2 no JWT, mas sem fator TOTP verificado --------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a1') $$,
  '42501', 'FORBIDDEN', 'F-24: CEO aal2 sem fator verificado não executa approve_current_stage'
);
SELECT tests.clear_authentication();

-- E-08: CEO aal2 com fator, mas sessão apagada, ou com perfil desativado -----------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a1') $$,
  '42501', 'FORBIDDEN', 'E-08: CEO com a sessão apagada não executa approve_current_stage'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c4', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a1') $$,
  '42501', 'FORBIDDEN', 'E-08: CEO desativado não executa approve_current_stage'
);
SELECT tests.clear_authentication();

-- AC-08, F-50 b: CEO com `aal2` no JWT e SEM atestado do backend (p_attested => false) ----------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c5', 'aal2', false);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a1') $$,
  '42501', 'FORBIDDEN', 'F-50 b: CEO com aal2 sem atestado não executa approve_current_stage'
);
SELECT is_empty($$ SELECT id FROM public.process_stages $$, 'F-50 b: CEO com aal2 sem atestado não lê nenhuma fase');
SELECT is_empty($$ SELECT process_id FROM public.stage_approvals $$, 'F-50 b: CEO com aal2 sem atestado não lê nenhuma aprovação');
SELECT tests.clear_authentication();

-- F-55: a autorização vem antes de qualquer trabalho com a entrada (a entrada inválida não muda a resposta) ----
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', NULL) $$,
  '42501', 'FORBIDDEN', 'F-55: cliente com a fase esperada nula recebe FORBIDDEN, não INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-00000000dead', '00000000-0000-4000-8000-0000000002a1') $$,
  '42501', 'FORBIDDEN', 'F-55: cliente com um processo inexistente recebe FORBIDDEN, não NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001e1', '00000000-0000-4000-8000-0000000002a1') $$,
  '42501', 'FORBIDDEN', 'F-55: cliente com um processo concluído recebe FORBIDDEN, não PROCESS_NOT_ACTIVE'
);
SELECT tests.clear_authentication();

-- Nada do que foi negado mudou alguma coisa -------------------------------------------------------------------
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.stage_approvals WHERE process_id IN (SELECT id FROM fixture_processes) $$,
  $$ VALUES (2) $$,
  'AC-08: nenhuma chamada negada gravou aprovação (só as 2 das fixtures)'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.audit_events WHERE action IN ('stage.approved', 'process.completed') AND process_id IN (SELECT id FROM fixture_processes) $$,
  $$ VALUES (0) $$,
  'AC-08: nenhuma chamada negada gravou auditoria'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.process_stages WHERE status = 'in_progress' AND process_id IN (SELECT id FROM fixture_processes) $$,
  $$ VALUES (7) $$,
  'AC-08: nenhuma chamada negada mexeu em fase (as 7 em andamento das fixtures saudáveis seguem como estavam)'
);

-- AC-16: o CEO aprova a fase atual de P3 (fase 1 de 3) -------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');

SELECT results_eq(
  $$ SELECT p.id, p.client_id, p.title, p.status::text, p.version, p.completed_at IS NULL, p.cancelled_at IS NULL,
            p.updated_at = now()
       FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a1') p $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000001a1'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid,
             'Processo A3', 'active', 2, true, true, true) $$,
  'AC-16: aprovar a fase 1 de 3 devolve o processo ativo, versão 2, sem concluí-lo'
);
SELECT results_eq(
  $$ SELECT s.position::int, s.status::text, s.started_at IS NOT NULL, s.completed_at IS NOT NULL
       FROM public.process_stages s WHERE s.process_id = '00000000-0000-4000-8000-0000000001a1' ORDER BY s.position $$,
  $$ VALUES (1, 'completed', true, true), (2, 'in_progress', true, false), (3, 'pending', false, false) $$,
  'AC-16, I2: a fase 1 fica completed, a 2 in_progress (com início) e a 3 segue pending, sem datas'
);
SELECT results_eq(
  $$ SELECT s.completed_at = now(), s.completed_at >= s.started_at
       FROM public.process_stages s WHERE s.id = '00000000-0000-4000-8000-0000000002a1' $$,
  $$ VALUES (true, true) $$,
  'AC-16: a fase concluída guarda o instante da aprovação, não antes do início'
);
SELECT results_eq(
  $$ SELECT s.started_at = a.approved_at
       FROM public.process_stages s
       JOIN public.stage_approvals a ON a.process_stage_id = '00000000-0000-4000-8000-0000000002a1'
      WHERE s.id = '00000000-0000-4000-8000-0000000002a2' $$,
  $$ VALUES (true) $$,
  'AC-16: a fase seguinte começa no mesmo instante da aprovação'
);
SELECT results_eq(
  $$ SELECT a.process_stage_id, a.process_id, a.approved_by, a.approved_at = now()
       FROM public.stage_approvals a WHERE a.process_id = '00000000-0000-4000-8000-0000000001a1' $$,
  $$ VALUES ('00000000-0000-4000-8000-0000000002a1'::uuid, '00000000-0000-4000-8000-0000000001a1'::uuid,
             '00000000-0000-4000-8000-0000000000c1'::uuid, true) $$,
  'AC-16, I5: a fase concluída tem exatamente uma aprovação, com o CEO da sessão (não um id recebido)'
);
SELECT tests.clear_authentication();

SELECT results_eq(
  $$ SELECT a.action, a.actor_id, a.actor_role::text, a.resource_type, a.resource_id, a.client_id, a.process_id,
            a.request_id, a.metadata
       FROM public.audit_events a WHERE a.process_id = '00000000-0000-4000-8000-0000000001a1' ORDER BY a.id $$,
  $$ VALUES ('stage.approved', '00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'stage',
             '00000000-0000-4000-8000-0000000002a1'::uuid, '00000000-0000-4000-8000-00000000000a'::uuid,
             '00000000-0000-4000-8000-0000000001a1'::uuid, 'req-approve-0001', '{}'::jsonb) $$,
  'AC-16: stage.approved na mesma transação: ator, papel, a fase como recurso, cliente, processo, request_id, sem metadados'
);

-- E-02: o retry da mesma aprovação (a primeira foi gravada): a fase esperada já não é a atual -----------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT sqlstate, message, detail, hint FROM pg_temp.try(
       $q$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a1') $q$) $$,
  $$ VALUES ('P0001', 'STALE_STAGE', NULL::text, NULL::text) $$,
  'E-02: repetir a aprovação da fase 1 é STALE_STAGE, sem DETAIL nem HINT (o app lê a fase atual de novo)'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT p.version, (SELECT count(*)::int FROM public.stage_approvals a WHERE a.process_id = p.id),
            (SELECT count(*)::int FROM public.audit_events e WHERE e.process_id = p.id AND e.action = 'stage.approved')
       FROM public.processes p WHERE p.id = '00000000-0000-4000-8000-0000000001a1' $$,
  $$ VALUES (2, 1, 1) $$,
  'E-02: o retry não avançou nada: versão 2, uma aprovação, um stage.approved (nunca avança duas fases)'
);

-- Qualquer CEO aprova (RF-10): outro CEO dá o "Ok" da fase 2 -----------------------------------------------
SELECT tests.set_request_id('req-approve-0002');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c7', 'aal2');
SELECT results_eq(
  $$ SELECT p.status::text, p.version, p.completed_at IS NULL
       FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a2') p $$,
  $$ VALUES ('active', 3, true) $$,
  'RF-10: outro CEO aprova a fase 2 (basta um CEO, não o mesmo): versão 3, ainda ativo'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT s.position::int, s.status::text, a.approved_by
       FROM public.process_stages s LEFT JOIN public.stage_approvals a ON a.process_stage_id = s.id
      WHERE s.process_id = '00000000-0000-4000-8000-0000000001a1' ORDER BY s.position $$,
  $$ VALUES (1, 'completed', '00000000-0000-4000-8000-0000000000c1'::uuid),
            (2, 'completed', '00000000-0000-4000-8000-0000000000c7'::uuid),
            (3, 'in_progress', NULL::uuid) $$,
  'RF-10, I5: cada fase concluída guarda o CEO que a aprovou; a fase 3 é a atual'
);

-- E-01: a fase esperada que não é a atual: a velha, a futura, a de outro processo, uma inexistente ---------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT sqlstate, message, detail, hint FROM pg_temp.try(
       $q$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a2') $q$) $$,
  $$ VALUES ('P0001', 'STALE_STAGE', NULL::text, NULL::text) $$,
  'E-01: aprovar a fase 2, já concluída, é STALE_STAGE'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001b1', '00000000-0000-4000-8000-0000000002a3') $$,
  'P0001', 'STALE_STAGE', 'E-01: a fase 3 de P3 não é a atual de PB: STALE_STAGE (e não NOT_FOUND)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001b1', '00000000-0000-4000-8000-0000000002c2') $$,
  'P0001', 'STALE_STAGE', 'E-01: aprovar uma fase pending (a seguinte, ainda não iniciada) é STALE_STAGE: nunca pula fase'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001b1', '00000000-0000-4000-8000-00000000dead') $$,
  'P0001', 'STALE_STAGE', 'E-01: uma fase que não existe é STALE_STAGE'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT p.version, p.status::text, (SELECT count(*)::int FROM public.stage_approvals a WHERE a.process_id = p.id)
       FROM public.processes p WHERE p.id = '00000000-0000-4000-8000-0000000001b1' $$,
  $$ VALUES (1, 'active', 0) $$,
  'E-01: as recusas por fase esperada não mudaram PB (versão 1, ativo, nenhuma aprovação)'
);
SELECT results_eq(
  $$ SELECT s.position::int, s.status::text FROM public.process_stages s
      WHERE s.process_id = '00000000-0000-4000-8000-0000000001b1' ORDER BY s.position $$,
  $$ VALUES (1, 'in_progress'), (2, 'pending') $$,
  'E-01, I2: PB segue com a fase 1 em andamento'
);

-- AC-18: a última fase conclui o processo ---------------------------------------------------------------------------
SELECT tests.set_request_id('req-approve-0003');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT p.status::text, p.version, p.completed_at = now(), p.cancelled_at IS NULL, p.updated_at = now()
       FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a3') p $$,
  $$ VALUES ('completed', 4, true, true, true) $$,
  'AC-18, I3: aprovar a última fase conclui o processo: completed, completed_at preenchido, versão 4'
);
SELECT results_eq(
  $$ SELECT count(*)::int, count(*) FILTER (WHERE s.status = 'completed')::int,
            count(*) FILTER (WHERE s.status = 'in_progress')::int
       FROM public.process_stages s WHERE s.process_id = '00000000-0000-4000-8000-0000000001a1' $$,
  $$ VALUES (3, 3, 0) $$,
  'AC-18, I3: as 3 fases ficam completed e nenhuma fica em andamento'
);
SELECT results_eq(
  $$ SELECT count(*)::int, count(DISTINCT a.process_stage_id)::int
       FROM public.stage_approvals a WHERE a.process_id = '00000000-0000-4000-8000-0000000001a1' $$,
  $$ VALUES (3, 3) $$,
  'AC-18, I5: três aprovações, uma por fase'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT a.action, a.resource_type, a.resource_id, a.request_id, a.metadata
       FROM public.audit_events a
      WHERE a.process_id = '00000000-0000-4000-8000-0000000001a1' AND a.request_id = 'req-approve-0003' ORDER BY a.id $$,
  $$ VALUES ('stage.approved', 'stage', '00000000-0000-4000-8000-0000000002a3'::uuid, 'req-approve-0003', '{}'::jsonb),
            ('process.completed', 'process', '00000000-0000-4000-8000-0000000001a1'::uuid, 'req-approve-0003', '{}'::jsonb) $$,
  'AC-18: a última aprovação grava stage.approved e depois process.completed, na mesma transação'
);

-- E-03, AC-18: depois de concluído, aprovar de novo é PROCESS_NOT_ACTIVE (que vence um STALE_STAGE) -----------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT sqlstate, message, detail, hint FROM pg_temp.try(
       $q$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a3') $q$) $$,
  $$ VALUES ('P0001', 'PROCESS_NOT_ACTIVE', NULL::text, NULL::text) $$,
  'AC-18, E-03: repetir a última aprovação é PROCESS_NOT_ACTIVE, sem DETAIL nem HINT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000002a1') $$,
  'P0001', 'PROCESS_NOT_ACTIVE', 'E-03: num processo concluído, até uma fase velha é PROCESS_NOT_ACTIVE (vence o STALE_STAGE)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001e1', '00000000-0000-4000-8000-0000000002e1') $$,
  'P0001', 'PROCESS_NOT_ACTIVE', 'E-03, I3: o processo concluído de fixture também é PROCESS_NOT_ACTIVE'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001e2', '00000000-0000-4000-8000-0000000002e3') $$,
  'P0001', 'PROCESS_NOT_ACTIVE', 'E-03, I4: o processo cancelado, com a fase parada como esperada, é PROCESS_NOT_ACTIVE'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001e2', '00000000-0000-4000-8000-00000000dead') $$,
  'P0001', 'PROCESS_NOT_ACTIVE', 'E-03, I4: o processo cancelado, com uma fase qualquer como esperada, é PROCESS_NOT_ACTIVE'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT p.status::text, p.version FROM public.processes p
      WHERE p.id IN ('00000000-0000-4000-8000-0000000001e1', '00000000-0000-4000-8000-0000000001e2', '00000000-0000-4000-8000-0000000001a1')
      ORDER BY p.id $$,
  $$ VALUES ('completed', 4), ('completed', 2), ('cancelled', 3) $$,
  'E-03, I3, I4: as recusas não mexeram em nenhum processo terminado (nem na versão)'
);
SELECT results_eq(
  $$ SELECT s.status::text FROM public.process_stages s WHERE s.process_id = '00000000-0000-4000-8000-0000000001e2' ORDER BY s.position $$,
  $$ VALUES ('completed'), ('in_progress') $$,
  'I4: a fase parada do processo cancelado continua em andamento'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.audit_events WHERE action IN ('stage.approved', 'process.completed') AND process_id IN (SELECT id FROM fixture_processes) $$,
  $$ VALUES (4) $$,
  'E-03: só os 3 stage.approved de P3 e o process.completed da última estão na auditoria: nada foi gravado por recusa'
);

-- E-04, AC-18: processo de uma fase só --------------------------------------------------------------------------------
SELECT tests.set_request_id('req-approve-0004');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT p.status::text, p.version, p.completed_at IS NOT NULL
       FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a2', '00000000-0000-4000-8000-0000000002b1') p $$,
  $$ VALUES ('completed', 2, true) $$,
  'E-04: a primeira (e única) aprovação conclui o processo de uma fase'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT a.action, a.resource_type FROM public.audit_events a
      WHERE a.process_id = '00000000-0000-4000-8000-0000000001a2' ORDER BY a.id $$,
  $$ VALUES ('stage.approved', 'stage'), ('process.completed', 'process') $$,
  'E-04: stage.approved e process.completed'
);

-- Entrada e processo: INVALID_INPUT, NOT_FOUND, e a precedência (papel, entrada, processo, status, fase) ------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT sqlstate, message, detail, hint FROM pg_temp.try(
       $q$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001b1', NULL) $q$) $$,
  $$ VALUES ('P0001', 'INVALID_INPUT', NULL::text, NULL::text) $$,
  'INVALID_INPUT: a fase esperada nula é recusada, sem DETAIL nem HINT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage(NULL, '00000000-0000-4000-8000-0000000002c1') $$,
  'P0001', 'INVALID_INPUT', 'INVALID_INPUT: o processo nulo é recusado'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001e1', NULL) $$,
  'P0001', 'INVALID_INPUT', 'precedência: a entrada vem antes do status (processo concluído com fase nula é INVALID_INPUT)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-00000000dead', NULL) $$,
  'P0001', 'INVALID_INPUT', 'precedência: a entrada vem antes da existência do processo'
);
SELECT results_eq(
  $$ SELECT sqlstate, message, detail, hint FROM pg_temp.try(
       $q$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-00000000dead', '00000000-0000-4000-8000-0000000002c1') $q$) $$,
  $$ VALUES ('P0001', 'NOT_FOUND', NULL::text, NULL::text) $$,
  'NOT_FOUND: um processo que não existe, sem DETAIL nem HINT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001e1', '00000000-0000-4000-8000-00000000dead') $$,
  'P0001', 'PROCESS_NOT_ACTIVE', 'precedência: o status vem antes da fase esperada (concluído com fase inexistente é PROCESS_NOT_ACTIVE)'
);
SELECT tests.clear_authentication();

-- AC-19, I4: cancelar e depois aprovar; aprovar e depois cancelar -----------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001b1', NULL, true) $$,
  'AC-19: o CEO cancela PB'
);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001b1', '00000000-0000-4000-8000-0000000002c1') $$,
  'P0001', 'PROCESS_NOT_ACTIVE', 'AC-19, I4: aprovar a fase em andamento de um processo cancelado é PROCESS_NOT_ACTIVE'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT p.status::text, p.version, p.cancelled_at IS NOT NULL,
            (SELECT count(*)::int FROM public.stage_approvals a WHERE a.process_id = p.id),
            (SELECT string_agg(s.status::text, ',' ORDER BY s.position) FROM public.process_stages s WHERE s.process_id = p.id)
       FROM public.processes p WHERE p.id = '00000000-0000-4000-8000-0000000001b1' $$,
  $$ VALUES ('cancelled', 2, true, 0, 'in_progress,pending') $$,
  'I4: o cancelamento que ganhou da aprovação deixa as fases como estavam, sem aprovação nenhuma'
);

-- F-87 (decisão do usuário pendente): hoje o cliente arquivado NÃO congela os processos que já tem ----------------------------
SELECT tests.set_request_id('req-approve-0005');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001d1', '00000000-0000-4000-8000-0000000002d1') $$,
  'F-87: a aprovação num processo de cliente arquivado vale hoje (Q-13: arquivar só impede processos e logins novos)'
);
SELECT lives_ok(
  $$ SELECT * FROM public.update_process('00000000-0000-4000-8000-0000000001d1', NULL, true) $$,
  'F-87: e o cancelamento depois da aprovação também'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT p.status::text, p.version, (SELECT string_agg(s.status::text, ',' ORDER BY s.position) FROM public.process_stages s WHERE s.process_id = p.id)
       FROM public.processes p WHERE p.id = '00000000-0000-4000-8000-0000000001d1' $$,
  $$ VALUES ('cancelled', 3, 'completed,in_progress') $$,
  'I4: aprovar e depois cancelar deixa a fase seguinte em andamento (congelada), versão 3'
);
SELECT results_eq(
  $$ SELECT a.action FROM public.audit_events a WHERE a.process_id = '00000000-0000-4000-8000-0000000001d1' ORDER BY a.id $$,
  $$ VALUES ('stage.approved'), ('process.cancelled') $$,
  'I4: a auditoria mostra a aprovação ANTES do cancelamento, na ordem em que as duas travas foram tomadas'
);

-- F-104: o instante da aprovação depois de uma espera de trava: a fase seguinte já começou "no futuro" -----------------------------
-- (o `now()` da aprovação que esperou é o do começo da transação, anterior ao `started_at` que a anterior gravou; a
-- tolerância é de 1 minuto: PF começou daqui a 1 segundo, e PG, daqui a 1 hora, é linha quebrada).
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001f1', '00000000-0000-4000-8000-0000000002f1') $$,
  'F-104: aprovar uma fase que começou depois do now() da transação, dentro da tolerância, não viola completed_at >= started_at'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT s.completed_at = s.started_at, s.completed_at = now() + interval '1 second'
       FROM public.process_stages s WHERE s.id = '00000000-0000-4000-8000-0000000002f1' $$,
  $$ VALUES (true, true) $$,
  'F-104: a fase é concluída no instante em que começou (o maior entre now() e o início), nunca antes'
);
SELECT results_eq(
  $$ SELECT s.started_at = now() + interval '1 second', a.approved_at = now() + interval '1 second'
       FROM public.process_stages s
       JOIN public.stage_approvals a ON a.process_stage_id = '00000000-0000-4000-8000-0000000002f1'
      WHERE s.id = '00000000-0000-4000-8000-0000000002f2' $$,
  $$ VALUES (true, true) $$,
  'F-104: a aprovação e o início da fase seguinte usam esse mesmo instante'
);
SELECT results_eq(
  $$ SELECT e.occurred_at = now(), e.occurred_at < a.approved_at
       FROM public.audit_events e
       JOIN public.stage_approvals a ON a.process_stage_id = e.resource_id
      WHERE e.action = 'stage.approved' AND e.resource_id = '00000000-0000-4000-8000-0000000002f1' $$,
  $$ VALUES (true, true) $$,
  'F-104: a auditoria guarda o now() da transação (a fonte forense), e não o instante clampado da aprovação'
);

-- F-104, T-49: além da tolerância (1 hora à frente) não é espera de trava, é linha quebrada: recusa, e nada muda ------------------
SELECT is(
  pg_temp.state_of('00000000-0000-4000-8000-0000000001a3'),
  'active/v1/1:in_progress,2:pending/approvals=0/audit=0',
  'F-104: PG, antes: ativo, versão 1, fase 1 em andamento (começada daqui a 1 hora), nenhuma aprovação, nenhuma auditoria'
);
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT sqlstate, message, detail, hint FROM pg_temp.try(
       $q$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a3', '00000000-0000-4000-8000-0000000002f3') $q$) $$,
  $$ VALUES ('P0001', 'INVARIANT_VIOLATION', NULL::text, NULL::text) $$,
  'F-104: uma fase que começou 1 hora à frente do relógio é INVARIANT_VIOLATION, sem DETAIL nem HINT'
);
SELECT tests.clear_authentication();
SELECT is(
  pg_temp.state_of('00000000-0000-4000-8000-0000000001a3'),
  'active/v1/1:in_progress,2:pending/approvals=0/audit=0',
  'F-104: a recusa não gravou nada: sem aprovação, sem auditoria, mesma versão, mesmas fases'
);

-- F-105, T-49: a função confere o que escreve: posições com buraco, fase anterior aberta, nenhuma fase atual -------------------
SELECT is(
  pg_temp.state_of('00000000-0000-4000-8000-0000000001a4'),
  'active/v1/1:in_progress,3:pending/approvals=0/audit=0',
  'F-105: PH, antes: posições 1 e 3 (com buraco), fase 1 em andamento'
);
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT sqlstate, message, detail, hint FROM pg_temp.try(
       $q$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a4', '00000000-0000-4000-8000-0000000002f5') $q$) $$,
  $$ VALUES ('P0001', 'INVARIANT_VIOLATION', NULL::text, NULL::text) $$,
  'F-105: posições 1 e 3: a fase seguinte (posição 2) não existe, e a aprovação é INVARIANT_VIOLATION, sem DETAIL nem HINT'
);
SELECT results_eq(
  $$ SELECT sqlstate, message, detail, hint FROM pg_temp.try(
       $q$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a5', '00000000-0000-4000-8000-0000000002f8') $q$) $$,
  $$ VALUES ('P0001', 'INVARIANT_VIOLATION', NULL::text, NULL::text) $$,
  'F-105: a última fase com uma anterior ainda aberta não conclui o processo: INVARIANT_VIOLATION'
);
SELECT results_eq(
  $$ SELECT sqlstate, message, detail, hint FROM pg_temp.try(
       $q$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001a6', '00000000-0000-4000-8000-0000000002f9') $q$) $$,
  $$ VALUES ('P0001', 'STALE_STAGE', NULL::text, NULL::text) $$,
  'NOT FOUND: um processo ativo sem fase em andamento (I2 quebrado) é STALE_STAGE, mesmo com a fase pending como esperada'
);
SELECT tests.clear_authentication();
SELECT is(
  pg_temp.state_of('00000000-0000-4000-8000-0000000001a4'),
  'active/v1/1:in_progress,3:pending/approvals=0/audit=0',
  'F-105: PH, depois da recusa: nada foi escrito (fase 1 ainda em andamento, versão 1, sem aprovação nem auditoria)'
);
SELECT is(
  pg_temp.state_of('00000000-0000-4000-8000-0000000001a5'),
  'active/v1/1:pending,2:in_progress/approvals=0/audit=0',
  'F-105: PI, depois da recusa: nada foi escrito (a fase 2 ainda em andamento, não concluída)'
);
SELECT is(
  pg_temp.state_of('00000000-0000-4000-8000-0000000001a6'),
  'active/v1/1:pending/approvals=0/audit=0',
  'NOT FOUND: PN, depois da recusa: nada foi escrito'
);

-- I2, I3, I5, I6 em tudo o que a função mexeu ---------------------------------------------------------------------------------
SELECT is_empty(
  $$ SELECT p.id FROM public.processes p
      WHERE p.id IN (SELECT id FROM fixture_processes)
        AND p.status = 'active'
        AND (SELECT count(*) FROM public.process_stages s WHERE s.process_id = p.id AND s.status = 'in_progress') <> 1 $$,
  'I2: todo processo ativo desta fixture tem exatamente uma fase em andamento'
);
SELECT is_empty(
  $$ SELECT s.id FROM public.process_stages s
      WHERE s.process_id IN (SELECT id FROM fixture_processes)
        AND (s.status = 'completed') <> EXISTS (SELECT 1 FROM public.stage_approvals a WHERE a.process_stage_id = s.id) $$,
  'I5: toda fase concluída desta fixture tem aprovação, e nenhuma outra fase tem'
);
SELECT is_empty(
  $$ SELECT p.id FROM public.processes p
      WHERE p.id IN (SELECT id FROM fixture_processes)
        AND p.status = 'completed'
        AND (p.completed_at IS NULL OR EXISTS (SELECT 1 FROM public.process_stages s WHERE s.process_id = p.id AND s.status <> 'completed')) $$,
  'I3: todo processo concluído tem todas as fases concluídas e completed_at'
);
SELECT is_empty(
  $$ SELECT a.id FROM public.stage_approvals a
       JOIN public.process_stages s ON s.id = a.process_stage_id
      WHERE a.process_id IN (SELECT id FROM fixture_processes)
        AND s.process_id <> a.process_id $$,
  'I5: a aprovação pertence ao processo da fase'
);
SELECT is_empty(
  $$ SELECT s.id FROM public.process_stages s
      WHERE s.process_id IN (SELECT id FROM fixture_processes)
        AND s.status = 'completed' AND s.completed_at < s.started_at $$,
  'I5: nenhuma fase conclui antes de começar'
);
SELECT results_eq(
  $$ SELECT p.version FROM public.processes p WHERE p.id = '00000000-0000-4000-8000-0000000001a1' $$,
  $$ VALUES (4) $$,
  'I6: a versão de P3 subiu uma vez por aprovação (1 + 3)'
);

-- Auditoria sem PII e escrita direta negada ---------------------------------------------------------------------------------------
SELECT is_empty(
  $$ SELECT a.id FROM public.audit_events a
      WHERE a.action IN ('stage.approved', 'process.completed')
        AND a.process_id IN (SELECT id FROM fixture_processes)
        AND (a.metadata <> '{}'::jsonb
             OR a.metadata::text ~* '(Processo|Fase|Cliente|CEO|Unica)') $$,
  'SEC-16: os eventos da aprovação não levam metadados, e nenhum título, nome de fase ou nome de pessoa'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.audit_events a
      WHERE a.process_id IN (SELECT id FROM fixture_processes)
        AND a.action = 'stage.approved' AND (a.actor_id IS NULL OR a.actor_role IS DISTINCT FROM 'ceo' OR a.request_id IS NULL
            OR a.resource_type <> 'stage' OR a.client_id IS NULL OR a.process_id IS NULL) $$,
  $$ VALUES (0) $$,
  'AC-16: todo stage.approved tem ator, papel, a fase como recurso, cliente, processo e request_id'
);
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)
     VALUES ('00000000-0000-4000-8000-0000000002c1', '00000000-0000-4000-8000-0000000001b1', '00000000-0000-4000-8000-0000000000c1') $$,
  '42501', NULL, 'SEC-04: nem o CEO aal2 faz INSERT direto em stage_approvals (só a função escreve)'
);
SELECT throws_ok(
  $$ UPDATE public.process_stages SET status = 'completed' WHERE id = '00000000-0000-4000-8000-0000000002c1' $$,
  '42501', NULL, 'SEC-04: nem o CEO aal2 muda uma fase com UPDATE direto'
);
SELECT throws_ok(
  $$ UPDATE public.processes SET status = 'completed' WHERE id = '00000000-0000-4000-8000-0000000001b1' $$,
  '42501', NULL, 'SEC-04: nem o CEO aal2 conclui um processo com UPDATE direto'
);
SELECT throws_ok(
  $$ UPDATE public.stage_approvals SET approved_by = '00000000-0000-4000-8000-0000000000c7'
      WHERE process_id = '00000000-0000-4000-8000-0000000001a1' $$,
  '42501', NULL, 'SEC-04: nem o CEO aal2 troca o CEO de uma aprovação com UPDATE direto'
);
SELECT throws_ok(
  $$ DELETE FROM public.stage_approvals $$,
  '42501', NULL, 'SEC-04: nem o CEO aal2 apaga aprovações'
);
SELECT tests.clear_authentication();

-- AC-09: isolamento por tenant do que a função grava ---------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT is_empty($$ SELECT process_id FROM public.stage_approvals $$, 'AC-09: o cliente A não lê nenhuma aprovação, nem a do próprio processo');
SELECT is_empty($$ SELECT id FROM public.audit_events $$, 'AC-09: o cliente A não lê a auditoria das aprovações');
SELECT results_eq(
  $$ SELECT s.position::int, s.status::text FROM public.process_stages s
      WHERE s.process_id = '00000000-0000-4000-8000-0000000001a1' ORDER BY s.position $$,
  $$ VALUES (1, 'completed'), (2, 'completed'), (3, 'completed') $$,
  'AC-09: o cliente A vê o andamento das fases do próprio processo (sem a aprovação)'
);
SELECT is_empty(
  $$ SELECT s.id FROM public.process_stages s WHERE s.process_id = '00000000-0000-4000-8000-0000000001d1' $$,
  'AC-09: o cliente A não vê as fases de um processo de outro cliente que o CEO aprovou'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000b1');
SELECT is_empty($$ SELECT process_id FROM public.stage_approvals $$, 'AC-09: o cliente B não lê nenhuma aprovação');
SELECT results_eq(
  $$ SELECT s.position::int, s.status::text FROM public.process_stages s
      WHERE s.process_id = '00000000-0000-4000-8000-0000000001b1' ORDER BY s.position $$,
  $$ VALUES (1, 'in_progress'), (2, 'pending') $$,
  'AC-09: controle positivo: o cliente B lê as fases do próprio processo (o que negou o resto foi o tenant)'
);
SELECT is_empty(
  $$ SELECT s.id FROM public.process_stages s WHERE s.process_id = '00000000-0000-4000-8000-0000000001a1' $$,
  'AC-09: o cliente B não vê as fases de P3, que o CEO aprovou'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.stage_approvals WHERE process_id IN (SELECT id FROM fixture_processes) $$,
  $$ VALUES (8) $$,
  'o CEO aal2 atestado lê as aprovações (2 de fixture, 3 de P3, 1 de P1, 1 de PX e 1 de PF)'
);
SELECT tests.clear_authentication();

-- F-50 b: o CEO sem atestado continua sem ver as aprovações que a função gravou, e a mesma sessão, atestada, passa ---------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c6', 'aal2', false);
SELECT is_empty($$ SELECT process_id FROM public.stage_approvals $$, 'F-50 b: o CEO com aal2 sem atestado não lê nenhuma aprovação gravada pela função');
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001f1', '00000000-0000-4000-8000-0000000002f2') $$,
  '42501', 'FORBIDDEN', 'F-50 b: o CEO com aal2 sem atestado não aprova uma fase que existe e está em andamento'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c6', 'aal2');
SELECT lives_ok(
  $$ SELECT * FROM public.approve_current_stage('00000000-0000-4000-8000-0000000001f1', '00000000-0000-4000-8000-0000000002f2') $$,
  'F-50 b: a mesma sessão, depois de atestada, aprova a mesma fase (o que negou foi a falta do atestado)'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  $$ SELECT p.status::text, p.version FROM public.processes p WHERE p.id = '00000000-0000-4000-8000-0000000001f1' $$,
  $$ VALUES ('completed', 3) $$,
  'F-50 b: o controle positivo concluiu PF (duas aprovações, versão 3)'
);

SELECT * FROM finish();
ROLLBACK;
