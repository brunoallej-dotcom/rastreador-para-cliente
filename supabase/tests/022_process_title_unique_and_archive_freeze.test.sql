-- Onda 10.2: F-80 (título de processo único entre os processos ativos de um cliente: 409 CONFLICT) e F-87 (cliente
-- arquivado congela os processos: 422 CLIENT_ARCHIVED). Spec §3.7.2, §3.7.3, §4.3, E-96 a E-102. Cobre:
--   F-80: o índice `processes_client_active_title_key` (único, parcial, com a chave de §3.7.1 e o `client_id`),
--   `create_process` e `update_process` recusando o título repetido (todas as grafias da chave), sem DETAIL, HINT nem
--   nome de constraint, sem evento, fase, versão nem linha nova, a unicidade que é do índice e não de uma consulta
--   (INSERT direto), o título livre (de processo concluído ou cancelado, de outro cliente), o renome para o próprio
--   título (no-op, só caixa, só espaços), o renome junto com o cancelamento (o estado final não disputa), a violação
--   de outro índice subindo crua (23505) e a autorização antes de qualquer conferência do título (42501 não revela
--   o título de ninguém: anon, cliente, CEO aal1 e CEO aal2 sem atestado).
--   F-87: aprovar, renomear e cancelar o processo de um cliente arquivado são `CLIENT_ARCHIVED` (qualquer status do
--   processo, sem escrever nada, sem auditar), a precedência (papel, entrada, processo, cliente arquivado, status,
--   título ou fase esperada), a leitura que continua (CEO e o login do próprio cliente arquivado, E-83), a criação
--   que continua recusada (E-16), desarquivar que descongela e arquivar de novo que congela de novo, a autorização
--   antes do arquivamento (o 42501 não revela se o cliente está arquivado), e a ordem de trava no catálogo:
--   cliente (FOR SHARE), processo e fase (FOR NO KEY UPDATE), de pai para filho. A espera de verdade (um arquivamento
--   em andamento) está nos testes de API, que seguram a trava numa segunda sessão.
BEGIN;
SELECT plan(155);

-- arrange (como postgres) --------------------------------------------------------------------------
-- A e B são clientes ativos; X é arquivado no meio do arquivo, pelo próprio `update_client`. a1 é login de A e x1,
-- de X (os dois com a senha definitiva: com a temporária o RLS não lê nada, F-83). c1 é CEO com fator verificado;
-- c2 e c3, CEOs com fator que NUNCA são atestados pelos helpers até o controle positivo (o que se obtém direto no
-- Auth): c2 para o F-80 e c3 para o F-87, porque o atestado fica depois do controle positivo.
INSERT INTO public.clients (id, name) VALUES
  ('00000000-0000-4000-8000-00000000a001', 'Cliente A'),
  ('00000000-0000-4000-8000-00000000a002', 'Cliente B'),
  ('00000000-0000-4000-8000-00000000a003', 'Cliente X');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000a001');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000d1', 'client', '00000000-0000-4000-8000-00000000a003');
UPDATE public.profiles SET must_change_password = false WHERE id IN (
  '00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000d1'
);
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c2', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c3', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c2');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c3');

-- O corpo de uma função sem os comentários (a ordem de trava olha o SQL que executa).
CREATE FUNCTION pg_temp.code(p_oid oid)
RETURNS text
LANGUAGE sql
AS $$
  SELECT regexp_replace(regexp_replace(p.prosrc, '/\*.*?\*/', '', 'g'), '--[^\n]*', '', 'g')
    FROM pg_proc p WHERE p.oid = p_oid
$$;

-- O que o banco guarda de um processo, numa linha: status, título, versão, fases, aprovações e auditoria. Um caso
-- que precisa provar "não escreveu nada" compara esta linha antes e depois, como postgres.
CREATE FUNCTION pg_temp.state_of(p_id uuid)
RETURNS text
LANGUAGE sql
AS $$
  SELECT p.status::text || '/' || p.title || '/v' || p.version || '/'
         || (SELECT string_agg(s.position || ':' || s.status::text, ',' ORDER BY s.position)
               FROM public.process_stages s WHERE s.process_id = p.id)
         || '/approvals=' || (SELECT count(*) FROM public.stage_approvals a WHERE a.process_id = p.id)
         || '/audit=' || (SELECT count(*) FROM public.audit_events e WHERE e.process_id = p.id)
    FROM public.processes p WHERE p.id = p_id
$$;

-- O que o banco guarda de um cliente: processos, fases e eventos de auditoria de processo (a recusa de um título
-- repetido não deixa nada: nem processo, nem fase órfã, nem evento).
CREATE FUNCTION pg_temp.client_state(p_id uuid)
RETURNS text
LANGUAGE sql
AS $$
  SELECT 'processes=' || (SELECT count(*) FROM public.processes p WHERE p.client_id = p_id)
         || '/stages=' || (SELECT count(*) FROM public.process_stages s JOIN public.processes p ON p.id = s.process_id WHERE p.client_id = p_id)
         || '/audit=' || (SELECT count(*) FROM public.audit_events e WHERE e.client_id = p_id AND e.process_id IS NOT NULL)
$$;

-- Os processos de teste, pelo apelido (preenchida depois da criação, como postgres).
CREATE TEMP TABLE proc (label text PRIMARY KEY, id uuid NOT NULL);
GRANT SELECT ON proc TO anon, authenticated;

-- Grafias que, depois de `visible_text` (NFC, pontas aparadas) e da chave do índice (`lower(normalize(.., NFKC))`,
-- sem as marcas de variação invisíveis, espaços repetidos reduzidos a um), são o título "Site novo" (e "Café Central").
CREATE TEMP TABLE taken_titles (label text PRIMARY KEY, value text NOT NULL);
INSERT INTO taken_titles (label, value) VALUES
  ('identico', 'Site novo'),
  ('maiusculas', 'SITE NOVO'),
  ('minusculas', 'site novo'),
  ('caixa mista', 'sItE nOvO'),
  ('dois espacos', 'Site  novo'),
  ('NBSP entre as palavras', 'Site' || chr(160) || 'novo'),
  ('espacos nas pontas', '  Site novo  '),
  ('largura total', U&'\FF33\FF49\FF54\FF45 \FF4E\FF4F\FF56\FF4F'),
  ('marca invisivel U+034F', 'Si' || chr(847) || 'te novo'),
  ('seletor de variacao U+FE0F', 'Site' || chr(65039) || ' novo');
GRANT SELECT ON taken_titles TO authenticated;
CREATE TEMP TABLE taken_accents (label text PRIMARY KEY, value text NOT NULL);
INSERT INTO taken_accents (label, value) VALUES
  ('acento decomposto', 'Cafe' || chr(769) || ' Central'),
  ('acento em maiuscula', 'CAF' || chr(201) || ' CENTRAL');
GRANT SELECT ON taken_accents TO authenticated;
-- Títulos que NÃO são os de acima: ficam livres (nenhuma grafia os confunde com "Site novo" nem com "Café Central").
CREATE TEMP TABLE free_titles (label text PRIMARY KEY, value text NOT NULL);
INSERT INTO free_titles (label, value) VALUES
  ('com numero', 'Site novo 2'),
  ('com hifen', 'Site-novo'),
  ('sem espaco', 'Sitenovo'),
  ('sem o acento', 'Cafe Central');
GRANT SELECT ON free_titles TO authenticated;

-- O índice (F-80, §4.3) ----------------------------------------------------------------------------
SELECT ok(
  (SELECT i.indisunique AND i.indpred IS NOT NULL
     FROM pg_index i WHERE i.indexrelid = 'public.processes_client_active_title_key'::regclass),
  'F-80: processes_client_active_title_key é um índice único e parcial'
);
SELECT ok(
  (SELECT pg_get_indexdef(i.indexrelid) ~ 'USING btree \(client_id, '
          AND pg_get_indexdef(i.indexrelid) ~* 'normalize\(title, NFKC\)'
          AND pg_get_indexdef(i.indexrelid) ~ 'lower\('
          AND pg_get_indexdef(i.indexrelid) ~ 'WHERE \(status = ''active''::process_status\)'
     FROM pg_index i WHERE i.indexrelid = 'public.processes_client_active_title_key'::regclass),
  'F-80: a chave leva o client_id e lower(normalize(title, NFKC)), e vale só para status = active'
);
SELECT ok(
  (SELECT i.indrelid = 'public.processes'::regclass FROM pg_index i
    WHERE i.indexrelid = 'public.processes_client_active_title_key'::regclass),
  'F-80: o índice é da tabela public.processes'
);
SELECT matches(
  obj_description('public.processes_client_active_title_key'::regclass, 'pg_class'),
  'F-80',
  'F-80: o índice tem comentário com o caso de uso'
);
SELECT is(lower(chr(201)), chr(233), 'F-80: o lower() do banco dobra letras acentuadas (o locale é Unicode: o índice só vale assim)');
SELECT is(lower(chr(913)), chr(945), 'F-80: ... e o grego também; sem isso "SITE" e "site" fora do ASCII passariam');
SELECT is(
  (SELECT count(*)::int FROM pg_indexes WHERE schemaname = 'public' AND tablename = 'processes'
      AND indexdef ~ 'UNIQUE' AND indexname <> 'processes_pkey' AND indexname <> 'processes_client_active_title_key'),
  0,
  'F-80: nenhum outro índice único em processes (o único erro 23505 esperado é o do título)'
);

-- Funções: configuração e privilégios (AC-25), as três que mudaram -------------------------------------
SELECT ok(
  (SELECT bool_and(p.prosecdef AND 'search_path=""' = ANY (p.proconfig)) FROM pg_proc p
    WHERE p.oid IN ('public.create_process(uuid, text, jsonb)'::regprocedure,
                    'public.update_process(uuid, text, boolean)'::regprocedure,
                    'public.approve_current_stage(uuid, uuid)'::regprocedure)),
  'AC-25: create_process, update_process e approve_current_stage seguem SECURITY DEFINER com search_path vazio'
);
SELECT ok(
  (SELECT NOT bool_or(has_function_privilege('anon', p.oid, 'EXECUTE') OR has_function_privilege('service_role', p.oid, 'EXECUTE'))
          AND bool_and(has_function_privilege('authenticated', p.oid, 'EXECUTE'))
     FROM pg_proc p
    WHERE p.oid IN ('public.create_process(uuid, text, jsonb)'::regprocedure,
                    'public.update_process(uuid, text, boolean)'::regprocedure,
                    'public.approve_current_stage(uuid, uuid)'::regprocedure)),
  'AC-10, SEC-04: só authenticated executa as três (nem anon, nem a secret key)'
);
SELECT is_empty(
  $$ SELECT p.proname FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE p.oid IN ('public.create_process(uuid, text, jsonb)'::regprocedure,
                      'public.update_process(uuid, text, boolean)'::regprocedure,
                      'public.approve_current_stage(uuid, uuid)'::regprocedure)
        AND a.grantee = 0 AND a.privilege_type = 'EXECUTE' $$,
  'AC-25: nenhuma das três concede EXECUTE a PUBLIC'
);

-- A ordem de trava e de erro, no catálogo (F-87, F-82): de pai para filho -----------------------------------
SELECT ok(
  (SELECT pg_temp.code(p.oid) ~ 'FROM public\.clients c\s+WHERE c\.id = v_client_id\s+FOR SHARE'
          AND pg_temp.code(p.oid) ~ 'FROM public\.processes p\s+WHERE p\.id = p_process_id\s+AND p\.client_id = v_client_id\s+FOR NO KEY UPDATE'
     FROM pg_proc p WHERE p.oid = 'public.update_process(uuid, text, boolean)'::regprocedure),
  'F-87: update_process trava o cliente (FOR SHARE) e depois o processo (FOR NO KEY UPDATE, o client_id lido antes)'
);
SELECT ok(
  (SELECT regexp_count(pg_temp.code(p.oid), 'FOR SHARE', 1, 'i') = 1
          AND regexp_count(pg_temp.code(p.oid), 'FOR NO KEY UPDATE', 1, 'i') = 1
          AND position('FOR SHARE' IN pg_temp.code(p.oid)) < position('FOR NO KEY UPDATE' IN pg_temp.code(p.oid))
          AND pg_temp.code(p.oid) !~* 'FOR\s+UPDATE\M' AND pg_temp.code(p.oid) !~* 'FOR\s+KEY\s+SHARE\M'
     FROM pg_proc p WHERE p.oid = 'public.update_process(uuid, text, boolean)'::regprocedure),
  'F-87: update_process: uma trava FOR SHARE (a do cliente), antes da única FOR NO KEY UPDATE (a do processo); nunca FOR UPDATE'
);
SELECT ok(
  (SELECT regexp_count(pg_temp.code(p.oid), 'public\.clients', 1, 'i') = 1
     FROM pg_proc p WHERE p.oid = 'public.update_process(uuid, text, boolean)'::regprocedure)
  AND (SELECT regexp_count(pg_temp.code(p.oid), 'public\.clients', 1, 'i') = 1
         FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'F-87: update_process e approve_current_stage só tocam public.clients na leitura travada do archived_at (nenhum UPDATE de cliente)'
);
SELECT ok(
  (SELECT pg_temp.code(p.oid) !~* 'FOR\s+SHARE\M'
          AND pg_temp.code(p.oid) ~ 'FROM public\.clients c\s+WHERE c\.id = p_client_id\s+FOR NO KEY UPDATE'
     FROM pg_proc p WHERE p.oid = 'public.create_process(uuid, text, jsonb)'::regprocedure),
  'F-87: create_process segue travando o cliente com FOR NO KEY UPDATE, sem FOR SHARE (o cliente vem antes do processo que ela insere)'
);
SELECT ok(
  (SELECT position('IF private.is_ceo() IS NOT TRUE THEN' IN pg_temp.code(p.oid)) > 0
          AND position('IF private.is_ceo() IS NOT TRUE THEN' IN pg_temp.code(p.oid)) < position('FOR SHARE' IN pg_temp.code(p.oid))
     FROM pg_proc p WHERE p.oid = 'public.update_process(uuid, text, boolean)'::regprocedure)
  AND (SELECT position('IF private.is_ceo() IS NOT TRUE THEN' IN pg_temp.code(p.oid)) > 0
              AND position('IF private.is_ceo() IS NOT TRUE THEN' IN pg_temp.code(p.oid)) < position('FOR SHARE' IN pg_temp.code(p.oid))
         FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'F-55: as duas abrem com IF private.is_ceo() IS NOT TRUE, antes da trava do cliente'
);
SELECT ok(
  (SELECT position('NOT_FOUND' IN pg_temp.code(p.oid)) > 0
          AND position('NOT_FOUND' IN pg_temp.code(p.oid)) < position('CLIENT_ARCHIVED' IN pg_temp.code(p.oid))
          AND position('CLIENT_ARCHIVED' IN pg_temp.code(p.oid)) < position('PROCESS_NOT_ACTIVE' IN pg_temp.code(p.oid))
          AND position('PROCESS_NOT_ACTIVE' IN pg_temp.code(p.oid)) < position('PROCESS_TITLE_TAKEN' IN pg_temp.code(p.oid))
     FROM pg_proc p WHERE p.oid = 'public.update_process(uuid, text, boolean)'::regprocedure),
  'F-87: update_process: a precedência é NOT_FOUND, CLIENT_ARCHIVED, PROCESS_NOT_ACTIVE e só então PROCESS_TITLE_TAKEN'
);
SELECT ok(
  (SELECT position('NOT_FOUND' IN pg_temp.code(p.oid)) > 0
          AND position('NOT_FOUND' IN pg_temp.code(p.oid)) < position('CLIENT_ARCHIVED' IN pg_temp.code(p.oid))
          AND position('CLIENT_ARCHIVED' IN pg_temp.code(p.oid)) < position('PROCESS_NOT_ACTIVE' IN pg_temp.code(p.oid))
          AND position('PROCESS_NOT_ACTIVE' IN pg_temp.code(p.oid)) < position('STALE_STAGE' IN pg_temp.code(p.oid))
     FROM pg_proc p WHERE p.oid = 'public.approve_current_stage(uuid, uuid)'::regprocedure),
  'F-87: approve_current_stage: a precedência é NOT_FOUND, CLIENT_ARCHIVED, PROCESS_NOT_ACTIVE e só então STALE_STAGE'
);
SELECT ok(
  (SELECT pg_temp.code(p.oid) ~ 'processes_client_active_title_key' AND pg_temp.code(p.oid) ~ 'unique_violation'
     FROM pg_proc p WHERE p.oid = 'public.create_process(uuid, text, jsonb)'::regprocedure)
  AND (SELECT pg_temp.code(p.oid) ~ 'processes_client_active_title_key' AND pg_temp.code(p.oid) ~ 'unique_violation'
         FROM pg_proc p WHERE p.oid = 'public.update_process(uuid, text, boolean)'::regprocedure),
  'F-80: create_process e update_process só traduzem a violação do NOSSO índice (pelo nome do constraint)'
);
SELECT ok(
  (SELECT pg_temp.code(p.oid) !~* 'FROM\s+public\.processes' AND pg_temp.code(p.oid) !~* 'normalize\('
     FROM pg_proc p WHERE p.oid = 'public.create_process(uuid, text, jsonb)'::regprocedure),
  'F-80: create_process não faz consulta prévia pelo título: quem decide é o índice (duas criações simultâneas não passam as duas)'
);

-- Fixtures: criados e movidos pelas funções, como o CEO ---------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT tests.set_request_id('req-title-0001');
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Site novo') $$,
  'F-80: o primeiro "Site novo" do cliente A é criado'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Site pronto') $$,
  'F-80: "Site pronto" também'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Site reserva') $$,
  'F-80: "Site reserva" também'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Site cancelando') $$,
  'F-80: "Site cancelando" também'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Site outro') $$,
  'F-80: "Site outro" também'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Café Central') $$,
  'F-80: "Café Central" (com acento) também'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a002', 'Site novo') $$,
  'F-80: o título de outro cliente não conta: o cliente B tem o seu "Site novo"'
);
SELECT tests.clear_authentication();
INSERT INTO proc (label, id)
SELECT v.label, p.id
  FROM (VALUES ('a-novo', 'Site novo'), ('a-pronto', 'Site pronto'), ('a-reserva', 'Site reserva'),
               ('a-cancelando', 'Site cancelando'), ('a-outro', 'Site outro'), ('a-cafe', 'Café Central')) v (label, title)
  JOIN public.processes p ON p.client_id = '00000000-0000-4000-8000-00000000a001' AND p.title = v.title;
INSERT INTO proc (label, id)
SELECT 'b-novo', p.id FROM public.processes p
 WHERE p.client_id = '00000000-0000-4000-8000-00000000a002' AND p.title = 'Site novo';

-- F-80: criar com um título já ativo no cliente (E-96) -------------------------------------------------------
SELECT set_config('t.a_before', pg_temp.client_state('00000000-0000-4000-8000-00000000a001'), false);
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT tests.set_request_id('req-title-0002');
SELECT throws_ok(
  format('SELECT * FROM public.create_process(%L, %L)', '00000000-0000-4000-8000-00000000a001', t.value),
  'P0001', 'PROCESS_TITLE_TAKEN',
  'E-96, F-80: create_process recusa o título repetido (' || t.label || ')'
) FROM taken_titles t ORDER BY t.label;
SELECT throws_ok(
  format('SELECT * FROM public.create_process(%L, %L)', '00000000-0000-4000-8000-00000000a001', t.value),
  'P0001', 'PROCESS_TITLE_TAKEN',
  'E-96, F-80: create_process recusa o título repetido (' || t.label || ')'
) FROM taken_accents t ORDER BY t.label;
SELECT throws_ok(
  format('SELECT * FROM public.create_process(%L, %L, %L::jsonb)', '00000000-0000-4000-8000-00000000a001', 'SITE NOVO',
         '[{"name":"Briefing"},{"name":"Entrega","description":"Fim"}]'),
  'P0001', 'PROCESS_TITLE_TAKEN',
  'E-96, F-80: o mesmo com as fases informadas (nada de fase órfã)'
);
SELECT tests.clear_authentication();
SELECT is(
  pg_temp.client_state('00000000-0000-4000-8000-00000000a001'),
  current_setting('t.a_before'),
  'E-96, F-80: as recusas não deixaram processo, fase nem evento de auditoria (a transação inteira voltou)'
);
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  format('SELECT * FROM public.create_process(%L, %L)', '00000000-0000-4000-8000-00000000a001', f.value),
  'E-98, F-80: um título diferente fica livre (' || f.label || ')'
) FROM free_titles f ORDER BY f.label;
SELECT tests.clear_authentication();

-- O erro não carrega nada além do código e da mensagem: nem DETAIL (que traria o título normalizado), nem HINT, nem
-- o nome do constraint, da tabela ou do esquema (que diria qual índice, e portanto qual processo) ----------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
DO $$
DECLARE
  v_calls text[] := ARRAY[
    $c$SELECT public.create_process('00000000-0000-4000-8000-00000000a001', 'SITE NOVO')$c$,
    $c$SELECT public.create_process('00000000-0000-4000-8000-00000000a001', 'SITE NOVO', '[{"name":"x"}]'::jsonb)$c$,
    format($c$SELECT public.update_process(%L, 'SITE NOVO', NULL)$c$, (SELECT p.id FROM proc p WHERE p.label = 'a-pronto'))
  ];
  v_sql        text;
  v_i          integer := 0;
  v_state      text;
  v_message    text;
  v_detail     text;
  v_hint       text;
  v_constraint text;
  v_table      text;
  v_schema     text;
  v_column     text;
  v_datatype   text;
BEGIN
  FOREACH v_sql IN ARRAY v_calls LOOP
    v_i := v_i + 1;
    BEGIN
      EXECUTE v_sql;
      PERFORM set_config('probe.shape' || v_i, 'no error', true);
    EXCEPTION WHEN OTHERS THEN
      GET STACKED DIAGNOSTICS
        v_state = RETURNED_SQLSTATE, v_message = MESSAGE_TEXT, v_detail = PG_EXCEPTION_DETAIL,
        v_hint = PG_EXCEPTION_HINT, v_constraint = CONSTRAINT_NAME, v_table = TABLE_NAME,
        v_schema = SCHEMA_NAME, v_column = COLUMN_NAME, v_datatype = PG_DATATYPE_NAME;
      PERFORM set_config(
        'probe.shape' || v_i,
        concat_ws('|', v_state, v_message, coalesce(v_detail, ''), coalesce(v_hint, ''),
                  coalesce(v_constraint, ''), coalesce(v_table, ''), coalesce(v_schema, ''),
                  coalesce(v_column, ''), coalesce(v_datatype, '')),
        true
      );
    END;
  END LOOP;
END $$;
SELECT is(
  current_setting('probe.shape1'), concat_ws('|', 'P0001', 'PROCESS_TITLE_TAKEN', '', '', '', '', '', '', ''),
  'F-80: create_process recusa com SQLSTATE e mensagem apenas (DETAIL, HINT, constraint, tabela e esquema vazios)'
);
SELECT is(
  current_setting('probe.shape2'), concat_ws('|', 'P0001', 'PROCESS_TITLE_TAKEN', '', '', '', '', '', '', ''),
  'F-80: create_process com as fases informadas recusa do mesmo jeito'
);
SELECT is(
  current_setting('probe.shape3'), concat_ws('|', 'P0001', 'PROCESS_TITLE_TAKEN', '', '', '', '', '', '', ''),
  'F-80: update_process ao renomear recusa do mesmo jeito'
);
SELECT tests.clear_authentication();

-- F-80: renomear para um título já ativo no cliente (E-97) ----------------------------------------------------
SELECT set_config('t.pronto_before', pg_temp.state_of((SELECT p.id FROM proc p WHERE p.label = 'a-pronto')), false);
SELECT set_config('t.a_before2', pg_temp.client_state('00000000-0000-4000-8000-00000000a001'), false);
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT tests.set_request_id('req-title-0003');
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'a-pronto'), t.value),
  'P0001', 'PROCESS_TITLE_TAKEN',
  'E-97, F-80: update_process recusa renomear para o título repetido (' || t.label || ')'
) FROM taken_titles t ORDER BY t.label;
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'a-pronto'), t.value),
  'P0001', 'PROCESS_TITLE_TAKEN',
  'E-97, F-80: update_process recusa renomear para o título repetido (' || t.label || ')'
) FROM taken_accents t ORDER BY t.label;
SELECT tests.clear_authentication();
SELECT is(
  pg_temp.state_of((SELECT p.id FROM proc p WHERE p.label = 'a-pronto')),
  current_setting('t.pronto_before'),
  'E-97, F-80: o processo recusado fica como estava (título, versão, fases e auditoria)'
);
SELECT is(
  pg_temp.client_state('00000000-0000-4000-8000-00000000a001'),
  current_setting('t.a_before2'),
  'E-97, F-80: nenhum evento de auditoria nasceu das recusas'
);
SELECT is_empty(
  $$ SELECT e.id FROM public.audit_events e WHERE e.process_id IS NOT NULL AND e.metadata::text ~* '(Site novo|SITE NOVO|Caf)' $$,
  'F-80: nenhum título foi para os metadados da auditoria'
);

-- o título mais forte que o resto: entrada inválida e papel vêm antes do título (precedência) -----------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'a-pronto'), '   '),
  'P0001', 'INVALID_INPUT',
  'F-80: título em branco no renome é INVALID_INPUT, antes de qualquer conferência de título'
);
SELECT throws_ok(
  format('SELECT * FROM public.create_process(%L, %L)', '00000000-0000-4000-8000-00000000a001', chr(160)),
  'P0001', 'INVALID_INPUT',
  'F-80: título em branco na criação é INVALID_INPUT, antes de qualquer conferência de título'
);
SELECT throws_ok(
  format('SELECT * FROM public.create_process(%L, %L)', '00000000-0000-4000-8000-00000000a0ff', 'Site novo'),
  'P0001', 'NOT_FOUND',
  'F-80: cliente inexistente é NOT_FOUND (a trava do cliente vem antes do título)'
);
-- o renome para o próprio título: no-op (E-61), só caixa e só espaços (permitidos) ---------------------------------
SELECT results_eq(
  format('SELECT title, version FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'a-reserva'), 'Site reserva'),
  $$ VALUES ('Site reserva', 1) $$,
  'E-61, F-80: renomear para o próprio título é o no-op: 200 sem 409, sem versão nova'
);
SELECT results_eq(
  format('SELECT title, version FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'a-reserva'), 'SITE RESERVA'),
  $$ VALUES ('SITE RESERVA', 2) $$,
  'E-97, F-80: trocar só as maiúsculas do próprio título é permitido (a linha não conflita com ela mesma)'
);
SELECT results_eq(
  format('SELECT title, version FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'a-reserva'), '  SITE   RESERVA '),
  $$ VALUES ('SITE   RESERVA', 3) $$,
  'E-97, F-80: trocar só os espaços do próprio título também'
);
SELECT results_eq(
  format('SELECT title, version FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'a-reserva'), 'SITE   RESERVA'),
  $$ VALUES ('SITE   RESERVA', 3) $$,
  'E-61, F-80: repetir o renome é idempotente (o retry depois de um 503 é seguro)'
);
SELECT tests.clear_authentication();

-- o estado final é o que vale: renomear e cancelar na mesma chamada não disputa o título (E-97) ----------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  format('SELECT status::text, title, version FROM public.update_process(%L, %L, true)', (SELECT p.id FROM proc p WHERE p.label = 'a-cancelando'), 'SITE NOVO'),
  $$ VALUES ('cancelled', 'SITE NOVO', 2) $$,
  'E-97, F-80: renomear para um título em uso e cancelar na mesma chamada vale: o processo cancelado sai do índice'
);
SELECT tests.clear_authentication();
SELECT results_eq(
  format($q$ SELECT e.action FROM public.audit_events e WHERE e.resource_id = %L AND e.action LIKE 'process.%%' AND e.action <> 'process.created' ORDER BY e.id $q$,
         (SELECT p.id FROM proc p WHERE p.label = 'a-cancelando')),
  $$ VALUES ('process.updated'), ('process.cancelled') $$,
  'E-97, F-80: os dois eventos, nessa ordem'
);
SELECT is(
  (SELECT count(*)::int FROM public.processes p
    WHERE p.client_id = '00000000-0000-4000-8000-00000000a001' AND p.status = 'active' AND lower(p.title) = 'site novo'),
  1,
  'F-80: continua um único "Site novo" ativo no cliente A (o outro está cancelado)'
);
-- renomear para o título de um processo cancelado, e para o de outro cliente (livre) ------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'a-outro'), 'Site novo'),
  'P0001', 'PROCESS_TITLE_TAKEN',
  'E-97, F-80: "Site novo" segue de um processo ativo (o outro, cancelado, não o libera para um terceiro)'
);
SELECT results_eq(
  format('SELECT title FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'a-outro'), 'Projeto Beta'),
  $$ VALUES ('Projeto Beta') $$,
  'E-98, F-80: um título que ninguém usa é livre'
);
SELECT tests.clear_authentication();

-- o título de um processo concluído ou cancelado pode ser usado de novo (E-98) -----------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Reuso concluido',
       '[{"name":"Unica"}]'::jsonb) $$,
  'E-98, F-80: cria o processo de uma fase "Reuso concluido"'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Reuso cancelado') $$,
  'E-98, F-80: cria o processo "Reuso cancelado"'
);
SELECT tests.clear_authentication();
INSERT INTO proc (label, id)
SELECT v.label, p.id
  FROM (VALUES ('a-reuso-concluido', 'Reuso concluido'), ('a-reuso-cancelado', 'Reuso cancelado')) v (label, title)
  JOIN public.processes p ON p.client_id = '00000000-0000-4000-8000-00000000a001' AND p.title = v.title;
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  format('SELECT status::text FROM public.approve_current_stage(%L, (SELECT s.id FROM public.process_stages s WHERE s.process_id = %L AND s.status = ''in_progress''))',
         (SELECT p.id FROM proc p WHERE p.label = 'a-reuso-concluido'), (SELECT p.id FROM proc p WHERE p.label = 'a-reuso-concluido')),
  $$ VALUES ('completed') $$,
  'E-98, F-80: a única fase aprovada conclui o processo'
);
SELECT results_eq(
  format('SELECT status::text FROM public.update_process(%L, NULL, true)', (SELECT p.id FROM proc p WHERE p.label = 'a-reuso-cancelado')),
  $$ VALUES ('cancelled') $$,
  'E-98, F-80: o outro é cancelado'
);
SELECT results_eq(
  format('SELECT title FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'a-pronto'), 'Reuso cancelado'),
  $$ VALUES ('Reuso cancelado') $$,
  'E-98, F-80: renomear para o título de um processo cancelado (e de nenhum ativo) vale'
);
SELECT results_eq(
  format('SELECT title FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'a-pronto'), 'Reuso concluido'),
  $$ VALUES ('Reuso concluido') $$,
  'E-98, F-80: e para o de um processo concluído (e de nenhum ativo)'
);
SELECT results_eq(
  format('SELECT title FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'a-pronto'), 'Site pronto'),
  $$ VALUES ('Site pronto') $$,
  'E-98, F-80: e de volta: o título que ele deixa fica livre'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Reuso concluido') $$,
  'E-98, F-80: o título do processo concluído pode ser usado de novo'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'REUSO CANCELADO') $$,
  'E-98, F-80: o título do processo cancelado também (em outra caixa)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Reuso concluido') $$,
  'P0001', 'PROCESS_TITLE_TAKEN',
  'E-98, F-80: mas só um ativo de cada vez: o terceiro, com o título de um ativo, é recusado'
);
SELECT tests.clear_authentication();

-- o índice decide, não uma consulta: o INSERT direto (como postgres) ----------------------------------------------
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title) VALUES ('00000000-0000-4000-8000-00000000a001', 'sItE  NoVo') $$,
  '23505', 'duplicate key value violates unique constraint "processes_client_active_title_key"',
  'F-80: o índice recusa o segundo título ativo igual, escreva quem escrever (a unicidade é dele, e por isso vale sob concorrência)'
);
SELECT lives_ok(
  $$ INSERT INTO public.processes (client_id, title, status, cancelled_at)
     VALUES ('00000000-0000-4000-8000-00000000a001', 'Site novo', 'cancelled', now()) $$,
  'F-80: o índice é parcial: um cancelado com o mesmo título entra'
);
SELECT lives_ok(
  $$ INSERT INTO public.processes (client_id, title) VALUES ('00000000-0000-4000-8000-00000000a003', 'Site novo') $$,
  'F-80: a chave leva o cliente: o mesmo título em outro cliente entra'
);

-- A autorização vem antes de qualquer conferência do título e do arquivamento: o 42501 não revela nada ------------
SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Site novo') $$,
  '42501', NULL, 'AC-10, F-80: anon não executa create_process (nem descobre um título em uso)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'a-pronto'), 'Site novo', NULL) $$,
  '42501', NULL, 'AC-10, F-80: anon não executa update_process'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Site novo') $$,
  '42501', 'FORBIDDEN', 'AC-08, F-80: o cliente (do próprio tenant, mesmo com aal2 no JWT) não descobre um título em uso: 42501, não 409'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'a-pronto'), 'Site novo', NULL) $$,
  '42501', 'FORBIDDEN', 'AC-08, F-80: o cliente não renomeia (nem descobre um título em uso)'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Site novo') $$,
  '42501', 'FORBIDDEN', 'AC-08, F-80: o CEO aal1 não descobre um título em uso: 42501, não 409'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'a-pronto'), 'Site novo', NULL) $$,
  '42501', 'FORBIDDEN', 'AC-08, F-80: o CEO aal1 não renomeia'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2', false);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Site novo') $$,
  '42501', 'FORBIDDEN', 'F-50 b, F-80: o CEO aal2 SEM atestado não descobre um título em uso: 42501, não 409'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'a-pronto'), 'Site novo', NULL) $$,
  '42501', 'FORBIDDEN', 'F-50 b, F-80: o CEO aal2 sem atestado não renomeia'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Site novo') $$,
  'P0001', 'PROCESS_TITLE_TAKEN', 'F-80: o controle positivo: o mesmo CEO, atestado, recebe a recusa do título'
);
SELECT tests.clear_authentication();

-- Outro índice único da tabela não vira PROCESS_TITLE_TAKEN: sobe cru (23505, com o nome do índice dele) -----------
CREATE UNIQUE INDEX zz_probe_one_process ON public.processes ((title IS NOT NULL)) WHERE title LIKE 'Probe %';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Probe 1') $$,
  'F-80: o primeiro processo "Probe" é criado'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a001', 'Probe 2') $$,
  '23505', 'duplicate key value violates unique constraint "zz_probe_one_process"',
  'F-80: create_process não traduz a violação de outro índice: sobe como 23505'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'a-outro'), 'Probe 3', NULL) $$,
  '23505', 'duplicate key value violates unique constraint "zz_probe_one_process"',
  'F-80: update_process não traduz a violação de outro índice: sobe como 23505'
);
SELECT tests.clear_authentication();
DROP INDEX public.zz_probe_one_process;

-- F-87: cliente arquivado congela os processos ----------------------------------------------------------------
-- O cliente X ganha os processos pelas funções (ativos, um concluído, um cancelado) e depois é arquivado pelo
-- próprio `update_client`, como o CEO faz.
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT tests.set_request_id('req-freeze-0001');
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a003', 'X ativo', '[{"name":"F1"},{"name":"F2"}]'::jsonb) $$,
  'F-87: cria o processo ativo "X ativo" (2 fases) no cliente X'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a003', 'X ativo dois', '[{"name":"G1"},{"name":"G2"}]'::jsonb) $$,
  'F-87: cria o processo ativo "X ativo dois"'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a003', 'X concluido', '[{"name":"H1"}]'::jsonb) $$,
  'F-87: cria o processo de uma fase "X concluido"'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a003', 'X cancelado') $$,
  'F-87: cria o processo "X cancelado"'
);
SELECT tests.clear_authentication();
INSERT INTO proc (label, id)
SELECT v.label, p.id
  FROM (VALUES ('x-ativo', 'X ativo'), ('x-ativo2', 'X ativo dois'), ('x-concluido', 'X concluido'), ('x-cancelado', 'X cancelado')) v (label, title)
  JOIN public.processes p ON p.client_id = '00000000-0000-4000-8000-00000000a003' AND p.title = v.title;
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  format('SELECT * FROM public.approve_current_stage(%L, (SELECT s.id FROM public.process_stages s WHERE s.process_id = %L AND s.status = ''in_progress''))',
         (SELECT p.id FROM proc p WHERE p.label = 'x-concluido'), (SELECT p.id FROM proc p WHERE p.label = 'x-concluido')),
  'F-87: "X concluido" é concluído (a única fase aprovada)'
);
SELECT lives_ok(
  format('SELECT * FROM public.update_process(%L, NULL, true)', (SELECT p.id FROM proc p WHERE p.label = 'x-cancelado')),
  'F-87: "X cancelado" é cancelado'
);
SELECT tests.clear_authentication();
SELECT set_config('t.x_ativo', pg_temp.state_of((SELECT p.id FROM proc p WHERE p.label = 'x-ativo')), false);
SELECT set_config('t.x_ativo2', pg_temp.state_of((SELECT p.id FROM proc p WHERE p.label = 'x-ativo2')), false);
SELECT set_config('t.x_concluido', pg_temp.state_of((SELECT p.id FROM proc p WHERE p.label = 'x-concluido')), false);
SELECT set_config('t.x_cancelado', pg_temp.state_of((SELECT p.id FROM proc p WHERE p.label = 'x-cancelado')), false);
SELECT set_config('t.x_stage1', (SELECT s.id::text FROM public.process_stages s
   WHERE s.process_id = (SELECT p.id FROM proc p WHERE p.label = 'x-ativo') AND s.status = 'in_progress'), false);
SELECT set_config('t.x_stage2', (SELECT s.id::text FROM public.process_stages s
   WHERE s.process_id = (SELECT p.id FROM proc p WHERE p.label = 'x-ativo') AND s.position = 2), false);
SELECT set_config('t.x2_stage1', (SELECT s.id::text FROM public.process_stages s
   WHERE s.process_id = (SELECT p.id FROM proc p WHERE p.label = 'x-ativo2') AND s.status = 'in_progress'), false);
SELECT set_config('t.x_done_stage', (SELECT s.id::text FROM public.process_stages s
   WHERE s.process_id = (SELECT p.id FROM proc p WHERE p.label = 'x-concluido')), false);
SELECT set_config('t.x_canc_stage', (SELECT s.id::text FROM public.process_stages s
   WHERE s.process_id = (SELECT p.id FROM proc p WHERE p.label = 'x-cancelado') AND s.status = 'in_progress'), false);

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000a003', NULL, true) $$,
  'F-87: o CEO arquiva o cliente X'
);
SELECT tests.set_request_id('req-freeze-0002');
-- aprovar ---------------------------------------------------------------------------------------------------------
SELECT throws_ok(
  format('SELECT * FROM public.approve_current_stage(%L, %L)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), current_setting('t.x_stage1')),
  'P0001', 'CLIENT_ARCHIVED', 'E-99, F-87: aprovar a fase atual de um processo de cliente arquivado é CLIENT_ARCHIVED'
);
SELECT throws_ok(
  format('SELECT * FROM public.approve_current_stage(%L, %L)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), current_setting('t.x_stage2')),
  'P0001', 'CLIENT_ARCHIVED', 'E-99, F-87: com uma fase esperada velha também (o arquivado vence STALE_STAGE)'
);
SELECT throws_ok(
  format('SELECT * FROM public.approve_current_stage(%L, %L)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), gen_random_uuid()),
  'P0001', 'CLIENT_ARCHIVED', 'E-99, F-87: com uma fase que não existe também'
);
SELECT throws_ok(
  format('SELECT * FROM public.approve_current_stage(%L, %L)', (SELECT p.id FROM proc p WHERE p.label = 'x-concluido'), current_setting('t.x_done_stage')),
  'P0001', 'CLIENT_ARCHIVED', 'E-99, F-87: processo concluído de cliente arquivado: CLIENT_ARCHIVED vence PROCESS_NOT_ACTIVE'
);
SELECT throws_ok(
  format('SELECT * FROM public.approve_current_stage(%L, %L)', (SELECT p.id FROM proc p WHERE p.label = 'x-cancelado'), current_setting('t.x_canc_stage')),
  'P0001', 'CLIENT_ARCHIVED', 'E-99, F-87: processo cancelado de cliente arquivado: CLIENT_ARCHIVED vence PROCESS_NOT_ACTIVE'
);
-- renomear e cancelar -----------------------------------------------------------------------------------------------
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), 'X ativo renomeado'),
  'P0001', 'CLIENT_ARCHIVED', 'E-99, F-87: renomear o processo de um cliente arquivado é CLIENT_ARCHIVED'
);
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, NULL, true)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo')),
  'P0001', 'CLIENT_ARCHIVED', 'E-99, F-87: cancelar também'
);
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, true)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), 'X ativo renomeado'),
  'P0001', 'CLIENT_ARCHIVED', 'E-99, F-87: renomear e cancelar juntos também'
);
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), 'X ativo'),
  'P0001', 'CLIENT_ARCHIVED', 'E-99, F-87: renomear para o próprio título (que seria o no-op) também: o arquivado é recusado antes'
);
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), 'X ativo dois'),
  'P0001', 'CLIENT_ARCHIVED', 'E-99, F-87: renomear para o título de outro ativo do mesmo cliente: CLIENT_ARCHIVED vence PROCESS_TITLE_TAKEN'
);
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'x-concluido'), 'X concluido renomeado'),
  'P0001', 'CLIENT_ARCHIVED', 'E-99, F-87: renomear um processo concluído de cliente arquivado: CLIENT_ARCHIVED vence PROCESS_NOT_ACTIVE'
);
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, NULL, true)', (SELECT p.id FROM proc p WHERE p.label = 'x-cancelado')),
  'P0001', 'CLIENT_ARCHIVED', 'E-99, F-87: cancelar de novo um processo cancelado de cliente arquivado: CLIENT_ARCHIVED vence PROCESS_NOT_ACTIVE'
);
-- a precedência: papel, entrada e processo vêm antes do arquivado ----------------------------------------------------
SELECT throws_ok(
  format('SELECT * FROM public.approve_current_stage(%L, %L)', gen_random_uuid(), current_setting('t.x_stage1')),
  'P0001', 'NOT_FOUND', 'E-99, F-87: processo inexistente é NOT_FOUND (o 404 vem antes do arquivado)'
);
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, NULL)', gen_random_uuid(), 'Qualquer'),
  'P0001', 'NOT_FOUND', 'E-99, F-87: idem no update_process'
);
SELECT throws_ok(
  format('SELECT * FROM public.approve_current_stage(%L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo')),
  'P0001', 'INVALID_INPUT', 'E-99, F-87: a fase esperada nula é INVALID_INPUT, antes do arquivado'
);
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, NULL, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo')),
  'P0001', 'INVALID_INPUT', 'E-99, F-87: update_process sem nada para mudar é INVALID_INPUT, antes do arquivado'
);
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), '   '),
  'P0001', 'INVALID_INPUT', 'E-99, F-87: título em branco é INVALID_INPUT, antes do arquivado'
);
-- criar continua recusado (E-16) ---------------------------------------------------------------------------------------
SELECT throws_ok(
  $$ SELECT * FROM public.create_process('00000000-0000-4000-8000-00000000a003', 'Novo no arquivado') $$,
  'P0001', 'CLIENT_ARCHIVED', 'E-16: criar processo para cliente arquivado segue CLIENT_ARCHIVED'
);
SELECT tests.clear_authentication();
SELECT is(pg_temp.state_of((SELECT p.id FROM proc p WHERE p.label = 'x-ativo')), current_setting('t.x_ativo'),
  'E-99, F-87: nada mudou em "X ativo" (status, título, versão, fases, aprovações e auditoria)');
SELECT is(pg_temp.state_of((SELECT p.id FROM proc p WHERE p.label = 'x-ativo2')), current_setting('t.x_ativo2'),
  'E-99, F-87: nada mudou em "X ativo dois"');
SELECT is(pg_temp.state_of((SELECT p.id FROM proc p WHERE p.label = 'x-concluido')), current_setting('t.x_concluido'),
  'E-99, F-87: nada mudou em "X concluido"');
SELECT is(pg_temp.state_of((SELECT p.id FROM proc p WHERE p.label = 'x-cancelado')), current_setting('t.x_cancelado'),
  'E-99, F-87: nada mudou em "X cancelado"');
SELECT is_empty(
  $$ SELECT e.id FROM public.audit_events e
      WHERE e.client_id = '00000000-0000-4000-8000-00000000a003' AND e.process_id IS NOT NULL
        AND e.id > (SELECT max(a.id) FROM public.audit_events a
                     WHERE a.action = 'client.archived' AND a.client_id = '00000000-0000-4000-8000-00000000a003') $$,
  'E-99, F-87: nenhum evento de processo depois do arquivamento (a recusa não grava nada)'
);

-- a leitura continua (E-83): o CEO e o login do próprio cliente arquivado ---------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT p.status::text, count(*)::int FROM public.processes p
      WHERE p.client_id = '00000000-0000-4000-8000-00000000a003' GROUP BY p.status::text ORDER BY p.status::text $$,
  $$ VALUES ('active', 3), ('cancelled', 1), ('completed', 1) $$,
  'E-83: o CEO lê os processos do cliente arquivado (3 ativos com "Site novo" do INSERT direto, 1 concluído, 1 cancelado)'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000d1', 'aal1');
SELECT results_eq(
  $$ SELECT p.title FROM public.processes p ORDER BY p.title $$,
  $$ VALUES ('Site novo'), ('X ativo'), ('X ativo dois'), ('X cancelado'), ('X concluido') $$,
  'E-83: o login do cliente arquivado lê os próprios processos (e só eles)'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.process_stages s $$,
  $$ VALUES (11) $$,
  'E-83: ... e as fases deles (2 + 2 + 1 + 6 do template: 11; o "Site novo" do INSERT direto não tem fase)'
);
SELECT tests.clear_authentication();

-- a autorização vem antes do arquivado: o 42501 não revela se o cliente está arquivado -----------------------------
SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage((SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), current_setting('t.x_stage1')::uuid) $$,
  '42501', NULL, 'AC-10, F-87: anon não executa approve_current_stage'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), NULL, true) $$,
  '42501', NULL, 'AC-10, F-87: anon não executa update_process'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000d1', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage((SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), current_setting('t.x_stage1')::uuid) $$,
  '42501', 'FORBIDDEN', 'AC-08, F-87: o login do cliente arquivado (aal2 no JWT) não aprova o próprio processo: 42501, não CLIENT_ARCHIVED'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), NULL, true) $$,
  '42501', 'FORBIDDEN', 'AC-08, F-87: nem cancela'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage((SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), current_setting('t.x_stage1')::uuid) $$,
  '42501', 'FORBIDDEN', 'AC-09, F-87: o cliente de outro tenant tampouco descobre que o cliente X está arquivado'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage((SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), current_setting('t.x_stage1')::uuid) $$,
  '42501', 'FORBIDDEN', 'AC-08, F-87: o CEO aal1 não aprova: 42501, não CLIENT_ARCHIVED'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), NULL, true) $$,
  '42501', 'FORBIDDEN', 'AC-08, F-87: o CEO aal1 não cancela'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2', false);
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage((SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), current_setting('t.x_stage1')::uuid) $$,
  '42501', 'FORBIDDEN', 'F-50 b, F-87: o CEO aal2 SEM atestado não aprova: 42501, não CLIENT_ARCHIVED'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), NULL, true) $$,
  '42501', 'FORBIDDEN', 'F-50 b, F-87: o CEO aal2 sem atestado não cancela'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.approve_current_stage((SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), current_setting('t.x_stage1')::uuid) $$,
  'P0001', 'CLIENT_ARCHIVED', 'F-87: o controle positivo: o mesmo CEO, atestado, recebe CLIENT_ARCHIVED ao aprovar'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_process((SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), NULL, true) $$,
  'P0001', 'CLIENT_ARCHIVED', 'F-87: ... e ao cancelar'
);
SELECT tests.clear_authentication();
SELECT is(pg_temp.state_of((SELECT p.id FROM proc p WHERE p.label = 'x-ativo')), current_setting('t.x_ativo'),
  'F-87: depois de todas as recusas e leituras, "X ativo" segue exatamente como estava');

-- desarquivar descongela (E-100) ---------------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT tests.set_request_id('req-freeze-0003');
SELECT lives_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000a003', NULL, false) $$,
  'E-100, F-87: o CEO desarquiva o cliente X'
);
SELECT results_eq(
  format('SELECT status::text, version FROM public.approve_current_stage(%L, %L)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), current_setting('t.x_stage1')),
  $$ VALUES ('active', 2) $$,
  'E-100, F-87: desarquivado, a aprovação volta a valer (a fase 2 passa a em andamento)'
);
SELECT results_eq(
  format('SELECT title, version FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo'), 'X ativo renomeado'),
  $$ VALUES ('X ativo renomeado', 3) $$,
  'E-100, F-87: e o renome'
);
SELECT results_eq(
  format('SELECT status::text, version FROM public.update_process(%L, NULL, true)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo')),
  $$ VALUES ('cancelled', 4) $$,
  'E-100, F-87: e o cancelamento'
);
SELECT throws_ok(
  format('SELECT * FROM public.approve_current_stage(%L, %L)', (SELECT p.id FROM proc p WHERE p.label = 'x-concluido'), current_setting('t.x_done_stage')),
  'P0001', 'PROCESS_NOT_ACTIVE', 'E-100, F-87: desarquivado, o processo concluído volta a ser PROCESS_NOT_ACTIVE (E-03)'
);
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'x-cancelado'), 'Outro nome'),
  'P0001', 'PROCESS_NOT_ACTIVE', 'E-100, F-87: e o cancelado também (E-60)'
);
-- arquivar de novo congela de novo (E-100) --------------------------------------------------------------------------------
SELECT lives_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000a003', NULL, true) $$,
  'E-100, F-87: o CEO arquiva o cliente X de novo'
);
SELECT throws_ok(
  format('SELECT * FROM public.approve_current_stage(%L, %L)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo2'), current_setting('t.x2_stage1')),
  'P0001', 'CLIENT_ARCHIVED', 'E-100, F-87: arquivado de novo, a aprovação volta a ser recusada'
);
SELECT throws_ok(
  format('SELECT * FROM public.update_process(%L, %L, NULL)', (SELECT p.id FROM proc p WHERE p.label = 'x-ativo2'), 'X ativo dois renomeado'),
  'P0001', 'CLIENT_ARCHIVED', 'E-100, F-87: e o renome'
);
SELECT tests.clear_authentication();
SELECT is(
  (SELECT p.version FROM public.processes p WHERE p.id = (SELECT x.id FROM proc x WHERE x.label = 'x-ativo2')),
  1,
  'E-100, F-87: arquivar e desarquivar o cliente não mexeu no processo "X ativo dois" (versão 1)'
);
SELECT is(
  (SELECT count(*)::int FROM public.audit_events e
    WHERE e.action IN ('client.archived', 'client.unarchived') AND e.client_id = '00000000-0000-4000-8000-00000000a003'),
  3,
  'E-100: arquivar, desarquivar e arquivar de novo gravam um evento cada (client.archived, client.unarchived, client.archived)'
);

SELECT * FROM finish();
ROLLBACK;
