-- Nome de cliente único entre os não arquivados (F-51, E-40 a E-46; spec §3.7.1): o índice parcial
-- `clients_active_name_key`, e `create_client` e `update_client` trocando a violação por
-- `CLIENT_NAME_TAKEN` (P0001), sem auditoria. Cobre: o índice (único, parcial, só sobre expressões
-- IMMUTABLE, com comentário), a escrita direta (secret key), a autorização antes da checagem do nome,
-- a criação e a renomeação recusadas por 24 variantes da mesma chave (maiúsculas, largura total,
-- espaços Unicode e repetidos, acento decomposto, ligadura, sinal Kelvin, marcas de variação
-- invisíveis), o locale do banco, o formato do erro CLIENT_NAME_TAKEN (sem detalhe, dica nem
-- constraint), uma violação de outro índice que sobe crua (23505), os nomes que continuam
-- livres (outro nome, só arquivados, homóglifo cirílico), o desarquivamento, renomear e arquivar na
-- mesma chamada, e que nenhuma recusa deixa linha nem evento.
BEGIN;
SELECT plan(95);

-- arrange (como postgres) --------------------------------------------------------------------------
-- CA, CB, CC, CF, CK, CH e CH2 são clientes ativos; CG, CD1, CD2, CU e CR, arquivados (dois deles com o
-- mesmo nome, "Delta"). c1 é CEO com fator TOTP verificado; a1 é login do cliente CA.
INSERT INTO public.clients (id, name, archived_at, created_at, updated_at) VALUES
  ('00000000-0000-4000-8000-00000000a001', 'Acme Ltda', NULL, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-00000000a002', 'Beta', NULL, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-00000000a003', 'Caf' || chr(233) || ' Central', NULL, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-00000000a004', 'Financeira Ltda', NULL, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-00000000a005', 'Kilo Ltda', NULL, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-00000000a006', 'Hotel', NULL, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-00000000a007', 'Hotel Dois', NULL, now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-00000000a008', 'Gamma', now() - interval '1 day', now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-00000000a009', 'Delta', now() - interval '1 day', now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-00000000a00a', 'Delta', now() - interval '1 day', now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-00000000a00b', 'Unarchive Me', now() - interval '1 day', now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-00000000a00c', 'Rename Archived', now() - interval '1 day', now() - interval '2 days', now() - interval '2 days');

SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000a001');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');

-- Grafias que, depois de `visible_text` (NFC, pontas aparadas) e da chave do índice
-- (`lower(normalize(.., NFKC))`, sem as marcas de variação invisíveis, espaços repetidos reduzidos a
-- um), são o nome de um cliente ativo
-- acima: "Acme Ltda" (CA), "Café Central" (CC), "Financeira Ltda" (CF) e "Kilo Ltda" (CK).
CREATE TEMP TABLE taken_names (label text PRIMARY KEY, value text NOT NULL);
INSERT INTO taken_names (label, value) VALUES
  ('identico', 'Acme Ltda'),
  ('maiusculas', 'ACME LTDA'),
  ('minusculas', 'acme ltda'),
  ('caixa mista', 'aCME lTDA'),
  ('largura total', translate('Acme Ltda', 'AcmeLtda', U&'\FF21\FF43\FF4D\FF45\FF2C\FF54\FF44\FF41')),
  ('largura total com espaco ideografico',
   translate('Acme Ltda', 'AcmeLtda ', U&'\FF21\FF43\FF4D\FF45\FF2C\FF54\FF44\FF41\3000')),
  ('NBSP entre as palavras', 'Acme' || chr(160) || 'Ltda'),
  ('dois espacos', 'Acme  Ltda'),
  ('espacos de varios tipos', 'Acme' || chr(160) || chr(8195) || ' ' || chr(12288) || 'Ltda'),
  ('U+1680 entre as palavras', 'Acme' || chr(5760) || 'Ltda'),
  ('espacos Unicode nas pontas', chr(160) || 'Acme Ltda' || chr(12288)),
  ('acento decomposto', 'Cafe' || chr(769) || ' Central'),
  ('acento em maiuscula', 'CAF' || chr(201) || ' CENTRAL'),
  ('acento decomposto em maiuscula', 'CAFE' || chr(769) || ' CENTRAL'),
  ('ligadura fi', chr(64257) || 'nanceira Ltda'),
  ('sinal Kelvin', chr(8490) || 'ilo Ltda'),
  ('U+034F (junção de grafemas) entre as letras', 'Ac' || chr(847) || 'me Ltda'),
  ('seletor de variacao VS16 U+FE0F', 'Acme' || chr(65039) || ' Ltda'),
  ('seletor de variacao mongol U+180B', 'Acme' || chr(6155) || ' Ltda'),
  ('seletor de variacao mongol U+180C', 'Acme' || chr(6156) || ' Ltda'),
  ('seletor de variacao mongol U+180D', 'Acme' || chr(6157) || ' Ltda'),
  ('seletor de variacao mongol U+180F', 'Acme' || chr(6159) || ' Ltda'),
  ('seletor de variacao VS17 U+E0100', 'Acme' || chr(917760) || ' Ltda'),
  ('marca invisivel entre dois espacos', 'Acme ' || chr(847) || ' Ltda');
GRANT SELECT ON taken_names TO authenticated;

-- O índice -----------------------------------------------------------------------------------------------
SELECT ok(
  EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'public' AND tablename = 'clients' AND indexname = 'clients_active_name_key'),
  'F-51: o índice clients_active_name_key existe'
);
SELECT results_eq(
  $$ SELECT i.indisunique, pg_get_expr(i.indpred, i.indrelid) COLLATE "default"
       FROM pg_index i WHERE i.indexrelid = 'public.clients_active_name_key'::regclass $$,
  $$ VALUES (true, '(archived_at IS NULL)') $$,
  'F-51: é único e parcial, só sobre os clientes não arquivados'
);
SELECT results_eq(
  $$ SELECT i.indnatts::int, i.indkey[0]::int
       FROM pg_index i WHERE i.indexrelid = 'public.clients_active_name_key'::regclass $$,
  $$ VALUES (1, 0) $$,
  'F-51: tem uma coluna só, e ela é uma expressão (a chave do nome), não a coluna crua'
);
SELECT ok(
  coalesce(obj_description('public.clients_active_name_key'::regclass, 'pg_class'), '') LIKE 'Caso de uso:%',
  'F-51: o índice tem comentário com o caso de uso'
);
-- As funções da expressão são nativas (do pg_catalog) e por isso não deixam linha em pg_depend; o
-- Postgres já recusaria o índice se alguma não fosse IMMUTABLE, e aqui a volatilidade de cada uma é
-- conferida pelo nome.
SELECT is_empty(
  $$ SELECT p.oid::regprocedure
       FROM pg_proc p
      WHERE p.oid IN ('pg_catalog.lower(text)'::regprocedure,
                      'pg_catalog.normalize(text, text)'::regprocedure,
                      'pg_catalog.regexp_replace(text, text, text, text)'::regprocedure)
        AND p.provolatile <> 'i' $$,
  'F-51: lower, normalize e regexp_replace, as funções da expressão do índice, são IMMUTABLE'
);
SELECT ok(
  pg_get_expr(i.indexprs, i.indrelid) ~* 'regexp_replace\(regexp_replace\(lower\(normalize\(name, NFKC\)\)',
  'F-51: a expressão é regexp_replace(regexp_replace(lower(normalize(name, NFKC)), ..), ..), e só isso (o Postgres 17 não tem casefold)'
) FROM pg_index i WHERE i.indexrelid = 'public.clients_active_name_key'::regclass;

-- O `lower()` do índice só dobra letras fora do ASCII se o locale do banco for Unicode (como o `[[:alnum:]]`
-- de visible_text, conferido no 013): sem isso "CAFÉ" e "café" teriam chaves diferentes.
SELECT ok(
  lower('CAF' || chr(201)) = 'caf' || chr(233)
  AND lower(chr(913) || chr(914) || chr(915)) = chr(945) || chr(946) || chr(947)
  AND lower(chr(1040)) = chr(1072),
  'F-51: o lower() do banco dobra o "É" latino, as maiúsculas gregas e o "А" cirílico (o locale é Unicode)'
);

-- Escrita direta (a secret key das fixtures, ou quem for postgres): o índice vale para todos -------------
SELECT throws_ok(
  $$ INSERT INTO public.clients (name) VALUES ('ACME LTDA') $$,
  '23505',
  'duplicate key value violates unique constraint "clients_active_name_key"',
  'F-51: um INSERT direto com o nome de um cliente ativo viola o índice'
);
SELECT lives_ok(
  $$ INSERT INTO public.clients (name, archived_at) VALUES ('ACME LTDA', now()) $$,
  'E-43: um INSERT direto de um cliente arquivado com o nome de um ativo passa (o índice é parcial)'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.clients WHERE name = 'Delta' AND archived_at IS NOT NULL $$,
  $$ VALUES (2) $$,
  'E-43: dois clientes arquivados podem ter o mesmo nome'
);

-- A autorização vem antes da checagem do nome: quem não é CEO não descobre que o nome existe ------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Acme Ltda') $$,
  '42501', 'FORBIDDEN', 'F-55: o login de cliente recebe FORBIDDEN em create_client com um nome em uso, não CLIENT_NAME_TAKEN'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000a002', 'Acme Ltda', NULL) $$,
  '42501', 'FORBIDDEN', 'F-55: o login de cliente recebe FORBIDDEN em update_client com um nome em uso'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Acme Ltda') $$,
  '42501', 'FORBIDDEN', 'F-55: o CEO aal1 recebe FORBIDDEN em create_client com um nome em uso'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000a002', 'Acme Ltda', NULL) $$,
  '42501', 'FORBIDDEN', 'F-55: o CEO aal1 recebe FORBIDDEN em update_client com um nome em uso'
);
SELECT tests.clear_authentication();

-- Criação: o nome em uso é recusado, em qualquer grafia da mesma chave ---------------------------------------
CREATE TEMP TABLE snapshot AS
  SELECT (SELECT count(*) FROM public.clients) AS clients,
         (SELECT count(*) FROM public.audit_events WHERE action LIKE 'client.%') AS events;

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  format('SELECT * FROM public.create_client(%L)', t.value),
  'P0001', 'CLIENT_NAME_TAKEN',
  'E-40: create_client recusa o nome em uso: ' || t.label
) FROM taken_names t ORDER BY t.label;
SELECT tests.clear_authentication();

SELECT results_eq(
  $$ SELECT count(*)::int FROM public.clients $$,
  $$ SELECT clients::int FROM snapshot $$,
  'E-40: nenhuma criação recusada deixou cliente'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.audit_events WHERE action LIKE 'client.%' $$,
  $$ SELECT events::int FROM snapshot $$,
  'E-40: nenhuma criação recusada gravou auditoria'
);

-- Nomes que continuam livres ----------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT name FROM public.create_client('Acme Ltda 2') $$,
  $$ VALUES ('Acme Ltda 2') $$,
  'E-40: um nome diferente (só parecido) é aceito'
);
SELECT results_eq(
  $$ SELECT name FROM public.create_client(chr(1040) || 'cme Ltda') $$,
  $$ VALUES (chr(1040) || 'cme Ltda') $$,
  'E-46: o "А" cirílico não é dobrado para o "A" latino (residual do T-33)'
);
SELECT results_eq(
  $$ SELECT name FROM public.create_client('Gamma') $$,
  $$ VALUES ('Gamma') $$,
  'E-43: o nome que só existe em um cliente arquivado está livre'
);
SELECT results_eq(
  $$ SELECT name FROM public.create_client('Delta') $$,
  $$ VALUES ('Delta') $$,
  'E-43: o nome de dois clientes arquivados está livre'
);
SELECT tests.clear_authentication();

-- Renomeação ---------------------------------------------------------------------------------------------------
DROP TABLE snapshot;
CREATE TEMP TABLE snapshot AS
  SELECT (SELECT count(*) FROM public.clients) AS clients,
         (SELECT count(*) FROM public.audit_events WHERE action LIKE 'client.%') AS events;

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  format('SELECT * FROM public.update_client(%L, %L, NULL)', '00000000-0000-4000-8000-00000000a002', t.value),
  'P0001', 'CLIENT_NAME_TAKEN',
  'E-41: update_client recusa renomear para o nome em uso: ' || t.label
) FROM taken_names t ORDER BY t.label;
SELECT tests.clear_authentication();

SELECT results_eq(
  $$ SELECT name, updated_at = now() - interval '2 days', archived_at IS NULL
       FROM public.clients WHERE id = '00000000-0000-4000-8000-00000000a002' $$,
  $$ VALUES ('Beta', true, true) $$,
  'E-41: o cliente que não pôde ser renomeado ficou como estava (nome, updated_at, ativo)'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.audit_events WHERE action LIKE 'client.%' $$,
  $$ SELECT events::int FROM snapshot $$,
  'E-41: nenhuma renomeação recusada gravou auditoria'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.clients $$,
  $$ SELECT clients::int FROM snapshot $$,
  'E-41: nenhuma renomeação recusada mudou a quantidade de clientes'
);

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT results_eq(
  $$ SELECT name, updated_at = now() - interval '2 days'
       FROM public.update_client('00000000-0000-4000-8000-00000000a002', 'Beta', NULL) $$,
  $$ VALUES ('Beta', true) $$,
  'E-41: renomear para o mesmo nome não é conflito: devolve o cliente como está'
);
SELECT results_eq(
  $$ SELECT name FROM public.update_client('00000000-0000-4000-8000-00000000a001', 'ACME LTDA', NULL) $$,
  $$ VALUES ('ACME LTDA') $$,
  'E-41: trocar só as maiúsculas do próprio nome não conflita com a própria linha'
);
SELECT results_eq(
  $$ SELECT name FROM public.update_client('00000000-0000-4000-8000-00000000a006', 'Rename Archived', NULL) $$,
  $$ VALUES ('Rename Archived') $$,
  'E-43: renomear para o nome de um cliente arquivado é permitido'
);
SELECT results_eq(
  $$ SELECT name, archived_at IS NOT NULL
       FROM public.update_client('00000000-0000-4000-8000-00000000a007', 'Acme Ltda', true) $$,
  $$ VALUES ('Acme Ltda', true) $$,
  'E-42: renomear para um nome em uso e arquivar na mesma chamada vale: o estado final não disputa o nome'
);
SELECT results_eq(
  $$ SELECT name, archived_at IS NOT NULL
       FROM public.update_client('00000000-0000-4000-8000-00000000a00c', 'Kilo Ltda', NULL) $$,
  $$ VALUES ('Kilo Ltda', true) $$,
  'E-43: renomear um cliente arquivado para o nome de um ativo é permitido (ele continua fora do índice)'
);

-- Desarquivamento -----------------------------------------------------------------------------------------------
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000a007', NULL, false) $$,
  'P0001', 'CLIENT_NAME_TAKEN',
  'E-42: desarquivar um cliente cujo nome é agora de um cliente ativo é recusado'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000a00c', NULL, false) $$,
  'P0001', 'CLIENT_NAME_TAKEN',
  'E-42: o mesmo para um cliente que foi renomeado enquanto arquivado'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000a007', 'Caf' || chr(233) || ' Central', false) $$,
  'P0001', 'CLIENT_NAME_TAKEN',
  'E-42: desarquivar junto com um novo nome em uso é recusado'
);
SELECT results_eq(
  $$ SELECT c.id::text, c.archived_at IS NOT NULL
       FROM public.clients c
      WHERE c.id IN ('00000000-0000-4000-8000-00000000a007', '00000000-0000-4000-8000-00000000a00c')
      ORDER BY c.id $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000a007', true), ('00000000-0000-4000-8000-00000000a00c', true) $$,
  'E-42: os desarquivamentos recusados deixaram os dois clientes arquivados'
);
SELECT results_eq(
  $$ SELECT name, archived_at IS NULL
       FROM public.update_client('00000000-0000-4000-8000-00000000a00c', 'Kilo Ltda Dois', false) $$,
  $$ VALUES ('Kilo Ltda Dois', true) $$,
  'E-42: desarquivar junto com um nome livre vale'
);
SELECT results_eq(
  $$ SELECT name FROM public.create_client('UNARCHIVE ME') $$,
  $$ VALUES ('UNARCHIVE ME') $$,
  'E-43: criar com o nome de um cliente arquivado (outra caixa) é permitido'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000a00b', NULL, false) $$,
  'P0001', 'CLIENT_NAME_TAKEN',
  'E-42: desarquivar o cliente cujo nome foi tomado por um ativo criado depois é recusado'
);
SELECT results_eq(
  $$ SELECT archived_at IS NOT NULL FROM public.update_client('00000000-0000-4000-8000-00000000a00b', 'Unarchive Me Two', NULL) $$,
  $$ VALUES (true) $$,
  'E-42: depois de uma recusa, renomear o cliente arquivado funciona (ele continua arquivado)'
);

-- Arquivar libera o nome ----------------------------------------------------------------------------------------
SELECT results_eq(
  $$ SELECT archived_at IS NOT NULL FROM public.update_client('00000000-0000-4000-8000-00000000a005', NULL, true) $$,
  $$ VALUES (true) $$,
  'E-43: arquivar o cliente "Kilo Ltda"'
);
SELECT results_eq(
  $$ SELECT name FROM public.create_client('KILO LTDA') $$,
  $$ VALUES ('KILO LTDA') $$,
  'E-43: arquivar libera o nome: outro cliente pode usá-lo'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000a005', NULL, false) $$,
  'P0001', 'CLIENT_NAME_TAKEN',
  'E-42: e o cliente arquivado não volta enquanto o nome estiver em uso'
);
SELECT tests.clear_authentication();

-- Nenhuma recusa gravou evento: só as escritas que deram certo, na ordem -------------------------------------
SELECT results_eq(
  $$ SELECT array_agg(e.action ORDER BY e.id)
       FROM public.audit_events e
      WHERE e.actor_id = '00000000-0000-4000-8000-0000000000c1' AND e.action LIKE 'client.%' $$,
  $$ VALUES (ARRAY[
       'client.created', 'client.created', 'client.created', 'client.created',
       'client.updated', 'client.updated', 'client.updated', 'client.archived', 'client.updated',
       'client.updated', 'client.unarchived', 'client.created', 'client.updated',
       'client.archived', 'client.created']::text[]) $$,
  'E-40 a E-43: só as escritas que deram certo geraram eventos (nenhuma das recusas gravou o seu)'
);
SELECT is_empty(
  $$ SELECT e.id FROM public.audit_events e
      WHERE e.action LIKE 'client.%' AND e.metadata::text ~* '(Acme|Beta|Kilo|Delta|Gamma|Unarchive)' $$,
  'E-40: nenhum nome de cliente foi para os metadados da auditoria'
);

-- O erro CLIENT_NAME_TAKEN não carrega nada além do código e da mensagem: nem DETAIL (que traria o nome
-- normalizado), nem HINT, nem o nome do constraint, da tabela ou do esquema (o que diria qual índice, e
-- portanto qual cliente). Lido com GET STACKED DIAGNOSTICS dentro de um DO, como o CEO aal2.
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
DO $$
DECLARE
  v_calls text[] := ARRAY[
    $c$SELECT public.create_client('ACME LTDA')$c$,
    $c$SELECT public.update_client('00000000-0000-4000-8000-00000000a002', 'ACME LTDA', NULL)$c$,
    $c$SELECT public.update_client('00000000-0000-4000-8000-00000000a007', NULL, false)$c$
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
  current_setting('probe.shape1'), concat_ws('|', 'P0001', 'CLIENT_NAME_TAKEN', '', '', '', '', '', '', ''),
  'F-51: create_client recusa com SQLSTATE e mensagem apenas (DETAIL, HINT, constraint, tabela e esquema vazios)'
);
SELECT is(
  current_setting('probe.shape2'), concat_ws('|', 'P0001', 'CLIENT_NAME_TAKEN', '', '', '', '', '', '', ''),
  'F-51: update_client ao renomear recusa com SQLSTATE e mensagem apenas'
);
SELECT is(
  current_setting('probe.shape3'), concat_ws('|', 'P0001', 'CLIENT_NAME_TAKEN', '', '', '', '', '', '', ''),
  'F-51: update_client ao desarquivar recusa com SQLSTATE e mensagem apenas'
);
SELECT tests.clear_authentication();

-- Só a violação do NOSSO índice vira CLIENT_NAME_TAKEN: a de outro índice da tabela sobe crua (23505, com
-- o nome do índice dela). Dois clientes "Probe" violam um índice único de teste, criado só nesta transação.
CREATE UNIQUE INDEX zz_probe_one_client ON public.clients ((name IS NOT NULL)) WHERE name LIKE 'Probe %';
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT lives_ok(
  $$ SELECT * FROM public.create_client('Probe 1') $$,
  'F-51: o primeiro cliente "Probe" é criado'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Probe 2') $$,
  '23505', 'duplicate key value violates unique constraint "zz_probe_one_client"',
  'F-51: create_client não traduz a violação de outro índice: sobe como 23505'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000a002', 'Probe 3', NULL) $$,
  '23505', 'duplicate key value violates unique constraint "zz_probe_one_client"',
  'F-51: update_client não traduz a violação de outro índice: sobe como 23505'
);
SELECT tests.clear_authentication();

SELECT * FROM finish();
ROLLBACK;
