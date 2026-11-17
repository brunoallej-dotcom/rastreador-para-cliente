-- Onda 6: private.visible_text, create_client e update_client (spec §3.7, §3.7.1). Cobre: privilégios e
-- search_path das funções (AC-25), anon (AC-10), cliente com aal1 e com aal2 no JWT (AC-08, AC-09: não
-- executa nem lê o outro cliente), CEO aal1, CEO aal2 sem fator TOTP verificado (F-24), CEO com sessão
-- morta ou desativado, escrita direta negada, o caminho feliz (AC-11), as regras do nome iguais às do
-- Zod (E-30, F-52: espaços Unicode nas pontas, fillers, "ao menos uma letra ou número", NFC), a
-- idempotência das mudanças e a auditoria gravada na mesma transação (ator, papel, recurso, cliente,
-- request_id, sem PII).
BEGIN;
SELECT plan(144);

-- A tabela inteira como o dono a vê (SECURITY DEFINER), para comparar com o que o RLS dá ao CEO. Vive só nesta transação.
CREATE FUNCTION tests.clients_count_all()
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$ SELECT count(*)::integer FROM public.clients $$;
GRANT EXECUTE ON FUNCTION tests.clients_count_all() TO anon, authenticated, service_role;

-- arrange (como postgres) --------------------------------------------------------------------------
-- A, B, D e E são os clientes das fixtures (A ativo, B arquivado há 3 dias, D e E ativos), com datas no
-- passado para provar quando `updated_at` mexe. a1 é login de A. c1 é CEO com fator verificado; c2, CEO
-- sem fator; c3, CEO com fator e sessão apagada; c4, CEO com fator e perfil desativado.
INSERT INTO public.clients (id, name, archived_at, created_at, updated_at) VALUES
  ('00000000-0000-4000-8000-00000000000a', 'Cliente A', NULL,
   now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-00000000000b', 'Cliente B', now() - interval '3 days',
   now() - interval '4 days', now() - interval '4 days'),
  ('00000000-0000-4000-8000-00000000000d', 'Cliente D', NULL,
   now() - interval '5 days', now() - interval '5 days'),
  ('00000000-0000-4000-8000-00000000000e', 'Cliente E', NULL,
   now() - interval '6 days', now() - interval '6 days');

SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');
-- o login de A é um cliente plenamente ativo (senha definitiva): com a senha temporária o RLS não lê o cliente
-- dele (F-83, arquivo 020), e aqui o que se prova é o isolamento entre clientes
UPDATE public.profiles SET must_change_password = false WHERE id = '00000000-0000-4000-8000-0000000000a1';
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c2', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c3', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c4', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c3');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c4');
DELETE FROM auth.sessions WHERE id = '00000000-0000-4000-8000-0000000000c3';
UPDATE public.profiles SET disabled_at = now() WHERE id = '00000000-0000-4000-8000-0000000000c4';

-- Nomes que o Zod (`visibleText`) recusa e que o banco também tem de recusar, na criação e na
-- atualização (um por linha; o NULL só vale para a criação).
CREATE TEMP TABLE bad_names (label text PRIMARY KEY, value text);
INSERT INTO bad_names (label, value) VALUES
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
GRANT SELECT ON bad_names TO authenticated;

-- Nomes que o Zod aceita (e como ficam guardados).
CREATE TEMP TABLE good_names (label text PRIMARY KEY, value text NOT NULL, expected text NOT NULL);
INSERT INTO good_names (label, value, expected) VALUES
  ('espacos nas pontas', '  Cliente Novo  ', 'Cliente Novo'),
  ('NBSP e U+3000 nas pontas', chr(160) || 'Acme' || chr(12288), 'Acme'),
  ('BOM nas pontas', chr(65279) || 'Acme BOM' || chr(65279), 'Acme BOM'),
  ('NFC (e + acento combinante)', 'Cafe' || chr(769), 'Caf' || chr(233)),
  ('japones', chr(26085) || chr(26412), chr(26085) || chr(26412)),
  ('grego', chr(913) || chr(946) || chr(947), chr(913) || chr(946) || chr(947)),
  ('digitos arabe-indicos', chr(1633) || chr(1634), chr(1633) || chr(1634)),
  ('pontuacao com letras', 'A&B - Consultoria (S/A)', 'A&B - Consultoria (S/A)'),
  ('so numeros', '2026', '2026'),
  ('160 caracteres', repeat('a', 160), repeat('a', 160));
GRANT SELECT ON good_names TO authenticated;

-- Como o PostgREST faz: o app manda o id da requisição, e a auditoria o guarda.
SELECT tests.set_request_id('req-clients-0001');

-- AC-25: privilégios e configuração das funções ------------------------------------------------------
SELECT ok(
  (SELECT p.prosecdef FROM pg_proc p WHERE p.oid = 'public.create_client(text)'::regprocedure),
  'create_client: SECURITY DEFINER'
);
SELECT ok(
  (SELECT p.prosecdef FROM pg_proc p WHERE p.oid = 'public.update_client(uuid, text, boolean)'::regprocedure),
  'update_client: SECURITY DEFINER'
);
SELECT ok(
  (SELECT 'search_path=""' = ANY (p.proconfig) FROM pg_proc p WHERE p.oid = 'public.create_client(text)'::regprocedure),
  'AC-25: create_client tem search_path vazio'
);
SELECT ok(
  (SELECT 'search_path=""' = ANY (p.proconfig) FROM pg_proc p WHERE p.oid = 'public.update_client(uuid, text, boolean)'::regprocedure),
  'AC-25: update_client tem search_path vazio'
);
SELECT ok(
  NOT has_function_privilege('anon', 'public.create_client(text)', 'EXECUTE'),
  'AC-10: anon não executa create_client'
);
SELECT ok(
  NOT has_function_privilege('anon', 'public.update_client(uuid, text, boolean)', 'EXECUTE'),
  'AC-10: anon não executa update_client'
);
SELECT ok(
  has_function_privilege('authenticated', 'public.create_client(text)', 'EXECUTE'),
  'create_client: authenticated executa (a checagem de CEO aal2 é por dentro)'
);
SELECT ok(
  has_function_privilege('authenticated', 'public.update_client(uuid, text, boolean)', 'EXECUTE'),
  'update_client: authenticated executa (a checagem de CEO aal2 é por dentro)'
);
SELECT ok(
  NOT has_function_privilege('service_role', 'public.create_client(text)', 'EXECUTE'),
  'SEC-04: service_role não executa create_client (nem a secret key escreve cliente de negócio)'
);
SELECT ok(
  NOT has_function_privilege('service_role', 'public.update_client(uuid, text, boolean)', 'EXECUTE'),
  'SEC-04: service_role não executa update_client'
);
SELECT is_empty(
  $$ SELECT p.proname
       FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE p.oid IN ('public.create_client(text)'::regprocedure,
                      'public.update_client(uuid, text, boolean)'::regprocedure,
                      'private.visible_text(text, integer)'::regprocedure)
        AND a.grantee = 0 AND a.privilege_type = 'EXECUTE' $$,
  'AC-25: create_client, update_client e visible_text não concedem EXECUTE a PUBLIC'
);

-- private.visible_text: configuração, privilégios e comportamento -------------------------------------
SELECT is(
  (SELECT p.provolatile::text FROM pg_proc p WHERE p.oid = 'private.visible_text(text, integer)'::regprocedure),
  'i',
  'visible_text: IMMUTABLE'
);
SELECT ok(
  (SELECT 'search_path=""' = ANY (p.proconfig) FROM pg_proc p WHERE p.oid = 'private.visible_text(text, integer)'::regprocedure),
  'visible_text: search_path vazio'
);
SELECT is_empty(
  $$ SELECT r.role
       FROM (VALUES ('anon'), ('authenticated'), ('service_role')) r (role)
      WHERE has_function_privilege(r.role, 'private.visible_text(text, integer)', 'EXECUTE') $$,
  'visible_text: nenhum papel da API a executa (só as funções SECURITY DEFINER do mesmo dono)'
);
SELECT ok(
  chr(26085) ~ '[[:alnum:]]' AND chr(945) ~ '[[:alnum:]]' AND chr(1633) ~ '[[:alnum:]]' AND chr(233) ~ '[[:alnum:]]',
  'visible_text: o [[:alnum:]] do banco é Unicode (japonês, grego, dígito arábico-índico, é): senão a regra "ao menos uma letra ou número" recusaria nomes legítimos'
);
SELECT is(
  private.visible_text(chr(160) || 'Acme' || chr(12288), 160), 'Acme',
  'visible_text: tira NBSP e U+3000 das pontas'
);
SELECT is(
  private.visible_text('Cafe' || chr(769), 160), 'Caf' || chr(233),
  'visible_text: normaliza para NFC'
);
SELECT is(
  private.visible_text(repeat(' ', 5000) || 'a' || repeat(chr(160), 5000), 160), 'a',
  'visible_text: uma corrida longa de espaços nas pontas não pesa'
);
SELECT ok(private.visible_text('abc', 2) IS NULL, 'visible_text: acima do máximo é NULL');
SELECT ok(private.visible_text('abc', NULL) IS NULL, 'visible_text: máximo nulo é NULL');
SELECT ok(private.visible_text(NULL, 160) IS NULL, 'visible_text: texto nulo é NULL');
SELECT ok(
  private.visible_text(repeat('a', 20000), 30000) IS NULL,
  'visible_text: acima de 16 KiB é NULL antes de qualquer trabalho'
);

-- AC-10: anon ------------------------------------------------------------------------------------------
SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Cliente do anon') $$,
  '42501', NULL, 'AC-10: anon não executa create_client'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', 'Renomeado pelo anon', NULL) $$,
  '42501', NULL, 'AC-10: anon não executa update_client'
);
SELECT throws_ok(
  $$ SELECT id FROM public.clients $$,
  '42501', NULL, 'AC-10: anon não lê clients'
);
RESET ROLE;

-- AC-08, AC-09: cliente A ----------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Cliente do cliente') $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não executa create_client'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', 'Renomeado pelo cliente', NULL) $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não executa update_client nem no próprio tenant'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000b', NULL, false) $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não executa update_client no tenant de outro cliente'
);
SELECT results_eq(
  $$ SELECT id FROM public.clients $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000a'::uuid) $$,
  'AC-09: cliente A lê só a própria linha de clients (não vê B, D nem E)'
);
SELECT throws_ok(
  $$ INSERT INTO public.clients (name) VALUES ('Escrita direta') $$,
  '42501', NULL, 'SEC-04: cliente não faz INSERT direto em clients'
);
SELECT throws_ok(
  $$ UPDATE public.clients SET name = 'Escrita direta' WHERE id = '00000000-0000-4000-8000-00000000000a' $$,
  '42501', NULL, 'SEC-04: cliente não faz UPDATE direto em clients'
);
SELECT throws_ok(
  $$ DELETE FROM public.clients WHERE id = '00000000-0000-4000-8000-00000000000a' $$,
  '42501', NULL, 'SEC-04: cliente não faz DELETE direto em clients'
);
SELECT tests.clear_authentication();

-- AC-08: cliente com `aal2` no JWT (um claim que ele mesmo não deveria conseguir; vale a checagem de papel) ----
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Cliente com aal2') $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente com aal2 no JWT não executa create_client'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', 'Renomeado com aal2', NULL) $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente com aal2 no JWT não executa update_client'
);
SELECT results_eq(
  $$ SELECT id FROM public.clients $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000a'::uuid) $$,
  'AC-09: cliente com aal2 no JWT continua lendo só a própria linha de clients'
);
SELECT tests.clear_authentication();

-- AC-08: CEO com aal1 (fator verificado, mas sessão só com a senha) --------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Cliente do CEO aal1') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 não executa create_client'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', 'Renomeado aal1', NULL) $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 não executa update_client'
);
SELECT is_empty(
  $$ SELECT id FROM public.clients $$,
  'AC-08: CEO aal1 não lê nenhum cliente'
);
SELECT tests.clear_authentication();

-- F-24: CEO com aal2 no JWT, mas sem fator TOTP verificado --------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Cliente do CEO sem fator') $$,
  '42501', 'FORBIDDEN', 'F-24: CEO aal2 sem fator verificado não executa create_client'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', 'Renomeado sem fator', NULL) $$,
  '42501', 'FORBIDDEN', 'F-24: CEO aal2 sem fator verificado não executa update_client'
);
SELECT is_empty(
  $$ SELECT id FROM public.clients $$,
  'F-24: CEO aal2 sem fator verificado não lê nenhum cliente'
);
SELECT tests.clear_authentication();

-- E-08: CEO aal2 com fator, mas sessão apagada, ou com perfil desativado -----------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Cliente da sessão morta') $$,
  '42501', 'FORBIDDEN', 'E-08: CEO com a sessão apagada não executa create_client'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', 'Renomeado sem sessão', NULL) $$,
  '42501', 'FORBIDDEN', 'E-08: CEO com a sessão apagada não executa update_client'
);
SELECT is_empty(
  $$ SELECT id FROM public.clients $$,
  'E-08: CEO com a sessão apagada não lê nenhum cliente'
);
SELECT tests.clear_authentication();
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c4', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Cliente do CEO desativado') $$,
  '42501', 'FORBIDDEN', 'E-08: CEO desativado não executa create_client'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', 'Renomeado desativado', NULL) $$,
  '42501', 'FORBIDDEN', 'E-08: CEO desativado não executa update_client'
);
SELECT is_empty(
  $$ SELECT id FROM public.clients $$,
  'E-08: CEO desativado não lê nenhum cliente'
);
SELECT tests.clear_authentication();

-- F-55: a autorização vem antes de qualquer trabalho com a entrada (um nome inválido não muda a resposta) -----
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT * FROM public.create_client(repeat('a', 20000)) $$,
  '42501', 'FORBIDDEN', 'F-55: cliente com um nome enorme recebe FORBIDDEN, não INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', chr(10), NULL) $$,
  '42501', 'FORBIDDEN', 'F-55: cliente com um nome inválido recebe FORBIDDEN, não INVALID_INPUT'
);
SELECT tests.clear_authentication();

-- Só o que ESTE arquivo escreveu (a mesma transação: `now()` é o instante dele, e as fixtures têm datas no passado):
-- o banco pode guardar os clientes e a auditoria de outros testes.
SELECT is_empty(
  $$ SELECT id FROM public.audit_events WHERE action LIKE 'client.%' AND occurred_at = now() $$,
  'AC-08: nenhuma chamada negada gravou auditoria'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.clients WHERE created_at = now() $$,
  $$ VALUES (0) $$,
  'AC-08: nenhuma chamada negada criou cliente (as 4 fixtures têm data no passado)'
);

-- AC-11: CEO aal2 com fator verificado, criação ---------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');

SELECT results_eq(
  $$ SELECT name, archived_at FROM public.create_client('Cliente Dois') $$,
  $$ VALUES ('Cliente Dois', NULL::timestamptz) $$,
  'AC-11: create_client devolve o cliente ativo'
);
SELECT is(
  (SELECT c.name FROM public.create_client(g.value) c), g.expected,
  'E-30: create_client aceita e guarda "' || g.label || '"'
) FROM good_names g ORDER BY g.label;
SELECT throws_ok(
  format('SELECT * FROM public.create_client(%L)', b.value),
  'P0001', 'INVALID_INPUT',
  'E-30: create_client recusa o nome: ' || b.label
) FROM bad_names b ORDER BY b.label;
SELECT tests.clear_authentication();

SELECT results_eq(
  $$ SELECT count(*)::int FROM public.clients WHERE created_at = now() $$,
  $$ SELECT (1 + count(*))::int FROM good_names $$,
  'AC-11: só os nomes válidos criaram cliente; os inválidos não deixaram linha'
);
SELECT results_eq(
  $$ SELECT e.action, e.actor_id, e.actor_role::text, e.resource_type, e.resource_id = c.id,
            e.client_id = c.id, e.process_id, e.request_id, e.metadata
       FROM public.audit_events e
      JOIN public.clients c ON c.id = e.resource_id
      WHERE c.name = 'Cliente Novo' $$,
  $$ VALUES ('client.created', '00000000-0000-4000-8000-0000000000c1'::uuid, 'ceo', 'client',
             true, true, NULL::uuid, 'req-clients-0001', '{}'::jsonb) $$,
  'SEC-16: create_client grava client.created com ator, papel, recurso, cliente e request_id'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.audit_events WHERE action = 'client.created' AND occurred_at = now() $$,
  $$ SELECT (1 + count(*))::int FROM good_names $$,
  'SEC-16: uma linha de auditoria por cliente criado'
);

-- AC-11: atualização ---------------------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');

SELECT results_eq(
  $$ SELECT name, updated_at = now() - interval '2 days'
       FROM public.update_client('00000000-0000-4000-8000-00000000000a', ' ' || chr(160) || 'Cliente A' || chr(12288), NULL) $$,
  $$ VALUES ('Cliente A', true) $$,
  'AC-11: renomear para o mesmo nome (depois da normalização) não muda nada nem mexe em updated_at'
);
SELECT results_eq(
  $$ SELECT name, archived_at, updated_at > created_at
       FROM public.update_client('00000000-0000-4000-8000-00000000000a', '  Cliente A Renomeado ', NULL) $$,
  $$ VALUES ('Cliente A Renomeado', NULL::timestamptz, true) $$,
  'AC-11: update_client renomeia (nome aparado), mantém ativo e move updated_at'
);
SELECT results_eq(
  $$ SELECT name FROM public.update_client('00000000-0000-4000-8000-00000000000a', chr(160) || 'Cliente A Renomeado' || chr(12288), NULL) $$,
  $$ VALUES ('Cliente A Renomeado') $$,
  'AC-11: renomear para o mesmo nome com espaços Unicode nas pontas devolve o cliente como está'
);
SELECT results_eq(
  $$ SELECT archived_at IS NOT NULL
       FROM public.update_client('00000000-0000-4000-8000-00000000000a', NULL, true) $$,
  $$ VALUES (true) $$,
  'AC-11: update_client arquiva (archived_at preenchido) sem mexer no nome'
);
SELECT results_eq(
  $$ SELECT name, archived_at IS NOT NULL
       FROM public.update_client('00000000-0000-4000-8000-00000000000a', NULL, true) $$,
  $$ VALUES ('Cliente A Renomeado', true) $$,
  'AC-11: arquivar de novo um cliente arquivado é idempotente'
);
SELECT results_eq(
  $$ SELECT archived_at = now() - interval '3 days', updated_at = now() - interval '4 days'
       FROM public.update_client('00000000-0000-4000-8000-00000000000b', NULL, true) $$,
  $$ VALUES (true, true) $$,
  'AC-11: arquivar quem já estava arquivado não troca archived_at nem updated_at'
);
SELECT results_eq(
  $$ SELECT archived_at, updated_at > created_at
       FROM public.update_client('00000000-0000-4000-8000-00000000000b', NULL, false) $$,
  $$ VALUES (NULL::timestamptz, true) $$,
  'AC-11: update_client desarquiva (archived_at nulo)'
);
SELECT results_eq(
  $$ SELECT archived_at FROM public.update_client('00000000-0000-4000-8000-00000000000b', NULL, false) $$,
  $$ VALUES (NULL::timestamptz) $$,
  'AC-11: desarquivar de novo um cliente ativo é idempotente'
);
SELECT results_eq(
  $$ SELECT name, archived_at IS NOT NULL
       FROM public.update_client('00000000-0000-4000-8000-00000000000d', 'Cafe' || chr(769), true) $$,
  $$ VALUES ('Caf' || chr(233), true) $$,
  'AC-11: update_client renomeia (em NFC) e arquiva numa chamada só'
);
-- (o nome "日本" já é de um cliente ativo criado acima: o japonês daqui é outro, por causa de E-41)
SELECT results_eq(
  $$ SELECT name FROM public.update_client('00000000-0000-4000-8000-00000000000e', chr(26085) || chr(26412) || chr(35486), NULL) $$,
  $$ VALUES (chr(26085) || chr(26412) || chr(35486)) $$,
  'E-30: update_client aceita um nome em japonês (o [[:alnum:]] é Unicode)'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', NULL, NULL) $$,
  'P0001', 'INVALID_INPUT', 'AC-11: update_client recusa a chamada sem nada para mudar'
);
SELECT throws_ok(
  format('SELECT * FROM public.update_client(%L, %L, NULL)', '00000000-0000-4000-8000-00000000000a', b.value),
  'P0001', 'INVALID_INPUT',
  'E-30: update_client recusa o nome: ' || b.label
) FROM bad_names b WHERE b.value IS NOT NULL ORDER BY b.label;
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', repeat('a', 161), true) $$,
  'P0001', 'INVALID_INPUT', 'AC-11: um nome inválido recusa a chamada inteira, mesmo com archived'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-0000000000ff', 'Cliente inexistente', NULL) $$,
  'P0001', 'NOT_FOUND', 'AC-11: update_client em cliente inexistente é NOT_FOUND'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client(NULL, 'Cliente sem id', NULL) $$,
  'P0001', 'NOT_FOUND', 'AC-11: update_client sem id é NOT_FOUND'
);
SELECT results_eq(
  $$ SELECT name, archived_at IS NULL FROM public.clients WHERE id = '00000000-0000-4000-8000-00000000000a' $$,
  $$ VALUES ('Cliente A Renomeado', false) $$,
  'AC-11: as chamadas inválidas não mudaram o cliente (só o nome e o arquivamento dos casos válidos)'
);

-- SEC-04: nem o CEO aal2 escreve direto na tabela ----------------------------------------------------------------
SELECT throws_ok(
  $$ INSERT INTO public.clients (name) VALUES ('Escrita direta do CEO') $$,
  '42501', NULL, 'SEC-04: CEO aal2 não faz INSERT direto em clients'
);
SELECT throws_ok(
  $$ UPDATE public.clients SET name = 'Escrita direta do CEO' WHERE id = '00000000-0000-4000-8000-00000000000a' $$,
  '42501', NULL, 'SEC-04: CEO aal2 não faz UPDATE direto em clients'
);
SELECT throws_ok(
  $$ DELETE FROM public.clients WHERE id = '00000000-0000-4000-8000-00000000000a' $$,
  '42501', NULL, 'SEC-04: CEO aal2 não faz DELETE direto em clients'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.clients
      WHERE created_at = now() OR id IN ('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-00000000000d', '00000000-0000-4000-8000-00000000000e') $$,
  $$ SELECT (4 + 1 + count(*))::int FROM good_names $$,
  'AC-09: CEO aal2 lê todos os clientes (fixtures e criados)'
);
SELECT results_eq(
  $$ SELECT count(*)::integer FROM public.clients $$,
  $$ SELECT tests.clients_count_all() $$,
  'AC-09: e o que o RLS dá ao CEO é a tabela inteira, a mesma contagem que o dono vê (sem filtro de fixture)'
);
SELECT tests.clear_authentication();

-- SEC-16: auditoria das atualizações -----------------------------------------------------------------------------
SELECT results_eq(
  $$ SELECT e.resource_id::text, e.action
       FROM public.audit_events e
      WHERE e.action IN ('client.updated', 'client.archived', 'client.unarchived') AND e.occurred_at = now()
      ORDER BY e.id $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000a', 'client.updated'),
            ('00000000-0000-4000-8000-00000000000a', 'client.archived'),
            ('00000000-0000-4000-8000-00000000000b', 'client.unarchived'),
            ('00000000-0000-4000-8000-00000000000d', 'client.updated'),
            ('00000000-0000-4000-8000-00000000000d', 'client.archived'),
            ('00000000-0000-4000-8000-00000000000e', 'client.updated') $$,
  'SEC-16: só as mudanças de verdade foram auditadas, na ordem (renomear antes de arquivar)'
);
SELECT is_empty(
  $$ SELECT e.id
       FROM public.audit_events e
      WHERE e.action LIKE 'client.%' AND e.occurred_at = now()
        AND (e.actor_id IS DISTINCT FROM '00000000-0000-4000-8000-0000000000c1'::uuid
             OR e.actor_role IS DISTINCT FROM 'ceo'
             OR e.resource_type <> 'client'
             OR e.client_id IS DISTINCT FROM e.resource_id
             OR e.process_id IS NOT NULL
             OR e.request_id IS DISTINCT FROM 'req-clients-0001') $$,
  'SEC-16: todo evento de cliente tem o CEO como ator, o próprio cliente como recurso e o request_id'
);
SELECT results_eq(
  $$ SELECT metadata FROM public.audit_events WHERE action = 'client.updated' AND resource_id = '00000000-0000-4000-8000-00000000000a' $$,
  $$ VALUES ('{"fields":["name"]}'::jsonb) $$,
  'SEC-16: client.updated guarda só o nome do campo, não o valor'
);
SELECT is_empty(
  $$ SELECT e.id
       FROM public.audit_events e
      WHERE e.action LIKE 'client.%' AND e.metadata::text ~* '(Renomeado|Cliente|Novo|Acme)' $$,
  'SEC-16: nenhum nome de cliente vai para os metadados da auditoria'
);
SELECT is_empty(
  $$ SELECT c.id
       FROM public.clients c
      WHERE c.id IN ('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000b')
        AND ((c.id = '00000000-0000-4000-8000-00000000000a' AND c.archived_at IS NULL)
          OR (c.id = '00000000-0000-4000-8000-00000000000b' AND c.archived_at IS NOT NULL)) $$,
  'AC-11: o estado final de A (arquivado) e de B (desarquivado) é o esperado'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.audit_events WHERE action LIKE 'client.%' AND occurred_at = now() $$,
  $$ SELECT (1 + count(*) + 6)::int FROM good_names $$,
  'SEC-16: as criações e 6 mudanças, nenhuma linha a mais'
);

SELECT * FROM finish();
ROLLBACK;
