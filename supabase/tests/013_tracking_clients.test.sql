-- Onda 6: create_client e update_client (spec §3.7). Cobre: privilégios e search_path das funções
-- (AC-25), anon (AC-10), cliente (AC-08, AC-09: não executa nem lê o outro cliente), CEO aal1, CEO
-- aal2 sem fator TOTP verificado (F-24), CEO com sessão morta ou desativado, escrita direta negada,
-- o caminho feliz (AC-11), as regras do nome espelhadas do Zod (E-30), a idempotência das mudanças
-- e a auditoria gravada na mesma transação (ator, papel, recurso, cliente, request_id, sem PII).
BEGIN;
SELECT plan(73);

-- arrange (como postgres) --------------------------------------------------------------------------
-- A e B são os clientes das fixtures (A ativo, B arquivado há 3 dias), com datas no passado para
-- provar quando `updated_at` mexe. D é um terceiro cliente, ativo, para renomear e arquivar numa
-- chamada só. a1 é login de A. c1 é CEO com fator verificado; c2, CEO sem fator; c3, CEO com fator e
-- sessão apagada; c4, CEO com fator e perfil desativado.
INSERT INTO public.clients (id, name, archived_at, created_at, updated_at) VALUES
  ('00000000-0000-4000-8000-00000000000a', 'Cliente A', NULL,
   now() - interval '2 days', now() - interval '2 days'),
  ('00000000-0000-4000-8000-00000000000b', 'Cliente B', now() - interval '3 days',
   now() - interval '4 days', now() - interval '4 days'),
  ('00000000-0000-4000-8000-00000000000d', 'Cliente D', NULL,
   now() - interval '5 days', now() - interval '5 days');

SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c2', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c3', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c4', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c3');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c4');
DELETE FROM auth.sessions WHERE id = '00000000-0000-4000-8000-0000000000c3';
UPDATE public.profiles SET disabled_at = now() WHERE id = '00000000-0000-4000-8000-0000000000c4';

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
                      'public.update_client(uuid, text, boolean)'::regprocedure)
        AND a.grantee = 0 AND a.privilege_type = 'EXECUTE' $$,
  'AC-25: create_client e update_client não concedem EXECUTE a PUBLIC'
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
  'AC-09: cliente A lê só a própria linha de clients (não vê B nem D)'
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
SELECT tests.clear_authentication();

SELECT is_empty(
  $$ SELECT id FROM public.audit_events WHERE action LIKE 'client.%' $$,
  'AC-08: nenhuma chamada negada gravou auditoria'
);
SELECT results_eq(
  $$ SELECT count(*)::int FROM public.clients $$,
  $$ VALUES (3) $$,
  'AC-08: nenhuma chamada negada criou cliente (só as 3 fixtures)'
);

-- AC-11: CEO aal2 com fator verificado, criação ---------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');

SELECT results_eq(
  $$ SELECT name, archived_at FROM public.create_client('  Cliente Novo  ') $$,
  $$ VALUES ('Cliente Novo', NULL::timestamptz) $$,
  'AC-11: create_client devolve o cliente com o nome aparado e ativo'
);
SELECT results_eq(
  $$ SELECT name FROM public.create_client('Cafe' || chr(769)) $$,
  $$ VALUES ('Caf' || chr(233)) $$,
  'E-30: create_client guarda o nome em NFC (e + acento combinante vira é)'
);
SELECT lives_ok(
  $$ SELECT * FROM public.create_client(repeat('a', 160)) $$,
  'AC-11: create_client aceita o nome com 160 caracteres'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_client(NULL) $$,
  'P0001', 'INVALID_INPUT', 'AC-11: create_client recusa nome nulo'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('') $$,
  'P0001', 'INVALID_INPUT', 'AC-11: create_client recusa nome vazio'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('   ') $$,
  'P0001', 'INVALID_INPUT', 'AC-11: create_client recusa nome só de espaços'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_client(repeat('a', 161)) $$,
  'P0001', 'INVALID_INPUT', 'AC-11: create_client recusa nome com 161 caracteres'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Linha' || chr(10) || 'dupla') $$,
  'P0001', 'INVALID_INPUT', 'E-30: create_client recusa quebra de linha no nome'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Zero' || chr(8203) || 'width') $$,
  'P0001', 'INVALID_INPUT', 'E-30: create_client recusa caractere de largura zero no nome'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Bidi' || chr(8238) || 'override') $$,
  'P0001', 'INVALID_INPUT', 'E-30: create_client recusa override bidirecional no nome'
);
SELECT throws_ok(
  $$ SELECT * FROM public.create_client('Bom' || chr(65279) || 'marca') $$,
  'P0001', 'INVALID_INPUT', 'E-30: create_client recusa BOM no nome'
);
SELECT tests.clear_authentication();

SELECT results_eq(
  $$ SELECT count(*)::int FROM public.clients $$,
  $$ VALUES (6) $$,
  'AC-11: só os 3 clientes válidos foram criados; os nomes inválidos não deixaram linha'
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
  $$ SELECT count(*)::int FROM public.audit_events WHERE action = 'client.created' $$,
  $$ VALUES (3) $$,
  'SEC-16: uma linha de auditoria por cliente criado'
);

-- AC-11: atualização ---------------------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');

SELECT results_eq(
  $$ SELECT name, archived_at, updated_at > created_at
       FROM public.update_client('00000000-0000-4000-8000-00000000000a', '  Cliente A Renomeado ', NULL) $$,
  $$ VALUES ('Cliente A Renomeado', NULL::timestamptz, true) $$,
  'AC-11: update_client renomeia (nome aparado), mantém ativo e move updated_at'
);
SELECT results_eq(
  $$ SELECT name FROM public.update_client('00000000-0000-4000-8000-00000000000a', 'Cliente A Renomeado', NULL) $$,
  $$ VALUES ('Cliente A Renomeado') $$,
  'AC-11: renomear para o mesmo nome devolve o cliente como está'
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
       FROM public.update_client('00000000-0000-4000-8000-00000000000d', 'Cliente D Novo', true) $$,
  $$ VALUES ('Cliente D Novo', true) $$,
  'AC-11: update_client renomeia e arquiva numa chamada só'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', NULL, NULL) $$,
  'P0001', 'INVALID_INPUT', 'AC-11: update_client recusa a chamada sem nada para mudar'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', '', NULL) $$,
  'P0001', 'INVALID_INPUT', 'AC-11: update_client recusa nome vazio'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', repeat('a', 161), true) $$,
  'P0001', 'INVALID_INPUT', 'AC-11: update_client recusa nome com 161 caracteres'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', 'Quebra' || chr(10) || 'de linha', NULL) $$,
  'P0001', 'INVALID_INPUT', 'E-30: update_client recusa caractere de controle no nome'
);
SELECT throws_ok(
  $$ SELECT * FROM public.update_client('00000000-0000-4000-8000-00000000000a', 'Largura' || chr(8203) || 'zero', NULL) $$,
  'P0001', 'INVALID_INPUT', 'E-30: update_client recusa caractere de formatação no nome'
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
  $$ SELECT name FROM public.clients WHERE id = '00000000-0000-4000-8000-00000000000a' $$,
  $$ VALUES ('Cliente A Renomeado') $$,
  'AC-11: as chamadas inválidas não mudaram o cliente'
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
  $$ SELECT count(*)::int FROM public.clients $$,
  $$ VALUES (6) $$,
  'AC-09: CEO aal2 lê todos os clientes (3 fixtures e 3 criados)'
);
SELECT tests.clear_authentication();

-- SEC-16: auditoria das atualizações -----------------------------------------------------------------------------
SELECT results_eq(
  $$ SELECT e.resource_id::text, e.action
       FROM public.audit_events e
      WHERE e.action IN ('client.updated', 'client.archived', 'client.unarchived')
      ORDER BY e.id $$,
  $$ VALUES ('00000000-0000-4000-8000-00000000000a', 'client.updated'),
            ('00000000-0000-4000-8000-00000000000a', 'client.archived'),
            ('00000000-0000-4000-8000-00000000000b', 'client.unarchived'),
            ('00000000-0000-4000-8000-00000000000d', 'client.updated'),
            ('00000000-0000-4000-8000-00000000000d', 'client.archived') $$,
  'SEC-16: só as mudanças de verdade foram auditadas, na ordem (renomear antes de arquivar)'
);
SELECT is_empty(
  $$ SELECT e.id
       FROM public.audit_events e
      WHERE e.action LIKE 'client.%'
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
      WHERE e.action LIKE 'client.%' AND e.metadata::text ~* '(Renomeado|Cliente|Novo)' $$,
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
  $$ SELECT count(*)::int FROM public.audit_events WHERE action LIKE 'client.%' $$,
  $$ VALUES (8) $$,
  'SEC-16: 3 criações e 5 mudanças, nenhuma linha a mais'
);

SELECT * FROM finish();
ROLLBACK;
