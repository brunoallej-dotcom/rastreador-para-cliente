-- Onda 5: proteção contra replay de código TOTP (F-21, RFC 6238 seção 5.2) e `private.is_ceo()` com
-- fator TOTP verificado (F-24). Cobre: privilégios da tabela e da função, anon, fator de outro
-- usuário, reuso dentro e depois da janela de 120 s, escrita direta negada e a exigência do fator
-- em toda leitura e função de CEO.
BEGIN;
SELECT plan(54);

-- arrange (como postgres) --------------------------------------------------------------------------
INSERT INTO public.clients (id, name) VALUES ('00000000-0000-4000-8000-00000000000a', 'Cliente A');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c2', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c3', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c4', 'ceo');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');

-- c1 e c2: fator verificado; c3: fator ainda não verificado (primeiro cadastro); c4: sem fator
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c2');
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
VALUES ('00000000-0000-4000-8000-0000000003c3', '00000000-0000-4000-8000-0000000000c3',
        'candidato', 'totp', 'unverified', now(), now(), 'TESTSECRET');
-- a c4 tem um fator que não é TOTP (nunca conta como MFA do app)
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, phone)
VALUES ('00000000-0000-4000-8000-0000000004c4', '00000000-0000-4000-8000-0000000000c4',
        'telefone', 'phone', 'verified', now(), now(), '+5511999990000');

CREATE TEMP TABLE factor_of AS
SELECT f.user_id, f.id AS factor_id
  FROM auth.mfa_factors f
 WHERE f.factor_type = 'totp' AND f.status = 'verified'
   AND f.user_id IN ('00000000-0000-4000-8000-0000000000c1', '00000000-0000-4000-8000-0000000000c2');
GRANT SELECT ON factor_of TO authenticated, service_role;

-- um digest por "código" (32 bytes, como o SHA-256 que o app envia)
CREATE TEMP TABLE digest_of (name text PRIMARY KEY, value bytea NOT NULL);
INSERT INTO digest_of (name, value) VALUES
  ('one', decode(repeat('01', 32), 'hex')),
  ('two', decode(repeat('02', 32), 'hex'));
GRANT SELECT ON digest_of TO authenticated, service_role;

-- privilégios: tabela e função ---------------------------------------------------------------------
SELECT ok(
  (SELECT c.relrowsecurity FROM pg_class c WHERE c.oid = 'private.totp_code_uses'::regclass),
  'totp_code_uses: RLS habilitado'
);
SELECT is_empty(
  $$ SELECT r.role
       FROM (VALUES ('anon'), ('authenticated'), ('service_role')) r (role)
      WHERE has_table_privilege(r.role, 'private.totp_code_uses',
                                'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') $$,
  'totp_code_uses: anon, authenticated e service_role não têm privilégio algum na tabela'
);
SELECT is_empty(
  $$ SELECT policyname FROM pg_policies WHERE schemaname = 'private' AND tablename = 'totp_code_uses' $$,
  'totp_code_uses: nenhuma policy (RLS sem policy nega a quem não é dono)'
);
SELECT ok(
  (SELECT p.prosecdef FROM pg_proc p WHERE p.oid = 'public.consume_totp_code(uuid, uuid, bytea)'::regprocedure),
  'consume_totp_code: SECURITY DEFINER'
);
SELECT ok(
  (SELECT 'search_path=""' = ANY (p.proconfig) FROM pg_proc p
    WHERE p.oid = 'public.consume_totp_code(uuid, uuid, bytea)'::regprocedure),
  'AC-25: consume_totp_code tem search_path vazio'
);
SELECT ok(
  to_regprocedure('public.consume_totp_code(uuid, bytea)') IS NULL,
  'F-65: a versão de dois argumentos, executável por authenticated, deixou de existir'
);
SELECT ok(
  NOT has_function_privilege('anon', 'public.consume_totp_code(uuid, uuid, bytea)', 'EXECUTE'),
  'consume_totp_code: anon não executa'
);
SELECT ok(
  NOT has_function_privilege('authenticated', 'public.consume_totp_code(uuid, uuid, bytea)', 'EXECUTE'),
  'F-65: consume_totp_code: authenticated NÃO executa (era um oráculo de código pelo PostgREST)'
);
SELECT ok(
  has_function_privilege('service_role', 'public.consume_totp_code(uuid, uuid, bytea)', 'EXECUTE'),
  'F-65: consume_totp_code: service_role executa (o app a chama depois dos limites da rota)'
);
SELECT is_empty(
  $$ SELECT a.grantee
       FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE p.oid = 'public.consume_totp_code(uuid, uuid, bytea)'::regprocedure
        AND a.privilege_type = 'EXECUTE'
        AND a.grantee NOT IN (p.proowner, 'service_role'::regrole) $$,
  'consume_totp_code: EXECUTE concedido apenas ao dono e ao service_role (nem PUBLIC)'
);

-- anon, authenticated e usuário que não existe: negados --------------------------------------------------
SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT public.consume_totp_code('00000000-0000-4000-8000-0000000000c3',
                                      '00000000-0000-4000-8000-0000000003c3',
                                      decode(repeat('ab', 32), 'hex')) $$,
  '42501', NULL, 'consume_totp_code: anon é negado (42501)'
);
RESET ROLE;

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT public.consume_totp_code('00000000-0000-4000-8000-0000000000c1', f.factor_id, decode(repeat('ab', 32), 'hex'))
       FROM factor_of f WHERE f.user_id = '00000000-0000-4000-8000-0000000000c1' $$,
  '42501', NULL, 'F-65: nem o CEO atestado, com a própria sessão, queima código pelo PostgREST (42501)'
);
SELECT tests.clear_authentication();

SET LOCAL ROLE service_role;
SELECT throws_ok(
  $$ SELECT public.consume_totp_code('99999999-9999-4999-8999-999999999999',
                                      '00000000-0000-4000-8000-0000000004c4',
                                      decode(repeat('ab', 32), 'hex')) $$,
  '42501', 'FORBIDDEN', 'consume_totp_code: usuário que não existe é FORBIDDEN'
);
RESET ROLE;

-- o dono consome; o mesmo código não é consumido duas vezes ---------------------------------------------
SET LOCAL ROLE service_role;
SELECT is(
  (SELECT public.consume_totp_code(f.user_id, f.factor_id, d.value) FROM factor_of f, digest_of d
    WHERE f.user_id = '00000000-0000-4000-8000-0000000000c1' AND d.name = 'one'),
  true,
  'F-21: o primeiro uso de um código é aceito'
);
SELECT is(
  (SELECT public.consume_totp_code(f.user_id, f.factor_id, d.value) FROM factor_of f, digest_of d
    WHERE f.user_id = '00000000-0000-4000-8000-0000000000c1' AND d.name = 'one'),
  false,
  'F-21: o mesmo código do mesmo fator, dentro da janela, é recusado (replay)'
);
SELECT is(
  (SELECT public.consume_totp_code(f.user_id, f.factor_id, d.value) FROM factor_of f, digest_of d
    WHERE f.user_id = '00000000-0000-4000-8000-0000000000c1' AND d.name = 'one'),
  false,
  'F-21: e continua recusado na terceira vez'
);
SELECT is(
  (SELECT public.consume_totp_code(f.user_id, f.factor_id, d.value) FROM factor_of f, digest_of d
    WHERE f.user_id = '00000000-0000-4000-8000-0000000000c1' AND d.name = 'two'),
  true,
  'F-21: outro código do mesmo fator é aceito'
);
RESET ROLE;

SELECT is(
  (SELECT count(*)::integer FROM private.totp_code_uses u WHERE u.factor_id IN (SELECT f.factor_id FROM factor_of f)),
  2,
  'F-21: a tabela guarda um digest por código aceito (as recusas não gravam nada)'
);
SELECT is(
  (SELECT bool_and(octet_length(u.code_digest) = 32) FROM private.totp_code_uses u WHERE u.factor_id IN (SELECT f.factor_id FROM factor_of f)),
  true,
  'F-21: o que é guardado é um digest de 32 bytes, nunca o código'
);

-- o fator é do usuário: nenhum outro queima os códigos dele ---------------------------------------------
SET LOCAL ROLE service_role;
SELECT throws_ok(
  $$ SELECT public.consume_totp_code('00000000-0000-4000-8000-0000000000c2', f.factor_id,
                                      decode(repeat('ab', 32), 'hex'))
       FROM factor_of f WHERE f.user_id = '00000000-0000-4000-8000-0000000000c1' $$,
  'P0001', 'NOT_FOUND', 'F-21: o fator de outro CEO é NOT_FOUND (ninguém queima os códigos alheios)'
);
SELECT throws_ok(
  $$ SELECT public.consume_totp_code('00000000-0000-4000-8000-0000000000c2',
                                      '99999999-9999-4999-8999-999999999999',
                                      decode(repeat('ab', 32), 'hex')) $$,
  'P0001', 'NOT_FOUND', 'F-21: um fator inexistente é NOT_FOUND, igual ao de outro usuário'
);
SELECT throws_ok(
  $$ SELECT public.consume_totp_code('00000000-0000-4000-8000-0000000000a1', f.factor_id,
                                      decode(repeat('ab', 32), 'hex'))
       FROM factor_of f WHERE f.user_id = '00000000-0000-4000-8000-0000000000c1' $$,
  'P0001', 'NOT_FOUND', 'F-21: um cliente também não alcança o fator de um CEO'
);
RESET ROLE;
SELECT is(
  (SELECT count(*)::integer FROM private.totp_code_uses u WHERE u.factor_id IN (SELECT f.factor_id FROM factor_of f)),
  2,
  'F-21: as tentativas sobre fator alheio ou inexistente não gravaram nada'
);

-- um fator que não é TOTP não conta
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c5', 'ceo');
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, phone)
VALUES ('00000000-0000-4000-8000-0000000005c5', '00000000-0000-4000-8000-0000000000c5',
        'telefone', 'phone', 'verified', now(), now(), '+5511999990001');
SET LOCAL ROLE service_role;
SELECT throws_ok(
  $$ SELECT public.consume_totp_code('00000000-0000-4000-8000-0000000000c5',
                                      '00000000-0000-4000-8000-0000000005c5',
                                      decode(repeat('ab', 32), 'hex')) $$,
  'P0001', 'NOT_FOUND', 'F-21: um fator que não é TOTP é NOT_FOUND'
);
RESET ROLE;

-- entrada inválida --------------------------------------------------------------------------------
SET LOCAL ROLE service_role;
SELECT throws_ok(
  $$ SELECT public.consume_totp_code(f.user_id, f.factor_id, '\x0102'::bytea)
       FROM factor_of f WHERE f.user_id = '00000000-0000-4000-8000-0000000000c1' $$,
  'P0001', 'INVALID_INPUT', 'consume_totp_code: digest que não tem 32 bytes é INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.consume_totp_code(f.user_id, f.factor_id, NULL)
       FROM factor_of f WHERE f.user_id = '00000000-0000-4000-8000-0000000000c1' $$,
  'P0001', 'INVALID_INPUT', 'consume_totp_code: digest nulo é INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.consume_totp_code('00000000-0000-4000-8000-0000000000c1', NULL, decode(repeat('ab', 32), 'hex')) $$,
  'P0001', 'INVALID_INPUT', 'consume_totp_code: fator nulo é INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT public.consume_totp_code(NULL, '00000000-0000-4000-8000-0000000003c3', decode(repeat('ab', 32), 'hex')) $$,
  'P0001', 'INVALID_INPUT', 'consume_totp_code: usuário nulo é INVALID_INPUT'
);
RESET ROLE;

-- a janela de 120 s ----------------------------------------------------------------------------------
-- (o teste roda numa transação só, e now() é fixo nela: o tempo é movido nas linhas gravadas)
UPDATE private.totp_code_uses SET used_at = now() - interval '119 seconds';
SET LOCAL ROLE service_role;
SELECT is(
  (SELECT public.consume_totp_code(f.user_id, f.factor_id, d.value) FROM factor_of f, digest_of d
    WHERE f.user_id = '00000000-0000-4000-8000-0000000000c1' AND d.name = 'one'),
  false,
  'F-21: com o código usado há 119 s, o reuso ainda é recusado'
);
RESET ROLE;

UPDATE private.totp_code_uses SET used_at = now() - interval '121 seconds';
SET LOCAL ROLE service_role;
SELECT is(
  (SELECT public.consume_totp_code(f.user_id, f.factor_id, d.value) FROM factor_of f, digest_of d
    WHERE f.user_id = '00000000-0000-4000-8000-0000000000c1' AND d.name = 'one'),
  true,
  'F-21: com o código usado há 121 s, o mesmo digest volta a ser aceito (a janela passou)'
);
RESET ROLE;
SELECT is(
  (SELECT count(*)::integer FROM private.totp_code_uses u WHERE u.factor_id IN (SELECT f.factor_id FROM factor_of f)),
  1,
  'F-21: a chamada apagou as linhas vencidas do fator e gravou a nova (o outro digest sumiu)'
);

-- escrita e leitura direta negadas ------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT code_digest FROM private.totp_code_uses $$, '42501', NULL,
  'totp_code_uses: authenticated (CEO aal2) não lê'
);
SELECT throws_ok(
  $$ INSERT INTO private.totp_code_uses (factor_id, code_digest)
     VALUES ('00000000-0000-4000-8000-0000000003c3', decode(repeat('ab', 32), 'hex')) $$,
  '42501', NULL, 'totp_code_uses: authenticated não insere direto'
);
SELECT throws_ok(
  $$ DELETE FROM private.totp_code_uses $$, '42501', NULL,
  'totp_code_uses: authenticated não apaga direto (não "libera" um código usado)'
);
SELECT tests.clear_authentication();

SET LOCAL ROLE service_role;
SELECT throws_ok(
  $$ INSERT INTO private.totp_code_uses (factor_id, code_digest)
     VALUES ('00000000-0000-4000-8000-0000000003c3', decode(repeat('ab', 32), 'hex')) $$,
  '42501', NULL, 'totp_code_uses: nem a secret key escreve direto'
);
RESET ROLE;

-- o fator removido leva as linhas (E-26) ---------------------------------------------------------------
DELETE FROM auth.mfa_factors f
 WHERE f.id = (SELECT factor_id FROM factor_of WHERE user_id = '00000000-0000-4000-8000-0000000000c1');
SELECT is(
  (SELECT count(*)::integer FROM private.totp_code_uses u WHERE u.factor_id IN (SELECT f.factor_id FROM factor_of f)),
  0,
  'F-21: remover o fator apaga os códigos registrados dele (ON DELETE CASCADE)'
);

-- F-24: is_ceo() exige o fator TOTP verificado --------------------------------------------------------
-- c2 tem aal2 e fator verificado: lê tudo
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal2');
SELECT is(
  (SELECT count(*)::integer FROM public.clients WHERE id = '00000000-0000-4000-8000-00000000000a'),
  1,
  'F-24: CEO aal2 com fator TOTP verificado lê os clientes'
);
SELECT lives_ok(
  $$ SELECT * FROM public.list_client_users('00000000-0000-4000-8000-00000000000a') $$,
  'F-24: CEO aal2 com fator TOTP verificado executa funções de CEO'
);
SELECT tests.clear_authentication();

-- c1 teve o fator removido acima: o JWT aal2 continua válido, mas não vale mais como CEO
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT is(
  (SELECT count(*)::integer FROM public.clients),
  0,
  'F-24: aal2 sem fator TOTP verificado (removido) não lê os clientes'
);
SELECT throws_ok(
  $$ SELECT * FROM public.list_client_users('00000000-0000-4000-8000-00000000000a') $$,
  '42501', 'FORBIDDEN', 'F-24: aal2 sem fator TOTP verificado não executa funções de CEO'
);
SELECT tests.clear_authentication();

-- c3: fator só candidato (não verificado): aal2 no JWT não basta
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c3', 'aal2');
SELECT is(
  (SELECT count(*)::integer FROM public.clients),
  0,
  'F-24: aal2 com fator ainda não verificado não lê os clientes'
);
SELECT tests.clear_authentication();

-- c4: um fator verificado que não é TOTP não vale
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c6', 'ceo');
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, phone)
VALUES ('00000000-0000-4000-8000-0000000006c6', '00000000-0000-4000-8000-0000000000c6',
        'telefone', 'phone', 'verified', now(), now(), '+5511999990002');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c6', 'aal2');
SELECT is(
  (SELECT count(*)::integer FROM public.clients),
  0,
  'F-24: aal2 com um fator verificado que não é TOTP não lê os clientes'
);
SELECT tests.clear_authentication();

-- aal1 continua negado, mesmo com o fator verificado
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal1');
SELECT is(
  (SELECT count(*)::integer FROM public.clients),
  0,
  'AC-08: aal1, mesmo com fator verificado, não lê os clientes'
);
SELECT tests.clear_authentication();

-- um fator novo NÃO traz o acesso de volta (Onda 6.1): o atestado era do fator removido e foi junto com
-- ele (ON DELETE CASCADE); só um verify novo pelo backend atesta de novo
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2', false);
SELECT is(
  (SELECT count(*)::integer FROM public.clients),
  0,
  'F-24, F-63: um fator verificado novo não devolve o acesso ao mesmo JWT aal2: o atestado era do fator removido'
);
SELECT tests.clear_authentication();
-- F-64: nem um verify novo pelo backend atesta o fator que veio DEPOIS do primeiro (o c1 já teve um
-- fator ativado): só o reset de MFA do operador (E-25) reabre isso
SELECT throws_ok(
  $$ SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2') $$,
  'P0001', NULL, 'F-64: um fator novo, depois do primeiro ativado, não é atestado (factor_reenrolled), nem com um verify pelo backend'
);
SELECT tests.reset_first_activation('00000000-0000-4000-8000-0000000000c1');
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT is(
  (SELECT count(*)::integer FROM public.clients WHERE id = '00000000-0000-4000-8000-00000000000a'),
  1,
  'F-24: depois do reset do operador e de um verify novo pelo backend, o CEO lê os clientes'
);
SELECT tests.clear_authentication();

-- AC-08 nas FUNÇÕES de CEO: aal1 com fator verificado (só a checagem de aal2 pode negar) ---------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c2', 'aal1');
SELECT throws_ok(
  $$ SELECT public.record_account_provisioned('00000000-0000-4000-8000-0000000000a1') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 com fator verificado não executa record_account_provisioned'
);
SELECT throws_ok(
  $$ SELECT public.set_account_disabled('00000000-0000-4000-8000-0000000000a1', true) $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 com fator verificado não executa set_account_disabled'
);
SELECT throws_ok(
  $$ SELECT public.set_account_display_name('00000000-0000-4000-8000-0000000000a1', 'Renomeado sem aal2') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 com fator verificado não executa set_account_display_name'
);
SELECT throws_ok(
  $$ SELECT public.require_password_change('00000000-0000-4000-8000-0000000000a1') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 com fator verificado não executa require_password_change'
);
SELECT throws_ok(
  $$ SELECT * FROM public.list_client_users('00000000-0000-4000-8000-00000000000a') $$,
  '42501', 'FORBIDDEN', 'AC-08: CEO aal1 com fator verificado não executa list_client_users'
);
SELECT tests.clear_authentication();

-- o dono queima código no fator AINDA NÃO verificado (é assim que a primeira ativação passa) -------------
SET LOCAL ROLE service_role;
SELECT is(
  public.consume_totp_code('00000000-0000-4000-8000-0000000000c3',
                           '00000000-0000-4000-8000-0000000003c3', decode(repeat('0c', 32), 'hex')),
  true,
  'F-21: o dono queima um código no próprio fator não verificado (primeira ativação)'
);
RESET ROLE;

-- perfil desativado não queima código -----------------------------------------------------------------
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c7', 'ceo');
INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
VALUES ('00000000-0000-4000-8000-0000000007c7', '00000000-0000-4000-8000-0000000000c7',
        'desativado', 'totp', 'verified', now(), now(), 'TESTSECRET');
UPDATE public.profiles SET disabled_at = now() WHERE id = '00000000-0000-4000-8000-0000000000c7';
SET LOCAL ROLE service_role;
SELECT throws_ok(
  $$ SELECT public.consume_totp_code('00000000-0000-4000-8000-0000000000c7',
                                      '00000000-0000-4000-8000-0000000007c7', decode(repeat('0d', 32), 'hex')) $$,
  '42501', 'FORBIDDEN', 'consume_totp_code: perfil desativado é negado'
);
RESET ROLE;

-- is_ceo() segue STABLE (as policies o chamam uma vez por consulta) -------------------------------------
SELECT is(
  (SELECT p.provolatile::text FROM pg_proc p
     JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'private' AND p.proname = 'is_ceo'),
  's',
  'F-24: private.is_ceo() continua STABLE'
);

SELECT * FROM finish();
ROLLBACK;
