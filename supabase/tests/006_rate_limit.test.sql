-- public.rate_limit_hit (Onda 2): contador de janela fixa, só para service_role (SEC-09, ADR 0004).
-- Dentro da transação now() é fixo, então a janela e o retry_after são determinísticos.
BEGIN;
SELECT plan(40);

SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
SELECT tests.verify_totp('00000000-0000-4000-8000-0000000000c1');
INSERT INTO public.clients (id, name) VALUES ('00000000-0000-4000-8000-00000000000a', 'Cliente A');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');

-- Os p_max primeiros hits passam; o seguinte é negado com retry_after_seconds ----------------------------
SET LOCAL ROLE service_role;

SELECT results_eq(
  $$ SELECT allowed, retry_after_seconds FROM public.rate_limit_hit('login:ip:a', 60, 3) $$,
  $$ VALUES (true, 0) $$,
  'rate_limit_hit: 1º hit (p_max = 3) é permitido com retry_after_seconds = 0'
);
SELECT results_eq(
  $$ SELECT allowed, retry_after_seconds FROM public.rate_limit_hit('login:ip:a', 60, 3) $$,
  $$ VALUES (true, 0) $$,
  'rate_limit_hit: 2º hit é permitido com retry_after_seconds = 0'
);
SELECT results_eq(
  $$ SELECT allowed, retry_after_seconds FROM public.rate_limit_hit('login:ip:a', 60, 3) $$,
  $$ VALUES (true, 0) $$,
  'rate_limit_hit: 3º hit (o último dentro de p_max) é permitido com retry_after_seconds = 0'
);
SELECT results_eq(
  $$ SELECT allowed, retry_after_seconds FROM public.rate_limit_hit('login:ip:a', 60, 3) $$,
  $$ SELECT false,
            greatest(1, ceil(extract(epoch FROM (
              to_timestamp(floor(extract(epoch FROM now()) / 60) * 60) + make_interval(secs => 60) - now()
            )))::integer) $$,
  'rate_limit_hit: 4º hit é negado e retry_after_seconds é o tempo até o fim da janela de 60 s'
);
SELECT results_eq(
  $$ SELECT allowed, retry_after_seconds BETWEEN 1 AND 60 FROM public.rate_limit_hit('login:ip:a', 60, 3) $$,
  $$ VALUES (false, true) $$,
  'rate_limit_hit: 5º hit continua negado, com retry_after_seconds entre 1 e a janela'
);

-- Buckets independentes ------------------------------------------------------------------------------------
SELECT results_eq(
  $$ SELECT allowed, retry_after_seconds FROM public.rate_limit_hit('login:ip:b', 60, 3) $$,
  $$ VALUES (true, 0) $$,
  'rate_limit_hit: outro bucket tem contador próprio (login:ip:a esgotado não afeta login:ip:b)'
);

-- p_max = 1: o segundo hit já é negado -------------------------------------------------------------------------
SELECT results_eq(
  $$ SELECT allowed, retry_after_seconds FROM public.rate_limit_hit('single:hit', 30, 1) $$,
  $$ VALUES (true, 0) $$,
  'rate_limit_hit: com p_max = 1, o 1º hit é permitido'
);
SELECT results_eq(
  $$ SELECT allowed, retry_after_seconds BETWEEN 1 AND 30 FROM public.rate_limit_hit('single:hit', 30, 1) $$,
  $$ VALUES (false, true) $$,
  'rate_limit_hit: com p_max = 1, o 2º hit é negado com retry_after_seconds entre 1 e 30'
);

-- Entradas inválidas -----------------------------------------------------------------------------------------------
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit(NULL, 60, 3) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: bucket nulo falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('', 60, 3) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: bucket vazio falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('bad bucket', 60, 3) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: bucket com espaço falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('a/b', 60, 3) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: bucket com barra falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('clíente', 60, 3) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: bucket com acento falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit(E'abc\n', 60, 3) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: bucket com quebra de linha no fim falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit(repeat('a', 201), 60, 3) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: bucket com 201 caracteres falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('bucket', 0, 3) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: janela 0 falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('bucket', -5, 3) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: janela negativa falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('bucket', 86401, 3) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: janela de 86401 s falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('bucket', NULL, 3) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: janela nula falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('bucket', 60, 0) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: p_max 0 falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('bucket', 60, -1) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: p_max negativo falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('bucket', 60, 100001) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: p_max 100001 falha com INVALID_INPUT'
);
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('bucket', 60, NULL) $$,
  'P0001', 'INVALID_INPUT', 'rate_limit_hit: p_max nulo falha com INVALID_INPUT'
);

-- Limites válidos ------------------------------------------------------------------------------------------------------
SELECT results_eq(
  $$ SELECT allowed FROM public.rate_limit_hit(repeat('a', 200), 60, 3) $$,
  $$ VALUES (true) $$,
  'rate_limit_hit: bucket com exatamente 200 caracteres é aceito'
);
SELECT results_eq(
  $$ SELECT allowed FROM public.rate_limit_hit('janela:maxima', 86400, 3) $$,
  $$ VALUES (true) $$,
  'rate_limit_hit: janela de 86400 s é aceita'
);
SELECT results_eq(
  $$ SELECT allowed FROM public.rate_limit_hit('max:maximo', 60, 100000) $$,
  $$ VALUES (true) $$,
  'rate_limit_hit: p_max 100000 é aceito'
);
SELECT results_eq(
  $$ SELECT allowed FROM public.rate_limit_hit('janela:minima', 1, 1) $$,
  $$ VALUES (true) $$,
  'rate_limit_hit: janela de 1 s e p_max 1 são aceitos'
);
SELECT results_eq(
  $$ SELECT allowed FROM public.rate_limit_hit('Login:IP.hmac_0-9:Z', 60, 3) $$,
  $$ VALUES (true) $$,
  'rate_limit_hit: bucket aceita letras, dígitos e os separadores : . _ -'
);

-- O mesmo bucket com janelas diferentes tem contadores independentes (a janela faz parte da chave).
-- Com 60 s e 120 s o início da janela coincide em metade dos horários: sem window_seconds na chave
-- os dois contadores se somariam.
SELECT results_eq(
  $$ SELECT allowed, retry_after_seconds FROM public.rate_limit_hit('dual:window', 60, 1) $$,
  $$ VALUES (true, 0) $$,
  'rate_limit_hit: mesmo bucket, janela de 60 s: o 1º hit (p_max = 1) é permitido'
);
SELECT results_eq(
  $$ SELECT allowed, retry_after_seconds BETWEEN 1 AND 60 FROM public.rate_limit_hit('dual:window', 60, 1) $$,
  $$ VALUES (false, true) $$,
  'rate_limit_hit: mesmo bucket, janela de 60 s: o 2º hit é negado'
);
SELECT results_eq(
  $$ SELECT allowed, retry_after_seconds FROM public.rate_limit_hit('dual:window', 120, 1) $$,
  $$ VALUES (true, 0) $$,
  'rate_limit_hit: mesmo bucket, janela de 120 s: o 1º hit é permitido (contador independente do de 60 s)'
);
SELECT results_eq(
  $$ SELECT allowed, retry_after_seconds BETWEEN 1 AND 120 FROM public.rate_limit_hit('dual:window', 120, 1) $$,
  $$ VALUES (false, true) $$,
  'rate_limit_hit: mesmo bucket, janela de 120 s: o 2º hit é negado'
);
RESET ROLE;

SELECT set_eq(
  $$ SELECT window_seconds, count FROM private.rate_limit_counters WHERE bucket = 'dual:window' $$,
  $$ VALUES (60, 2), (120, 2) $$,
  'rate_limit_hit: o mesmo bucket tem uma linha por janela, cada uma com o próprio contador'
);

-- O contador fica gravado no schema private ---------------------------------------------------------------------------------
SELECT is(
  (SELECT count FROM private.rate_limit_counters WHERE bucket = 'login:ip:a'),
  5,
  'rate_limit_hit: o contador de login:ip:a guarda os 5 hits, inclusive os negados'
);
SELECT is(
  (SELECT count(*)::int FROM private.rate_limit_counters WHERE bucket = 'login:ip:a'),
  1,
  'rate_limit_hit: os 5 hits caíram numa única janela (uma linha por bucket e janela)'
);
SELECT is(
  (SELECT (extract(epoch FROM window_start))::bigint % 60 FROM private.rate_limit_counters WHERE bucket = 'login:ip:a'),
  0::bigint,
  'rate_limit_hit: window_start está alinhado a múltiplos da janela'
);
SELECT is_empty(
  $$ SELECT bucket FROM private.rate_limit_counters WHERE bucket IN ('', 'bad bucket', 'a/b', 'bucket') $$,
  'rate_limit_hit: entradas inválidas não criam contador'
);

-- Quem não é service_role não executa ---------------------------------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('login:ip:a', 60, 3) $$,
  '42501', NULL, 'rate_limit_hit: CEO aal2 autenticado não executa'
);
SELECT tests.clear_authentication();

SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('login:ip:a', 60, 3) $$,
  '42501', NULL, 'rate_limit_hit: cliente autenticado não executa'
);
SELECT tests.clear_authentication();

SET LOCAL ROLE anon;
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('login:ip:a', 60, 3) $$,
  '42501', NULL, 'rate_limit_hit: anon não executa'
);
RESET ROLE;

SELECT * FROM finish();
ROLLBACK;
