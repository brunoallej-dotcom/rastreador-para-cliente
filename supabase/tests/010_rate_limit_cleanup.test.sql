-- public.rate_limit_hit: limpeza oportunista de janelas vencidas (spec §3.9, ADR 0004). Em cerca de 1%
-- das chamadas apaga, em lote limitado (500), janelas que começaram há mais de 48 h, sem tocar nos
-- contadores vivos nem mudar a decisão da chamada. A amostragem usa random(): o teste fixa a semente
-- com setseed(), então a sequência é a mesma em toda execução, e confere o efeito, não uma contagem
-- exata de chamadas.
BEGIN;
SELECT plan(16);

-- arrange (como postgres) ----------------------------------------------------------------------------------
-- 700 janelas de 60 s com 3 dias e uma janela de 86400 s com 49 h: todas vencidas e antigas.
INSERT INTO private.rate_limit_counters (bucket, window_seconds, window_start, count)
SELECT 'old:' || g, 60, now() - interval '3 days' - make_interval(secs => g), 5
  FROM generate_series(1, 700) g;
INSERT INTO private.rate_limit_counters (bucket, window_seconds, window_start, count)
VALUES ('old:long', 86400, now() - interval '49 hours', 9);
-- Vencidas pela própria janela, mas com menos de 48 h: o critério é conservador, ficam (inclusive
-- uma janela de 86400 s iniciada há 47 h, que venceu há 23 h).
INSERT INTO private.rate_limit_counters (bucket, window_seconds, window_start, count)
SELECT 'recent:' || g, 60, now() - interval '23 hours' - make_interval(secs => g), 5
  FROM generate_series(1, 3) g;
INSERT INTO private.rate_limit_counters (bucket, window_seconds, window_start, count)
VALUES ('recent:long', 86400, now() - interval '47 hours', 6);
-- Vivas: a janela atual de 3600 s, a atual de 60 s e uma de 86400 s iniciada há 2 h.
INSERT INTO private.rate_limit_counters (bucket, window_seconds, window_start, count)
VALUES ('live:a', 3600, to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600), 7),
       ('live:b', 60, to_timestamp(floor(extract(epoch FROM now()) / 60) * 60), 2),
       ('live:day', 86400, now() - interval '2 hours', 4);

SELECT is((SELECT count(*)::int FROM private.rate_limit_counters WHERE bucket LIKE 'old:%'), 701,
  'arrange: 701 janelas vencidas e antigas');

-- 3000 chamadas (50 buckets x 60 hits): com 1% de chance cada, a limpeza roda dezenas de vezes ---------------
SELECT setseed(0.42);
CREATE TEMP TABLE sizes (
  call_no int PRIMARY KEY, old int NOT NULL, allowed boolean NOT NULL, retry int NOT NULL
) ON COMMIT DROP;

DO $$
DECLARE
  v_call int := 0;
  v_allowed boolean;
  v_retry int;
BEGIN
  WHILE v_call < 3000 LOOP
    v_call := v_call + 1;
    SELECT h.allowed, h.retry_after_seconds INTO v_allowed, v_retry
      FROM public.rate_limit_hit('probe:' || (v_call % 50), 60, 100000) h;
    INSERT INTO sizes
    SELECT v_call, count(*)::int, v_allowed, v_retry
      FROM private.rate_limit_counters WHERE bucket LIKE 'old:%';
  END LOOP;
END
$$;

CREATE TEMP TABLE drops ON COMMIT DROP AS
SELECT call_no, lag(old, 1, 701) OVER (ORDER BY call_no) - old AS deleted FROM sizes;

SELECT is((SELECT min(old) FROM sizes), 0,
  'a limpeza oportunista apagou as 701 janelas vencidas e antigas');
SELECT ok((SELECT max(deleted) FROM drops) BETWEEN 1 AND 500,
  'cada limpeza apaga no máximo 500 linhas (o lote é limitado)');
SELECT is((SELECT deleted FROM drops WHERE deleted > 0 ORDER BY call_no LIMIT 1), 500,
  'com 701 janelas vencidas, a primeira limpeza apaga exatamente um lote cheio (500)');
SELECT ok((SELECT bool_and(allowed AND retry = 0) FROM sizes),
  'a limpeza não muda a decisão: as 3000 chamadas devolveram (permitido, retry 0), limpassem ou não');
SELECT ok((SELECT count(*) FROM drops WHERE deleted > 0) >= 2,
  '701 > 500: foram necessárias pelo menos duas limpezas');

-- Nada vivo é tocado e nenhuma decisão muda ------------------------------------------------------------------
SELECT is((SELECT count FROM private.rate_limit_counters WHERE bucket = 'live:a'), 7,
  'a janela viva de 3600 s continua com o contador intacto');
SELECT is((SELECT count FROM private.rate_limit_counters WHERE bucket = 'live:b'), 2,
  'a janela viva de 60 s continua com o contador intacto');
SELECT is((SELECT count FROM private.rate_limit_counters WHERE bucket = 'live:day'), 4,
  'a janela de 86400 s iniciada há 2 h continua com o contador intacto');
SELECT is((SELECT count(*)::int FROM private.rate_limit_counters WHERE bucket LIKE 'recent:%'), 4,
  'janelas com menos de 48 h não são apagadas, mesmo vencidas pela própria janela (inclui a de 86400 s iniciada há 47 h)');
SELECT ok(
  (SELECT bool_and(count = 60) AND count(*) = 50 FROM private.rate_limit_counters WHERE bucket LIKE 'probe:%'),
  'a limpeza não altera a contagem das chamadas: cada um dos 50 buckets contou exatamente 60 hits'
);
SELECT is((SELECT count(*)::int FROM private.rate_limit_counters), 57,
  'sobraram só as 4 recentes, as 3 vivas e as 50 de teste: nenhuma outra linha foi apagada');

-- Mesmas permissões, mesma disciplina de SECURITY DEFINER -----------------------------------------------------
SELECT is(
  has_function_privilege('anon', 'public.rate_limit_hit(text,integer,integer)', 'EXECUTE')
    OR has_function_privilege('authenticated', 'public.rate_limit_hit(text,integer,integer)', 'EXECUTE'),
  false,
  'AC-25: rate_limit_hit continua sem EXECUTE para anon e authenticated'
);
SELECT is(
  has_function_privilege('service_role', 'public.rate_limit_hit(text,integer,integer)', 'EXECUTE'),
  true,
  'rate_limit_hit continua executável pela secret key (service_role)'
);
SELECT is(
  (SELECT p.prosecdef AND coalesce(p.proconfig @> ARRAY['search_path=""'], false)
     FROM pg_proc p WHERE p.oid = 'public.rate_limit_hit(text,integer,integer)'::regprocedure),
  true,
  'AC-25: rate_limit_hit continua SECURITY DEFINER com search_path vazio'
);
SET LOCAL ROLE authenticated;
SELECT throws_ok(
  $$ SELECT * FROM public.rate_limit_hit('x:y', 60, 1) $$,
  '42501', NULL, 'AC-25: authenticated não executa rate_limit_hit'
);
RESET ROLE;

SELECT * FROM finish();
ROLLBACK;
