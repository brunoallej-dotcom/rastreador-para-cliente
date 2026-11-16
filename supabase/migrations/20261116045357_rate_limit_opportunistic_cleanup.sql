-- Spec: docs/specs/client-delivery-tracker.md §3.9; ADR 0004 — `private.rate_limit_counters` ganha
-- uma linha por (bucket, janela) e ninguém as apaga: um atacante que varie o sujeito (IPs, e-mails)
-- faz a tabela crescer sem limite. A limpeza diária por `pg_cron` entra na Onda 11; até lá,
-- `rate_limit_hit` apaga, de forma oportunista, janelas vencidas.
--
-- Mesma assinatura e mesmas permissões (CREATE OR REPLACE as preserva: EXECUTE só para
-- `service_role`). Continua SECURITY DEFINER com `search_path` vazio.
--
-- A limpeza:
--  - roda em cerca de 1% das chamadas (random() < 0.01), para não custar nada na maioria;
--  - apaga no máximo 500 linhas por vez, escolhidas pelo índice de `window_start`
--    (rate_limit_counters_window_start_idx) e apagadas pela chave primária;
--  - só apaga janelas com `window_start` anterior a 48 HORAS: a maior janela aceita é de 86400 s
--    (24 h), então toda linha com mais de 48 h venceu há mais de um dia e nenhum contador vivo é
--    tocado, nem por uma chamada em voo na virada da janela. O corte é em horas, que são absolutas:
--    `interval '1 day'` seria um dia de calendário no fuso da sessão (23 h na mudança de horário de
--    verão) e não deixaria folga sobre a janela máxima;
--  - usa FOR UPDATE SKIP LOCKED, para nunca esperar nem brigar com outra chamada;
--  - é "melhor esforço": se a limpeza falhar (statement_timeout, disco), a chamada ainda conta e
--    responde; o erro vira um WARNING no log do banco, não uma queda do limitador.

CREATE OR REPLACE FUNCTION public.rate_limit_hit(p_bucket text, p_window_seconds integer, p_max integer)
RETURNS TABLE (allowed boolean, retry_after_seconds integer)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
#variable_conflict use_column
DECLARE
  c_max_counter       CONSTANT integer := 2147483647;
  c_cleanup_chance    CONSTANT double precision := 0.01;
  c_cleanup_batch     CONSTANT integer := 500;
  c_cleanup_min_age   CONSTANT interval := interval '48 hours';
  v_now          timestamptz := now();
  v_window_start timestamptz;
  v_count        integer;
BEGIN
  IF p_bucket IS NULL OR char_length(p_bucket) NOT BETWEEN 1 AND 200 OR p_bucket !~ '^[A-Za-z0-9:._-]+$'
     OR p_window_seconds IS NULL OR p_window_seconds NOT BETWEEN 1 AND 86400
     OR p_max IS NULL OR p_max NOT BETWEEN 1 AND 100000 THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  v_window_start := to_timestamp(floor(extract(epoch FROM v_now) / p_window_seconds) * p_window_seconds);

  INSERT INTO private.rate_limit_counters AS c (bucket, window_seconds, window_start, count)
  VALUES (p_bucket, p_window_seconds, v_window_start, 1)
  ON CONFLICT (bucket, window_seconds, window_start)
  DO UPDATE SET count = least(c.count, c_max_counter - 1) + 1
  RETURNING c.count INTO v_count;

  -- Limpeza oportunista de janelas vencidas (ver o cabeçalho). Depois do INSERT, para a contagem
  -- desta chamada nunca esperar por ela.
  IF random() < c_cleanup_chance THEN
    BEGIN
      DELETE FROM private.rate_limit_counters d
       WHERE (d.bucket, d.window_seconds, d.window_start) IN (
         SELECT o.bucket, o.window_seconds, o.window_start
           FROM private.rate_limit_counters o
          WHERE o.window_start < v_now - c_cleanup_min_age
          ORDER BY o.window_start
          LIMIT c_cleanup_batch
            FOR UPDATE SKIP LOCKED
       );
    EXCEPTION WHEN OTHERS THEN
      RAISE WARNING 'rate_limit_hit: cleanup skipped (SQLSTATE %)', SQLSTATE;
    END;
  END IF;

  allowed := v_count <= p_max;
  retry_after_seconds := CASE
    WHEN v_count <= p_max THEN 0
    ELSE greatest(1, ceil(extract(epoch FROM (v_window_start + make_interval(secs => p_window_seconds) - v_now)))::integer)
  END;
  RETURN NEXT;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.rate_limit_hit(text, integer, integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.rate_limit_hit(text, integer, integer) TO service_role;
