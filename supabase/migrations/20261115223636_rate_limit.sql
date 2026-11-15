-- Spec: docs/specs/client-delivery-tracker.md §3.9, SEC-09; ADR 0004 — contadores de janela fixa
-- no Postgres. As chaves chegam como HMAC (o banco não guarda IP nem e-mail em claro). Só a
-- secret key (service_role) executa; a limpeza diária via pg_cron entra na Onda 11.

-- A janela faz parte da chave: o mesmo bucket com janelas diferentes nunca soma contadores.
CREATE TABLE private.rate_limit_counters (
  bucket         text NOT NULL CHECK (char_length(bucket) BETWEEN 1 AND 200),
  window_seconds integer NOT NULL CHECK (window_seconds BETWEEN 1 AND 86400),
  window_start   timestamptz NOT NULL,
  count          integer NOT NULL CHECK (count >= 0),
  PRIMARY KEY (bucket, window_seconds, window_start)
);
ALTER TABLE private.rate_limit_counters ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON private.rate_limit_counters FROM PUBLIC, anon, authenticated, service_role;

-- Índice: limpeza das janelas vencidas (pg_cron, Onda 11)
CREATE INDEX rate_limit_counters_window_start_idx ON private.rate_limit_counters (window_start);

CREATE FUNCTION public.rate_limit_hit(p_bucket text, p_window_seconds integer, p_max integer)
RETURNS TABLE (allowed boolean, retry_after_seconds integer)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
#variable_conflict use_column
DECLARE
  c_max_counter CONSTANT integer := 2147483647;
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
