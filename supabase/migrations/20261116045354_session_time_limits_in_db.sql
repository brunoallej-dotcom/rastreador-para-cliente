-- Spec: docs/specs/client-delivery-tracker.md SEC-07; ADR 0009 — a sessão dura no máximo 12 h e
-- acaba após 4 h sem uso. O Auth já aplica `[auth.sessions] timebox` e `inactivity_timeout`
-- (supabase/config.toml), mas só quando está configurado: no Supabase hospedado exigem o plano Pro e
-- só chegam ao projeto remoto na Onda 11. O banco repete os dois limites, para que valham desde já,
-- em todo ambiente, e para que nenhuma mudança de configuração do Auth os desligue em silêncio.
--
-- Os limites são os mesmos do ADR 0009 e de SESSION_COOKIE_MAX_AGE_SECONDS (src/shared/db/
-- session-cookies.ts): 12 horas desde a criação e 4 horas desde a última atividade. Mude os três
-- juntos.
--
-- `private.session_is_alive()` é a base de `current_active_user_id()`, `current_client_id()`,
-- `is_ceo()` e `current_principal()`: uma sessão vencida deixa de ter principal, a RLS nega tudo e a
-- API responde 401, mesmo com um JWT ainda válido (E-08). CREATE OR REPLACE preserva as permissões
-- (EXECUTE só para o dono e, via SECURITY DEFINER, para as funções que a chamam).

CREATE OR REPLACE FUNCTION private.session_is_alive()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM auth.sessions s
     WHERE s.id = CASE
                    WHEN auth.jwt() ->> 'session_id' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                    THEN (auth.jwt() ->> 'session_id')::uuid
                  END
       AND s.user_id = auth.uid()
       AND (s.not_after IS NULL OR s.not_after > now())
       -- ADR 0009: no máximo 12 h desde a criação (created_at NULL: sem prova de idade, nega)
       AND s.created_at > now() - interval '12 hours'
       -- ADR 0009: no máximo 4 h desde a última atividade, que é a mais recente de três marcas:
       --  * `refreshed_at`: `timestamp` SEM fuso, em UTC (AT TIME ZONE 'UTC' o converte). O GoTrue NÃO
       --    o grava em toda renovação (no Postgres local, 4 de 18 sessões renovadas o tinham), então
       --    sozinho derrubaria uma sessão em uso 4 h depois do login;
       --  * o `created_at` do refresh token mais novo da sessão: cada renovação rotaciona o token e
       --    cria um novo, e é a marca que o próprio GoTrue usa quando `refreshed_at` falta;
       --  * `created_at` da sessão, para a que nunca foi renovada.
       -- greatest() ignora as marcas nulas.
       AND greatest(
             s.refreshed_at AT TIME ZONE 'UTC',
             (SELECT max(rt.created_at) FROM auth.refresh_tokens rt WHERE rt.session_id = s.id),
             s.created_at
           ) > now() - interval '4 hours'
  );
$$;
REVOKE EXECUTE ON FUNCTION private.session_is_alive() FROM PUBLIC, anon, authenticated;
