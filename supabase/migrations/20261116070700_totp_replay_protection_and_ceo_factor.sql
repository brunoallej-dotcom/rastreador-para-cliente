-- Spec: docs/specs/client-delivery-tracker.md §3.4 (MFA TOTP), §3.5, SEC-11; threat model T-22 (F-21, F-24).
--
-- 1. Proteção contra replay de código TOTP (RFC 6238, seção 5.2). O Auth aceita o mesmo código mais
--    de uma vez dentro da janela de validade (período anterior, atual e próximo: até ~90 s). A
--    função `consume_totp_code` registra o código (como digest) antes de o app pedir a verificação
--    ao Auth, e recusa o segundo uso do mesmo código do mesmo fator dentro de 120 s.
-- 2. `private.is_ceo()` passa a exigir também um fator TOTP verificado. Antes só olhava a claim
--    `aal` do JWT: um fator removido deixava um JWT `aal2` com acesso de CEO (RLS e funções) até o
--    fim dos 15 min do token.

-- Códigos TOTP usados -------------------------------------------------------------------------
-- Guarda só o SHA-256 de `<factor_id>:<código>` (o app calcula; o código nunca chega ao banco). O
-- fator removido leva as linhas junto (ON DELETE CASCADE): o E-26 apaga o fator antigo.
CREATE TABLE private.totp_code_uses (
  factor_id   uuid NOT NULL REFERENCES auth.mfa_factors (id) ON DELETE CASCADE,
  code_digest bytea NOT NULL CHECK (octet_length(code_digest) = 32),
  used_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (factor_id, code_digest)
);
ALTER TABLE private.totp_code_uses ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON private.totp_code_uses FROM PUBLIC, anon, authenticated, service_role;

-- Consome um código TOTP: true na primeira vez, false se o mesmo código do mesmo fator já foi
-- consumido nos últimos 120 s. Só o dono do fator consome (ninguém queima os códigos de outro).
--  * sem principal ativo (sessão morta, perfil desativado) → 42501 FORBIDDEN;
--  * fator inexistente, de outro usuário ou que não é TOTP → P0001 NOT_FOUND (o app responde como
--    a um código errado: sem sondagem de ids de fator);
--  * a chave primária decide a corrida de duas requisições com o mesmo código: a segunda espera a
--    primeira e não atualiza a linha, então devolve false.
-- A janela de 120 s cobre os três períodos de 30 s que o Auth aceita, com folga.
CREATE FUNCTION public.consume_totp_code(p_factor_id uuid, p_code_digest bytea)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  c_reuse_window CONSTANT interval := interval '120 seconds';
  v_user_id      uuid := private.current_active_user_id();
  v_consumed     boolean;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;
  IF p_factor_id IS NULL OR p_code_digest IS NULL OR octet_length(p_code_digest) <> 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  PERFORM 1
     FROM auth.mfa_factors f
    WHERE f.id = p_factor_id
      AND f.user_id = v_user_id
      AND f.factor_type = 'totp';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  DELETE FROM private.totp_code_uses u
   WHERE u.factor_id = p_factor_id
     AND u.used_at < now() - c_reuse_window;

  BEGIN
    INSERT INTO private.totp_code_uses AS u (factor_id, code_digest, used_at)
    VALUES (p_factor_id, p_code_digest, now())
    ON CONFLICT (factor_id, code_digest)
    DO UPDATE SET used_at = now()
    WHERE u.used_at < now() - c_reuse_window
    RETURNING true INTO v_consumed;
  EXCEPTION WHEN foreign_key_violation THEN
    -- o fator foi apagado entre a checagem acima e o INSERT (um enroll em outra aba): é o mesmo
    -- NOT_FOUND de um fator inexistente, não uma falha do banco (que viraria 503)
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END;

  RETURN coalesce(v_consumed, false);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.consume_totp_code(uuid, bytea) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.consume_totp_code(uuid, bytea) TO authenticated;

-- CEO com MFA de verdade (SEC-11) -----------------------------------------------------------------
-- A claim `aal2` prova que a sessão passou por um segundo fator, mas o JWT dura até 15 min: sem
-- olhar o fator, remover o fator (ou a conta de TOTP) não tirava o acesso de CEO do token já
-- emitido. Agora o CEO também precisa de um fator TOTP verificado neste instante. CREATE OR
-- REPLACE preserva as permissões; elas são repetidas abaixo por clareza. As policies chamam
-- `(SELECT private.is_ceo())`, avaliado uma vez por comando, então o EXISTS extra (índice por
-- user_id em auth.mfa_factors) não vira custo por linha.
CREATE OR REPLACE FUNCTION private.is_ceo()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT coalesce(auth.jwt() ->> 'aal', '') = 'aal2'
     AND EXISTS (
       SELECT 1
         FROM public.profiles p
        WHERE p.id = private.current_active_user_id()
          AND p.role = 'ceo'
          AND EXISTS (
            SELECT 1
              FROM auth.mfa_factors f
             WHERE f.user_id = p.id
               AND f.factor_type = 'totp'
               AND f.status = 'verified'
          )
     );
$$;
REVOKE EXECUTE ON FUNCTION private.is_ceo() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION private.is_ceo() TO authenticated;
