-- Spec: docs/specs/client-delivery-tracker.md §3.4 (MFA TOTP), §3.5, §4.1, SEC-10, SEC-11, RF-04;
-- ADR 0013; threat model T-22 e §8 (F-41, F-50 b, F-60, F-61, F-63).
--
-- Parte A: elevação de CEO atestada pelo backend.
--   Quem tem a senha de um CEO e a publishable key chama o Auth direto e consegue uma sessão `aal2`,
--   sem passar por nenhum limite do BFF (5 / 5 min, 20 / dia, queima de código). Até aqui `is_ceo()`
--   aceitava essa sessão. Agora só vale como CEO a sessão que o backend ATESTOU, depois de o verify de
--   TOTP ter passado por ele. O atestado é gravado por `public.attest_mfa_session`, que só o
--   `service_role` executa e que revalida tudo em SQL (nada que vem do app é confiado).
--
--   Três registros privados (RLS ligado, sem policy, sem privilégio algum para os papéis da API):
--     * `private.mfa_backend_factors`: os fatores TOTP que o backend cadastrou (enroll). É a base da
--       correção de raiz do F-60 (o candidato do verify sem `factorId` só pode ser um fator do backend)
--       e do F-61 (um fator verificado que o backend nunca ativou não recebe atestado);
--     * `private.mfa_backend_challenges`: cada challenge que o backend criou, gravado ANTES de o Auth
--       verificar. A checagem do oráculo exclui os challenges do próprio backend, nunca compara IP (o IP
--       de saída da Vercel é compartilhado) e cobre um login legítimo concorrente em outro dispositivo;
--     * `private.mfa_session_attestations`: um atestado por sessão do Auth.
--
--   Oráculo (F-50 b): o Auth não tem proteção contra replay. Quem chuta o TOTP direto no Auth e acerta
--   deixa um challenge verificado que o backend não criou, e poderia reapresentar o código ao backend
--   enquanto ele ainda vale. O atestado é recusado quando o fator tem, nos últimos 120 s, um challenge
--   verificado fora do registro do backend. A janela é a mesma do `consume_totp_code`: o Auth aceita um
--   código por no máximo ~90 s depois de verificado (período anterior, atual e próximo).
--
-- Parte B: a senha temporária vale 72 h (F-41). `private.current_active_user_id()` devolve NULL
--   (sem principal) para o perfil com `must_change_password` cuja linha de base da senha temporária
--   (`private.password_baselines`, gravada na criação e no reset) é mais velha que o prazo. O login
--   então cai no mesmo caminho da conta desativada (401 genérico); um reset grava uma linha nova e o
--   prazo recomeça.
--
-- Comportamento do GoTrue local em que isto se apoia (verificado na Onda 6.1, anotado no ADR 0013):
--   * `auth.sessions.aal` existe e vira `aal2` na mesma linha (mesmo `id`) quando o verify passa; o
--     claim `session_id` do JWT é o `auth.sessions.id` e sobrevive ao refresh; o refresh mantém `aal2`;
--   * `auth.mfa_challenges` guarda `id`, `factor_id`, `created_at`, `verified_at` e `ip_address`; as
--     linhas ficam depois do verify (as verificadas e as não verificadas), e o mesmo código aceito duas
--     vezes deixa dois challenges verificados.

-- Registros privados -----------------------------------------------------------------------------

-- Fatores TOTP que o backend cadastrou. `activated_at` só é preenchido pela função de atestado, na
-- primeira vez em que ela prova que o backend (e só ele) ativou o fator. `enrolled_session_id` é só
-- para investigação (sem FK: a sessão some no logout e o registro fica).
CREATE TABLE private.mfa_backend_factors (
  factor_id               uuid PRIMARY KEY REFERENCES auth.mfa_factors (id) ON DELETE CASCADE,
  user_id                 uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  enrolled_session_id     uuid,
  enrolled_at             timestamptz NOT NULL DEFAULT now(),
  activated_at            timestamptz,
  activation_challenge_id uuid,
  CONSTRAINT mfa_backend_factors_activation_ck CHECK (
    (activated_at IS NULL) = (activation_challenge_id IS NULL)
  )
);
ALTER TABLE private.mfa_backend_factors ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON private.mfa_backend_factors FROM PUBLIC, anon, authenticated, service_role;

-- Índice: o verify sem factorId lista os fatores do usuário (list_backend_totp_factors) e o ON DELETE
-- CASCADE de auth.users
CREATE INDEX mfa_backend_factors_user_id_idx ON private.mfa_backend_factors (user_id);

-- Challenges que o backend criou. `factor_was_verified` guarda o estado do fator no momento em que o
-- backend registrou o challenge (antes do verify): é a prova de que um challenge pode ter sido a
-- ativação do fator. O challenge apagado pelo Auth leva a linha junto (ON DELETE CASCADE).
CREATE TABLE private.mfa_backend_challenges (
  challenge_id        uuid PRIMARY KEY REFERENCES auth.mfa_challenges (id) ON DELETE CASCADE,
  factor_id           uuid NOT NULL REFERENCES auth.mfa_factors (id) ON DELETE CASCADE,
  user_id             uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  factor_was_verified boolean NOT NULL,
  recorded_at         timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE private.mfa_backend_challenges ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON private.mfa_backend_challenges FROM PUBLIC, anon, authenticated, service_role;

-- Índice: o atestado compara os challenges verificados de um fator com os do backend, e o ON DELETE
-- CASCADE de auth.mfa_factors
CREATE INDEX mfa_backend_challenges_factor_id_idx ON private.mfa_backend_challenges (factor_id);

-- Um atestado por sessão do Auth (sessão apagada = atestado apagado). `challenge_id` não tem FK de
-- propósito: se o Auth apagasse o challenge, o CEO perderia a sessão sem motivo. O fator tem FK com
-- CASCADE: remover o fator derruba o atestado (F-24).
CREATE TABLE private.mfa_session_attestations (
  session_id   uuid PRIMARY KEY REFERENCES auth.sessions (id) ON DELETE CASCADE,
  user_id      uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  factor_id    uuid NOT NULL REFERENCES auth.mfa_factors (id) ON DELETE CASCADE,
  challenge_id uuid NOT NULL,
  attested_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE private.mfa_session_attestations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON private.mfa_session_attestations FROM PUBLIC, anon, authenticated, service_role;

-- Índice: o ON DELETE CASCADE de auth.users e a remoção de todas as sessões de um usuário
CREATE INDEX mfa_session_attestations_user_id_idx ON private.mfa_session_attestations (user_id);
-- Índice: o ON DELETE CASCADE de auth.mfa_factors (remover o fator derruba os atestados dele)
CREATE INDEX mfa_session_attestations_factor_id_idx ON private.mfa_session_attestations (factor_id);

-- Validade da senha temporária ----------------------------------------------------------------------
-- Prazo de uma senha temporária (criação ou reset): 72 h (decisão de 2026-11-16, F-41). Um lugar só;
-- mude junto com o ADR 0013 e a spec (SEC-10).
CREATE FUNCTION private.temporary_password_validity()
RETURNS interval
LANGUAGE sql
IMMUTABLE
SET search_path = ''
AS $$
  SELECT interval '72 hours';
$$;
REVOKE EXECUTE ON FUNCTION private.temporary_password_validity() FROM PUBLIC, anon, authenticated;

-- Usuário da requisição, só com sessão viva, perfil ativo e, se a senha ainda é temporária, dentro do
-- prazo. Sem linha de base da senha temporária o perfil com `must_change_password` também fica sem
-- principal (fail closed). Troca de senha e reset gravam uma linha de base nova (recorded_at = now()).
CREATE OR REPLACE FUNCTION private.current_active_user_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT p.id
    FROM public.profiles p
   WHERE p.id = auth.uid()
     AND p.disabled_at IS NULL
     AND private.session_is_alive()
     AND (
       NOT p.must_change_password
       OR EXISTS (
         SELECT 1
           FROM private.password_baselines b
          WHERE b.user_id = p.id
            AND b.recorded_at > now() - private.temporary_password_validity()
       )
     );
$$;
REVOKE EXECUTE ON FUNCTION private.current_active_user_id() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION private.current_active_user_id() TO authenticated;

-- Sessão atestada ----------------------------------------------------------------------------------
-- A sessão do JWT é `aal2` E tem um atestado do backend para este usuário, cujo fator TOTP ainda está
-- verificado. É a única definição de "aal2 de verdade" do banco: is_ceo(), current_principal() e
-- mark_password_changed() a usam. Um claim `aal2` sem atestado (obtido direto no Auth) não vale nada.
CREATE FUNCTION private.session_is_attested()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT coalesce(auth.jwt() ->> 'aal', '') = 'aal2'
     AND EXISTS (
       SELECT 1
         FROM private.mfa_session_attestations a
         JOIN auth.mfa_factors f ON f.id = a.factor_id
        WHERE a.session_id = CASE
                               WHEN auth.jwt() ->> 'session_id' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                               THEN (auth.jwt() ->> 'session_id')::uuid
                             END
          AND a.user_id = auth.uid()
          AND f.user_id = a.user_id
          AND f.factor_type = 'totp'
          AND f.status = 'verified'
     );
$$;
REVOKE EXECUTE ON FUNCTION private.session_is_attested() FROM PUBLIC, anon, authenticated;

-- CEO: papel `ceo`, sessão viva, perfil ativo e sessão ATESTADA (SEC-11). O atestado já exige o fator
-- TOTP (o que atestou a sessão) ainda verificado: remover o fator tira o acesso de CEO na hora, mesmo
-- com um JWT `aal2` vivo (F-24). As policies chamam `(SELECT private.is_ceo())`, avaliado uma vez por
-- comando. Toda função de CEO e toda policy de CEO passam por aqui: nenhuma outra olha o claim `aal`.
CREATE OR REPLACE FUNCTION private.is_ceo()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT private.session_is_attested()
     AND EXISTS (
       SELECT 1
         FROM public.profiles p
        WHERE p.id = private.current_active_user_id()
          AND p.role = 'ceo'
     );
$$;
REVOKE EXECUTE ON FUNCTION private.is_ceo() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION private.is_ceo() TO authenticated;

-- Principal: `aal` só é `aal2` com o atestado. Um CEO com `aal2` sem atestado vira `aal1` aqui, e o app
-- calcula a pendência `VERIFY_MFA` exatamente como faz para uma sessão `aal1`.
CREATE OR REPLACE FUNCTION public.current_principal()
RETURNS TABLE (
  user_id              uuid,
  role                 public.app_role,
  client_id            uuid,
  display_name         text,
  aal                  text,
  has_verified_totp    boolean,
  must_change_password boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT p.id,
         p.role,
         p.client_id,
         p.display_name,
         CASE WHEN private.session_is_attested() THEN 'aal2' ELSE 'aal1' END,
         EXISTS (
           SELECT 1
             FROM auth.mfa_factors f
            WHERE f.user_id = p.id
              AND f.factor_type = 'totp'
              AND f.status = 'verified'
         ),
         p.must_change_password
    FROM public.profiles p
   WHERE p.id = private.current_active_user_id();
$$;
REVOKE EXECUTE ON FUNCTION public.current_principal() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.current_principal() TO authenticated;

-- mark_password_changed(): igual à da Onda 2, com uma diferença. Um CEO com TOTP verificado precisa de
-- sessão ATESTADA (e não só de um claim `aal2`): o `aal2` obtido direto no Auth não troca a senha por aqui.
CREATE OR REPLACE FUNCTION public.mark_password_changed()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_user_id   uuid;
  v_role      public.app_role;
  v_client_id uuid;
BEGIN
  SELECT p.id, p.role, p.client_id
    INTO v_user_id, v_role, v_client_id
    FROM public.profiles p
   WHERE p.id = private.current_active_user_id()
     FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  IF v_role = 'ceo'
     AND NOT private.session_is_attested()
     AND EXISTS (
       SELECT 1
         FROM auth.mfa_factors f
        WHERE f.user_id = v_user_id
          AND f.factor_type = 'totp'
          AND f.status = 'verified'
     ) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM private.password_baselines b
     WHERE b.user_id = v_user_id
       AND b.hash_digest IS DISTINCT FROM private.password_digest(v_user_id)
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'PASSWORD_UNCHANGED';
  END IF;

  PERFORM private.record_password_baseline(v_user_id);

  UPDATE public.profiles
     SET must_change_password = false,
         updated_at = now()
   WHERE id = v_user_id;

  DELETE FROM auth.sessions s
   WHERE s.user_id = v_user_id
     AND s.id <> (auth.jwt() ->> 'session_id')::uuid;

  PERFORM private.record_audit_event(v_role, 'account.password_changed', 'account', v_user_id, v_client_id, NULL);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.mark_password_changed() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.mark_password_changed() TO authenticated;

-- Fatores do próprio usuário que o backend cadastrou ----------------------------------------------
-- O verify sem `factorId` resolve o candidato SÓ entre estes (F-60): um fator plantado direto no Auth
-- não aparece aqui e nunca torna o verify ambíguo. Só o próprio usuário, com a própria sessão
-- (nenhum client admin); devolve nada para quem não tem principal ativo.
CREATE FUNCTION public.list_backend_totp_factors()
RETURNS TABLE (factor_id uuid)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT b.factor_id
    FROM private.mfa_backend_factors b
   WHERE b.user_id = private.current_active_user_id()
   ORDER BY b.enrolled_at, b.factor_id;
$$;
REVOKE EXECUTE ON FUNCTION public.list_backend_totp_factors() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.list_backend_totp_factors() TO authenticated;

-- Funções do service_role (o app chama pelo client admin da infraestrutura de identidade) ------------
-- Nenhuma lê `auth.uid()`: o ator é o próprio app, e os ids vêm como parâmetro. Por isso cada uma
-- revalida tudo contra `auth.*` e confia em nada: dono, tipo, estado, sessão.

-- Registra um fator TOTP recém-criado pelo enroll do backend.
CREATE FUNCTION public.register_backend_totp_factor(p_user_id uuid, p_factor_id uuid, p_session_id uuid)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_user_id IS NULL OR p_factor_id IS NULL OR p_session_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  -- só CEO tem MFA (SEC-11); a sessão que cadastra é do próprio usuário
  PERFORM 1
     FROM public.profiles p
    WHERE p.id = p_user_id
      AND p.role = 'ceo'
      AND p.disabled_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  PERFORM 1
     FROM auth.sessions s
    WHERE s.id = p_session_id
      AND s.user_id = p_user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  -- o fator acabou de ser criado: do usuário, TOTP, ainda não verificado
  PERFORM 1
     FROM auth.mfa_factors f
    WHERE f.id = p_factor_id
      AND f.user_id = p_user_id
      AND f.factor_type = 'totp'
      AND f.status = 'unverified';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  BEGIN
    INSERT INTO private.mfa_backend_factors (factor_id, user_id, enrolled_session_id)
    VALUES (p_factor_id, p_user_id, p_session_id)
    ON CONFLICT (factor_id) DO NOTHING;
  EXCEPTION WHEN foreign_key_violation THEN
    -- o fator foi removido entre a checagem e o INSERT (outro enroll): é o NOT_FOUND de um fator que não existe
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.register_backend_totp_factor(uuid, uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.register_backend_totp_factor(uuid, uuid, uuid) TO service_role;

-- Registra um challenge que o backend acabou de criar no Auth, ANTES de ele ser respondido. Grava o
-- estado do fator agora: um challenge registrado com o fator ainda não verificado é o único que pode ter
-- sido a ativação. Não exige que o fator seja do backend: um fator plantado também é registrado, para o
-- atestado recusá-lo com alerta (F-61) em vez de a chamada falhar sem rastro.
CREATE FUNCTION public.record_backend_mfa_challenge(p_user_id uuid, p_factor_id uuid, p_challenge_id uuid)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  c_prune_after CONSTANT interval := interval '7 days';
  v_factor_status auth.factor_status;
BEGIN
  IF p_user_id IS NULL OR p_factor_id IS NULL OR p_challenge_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  SELECT f.status
    INTO v_factor_status
    FROM auth.mfa_factors f
   WHERE f.id = p_factor_id
     AND f.user_id = p_user_id
     AND f.factor_type = 'totp';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  -- o challenge existe e é DESTE fator (o app não escolhe um challenge qualquer)
  PERFORM 1
     FROM auth.mfa_challenges c
    WHERE c.id = p_challenge_id
      AND c.factor_id = p_factor_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  BEGIN
    INSERT INTO private.mfa_backend_challenges (challenge_id, factor_id, user_id, factor_was_verified)
    VALUES (p_challenge_id, p_factor_id, p_user_id, v_factor_status = 'verified')
    ON CONFLICT (challenge_id) DO NOTHING;
  EXCEPTION WHEN foreign_key_violation THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END;

  -- Limpeza oportunista, só deste fator e só depois da ativação: o oráculo olha 120 s, e a prova da
  -- ativação (challenge com o fator ainda não verificado) é guardada para sempre.
  DELETE FROM private.mfa_backend_challenges b
   WHERE b.factor_id = p_factor_id
     AND b.factor_was_verified
     AND b.recorded_at < now() - c_prune_after
     AND EXISTS (
       SELECT 1
         FROM private.mfa_backend_factors bf
        WHERE bf.factor_id = p_factor_id
          AND bf.activated_at IS NOT NULL
     );
END;
$$;
REVOKE EXECUTE ON FUNCTION public.record_backend_mfa_challenge(uuid, uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_backend_mfa_challenge(uuid, uuid, uuid) TO service_role;

-- Recusa de atestado: apaga TODAS as sessões do usuário (a senha e um código válido vazaram, ou o
-- estado do Auth não bate com o do backend) e deixa a trilha de auditoria. Devolve o motivo. É uma
-- função à parte porque a recusa é um RETORNO, não uma exceção: a exceção desfaria a auditoria e a
-- revogação. O motivo e o id do fator não são PII.
CREATE FUNCTION private.refuse_mfa_attestation(p_user_id uuid, p_factor_id uuid, p_reason text)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  DELETE FROM auth.sessions s WHERE s.user_id = p_user_id;

  PERFORM private.record_audit_event(
    NULL::public.app_role,
    'auth.mfa_attestation_refused',
    'account',
    p_user_id,
    NULL::uuid,
    NULL::uuid,
    jsonb_build_object('reason', p_reason, 'factor_id', p_factor_id)
  );

  RETURN p_reason;
END;
$$;
REVOKE EXECUTE ON FUNCTION private.refuse_mfa_attestation(uuid, uuid, text) FROM PUBLIC, anon, authenticated;

-- Atestado de sessão. O backend chama logo depois de um verify de TOTP que o Auth aceitou, com os ids
-- que ele tem. Devolve 'attested' ou o motivo da recusa (um valor do conjunto abaixo); só levanta
-- exceção para entrada nula (INVALID_INPUT).
--
-- Tudo é conferido aqui, contra `auth.*` e os registros do backend:
--   * a sessão existe, é do usuário e está em `aal2`; o usuário é um CEO ativo;
--   * o fator é do usuário, é TOTP e está verificado, e é um fator que o backend cadastrou;
--   * o challenge é deste fator, foi verificado há menos de 120 s e é um challenge do backend;
--   * oráculo: nenhum challenge verificado nos últimos 120 s foi criado fora do backend;
--   * ativação: um fator que o backend cadastrou só é "ativado pelo backend" se um challenge dele,
--     registrado quando o fator ainda não estava verificado, foi verificado, e nenhum challenge
--     verificado de fora do backend jamais existiu para ele. A ativação é derivada, então um atestado
--     que falhou por indisponibilidade depois de o Auth já ter ativado o fator se recupera no
--     próximo verify, sem trancar o CEO.
-- Qualquer recusa apaga todas as sessões do usuário e audita (`auth.mfa_attestation_refused`).
-- Não dá para transformar isto em negação de serviço contra um CEO sem um código TOTP verificado
-- direto no Auth: código errado não deixa challenge verificado.
CREATE FUNCTION public.attest_mfa_session(
  p_user_id      uuid,
  p_session_id   uuid,
  p_factor_id    uuid,
  p_challenge_id uuid
)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  c_oracle_window CONSTANT interval := interval '120 seconds';
  v_session_aal   auth.aal_level;
  v_factor_type   auth.factor_type;
  v_factor_status auth.factor_status;
  v_challenge_factor uuid;
  v_verified_at   timestamptz;
  v_activated_at  timestamptz;
  v_activation_challenge uuid;
BEGIN
  IF p_user_id IS NULL OR p_session_id IS NULL OR p_factor_id IS NULL OR p_challenge_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  -- usuário: CEO ativo
  PERFORM 1
     FROM public.profiles p
    WHERE p.id = p_user_id
      AND p.role = 'ceo'
      AND p.disabled_at IS NULL;
  IF NOT FOUND THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'not_ceo');
  END IF;

  -- sessão: do usuário e aal2 (o Auth a elevou)
  SELECT s.aal
    INTO v_session_aal
    FROM auth.sessions s
   WHERE s.id = p_session_id
     AND s.user_id = p_user_id;
  IF NOT FOUND THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'session_not_found');
  END IF;
  IF v_session_aal IS DISTINCT FROM 'aal2' THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'session_not_aal2');
  END IF;

  -- fator: do usuário, TOTP, verificado
  SELECT f.factor_type, f.status
    INTO v_factor_type, v_factor_status
    FROM auth.mfa_factors f
   WHERE f.id = p_factor_id
     AND f.user_id = p_user_id;
  IF NOT FOUND THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'factor_not_found');
  END IF;
  IF v_factor_type IS DISTINCT FROM 'totp' THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'factor_not_totp');
  END IF;
  IF v_factor_status IS DISTINCT FROM 'verified' THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'factor_not_verified');
  END IF;

  -- fator do backend (F-61: um fator verificado plantado direto no Auth nunca é atestado). A linha é
  -- travada: duas ativações concorrentes do mesmo fator se serializam.
  SELECT bf.activated_at
    INTO v_activated_at
    FROM private.mfa_backend_factors bf
   WHERE bf.factor_id = p_factor_id
     AND bf.user_id = p_user_id
     FOR UPDATE;
  IF NOT FOUND THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'factor_not_backend');
  END IF;

  -- challenge: deste fator, verificado agora há pouco, e criado pelo backend
  SELECT c.factor_id, c.verified_at
    INTO v_challenge_factor, v_verified_at
    FROM auth.mfa_challenges c
   WHERE c.id = p_challenge_id;
  IF NOT FOUND OR v_challenge_factor IS DISTINCT FROM p_factor_id THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'challenge_not_found');
  END IF;
  IF v_verified_at IS NULL THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'challenge_not_verified');
  END IF;
  IF v_verified_at <= now() - c_oracle_window THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'challenge_stale');
  END IF;
  PERFORM 1
     FROM private.mfa_backend_challenges b
    WHERE b.challenge_id = p_challenge_id
      AND b.factor_id = p_factor_id
      AND b.user_id = p_user_id;
  IF NOT FOUND THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'challenge_not_backend');
  END IF;

  -- oráculo (F-50 b): um código aceito direto no Auth, na janela do TOTP, pode ser o que o backend
  -- acabou de ver; o Auth não protege contra replay. Challenges do próprio backend (inclusive o de um
  -- login legítimo em outro dispositivo) nunca contam. O IP nunca entra na conta.
  IF EXISTS (
    SELECT 1
      FROM auth.mfa_challenges c
     WHERE c.factor_id = p_factor_id
       AND c.verified_at IS NOT NULL
       AND c.verified_at > now() - c_oracle_window
       AND NOT EXISTS (
         SELECT 1
           FROM private.mfa_backend_challenges b
          WHERE b.challenge_id = c.id
       )
  ) THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'oracle');
  END IF;

  -- ativação pelo backend, na primeira vez
  IF v_activated_at IS NULL THEN
    -- um challenge verificado que o backend não criou, em qualquer época, pode ter ativado o fator
    IF EXISTS (
      SELECT 1
        FROM auth.mfa_challenges c
       WHERE c.factor_id = p_factor_id
         AND c.verified_at IS NOT NULL
         AND NOT EXISTS (
           SELECT 1
             FROM private.mfa_backend_challenges b
            WHERE b.challenge_id = c.id
         )
    ) THEN
      RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'factor_not_activated_by_backend');
    END IF;

    -- o challenge do backend, registrado com o fator ainda não verificado, que foi verificado
    SELECT b.challenge_id
      INTO v_activation_challenge
      FROM private.mfa_backend_challenges b
      JOIN auth.mfa_challenges c ON c.id = b.challenge_id
     WHERE b.factor_id = p_factor_id
       AND b.user_id = p_user_id
       AND NOT b.factor_was_verified
       AND c.verified_at IS NOT NULL
     ORDER BY c.verified_at, b.challenge_id
     LIMIT 1;
    IF NOT FOUND THEN
      RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'factor_not_activated_by_backend');
    END IF;

    UPDATE private.mfa_backend_factors bf
       SET activated_at = now(),
           activation_challenge_id = v_activation_challenge
     WHERE bf.factor_id = p_factor_id;
  END IF;

  INSERT INTO private.mfa_session_attestations AS a (session_id, user_id, factor_id, challenge_id)
  VALUES (p_session_id, p_user_id, p_factor_id, p_challenge_id)
  ON CONFLICT (session_id) DO UPDATE
    SET factor_id = EXCLUDED.factor_id,
        challenge_id = EXCLUDED.challenge_id,
        attested_at = now()
    WHERE a.user_id = EXCLUDED.user_id;

  RETURN 'attested';
END;
$$;
REVOKE EXECUTE ON FUNCTION public.attest_mfa_session(uuid, uuid, uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.attest_mfa_session(uuid, uuid, uuid, uuid) TO service_role;
