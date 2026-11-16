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
-- Endurecimento da revisão da Onda 6.1 (ADR 0013, threat model F-64 a F-72):
--   * F-64: `private.mfa_first_activations`, sem FK para o fator, impede que quem apagou o fator do CEO
--     direto no Auth cadastre e ative o dele no lugar;
--   * F-65: a queima de código TOTP deixa de ser executável por `authenticated` (era um oráculo de
--     código pelo PostgREST) e passa ao `service_role`;
--   * F-66: só os sinais de ataque derrubam todas as sessões; corrida e inconsistência só recusam;
--   * F-67: o challenge registrado tem de ser novo e não verificado; a sessão tem de ter sido elevada
--     pelo fator atestado; um challenge atesta uma sessão só;
--   * F-71: a prova da ativação não depende de o Auth guardar as linhas de `mfa_challenges`;
--   * F-69: a migration para se existir CEO com fator verificado fora do registro;
--   * F-73: um gatilho em `auth.mfa_factors` grava a marca da primeira ativação e a PROVA da ativação
--     (o challenge que ativou, o instante e se foi do backend) NA TRANSAÇÃO em que o Auth ativa o fator,
--     sem depender de o atestado dar certo depois nem de o Auth guardar o challenge;
--   * F-74: o atestado que ativa o fator apaga as outras sessões do usuário na própria transação (F-20).
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
  -- A PROVA da ativação, gravada pelo gatilho `on_mfa_factor_verified` na transação em que o Auth
  -- marca o fator como verificado (F-73): o challenge verificado mais recente do fator, o instante em
  -- que foi verificado e se a ativação foi do backend (esse challenge foi registrado com o fator ainda
  -- não verificado e nenhum challenge verificado de fora do backend existe para o fator). NULL = o
  -- fator ainda não foi verificado, ou foi por um caminho que o gatilho não viu: nunca é atestado.
  proof_challenge_id      uuid,
  proof_verified_at       timestamptz,
  proof_by_backend        boolean,
  CONSTRAINT mfa_backend_factors_activation_ck CHECK (
    (activated_at IS NULL) = (activation_challenge_id IS NULL)
  )
);
ALTER TABLE private.mfa_backend_factors ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON private.mfa_backend_factors FROM PUBLIC, anon, authenticated, service_role;

-- Índice: o verify sem factorId lista os fatores do usuário (list_backend_totp_factors) e o ON DELETE
-- CASCADE de auth.users
CREATE INDEX mfa_backend_factors_user_id_idx ON private.mfa_backend_factors (user_id);

-- Marca de que o usuário JÁ teve um fator ativado (F-64). NÃO tem FK para o fator: apagar o fator (o
-- `DELETE /factors/{id}` do Auth, que uma `aal2` obtida direto no Auth consegue) leva o registro do
-- fator e os atestados pelo CASCADE, mas não esta linha. Com ela, nem o cadastro nem a ativação de um
-- fator NOVO passam pelo backend (`register_backend_totp_factor` e `attest_mfa_session` recusam com
-- `factor_reenrolled`): quem apagou o fator do CEO não consegue cadastrar o dele no lugar. Quem a grava
-- é o gatilho `on_mfa_factor_verified`, no instante em que o Auth ativa um fator do registro (F-73), e
-- só então: uma marca escrita cedo só bloqueia. `factor_id` diz QUAL fator a criou (sem FK): o atestado
-- do próprio fator marcado passa, o de qualquer outro é `factor_reenrolled`. Só o runbook de reset de
-- MFA (E-25, Onda 11) apaga a linha, por SQL, como operação manual, junto com os registros do usuário
-- (F-75). Nenhuma função da API a apaga.
CREATE TABLE private.mfa_first_activations (
  user_id            uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  factor_id          uuid NOT NULL,
  first_activated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE private.mfa_first_activations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON private.mfa_first_activations FROM PUBLIC, anon, authenticated, service_role;

-- Challenges que o backend criou. `factor_was_verified` guarda o estado do fator no momento em que o
-- backend registrou o challenge (antes do verify): é a prova de que um challenge pode ter sido a
-- ativação do fator. Sem FK para `auth.mfa_challenges` de propósito (F-71): se o Auth apagar o
-- challenge, a prova não some com ele (o instante da verificação fica no registro do fator, gravado
-- pelo gatilho). O fator apagado leva as linhas (CASCADE).
CREATE TABLE private.mfa_backend_challenges (
  challenge_id        uuid PRIMARY KEY,
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
-- propósito: se o Auth apagasse o challenge, o CEO perderia a sessão sem motivo. É UNIQUE: um
-- challenge atesta uma sessão só (o atestado de outra sessão com o mesmo challenge é recusado). O
-- fator tem FK com CASCADE: remover o fator derruba o atestado (F-24).
CREATE TABLE private.mfa_session_attestations (
  session_id   uuid PRIMARY KEY REFERENCES auth.sessions (id) ON DELETE CASCADE,
  user_id      uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  factor_id    uuid NOT NULL REFERENCES auth.mfa_factors (id) ON DELETE CASCADE,
  challenge_id uuid NOT NULL UNIQUE,
  attested_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE private.mfa_session_attestations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON private.mfa_session_attestations FROM PUBLIC, anon, authenticated, service_role;

-- Índice: o ON DELETE CASCADE de auth.users e a remoção de todas as sessões de um usuário
CREATE INDEX mfa_session_attestations_user_id_idx ON private.mfa_session_attestations (user_id);
-- Índice: o ON DELETE CASCADE de auth.mfa_factors (remover o fator derruba os atestados dele)
CREATE INDEX mfa_session_attestations_factor_id_idx ON private.mfa_session_attestations (factor_id);

-- Fatores que antecedem o registro (F-69) ----------------------------------------------------------
-- Não há backfill: ainda não existe ambiente hospedado com CEO, e o banco local é recriado. Um CEO
-- com fator TOTP verificado ANTES desta migration não tem ativação do backend registrada e ficaria
-- sem acesso (`factor_not_backend`). Se algum existir, a migration para: quem opera decide, para
-- cada CEO, se zera o fator (E-25) ou se registra a ativação à mão, e então aplica de novo.
DO $$
DECLARE
  v_orphans integer;
BEGIN
  SELECT count(*)
    INTO v_orphans
    FROM auth.mfa_factors f
    JOIN public.profiles p ON p.id = f.user_id
   WHERE p.role = 'ceo'
     AND f.factor_type = 'totp'
     AND f.status = 'verified'
     AND NOT EXISTS (
       SELECT 1 FROM private.mfa_backend_factors bf WHERE bf.factor_id = f.id
     );
  IF v_orphans > 0 THEN
    RAISE EXCEPTION
      'ceo_attestation: % CEO(s) have a verified TOTP factor that predates the backend registry; decide per CEO (reset the factor or register its activation by hand) before applying this migration',
      v_orphans;
  END IF;
END;
$$;

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

-- Gatilho de ativação (F-73) -------------------------------------------------------------------------
-- O Auth ativa um fator com `UPDATE auth.mfa_factors SET status = 'verified'`, na MESMA transação em
-- que marca o challenge como verificado (`challenge.Verify` vem antes do `UpdateStatus`, em
-- `verifyTOTPFactor`). Este gatilho roda nessa transação, para fatores que o backend cadastrou, e:
--   * grava a marca da primeira ativação do usuário (`mfa_first_activations`), com o fator: dali em
--     diante o F-64 vale mesmo que o atestado falhe (503, `session_not_found` forçado por um logout
--     global de quem tem a senha, `challenge_stale`...) e o CEO só volte a verificar depois;
--   * grava no registro do fator a PROVA da ativação, uma vez: o challenge verificado mais recente, o
--     instante dele e se a ativação foi do backend (esse challenge foi registrado com o fator ainda não
--     verificado, e nenhum challenge verificado de fora do backend existe para o fator).
-- O atestado confia só nas tabelas do backend para "ativado pelo backend": não relê `auth.mfa_challenges`
-- para isso, que o Auth hospedado pode não guardar. Gravar a marca de um fator ativado por outro
-- caminho (um chute certo direto no Auth no candidato do backend) também só bloqueia: falha segura.
-- Um fator que o backend não cadastrou (plantado) não passa por aqui. O gatilho não levanta erro por
-- dado inesperado (um erro derrubaria o verify do Auth, e o MFA com ele).
-- Precedente: `on_auth_user_created`, em `auth.users`. O suporte a gatilhos em `auth.mfa_factors` (e ao
-- REFERENCES para `auth.sessions` e `auth.mfa_factors`, das tabelas acima) no Supabase hospedado precisa
-- ser conferido na Onda 11.
CREATE FUNCTION private.snapshot_mfa_activation()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_user_id    uuid;
  v_challenge  uuid;
  v_verified   timestamptz;
  v_by_backend boolean;
BEGIN
  -- só fatores do backend; a linha é travada (a ativação e o atestado se serializam)
  SELECT bf.user_id
    INTO v_user_id
    FROM private.mfa_backend_factors bf
   WHERE bf.factor_id = NEW.id
     FOR UPDATE;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  INSERT INTO private.mfa_first_activations (user_id, factor_id)
  VALUES (v_user_id, NEW.id)
  ON CONFLICT (user_id) DO NOTHING;

  -- a prova: o challenge verificado mais recente é o que acabou de ativar o fator
  SELECT c.id, c.verified_at
    INTO v_challenge, v_verified
    FROM auth.mfa_challenges c
   WHERE c.factor_id = NEW.id
     AND c.verified_at IS NOT NULL
   ORDER BY c.verified_at DESC, c.id
   LIMIT 1;

  v_by_backend := v_challenge IS NOT NULL
    AND EXISTS (
      SELECT 1
        FROM private.mfa_backend_challenges b
       WHERE b.challenge_id = v_challenge
         AND b.factor_id = NEW.id
         AND NOT b.factor_was_verified
    )
    AND NOT EXISTS (
      SELECT 1
        FROM auth.mfa_challenges c
       WHERE c.factor_id = NEW.id
         AND c.verified_at IS NOT NULL
         AND NOT EXISTS (
           SELECT 1 FROM private.mfa_backend_challenges b WHERE b.challenge_id = c.id
         )
    );

  UPDATE private.mfa_backend_factors bf
     SET proof_challenge_id = v_challenge,
         proof_verified_at = v_verified,
         proof_by_backend = v_by_backend
   WHERE bf.factor_id = NEW.id
     AND bf.proof_by_backend IS NULL;

  RETURN NULL;
END;
$$;
REVOKE EXECUTE ON FUNCTION private.snapshot_mfa_activation() FROM PUBLIC, anon, authenticated;

CREATE TRIGGER on_mfa_factor_verified
  AFTER UPDATE OF status ON auth.mfa_factors
  FOR EACH ROW
  WHEN (NEW.status = 'verified' AND OLD.status IS DISTINCT FROM NEW.status)
  EXECUTE FUNCTION private.snapshot_mfa_activation();

-- Funções do service_role (o app chama pelo client admin da infraestrutura de identidade) ------------
-- Nenhuma lê `auth.uid()`: o ator é o próprio app, e os ids vêm como parâmetro. Por isso cada uma
-- revalida tudo contra `auth.*` e confia em nada: dono, tipo, estado, sessão.

-- Queima de código TOTP (F-21) agora é do service_role (F-65). A versão da Onda 5,
-- `consume_totp_code(p_factor_id, p_code_digest)`, era executável por `authenticated`: com uma sessão
-- só de senha, quem tem a publishable key mandava os 10^6 digests possíveis pelo PostgREST, sem limite
-- nenhum; um `false` revelava o código que o CEO acabou de usar (o Auth ainda o aceita por ~90 s) e
-- cada `true` queimava um código do CEO. A nova função faz o mesmo, só que o app a chama depois dos
-- limites da rota (5 / 5 min e 20 / dia), com o usuário que ele autenticou.
DROP FUNCTION public.consume_totp_code(uuid, bytea);

-- Queima um código TOTP: true na primeira vez, false se o mesmo código do mesmo fator já foi consumido
-- nos últimos 120 s. Só o dono do fator consome (ninguém queima os códigos de outro).
--  * usuário desativado ou que não existe → 42501 FORBIDDEN;
--  * fator inexistente, de outro usuário ou que não é TOTP → P0001 NOT_FOUND (o app responde como a um
--    código errado: sem sondagem de ids de fator);
--  * a chave primária decide a corrida de duas requisições com o mesmo código: a segunda espera a
--    primeira e não atualiza a linha, então devolve false.
-- A janela de 120 s cobre os três períodos de 30 s que o Auth aceita, com folga.
CREATE FUNCTION public.consume_totp_code(p_user_id uuid, p_factor_id uuid, p_code_digest bytea)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  c_reuse_window CONSTANT interval := interval '120 seconds';
  v_consumed     boolean;
BEGIN
  IF p_user_id IS NULL OR p_factor_id IS NULL OR p_code_digest IS NULL OR octet_length(p_code_digest) <> 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  PERFORM 1
     FROM public.profiles p
    WHERE p.id = p_user_id
      AND p.disabled_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  PERFORM 1
     FROM auth.mfa_factors f
    WHERE f.id = p_factor_id
      AND f.user_id = p_user_id
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
REVOKE EXECUTE ON FUNCTION public.consume_totp_code(uuid, uuid, bytea) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_totp_code(uuid, uuid, bytea) TO service_role;

-- Recusa de atestado ou de cadastro: devolve o motivo, audita sempre e, quando o motivo é SINAL DE
-- ATAQUE, apaga TODAS as sessões do usuário (a senha e um código válido vazaram, ou um fator ou
-- challenge que o backend não criou apareceu). A recusa é um RETORNO, não uma exceção: a exceção
-- desfaria a auditoria e a revogação. Os motivos de corrida ou de inconsistência (a sessão sumiu entre
-- o verify e o atestado, o challenge envelheceu...) recusam sem revogar: quem os provoca não precisa
-- de um código válido, e derrubar as sessões do CEO por uma corrida seria uma negação de serviço
-- barata (F-66). A auditoria leva `severity` (`alert` para os sinais de ataque, `warning` para os
-- demais) e `revoked`: o alerta sai do `audit_events`, que sobrevive a um 503 depois do COMMIT (F-68).
-- O motivo e o id do fator não são PII.
CREATE FUNCTION private.refuse_mfa_attestation(p_user_id uuid, p_factor_id uuid, p_reason text)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_attack boolean := p_reason IN (
    'oracle',
    'factor_not_backend',
    'factor_not_activated_by_backend',
    'challenge_not_backend',
    'challenge_not_found',
    'challenge_reused',
    'session_factor_mismatch',
    'factor_reenrolled'
  );
BEGIN
  IF v_attack THEN
    DELETE FROM auth.sessions s WHERE s.user_id = p_user_id;
  END IF;

  PERFORM private.record_audit_event(
    NULL::public.app_role,
    'auth.mfa_attestation_refused',
    'account',
    p_user_id,
    NULL::uuid,
    NULL::uuid,
    jsonb_build_object(
      'reason', p_reason,
      'factor_id', p_factor_id,
      'severity', CASE WHEN v_attack THEN 'alert' ELSE 'warning' END,
      'revoked', v_attack
    )
  );

  RETURN p_reason;
END;
$$;
REVOKE EXECUTE ON FUNCTION private.refuse_mfa_attestation(uuid, uuid, text) FROM PUBLIC, anon, authenticated;

-- Registra um fator TOTP recém-criado pelo enroll do backend. Devolve `registered`, ou
-- `factor_reenrolled` quando o usuário JÁ ativou um fator pelo backend e esse fator não existe mais
-- (F-64): quem apagou o fator do CEO direto no Auth não cadastra o dele no lugar. A recusa audita e
-- apaga todas as sessões do usuário (ver `refuse_mfa_attestation`). Só o reset de MFA do operador
-- (E-25) apaga a marca e reabre o cadastro.
CREATE FUNCTION public.register_backend_totp_factor(p_user_id uuid, p_factor_id uuid, p_session_id uuid)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_user_id IS NULL OR p_factor_id IS NULL OR p_session_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  -- só CEO tem MFA (SEC-11), e um CEO desativado não cadastra; a sessão que cadastra é do próprio usuário
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

  -- F-64: o primeiro fator ativado pelo backend já existiu; um fator novo só depois do reset do operador
  IF EXISTS (SELECT 1 FROM private.mfa_first_activations a WHERE a.user_id = p_user_id) THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'factor_reenrolled');
  END IF;

  BEGIN
    INSERT INTO private.mfa_backend_factors (factor_id, user_id, enrolled_session_id)
    VALUES (p_factor_id, p_user_id, p_session_id)
    ON CONFLICT (factor_id) DO NOTHING;
  EXCEPTION WHEN foreign_key_violation THEN
    -- o fator foi removido entre a checagem e o INSERT (outro enroll): é o NOT_FOUND de um fator que não existe
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END;

  RETURN 'registered';
END;
$$;
REVOKE EXECUTE ON FUNCTION public.register_backend_totp_factor(uuid, uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.register_backend_totp_factor(uuid, uuid, uuid) TO service_role;

-- Registra um challenge que o backend acabou de criar no Auth, ANTES de ele ser respondido. Só aceita
-- um challenge ainda NÃO verificado e criado há menos de 60 s (F-67): o app registra logo depois de
-- criá-lo, e um challenge que já foi verificado ou é velho não é um que o backend acabou de criar (ninguém
-- "adota" um challenge verificado direto no Auth para escapar do oráculo). Grava o estado do fator
-- agora: um challenge registrado com o fator ainda não verificado é o único que pode ter sido a
-- ativação. Não exige que o fator seja do backend: um fator plantado também é registrado, para o
-- atestado recusá-lo com alerta (F-61) em vez de a chamada falhar sem rastro.
CREATE FUNCTION public.record_backend_mfa_challenge(p_user_id uuid, p_factor_id uuid, p_challenge_id uuid)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  c_prune_after     CONSTANT interval := interval '7 days';
  c_challenge_fresh CONSTANT interval := interval '60 seconds';
  v_factor_status   auth.factor_status;
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

  -- o challenge existe, é DESTE fator, não foi verificado e acabou de ser criado
  PERFORM 1
     FROM auth.mfa_challenges c
    WHERE c.id = p_challenge_id
      AND c.factor_id = p_factor_id
      AND c.verified_at IS NULL
      AND c.created_at > now() - c_challenge_fresh;
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

-- Atestado de sessão. O backend chama logo depois de um verify de TOTP que o Auth aceitou, com os ids
-- que ele tem. Devolve `attested`, `attested_activated` (este atestado ativou o fator pelo backend:
-- o app derruba as outras sessões, F-20) ou o motivo da recusa (um valor do conjunto abaixo); só
-- levanta exceção para entrada nula (INVALID_INPUT).
--
-- Tudo é conferido aqui, contra `auth.*` e os registros do backend:
--   * o usuário é um CEO ativo;
--   * a sessão existe, é dele, está em `aal2` e foi elevada por ESTE fator (`auth.sessions.factor_id`);
--   * o fator é do usuário, é TOTP, está verificado e é um fator que o backend cadastrou;
--   * o challenge é desse fator, foi verificado há menos de 120 s e é um challenge do backend, e
--     nenhuma outra sessão foi atestada com ele;
--   * oráculo: nenhum challenge verificado nos últimos 120 s foi criado fora do backend;
--   * ativação: um fator que o backend cadastrou só é "ativado pelo backend" se a PROVA que o gatilho
--     `on_mfa_factor_verified` gravou no registro do fator (F-73) diz que foi: um challenge dele,
--     registrado quando o fator ainda não estava verificado, o verificou, e nenhum challenge
--     verificado de fora do backend existia. O atestado lê só as tabelas do backend para isso (F-71),
--     então um atestado que falhou por indisponibilidade depois de o Auth já ter ativado o fator se
--     recupera no próximo verify, sem trancar o CEO. E só acontece UMA vez por usuário
--     (`mfa_first_activations`, F-64): depois do primeiro fator, um fator novo (de quem apagou o
--     antigo no Auth) é recusado com `factor_reenrolled`. O atestado que ativa apaga as outras sessões
--     do usuário na própria transação (F-20, F-74).
-- Toda recusa audita (`auth.mfa_attestation_refused`) e as de sinal de ataque apagam todas as
-- sessões do usuário (ver `refuse_mfa_attestation`). Não dá para transformar isto em negação de
-- serviço contra um CEO sem um código TOTP verificado direto no Auth: código errado não deixa
-- challenge verificado.
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
  v_session_factor uuid;
  v_factor_type   auth.factor_type;
  v_factor_status auth.factor_status;
  v_challenge_factor uuid;
  v_verified_at   timestamptz;
  v_activated_at  timestamptz;
  v_proof_challenge uuid;
  v_proof_by_backend boolean;
  v_mark_factor   uuid;
  v_activated     boolean := false;
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

  -- sessão: do usuário, aal2 (o Auth a elevou) e elevada por este fator
  SELECT s.aal, s.factor_id
    INTO v_session_aal, v_session_factor
    FROM auth.sessions s
   WHERE s.id = p_session_id
     AND s.user_id = p_user_id;
  IF NOT FOUND THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'session_not_found');
  END IF;
  IF v_session_aal IS DISTINCT FROM 'aal2' THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'session_not_aal2');
  END IF;
  IF v_session_factor IS DISTINCT FROM p_factor_id THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'session_factor_mismatch');
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
  SELECT bf.activated_at, bf.proof_challenge_id, bf.proof_by_backend
    INTO v_activated_at, v_proof_challenge, v_proof_by_backend
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
  -- um challenge atesta uma sessão só (o UNIQUE da tabela também garante)
  IF EXISTS (
    SELECT 1
      FROM private.mfa_session_attestations a
     WHERE a.challenge_id = p_challenge_id
       AND a.session_id <> p_session_id
  ) THEN
    RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'challenge_reused');
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

  -- ativação pelo backend, na primeira vez do fator
  IF v_activated_at IS NULL THEN
    -- Trava o perfil: duas ativações do mesmo usuário (de fatores diferentes) se serializam, e a marca
    -- abaixo é decidida por uma só.
    PERFORM 1
       FROM public.profiles p
      WHERE p.id = p_user_id
        FOR NO KEY UPDATE;

    -- Só a prova que o gatilho gravou no registro vale (F-73): o fator foi ativado por um challenge do
    -- backend, registrado com o fator ainda não verificado, e nenhum challenge verificado de fora do
    -- backend existia. Sem prova (NULL: um caminho que o gatilho não viu) ou com prova de fora: recusa.
    IF v_proof_by_backend IS NOT TRUE THEN
      RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'factor_not_activated_by_backend');
    END IF;

    -- F-64: a marca do usuário é deste fator (o gatilho a gravou na ativação) ou não existe ainda; de
    -- outro fator, este é um fator NOVO (o antigo foi apagado) e é recusado. Nada inserido e marca de
    -- outro fator = recusa, nunca um silencioso "já existe".
    INSERT INTO private.mfa_first_activations (user_id, factor_id)
    VALUES (p_user_id, p_factor_id)
    ON CONFLICT (user_id) DO NOTHING
    RETURNING factor_id INTO v_mark_factor;
    IF v_mark_factor IS NULL THEN
      SELECT m.factor_id
        INTO v_mark_factor
        FROM private.mfa_first_activations m
       WHERE m.user_id = p_user_id;
      IF v_mark_factor IS DISTINCT FROM p_factor_id THEN
        RETURN private.refuse_mfa_attestation(p_user_id, p_factor_id, 'factor_reenrolled');
      END IF;
    END IF;

    UPDATE private.mfa_backend_factors bf
       SET activated_at = now(),
           activation_challenge_id = v_proof_challenge
     WHERE bf.factor_id = p_factor_id;

    -- F-20, F-74: a conta ganhou o segundo fator; uma sessão aberta só com a senha (ou um cookie
    -- roubado) não sobrevive a este momento. Dentro do atestado, na mesma transação, como o
    -- `mark_password_changed()` faz: o `signOut` do app era melhor esforço, fora da transação, e se
    -- falhasse nada o repetia.
    DELETE FROM auth.sessions s
     WHERE s.user_id = p_user_id
       AND s.id <> p_session_id;

    v_activated := true;
  END IF;

  INSERT INTO private.mfa_session_attestations AS a (session_id, user_id, factor_id, challenge_id)
  VALUES (p_session_id, p_user_id, p_factor_id, p_challenge_id)
  ON CONFLICT (session_id) DO UPDATE
    SET factor_id = EXCLUDED.factor_id,
        challenge_id = EXCLUDED.challenge_id,
        attested_at = now()
    WHERE a.user_id = EXCLUDED.user_id;

  RETURN CASE WHEN v_activated THEN 'attested_activated' ELSE 'attested' END;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.attest_mfa_session(uuid, uuid, uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.attest_mfa_session(uuid, uuid, uuid, uuid) TO service_role;
