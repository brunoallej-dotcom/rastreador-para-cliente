-- Spec: docs/specs/client-delivery-tracker.md §3.4 (logins de cliente), §3.7.4, §3.10; threat model
-- F-92 (b), F-93 (Onda 10.1) — a auditoria do que o app faz no Auth, e as lacunas da auditoria do
-- provisionamento.
--
-- Parte A, F-92 (b): auditoria de INTENÇÃO antes de cada escrita no Auth.
--   Desativar, reativar e resetar um login escrevem em dois sistemas (o banco, por funções que auditam, e
--   o Auth Admin API, que não passa por função nenhuma). Uma escrita no Auth cujo passo do banco falha
--   depois só deixava o log. `begin_client_login_admin` grava, numa transação própria e ANTES da escrita no
--   Auth, que o CEO vai fazê-la; se ela falha, o app não toca no Auth. Os três nomes do que o app escreve
--   no Auth em nome de um login de cliente (a lista é fechada, e é a mesma do `AccountAdminGateway`):
--     'ban'          -> account.ban_intent            (desativar: segunda trava; recolocar o ban de uma
--                                                      reativação que falhou no banco)
--     'unban'        -> account.unban_intent          (reativar: tira o ban antes do banco)
--     'set_password' -> account.password_set_intent   (resetar: grava a senha temporária nova)
--   Criar e apagar a conta também são escritas no Auth, mas a criação ainda não tem id para auditar e a
--   exclusão é a compensação do provisionamento, que tem o evento próprio da Parte B.
--   São eventos internos da auditoria (`audit_events` só é lida por CEO atestado, e nenhum DTO do contrato
--   os lista). Sem PII: o login é o `resource_id`, e os metadados levam só a palavra da ação.
--
-- Parte B, F-93: as lacunas da auditoria do provisionamento.
--   (1) `record_account_provisioned` devolve a linha do login (as colunas de `list_client_users`): o app
--       deixa de reler a lista depois do registro, e a releitura deixa de poder falhar depois dele e forçar a
--       compensação. Muda o tipo de retorno, então a função antiga é apagada e criada de novo (nome, assinatura
--       de entrada e privilégios iguais).
--   (2) `record_account_provision_reverted`: o app a chama ANTES de apagar a conta que acabou de criar (a
--       compensação de E-23 e de E-50). Sem ela a conta apagada deixava um `account.provisioned` sem fim, e o
--       log era o único rastro. Só vale para um login que ninguém usou (senha temporária pendente e nenhum
--       acesso): reverter o provisionamento de uma conta em uso seria um registro falso. Grava uma vez só.
--   (3) `require_password_change` (o reset) faz o registro tardio de `account.provisioned` quando o login
--       nunca o teve: é a recuperação de uma conta órfã (E-53, `provision_orphaned` e `provision_answer_lost`),
--       que só é entregue pelo reset. O evento leva `{"late": true}` nos metadados e vem ANTES do
--       `account.password_reset`, na mesma transação.

-- A. Auditoria de intenção ---------------------------------------------------------------------------------------
-- Grava a intenção de uma escrita no Auth sobre um login de cliente, depois de conferir que quem chama é
-- CEO atestado, que a ação é uma das três e que o login é do cliente informado e tem papel `client` (um CEO,
-- um login de outro cliente e um id inexistente são o mesmo NOT_FOUND, E-19). Não muda estado: só grava o
-- evento, uma linha por chamada (a intenção de cada tentativa fica no registro, e uma repetição é outra
-- tentativa).
CREATE FUNCTION public.begin_client_login_admin(p_client_id uuid, p_user_id uuid, p_action text)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF private.is_ceo() IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  IF p_client_id IS NULL OR p_user_id IS NULL OR p_action IS NULL
     OR p_action NOT IN ('ban', 'unban', 'set_password') THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  PERFORM 1
     FROM public.profiles p
    WHERE p.id = p_user_id
      AND p.role = 'client'
      AND p.client_id = p_client_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  PERFORM private.record_audit_event(
    'ceo',
    CASE p_action
      WHEN 'ban' THEN 'account.ban_intent'
      WHEN 'unban' THEN 'account.unban_intent'
      ELSE 'account.password_set_intent'
    END,
    'account', p_user_id, p_client_id, NULL,
    jsonb_build_object('action', p_action)
  );
END;
$$;
REVOKE EXECUTE ON FUNCTION public.begin_client_login_admin(uuid, uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.begin_client_login_admin(uuid, uuid, text) TO authenticated;

-- B1. record_account_provisioned devolve a linha do login ---------------------------------------------------------
-- Mesmas regras da versão da Onda 2 (CEO atestado, alvo `client`, um registro por login: o segundo é
-- INVALID_INPUT), mais a linha do login, com as colunas e a ordem de `list_client_users`, lida depois do
-- registro, na mesma transação.
DROP FUNCTION public.record_account_provisioned(uuid);
CREATE FUNCTION public.record_account_provisioned(p_user_id uuid)
RETURNS TABLE (
  user_id              uuid,
  email                text,
  display_name         text,
  disabled_at          timestamptz,
  must_change_password boolean,
  last_sign_in_at      timestamptz,
  created_at           timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
#variable_conflict use_column
DECLARE
  v_client_id uuid;
BEGIN
  IF private.is_ceo() IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  SELECT p.client_id INTO v_client_id
    FROM public.profiles p
   WHERE p.id = p_user_id
     AND p.role = 'client'
     FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  -- Idempotência: um login é provisionado uma única vez (auditoria não enganosa).
  IF EXISTS (
    SELECT 1
      FROM public.audit_events e
     WHERE e.resource_id = p_user_id
       AND e.action = 'account.provisioned'
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  PERFORM private.record_audit_event('ceo', 'account.provisioned', 'account', p_user_id, v_client_id, NULL);

  RETURN QUERY
    SELECT p.id, u.email::text, p.display_name, p.disabled_at, p.must_change_password,
           u.last_sign_in_at, p.created_at
      FROM public.profiles p
      JOIN auth.users u ON u.id = p.id
     WHERE p.id = p_user_id;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.record_account_provisioned(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.record_account_provisioned(uuid) TO authenticated;

-- B2. A compensação do provisionamento deixa rastro -----------------------------------------------------------------
-- Chamada pelo app ANTES de apagar no Auth a conta que ele acabou de criar (e que o profile trigger já
-- transformou em perfil): depois da exclusão o perfil não existe mais, e esta função não teria o que conferir.
-- O motivo é uma de duas palavras fechadas (as do `ProvisionTakeBackReason` do app). Só um login que ninguém
-- usou pode ser revertido; uma segunda chamada para o mesmo login não grava outro evento.
CREATE FUNCTION public.record_account_provision_reverted(p_user_id uuid, p_reason text)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_client_id uuid;
BEGIN
  IF private.is_ceo() IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  IF p_user_id IS NULL OR p_reason IS NULL OR p_reason NOT IN ('record_failed', 'answer_lost') THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  SELECT p.client_id INTO v_client_id
    FROM public.profiles p
    JOIN auth.users u ON u.id = p.id
   WHERE p.id = p_user_id
     AND p.role = 'client'
     AND p.must_change_password
     AND u.last_sign_in_at IS NULL
     FOR UPDATE OF p;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM public.audit_events e
     WHERE e.resource_id = p_user_id
       AND e.action = 'account.provision_reverted'
  ) THEN
    RETURN;
  END IF;

  PERFORM private.record_audit_event(
    'ceo', 'account.provision_reverted', 'account', p_user_id, v_client_id, NULL,
    jsonb_build_object('reason', p_reason)
  );
END;
$$;
REVOKE EXECUTE ON FUNCTION public.record_account_provision_reverted(uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.record_account_provision_reverted(uuid, text) TO authenticated;

-- B3. O reset registra o provisionamento que faltou ---------------------------------------------------------------------
-- Igual à da Onda 2, mais o registro tardio: um login que nunca teve `account.provisioned` (a conta órfã
-- que o app criou e não conseguiu registrar nem apagar, E-53) ganha o evento no reset que a entrega, com
-- `{"late": true}`, antes do `account.password_reset` e na mesma transação.
CREATE OR REPLACE FUNCTION public.require_password_change(p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_client_id uuid;
BEGIN
  IF private.is_ceo() IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  SELECT p.client_id INTO v_client_id
    FROM public.profiles p
   WHERE p.id = p_user_id
     AND p.role = 'client'
     FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  UPDATE public.profiles
     SET must_change_password = true,
         updated_at = now()
   WHERE id = p_user_id;

  PERFORM private.record_password_baseline(p_user_id);

  DELETE FROM auth.sessions s WHERE s.user_id = p_user_id;

  IF NOT EXISTS (
    SELECT 1
      FROM public.audit_events e
     WHERE e.resource_id = p_user_id
       AND e.action = 'account.provisioned'
  ) THEN
    PERFORM private.record_audit_event(
      'ceo', 'account.provisioned', 'account', p_user_id, v_client_id, NULL,
      '{"late": true}'::jsonb
    );
  END IF;

  PERFORM private.record_audit_event('ceo', 'account.password_reset', 'account', p_user_id, v_client_id, NULL);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.require_password_change(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.require_password_change(uuid) TO authenticated;
