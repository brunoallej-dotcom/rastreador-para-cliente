-- Spec: docs/specs/client-delivery-tracker.md §3.4, §3.5, §3.7 — principal da requisição e funções
-- de conta. Escrita só por SECURITY DEFINER com checagem de papel e alvo; auditoria na mesma
-- transação. Ator e tenant vêm de auth.uid(), nunca de parâmetro.

-- Principal da requisição (ou nenhuma linha) ------------------------------------------------
CREATE FUNCTION public.current_principal()
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
         CASE WHEN auth.jwt() ->> 'aal' = 'aal2' THEN 'aal2' ELSE 'aal1' END,
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

-- O próprio usuário, depois de trocar a senha no Auth --------------------------------------
-- Exige prova da troca (o hash atual difere da linha de base) e, para CEO com TOTP verificado,
-- sessão aal2 (POST /auth/password não libera VERIFY_MFA, §3.5). Limpa a pendência, renova a
-- linha de base e revoga as demais sessões do usuário (AC-06), mantendo a da requisição.
CREATE FUNCTION public.mark_password_changed()
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
     AND coalesce(auth.jwt() ->> 'aal', '') <> 'aal2'
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

-- Funções de CEO sobre logins de cliente --------------------------------------------------
-- Alvo inexistente, de CEO ou de outro papel → NOT_FOUND (nunca age sobre CEO, E-19).

CREATE FUNCTION public.record_account_provisioned(p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_client_id uuid;
BEGIN
  IF NOT private.is_ceo() THEN
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
END;
$$;
REVOKE EXECUTE ON FUNCTION public.record_account_provisioned(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.record_account_provisioned(uuid) TO authenticated;

-- Desativa (apaga as sessões) ou reativa. Só audita quando o estado muda.
CREATE FUNCTION public.set_account_disabled(p_user_id uuid, p_disabled boolean)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_client_id    uuid;
  v_was_disabled boolean;
BEGIN
  IF NOT private.is_ceo() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;
  IF p_disabled IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  SELECT p.client_id, p.disabled_at IS NOT NULL
    INTO v_client_id, v_was_disabled
    FROM public.profiles p
   WHERE p.id = p_user_id
     AND p.role = 'client'
     FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  UPDATE public.profiles
     SET disabled_at = CASE WHEN p_disabled THEN coalesce(disabled_at, now()) END,
         updated_at = now()
   WHERE id = p_user_id;

  IF p_disabled THEN
    DELETE FROM auth.sessions s WHERE s.user_id = p_user_id;
  END IF;

  IF v_was_disabled IS DISTINCT FROM p_disabled THEN
    PERFORM private.record_audit_event(
      'ceo',
      CASE WHEN p_disabled THEN 'account.disabled' ELSE 'account.enabled' END,
      'account', p_user_id, v_client_id, NULL
    );
  END IF;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.set_account_disabled(uuid, boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.set_account_disabled(uuid, boolean) TO authenticated;

-- Renomeia o login (PATCH …/users/{userId} com displayName).
CREATE FUNCTION public.set_account_display_name(p_user_id uuid, p_display_name text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_client_id uuid;
  v_name      text := btrim(p_display_name);
BEGIN
  IF NOT private.is_ceo() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;
  IF v_name IS NULL OR char_length(v_name) NOT BETWEEN 1 AND 120 OR v_name ~ '[[:cntrl:]\u00AD\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u180E\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0001\U000E0020-\U000E007F]' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
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
     SET display_name = v_name,
         updated_at = now()
   WHERE id = p_user_id;

  PERFORM private.record_audit_event('ceo', 'account.updated', 'account', p_user_id, v_client_id, NULL);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.set_account_display_name(uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.set_account_display_name(uuid, text) TO authenticated;

-- Depois do reset da senha no Auth: troca obrigatória no próximo login, nova linha de base da
-- senha temporária e sessões revogadas.
CREATE FUNCTION public.require_password_change(p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_client_id uuid;
BEGIN
  IF NOT private.is_ceo() THEN
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

  PERFORM private.record_audit_event('ceo', 'account.password_reset', 'account', p_user_id, v_client_id, NULL);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.require_password_change(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.require_password_change(uuid) TO authenticated;

-- Logins do cliente com e-mail e último acesso (auth.users não é exposto pelo PostgREST).
CREATE FUNCTION public.list_client_users(p_client_id uuid)
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
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
#variable_conflict use_column
BEGIN
  IF NOT private.is_ceo() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.clients c WHERE c.id = p_client_id) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  RETURN QUERY
    SELECT p.id, u.email::text, p.display_name, p.disabled_at, p.must_change_password,
           u.last_sign_in_at, p.created_at
      FROM public.profiles p
      JOIN auth.users u ON u.id = p.id
     WHERE p.client_id = p_client_id
       AND p.role = 'client'
     ORDER BY p.created_at, p.id;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.list_client_users(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.list_client_users(uuid) TO authenticated;
