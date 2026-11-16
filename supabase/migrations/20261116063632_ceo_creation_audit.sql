-- Spec: docs/specs/client-delivery-tracker.md §3.4, RF-14, SEC-16 — a conta de CEO só nasce pelo
-- script operacional (`pnpm ceo:create`, Auth Admin API), e esse é o evento mais sensível de conta
-- do sistema: a criação de um CEO passa a gravar `account.provisioned` na trilha de auditoria,
-- na mesma transação em que o usuário é criado.
--
-- O gatilho de perfil (`on_auth_user_created`) é um CONSTRAINT TRIGGER adiado: roda no COMMIT, na
-- transação do GoTrue, e relê a linha final de auth.users. A auditoria entra aí, depois do INSERT em
-- `profiles`: se ela falhar, o COMMIT falha e o usuário não é criado (fail closed, como o resto do
-- gatilho). O corpo da função é o da migration `profile_trigger_commit_time_check`, linha por
-- linha, mais o bloco do evento.
--
-- Sem ator: o GoTrue não carrega claims de usuário nesta transação, então `actor_id` (auth.uid()) e
-- `request_id` saem NULL, e o papel do ator também. Só o papel `ceo` grava evento: um login de
-- cliente é auditado por `record_account_provisioned()`, que um CEO chama depois de criá-lo; gravar
-- aqui também faria a idempotência dessa função recusar o provisionamento (INVALID_INPUT).

CREATE OR REPLACE FUNCTION private.handle_new_auth_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  c_max_logins_per_client CONSTANT integer := 10;
  v_meta         jsonb;
  v_role         text;
  v_client_text  text;
  v_display_name text;
  v_client_id    uuid;
BEGIN
  -- Roda no fim da transação: lê a linha como ela está agora, não como foi inserida.
  SELECT coalesce(u.raw_app_meta_data, '{}'::jsonb)
    INTO v_meta
    FROM auth.users u
   WHERE u.id = NEW.id;
  IF NOT FOUND THEN
    -- Usuário apagado na mesma transação em que foi criado: não há o que provisionar.
    RETURN NULL;
  END IF;

  v_role := v_meta ->> 'role';
  v_client_text := v_meta ->> 'client_id';
  v_display_name := btrim(coalesce(v_meta ->> 'display_name', ''));

  IF v_role IS NULL OR v_role NOT IN ('ceo', 'client') THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT', DETAIL = 'app_metadata.role';
  END IF;

  IF char_length(v_display_name) NOT BETWEEN 1 AND 120 OR v_display_name ~ '[[:cntrl:]\u00AD\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u180E\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0001\U000E0020-\U000E007F]' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT', DETAIL = 'app_metadata.display_name';
  END IF;

  IF v_role = 'client' THEN
    IF v_client_text IS NULL
       OR v_client_text !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT', DETAIL = 'app_metadata.client_id';
    END IF;
    v_client_id := v_client_text::uuid;

    -- Trava o cliente: serializa provisionamentos concorrentes (limite de logins, E-18). Com o
    -- trigger adiado a trava é pega no COMMIT e solta logo em seguida; quem espera vê o commit do outro.
    PERFORM 1 FROM public.clients c WHERE c.id = v_client_id FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
    END IF;
    IF EXISTS (SELECT 1 FROM public.clients c WHERE c.id = v_client_id AND c.archived_at IS NOT NULL) THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'CLIENT_ARCHIVED';
    END IF;
    IF (SELECT count(*) FROM public.profiles p WHERE p.client_id = v_client_id) >= c_max_logins_per_client THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'USER_LIMIT_REACHED';
    END IF;
  ELSIF v_client_text IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT', DETAIL = 'app_metadata.client_id';
  END IF;

  INSERT INTO public.profiles (id, role, client_id, display_name)
  VALUES (NEW.id, v_role::public.app_role, v_client_id, v_display_name);

  PERFORM private.record_password_baseline(NEW.id);

  -- RF-14: a conta de CEO é criada pelo Auth Admin API (o script `ceo:create`). Sem ator e sem
  -- request_id (ver o cabeçalho); o canal fica nos metadados.
  IF v_role = 'ceo' THEN
    PERFORM private.record_audit_event(
      NULL::public.app_role,
      'account.provisioned',
      'account',
      NEW.id,
      NULL::uuid,
      NULL::uuid,
      jsonb_build_object('role', 'ceo', 'channel', 'auth_admin')
    );
  END IF;

  RETURN NULL;
END;
$$;
REVOKE EXECUTE ON FUNCTION private.handle_new_auth_user() FROM PUBLIC, anon, authenticated;
