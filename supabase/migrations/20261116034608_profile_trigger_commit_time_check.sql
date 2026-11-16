-- Spec: docs/specs/client-delivery-tracker.md §3.4 — o perfil nasce com o usuário, na mesma transação,
-- a partir de raw_app_meta_data (fail closed). Correção da Onda 2, descoberta na Onda 3 contra o
-- Auth real.
--
-- Problema: `auth.admin.createUser({ app_metadata })` do GoTrue faz INSERT em auth.users com
-- raw_app_meta_data = {"provider":"email","providers":["email"]} e só DEPOIS, na mesma transação,
-- grava o app_metadata recebido (UPDATE). O trigger AFTER INSERT imediato da Onda 2 só enxergava
-- o primeiro estado, sem papel, e derrubava TODA criação de usuário pela Admin API
-- ("Database error creating new user"). Os testes pgTAP da Onda 2 inserem direto em auth.users com o
-- app_metadata já completo e por isso não pegaram.
--
-- Correção: o trigger vira um CONSTRAINT TRIGGER adiado (DEFERRABLE INITIALLY DEFERRED). Ele roda
-- no COMMIT e relê a linha de auth.users (a versão do INSERT, que NEW carrega, é a velha). Tudo
-- continua na mesma transação e fail closed: papel, cliente ou nome inválido derrubam o COMMIT, e o
-- usuário não é criado. A regra continua só no INSERT: mudar app_metadata depois não promove ninguém
-- (AC-31).

DROP TRIGGER on_auth_user_created ON auth.users;

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

  RETURN NULL;
END;
$$;
REVOKE EXECUTE ON FUNCTION private.handle_new_auth_user() FROM PUBLIC, anon, authenticated;

CREATE CONSTRAINT TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION private.handle_new_auth_user();
