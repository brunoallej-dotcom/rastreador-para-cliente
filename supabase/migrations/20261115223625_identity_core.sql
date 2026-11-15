-- Spec: docs/specs/client-delivery-tracker.md §3.4, §3.5, §4.1, §4.2 — tenant (clients), perfis,
-- helpers de RLS e criação de perfil a partir de auth.users (fail closed).
--
-- Textos visíveis (nomes, títulos) recusam caracteres de controle e de formatação Unicode
-- (categoria Cf: bidi override, zero-width, BOM, tags…) e separadores de linha/parágrafo, que
-- permitiriam falsificar ou esconder texto nos painéis (E-30):
--   [[:cntrl:]\u00AD\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u180E\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0001\U000E0020-\U000E007F]

-- Tabelas ------------------------------------------------------------------------
CREATE TABLE public.clients (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL
              CHECK (char_length(btrim(name)) BETWEEN 1 AND 160 AND name !~ '[[:cntrl:]\u00AD\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u180E\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0001\U000E0020-\U000E007F]'),
  archived_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.clients ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.clients FROM anon, authenticated;
GRANT SELECT ON public.clients TO authenticated;

-- Índice: paginação por cursor da lista de clientes do painel de CEO
CREATE INDEX clients_created_at_id_idx ON public.clients (created_at DESC, id);

CREATE TABLE public.profiles (
  id                   uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  role                 public.app_role NOT NULL,
  client_id            uuid REFERENCES public.clients (id) ON DELETE RESTRICT,
  display_name         text NOT NULL
                       CHECK (char_length(btrim(display_name)) BETWEEN 1 AND 120
                              AND display_name !~ '[[:cntrl:]\u00AD\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u180E\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0001\U000E0020-\U000E007F]'),
  must_change_password boolean NOT NULL DEFAULT true,
  disabled_at          timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT profiles_role_client_ck CHECK (
    (role = 'client' AND client_id IS NOT NULL) OR (role = 'ceo' AND client_id IS NULL)
  )
);
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.profiles FROM anon, authenticated;
-- Nem a secret key escreve perfis: papel e cliente só nascem no trigger de auth.users (AC-31).
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.profiles FROM service_role;
GRANT SELECT ON public.profiles TO authenticated;

-- Índice: listar os logins de um cliente (painel de CEO) e contar o limite de 10 por cliente
CREATE INDEX profiles_client_id_idx ON public.profiles (client_id) WHERE role = 'client';

-- Helpers (private, SECURITY DEFINER STABLE) --------------------------------------------

-- Sessão do JWT ainda existe em auth.sessions: logout, desativação e reset de senha apagam a
-- sessão e cortam o acesso na hora, mesmo com o JWT ainda válido (SEC-07).
CREATE FUNCTION private.session_is_alive()
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
  );
$$;
REVOKE EXECUTE ON FUNCTION private.session_is_alive() FROM PUBLIC, anon, authenticated;

-- Usuário da requisição, só com sessão viva e perfil ativo.
CREATE FUNCTION private.current_active_user_id()
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
     AND private.session_is_alive();
$$;
REVOKE EXECUTE ON FUNCTION private.current_active_user_id() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION private.current_active_user_id() TO authenticated;

-- Tenant da sessão (null para CEO, sessão morta ou perfil desativado).
CREATE FUNCTION private.current_client_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT p.client_id
    FROM public.profiles p
   WHERE p.id = private.current_active_user_id()
     AND p.role = 'client';
$$;
REVOKE EXECUTE ON FUNCTION private.current_client_id() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION private.current_client_id() TO authenticated;

-- CEO com MFA verificado (aal2), sessão viva e perfil ativo (SEC-11).
CREATE FUNCTION private.is_ceo()
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
     );
$$;
REVOKE EXECUTE ON FUNCTION private.is_ceo() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION private.is_ceo() TO authenticated;

-- X-Request-Id enviado pelo app ao PostgREST, saneado, para a auditoria (RNF-04).
CREATE FUNCTION private.request_id()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT CASE WHEN h.value ~ '^[A-Za-z0-9-]{1,64}$' THEN h.value END
    FROM (
      SELECT (NULLIF(current_setting('request.headers', true), ''))::json ->> 'x-request-id' AS value
    ) h;
$$;
REVOKE EXECUTE ON FUNCTION private.request_id() FROM PUBLIC, anon, authenticated;

-- Policies (somente leitura) --------------------------------------------------------
CREATE POLICY clients_select_own_tenant ON public.clients
  FOR SELECT TO authenticated
  USING (id = (SELECT private.current_client_id()));

CREATE POLICY clients_select_ceo ON public.clients
  FOR SELECT TO authenticated
  USING ((SELECT private.is_ceo()));

CREATE POLICY profiles_select_self ON public.profiles
  FOR SELECT TO authenticated
  USING (id = (SELECT private.current_active_user_id()));

CREATE POLICY profiles_select_ceo ON public.profiles
  FOR SELECT TO authenticated
  USING ((SELECT private.is_ceo()));

-- Linha de base da senha (troca obrigatória comprovada) ------------------------------------
-- Digest do hash da senha temporária (criação ou reset). mark_password_changed() só limpa a
-- pendência se o hash atual for diferente: chamar a RPC direto pelo PostgREST, sem trocar a
-- senha no Auth, não contorna a troca obrigatória (AC-05, SEC-10).
CREATE TABLE private.password_baselines (
  user_id     uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  hash_digest bytea NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE private.password_baselines ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON private.password_baselines FROM PUBLIC, anon, authenticated, service_role;

CREATE FUNCTION private.password_digest(p_user_id uuid)
RETURNS bytea
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT extensions.digest(coalesce(u.encrypted_password, '')::text, 'sha256')
    FROM auth.users u
   WHERE u.id = p_user_id;
$$;
REVOKE EXECUTE ON FUNCTION private.password_digest(uuid) FROM PUBLIC, anon, authenticated, service_role;

CREATE FUNCTION private.record_password_baseline(p_user_id uuid)
RETURNS void
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
  INSERT INTO private.password_baselines (user_id, hash_digest)
  SELECT p_user_id, private.password_digest(p_user_id)
   WHERE private.password_digest(p_user_id) IS NOT NULL
  ON CONFLICT (user_id) DO UPDATE
    SET hash_digest = EXCLUDED.hash_digest,
        recorded_at = now();
$$;
REVOKE EXECUTE ON FUNCTION private.record_password_baseline(uuid) FROM PUBLIC, anon, authenticated, service_role;

-- Perfil nasce com o usuário, na mesma transação (§3.4) --------------------------------
-- Lê SÓ raw_app_meta_data (gravável apenas com a secret key). raw_user_meta_data, que o
-- próprio usuário edita, nunca é lido. Papel, cliente ou nome inválidos → o usuário não é criado.
CREATE FUNCTION private.handle_new_auth_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  c_max_logins_per_client CONSTANT integer := 10;
  v_meta         jsonb := coalesce(NEW.raw_app_meta_data, '{}'::jsonb);
  v_role         text := v_meta ->> 'role';
  v_client_text  text := v_meta ->> 'client_id';
  v_display_name text := btrim(coalesce(v_meta ->> 'display_name', ''));
  v_client_id    uuid;
BEGIN
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

    -- Trava o cliente: serializa provisionamentos concorrentes (limite de logins, E-18).
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

  RETURN NEW;
END;
$$;
REVOKE EXECUTE ON FUNCTION private.handle_new_auth_user() FROM PUBLIC, anon, authenticated;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION private.handle_new_auth_user();
