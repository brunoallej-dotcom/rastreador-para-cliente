-- Spec: docs/specs/client-delivery-tracker.md §3.7, §4.1 — escrita de clientes (Onda 6): único
-- caminho de escrita de `public.clients` para o app. A tabela, as policies de leitura e o índice
-- `clients (created_at DESC, id)` já existem (Onda 2); aqui entram só as duas funções de CEO.
--
-- Nome do cliente: as mesmas regras do CHECK de `clients.name` e do Zod (`visibleText`, E-30):
-- NFC, sem espaços nas pontas, 1 a 160 caracteres e nenhum caractere de controle ou de formatação
-- Unicode (a classe é a de identity_core, com escapes `\uXXXX`/`\UXXXXXXXX`).
--
-- As duas funções devolvem a linha de `public.clients` (o app calcula os contadores pela leitura).
-- Auditoria na mesma transação, via `private.record_audit_event`, sem PII (o nome do cliente não
-- vai para os metadados): `client.created`, `client.updated`, `client.archived`,
-- `client.unarchived`.

-- Cria o cliente. Evento `client.created`.
CREATE FUNCTION public.create_client(p_name text)
RETURNS public.clients
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_name text := normalize(btrim(p_name), NFC);
  v_row  public.clients;
BEGIN
  IF NOT private.is_ceo() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  IF v_name IS NULL OR char_length(v_name) NOT BETWEEN 1 AND 160 OR v_name ~ '[[:cntrl:]\u00AD\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u180E\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0001\U000E0020-\U000E007F]' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  INSERT INTO public.clients (name)
  VALUES (v_name)
  RETURNING * INTO v_row;

  PERFORM private.record_audit_event('ceo', 'client.created', 'client', v_row.id, v_row.id, NULL);

  RETURN v_row;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.create_client(text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.create_client(text) TO authenticated;

-- Renomeia, arquiva ou desarquiva. NULL em `p_name` ou `p_archived` = "não mexe"; os dois NULL é
-- entrada inválida. Só audita e só toca `updated_at` quando algo muda de fato (como
-- `set_account_disabled`): renomear para o mesmo nome ou arquivar um cliente já arquivado devolve
-- a linha como está. `p_archived = true` mantém o `archived_at` original de um cliente que já
-- estava arquivado. Arquivar não desativa os logins (Q-08).
CREATE FUNCTION public.update_client(
  p_client_id uuid,
  p_name      text DEFAULT NULL,
  p_archived  boolean DEFAULT NULL
)
RETURNS public.clients
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_name            text := normalize(btrim(p_name), NFC);
  v_row             public.clients;
  v_renamed         boolean;
  v_archive_changed boolean;
BEGIN
  IF NOT private.is_ceo() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  IF p_name IS NULL AND p_archived IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;
  IF p_name IS NOT NULL
     AND (v_name IS NULL OR char_length(v_name) NOT BETWEEN 1 AND 160 OR v_name ~ '[[:cntrl:]\u00AD\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u180E\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0001\U000E0020-\U000E007F]') THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  SELECT c.id, c.name, c.archived_at, c.created_at, c.updated_at
    INTO v_row
    FROM public.clients c
   WHERE c.id = p_client_id
     FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  v_renamed := v_name IS NOT NULL AND v_name IS DISTINCT FROM v_row.name;
  v_archive_changed := p_archived IS NOT NULL AND p_archived IS DISTINCT FROM (v_row.archived_at IS NOT NULL);

  IF NOT v_renamed AND NOT v_archive_changed THEN
    RETURN v_row;
  END IF;

  UPDATE public.clients c
     SET name = CASE WHEN v_renamed THEN v_name ELSE c.name END,
         archived_at = CASE
                         WHEN NOT v_archive_changed THEN c.archived_at
                         WHEN p_archived THEN now()
                       END,
         updated_at = now()
   WHERE c.id = p_client_id
  RETURNING * INTO v_row;

  IF v_renamed THEN
    PERFORM private.record_audit_event(
      'ceo', 'client.updated', 'client', v_row.id, v_row.id, NULL, '{"fields":["name"]}'::jsonb
    );
  END IF;
  IF v_archive_changed THEN
    PERFORM private.record_audit_event(
      'ceo',
      CASE WHEN p_archived THEN 'client.archived' ELSE 'client.unarchived' END,
      'client', v_row.id, v_row.id, NULL
    );
  END IF;

  RETURN v_row;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.update_client(uuid, text, boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.update_client(uuid, text, boolean) TO authenticated;
