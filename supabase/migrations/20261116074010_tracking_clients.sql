-- Spec: docs/specs/client-delivery-tracker.md §3.7, §3.7.1, §4.1 — escrita de clientes (Onda 6):
-- único caminho de escrita de `public.clients` para o app. A tabela, as policies de leitura e o
-- índice `clients (created_at DESC, id)` já existem (Onda 2); aqui entram o validador de texto
-- visível e as duas funções de CEO.
--
-- Nome do cliente: as mesmas regras do Zod (`visibleText`, E-30), todas num lugar só,
-- `private.visible_text`, que as Ondas 8 e 9 (título do processo, nome e descrição da fase)
-- reutilizam. O CHECK de `clients.name` (Onda 2) é mais fraco de propósito e continua como última
-- barreira; a função é quem decide.
--
-- As duas funções devolvem a linha de `public.clients` (o app calcula os contadores pela leitura).
-- Auditoria na mesma transação, via `private.record_audit_event`, sem PII (o nome do cliente não
-- vai para os metadados): `client.created`, `client.updated`, `client.archived`,
-- `client.unarchived`.

-- Validador de texto visível -------------------------------------------------------------------
-- Devolve o texto normalizado ou NULL quando a entrada não vale. Faz o que o Zod faz, na mesma
-- ordem: (1) NFC; (2) tira as pontas com o conjunto de espaços do `String.prototype.trim` do
-- JavaScript (espaço, tabulações, quebras de linha, NBSP, U+1680, U+2000 a U+200A, U+2028, U+2029,
-- U+202F, U+205F, U+3000 e o BOM U+FEFF), e não só o U+0020 do `btrim` padrão; (3) conta em
-- caracteres (code points), de 1 a `p_max`; (4) recusa caractere de controle ou de formatação
-- Unicode (a classe de identity_core, E-30); (5) recusa os "fillers" invisíveis que não são
-- controle nem formatação (Hangul U+115F, U+1160, U+3164, U+FFA0, Khmer U+17B4, U+17B5 e o braille
-- em branco U+2800); (6) exige ao menos uma letra ou um número (`[[:alnum:]]`, que só é Unicode
-- se o locale do banco for: o pgTAP confere com nomes em japonês e em grego).
-- A entrada acima de 16 KiB (o limite de corpo da API, SEC-17) é recusada antes de qualquer
-- trabalho. IMMUTABLE: o resultado só depende da entrada (o locale é fixo por banco).
-- É chamada só por funções SECURITY DEFINER do mesmo dono; nenhum papel da API a executa.
CREATE FUNCTION private.visible_text(p text, p_max integer)
RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = ''
AS $$
  SELECT CASE
           WHEN p_max IS NULL OR char_length(s.t) NOT BETWEEN 1 AND p_max THEN NULL
           WHEN s.t ~ '[[:cntrl:]\u00AD\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u180E\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0001\U000E0020-\U000E007F]' THEN NULL
           WHEN s.t ~ U&'[\115F\1160\17B4\17B5\2800\3164\FFA0]' THEN NULL
           WHEN s.t !~ '[[:alnum:]]' THEN NULL
           ELSE s.t
         END
    FROM (
      SELECT btrim(
               normalize(p, NFC),
               U&'\0009\000A\000B\000C\000D\0020\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000\FEFF'
             ) AS t
       WHERE p IS NOT NULL AND octet_length(p) <= 16384
    ) s
$$;
REVOKE EXECUTE ON FUNCTION private.visible_text(text, integer) FROM PUBLIC, anon, authenticated;

-- Cria o cliente. Evento `client.created`.
CREATE FUNCTION public.create_client(p_name text)
RETURNS public.clients
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_name text;
  v_row  public.clients;
BEGIN
  IF private.is_ceo() IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  v_name := private.visible_text(p_name, 160);
  IF v_name IS NULL THEN
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
-- `set_account_disabled`): renomear para o mesmo nome (depois da normalização) ou arquivar um
-- cliente já arquivado devolve a linha como está. `p_archived = true` mantém o `archived_at`
-- original de um cliente que já estava arquivado. Arquivar não desativa os logins (Q-08).
-- `FOR NO KEY UPDATE`: serializa com as outras escritas do cliente e com o gatilho de perfil
-- (`FOR UPDATE`), mas não trava quem só referencia o cliente por FK (processos, perfis).
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
  v_name            text;
  v_row             public.clients;
  v_renamed         boolean;
  v_archive_changed boolean;
BEGIN
  IF private.is_ceo() IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  IF p_name IS NULL AND p_archived IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;
  IF p_name IS NOT NULL THEN
    v_name := private.visible_text(p_name, 160);
    IF v_name IS NULL THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
    END IF;
  END IF;

  SELECT c.id, c.name, c.archived_at, c.created_at, c.updated_at
    INTO v_row
    FROM public.clients c
   WHERE c.id = p_client_id
     FOR NO KEY UPDATE;
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
