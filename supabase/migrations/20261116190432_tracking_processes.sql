-- Spec: docs/specs/client-delivery-tracker.md §3.6, §3.7, §3.7.2, §4.1 — escrita de processos
-- (Onda 8): único caminho de escrita de `public.processes` e `public.process_stages` para o app. As
-- tabelas, as constraints (I1, I2, I5 estruturais), as policies de leitura e o índice
-- `processes (client_id, created_at DESC, id)` já existem (Onda 2); aqui entram as duas funções de
-- CEO. `approve_current_stage` chega na Onda 9.
--
-- Textos: título do processo e nome e descrição da fase passam por `private.visible_text` (Onda 6),
-- o mesmo validador do `visibleText` do Zod (E-30). Os CHECKs das tabelas continuam mais fracos de
-- propósito, como última barreira.
--
-- Ambas as funções checam `private.is_ceo()` antes de qualquer trabalho com a entrada, devolvem a
-- linha de `public.processes` (o app lê o detalhe depois, com as fases, as aprovações e o cliente) e
-- gravam a auditoria na mesma transação, só quando algo muda de fato, sem título nem nome nos
-- metadados.

-- Cria o processo e as fases. `p_stages` nulo = template padrão; senão, um array JSON de 1 a 30
-- objetos `{"name": ..., "description": ...}` (nada além dessas duas chaves; `description` pode faltar
-- ou ser `null`). As posições são as do array, de 1 a n (I1); a fase 1 nasce `in_progress` junto com o
-- processo (I2); as demais, `pending`. Evento `process.created`.
-- O cliente é travado com `FOR NO KEY UPDATE`: criar um processo e arquivar o cliente se serializam, então
-- um processo nunca nasce num cliente que acabou de ser arquivado (E-16); `FOR NO KEY UPDATE` não
-- bloqueia quem só referencia o cliente por FK.
CREATE FUNCTION public.create_process(
  p_client_id uuid,
  p_title     text,
  p_stages    jsonb DEFAULT NULL
)
RETURNS public.processes
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  c_max_stages constant integer := 30;
  v_title      text;
  v_stage      jsonb;
  v_name       text;
  v_description text;
  v_names      text[] := ARRAY[]::text[];
  v_descriptions text[] := ARRAY[]::text[];
  v_archived_at timestamptz;
  v_row        public.processes;
BEGIN
  IF private.is_ceo() IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  v_title := private.visible_text(p_title, 160);
  IF v_title IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  IF p_stages IS NULL THEN
    -- Template padrão (Q-01). As posições do processo são as do array, contíguas de 1 a n, mesmo que o
    -- template tenha buracos.
    SELECT array_agg(t.name ORDER BY t.position), array_agg(t.description ORDER BY t.position)
      INTO v_names, v_descriptions
      FROM public.default_stage_template t;
    IF v_names IS NULL THEN
      -- Template vazio é defeito de migration, não entrada do CEO: sem código do catálogo (500).
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'TEMPLATE_EMPTY';
    END IF;
  ELSE
    -- I1: de 1 a 30 fases. O tamanho vem antes de tocar em qualquer elemento.
    IF jsonb_typeof(p_stages) <> 'array'
       OR jsonb_array_length(p_stages) NOT BETWEEN 1 AND c_max_stages THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
    END IF;

    FOR v_stage IN
      SELECT e.value FROM jsonb_array_elements(p_stages) WITH ORDINALITY AS e (value, ord) ORDER BY e.ord
    LOOP
      -- como o Zod `.strict()`: objeto, só `name` e `description`
      IF jsonb_typeof(v_stage) <> 'object'
         OR EXISTS (
           SELECT 1 FROM jsonb_object_keys(v_stage) AS k (key) WHERE k.key NOT IN ('name', 'description')
         )
         OR jsonb_typeof(v_stage -> 'name') IS DISTINCT FROM 'string' THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
      END IF;

      v_name := private.visible_text(v_stage ->> 'name', 120);
      IF v_name IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
      END IF;

      -- ausente ou null = sem descrição; texto = precisa ser texto visível (o app já tira o vazio)
      v_description := NULL;
      IF v_stage ? 'description' AND jsonb_typeof(v_stage -> 'description') <> 'null' THEN
        IF jsonb_typeof(v_stage -> 'description') <> 'string' THEN
          RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
        END IF;
        v_description := private.visible_text(v_stage ->> 'description', 2000);
        IF v_description IS NULL THEN
          RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
        END IF;
      END IF;

      v_names := array_append(v_names, v_name);
      v_descriptions := array_append(v_descriptions, v_description);
    END LOOP;
  END IF;

  SELECT c.archived_at
    INTO v_archived_at
    FROM public.clients c
   WHERE c.id = p_client_id
     FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;
  IF v_archived_at IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'CLIENT_ARCHIVED';
  END IF;

  INSERT INTO public.processes (client_id, title)
  VALUES (p_client_id, v_title)
  RETURNING * INTO v_row;

  INSERT INTO public.process_stages (process_id, position, name, description, status, started_at)
  SELECT v_row.id,
         s.ord::smallint,
         s.name,
         s.description,
         CASE WHEN s.ord = 1 THEN 'in_progress'::public.stage_status ELSE 'pending'::public.stage_status END,
         CASE WHEN s.ord = 1 THEN v_row.created_at END
    FROM unnest(v_names, v_descriptions) WITH ORDINALITY AS s (name, description, ord);

  PERFORM private.record_audit_event(
    'ceo', 'process.created', 'process', v_row.id, v_row.client_id, v_row.id
  );

  RETURN v_row;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.create_process(uuid, text, jsonb) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.create_process(uuid, text, jsonb) TO authenticated;

-- Renomeia e/ou cancela um processo ATIVO. `p_title` nulo = não renomeia; `p_cancel` nulo = não
-- cancela; `true` cancela; `false` e a chamada sem nenhuma das duas coisas são `INVALID_INPUT` (não há
-- caminho de volta, I4). Processo que não está `active` (concluído ou cancelado) recusa tudo, até um
-- renome para o mesmo título: `PROCESS_NOT_ACTIVE`. Cancelar congela as fases como estão (I4) e
-- preenche `cancelled_at`.
-- Só audita e só mexe em `version` e `updated_at` quando algo muda de fato: renomear para o mesmo
-- título (depois da normalização) devolve a linha como está. Renomear e cancelar na mesma chamada grava
-- dois eventos, nessa ordem, e soma 1 à versão. `FOR NO KEY UPDATE`: serializa com as outras escritas do
-- processo (a aprovação da Onda 9), sem bloquear quem só referencia o processo por FK.
CREATE FUNCTION public.update_process(
  p_process_id uuid,
  p_title      text DEFAULT NULL,
  p_cancel     boolean DEFAULT NULL
)
RETURNS public.processes
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_title      text;
  v_row        public.processes;
  v_renamed    boolean;
  v_cancelling boolean;
BEGIN
  IF private.is_ceo() IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  IF (p_title IS NULL AND p_cancel IS NULL) OR p_cancel IS FALSE THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;
  IF p_title IS NOT NULL THEN
    v_title := private.visible_text(p_title, 160);
    IF v_title IS NULL THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
    END IF;
  END IF;

  SELECT p.id, p.client_id, p.title, p.status, p.version, p.created_at, p.updated_at,
         p.completed_at, p.cancelled_at
    INTO v_row
    FROM public.processes p
   WHERE p.id = p_process_id
     FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;
  IF v_row.status <> 'active' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'PROCESS_NOT_ACTIVE';
  END IF;

  v_renamed := v_title IS NOT NULL AND v_title IS DISTINCT FROM v_row.title;
  v_cancelling := p_cancel IS TRUE;

  IF NOT v_renamed AND NOT v_cancelling THEN
    RETURN v_row;
  END IF;

  UPDATE public.processes p
     SET title = CASE WHEN v_renamed THEN v_title ELSE p.title END,
         status = CASE WHEN v_cancelling THEN 'cancelled'::public.process_status ELSE p.status END,
         cancelled_at = CASE WHEN v_cancelling THEN now() ELSE p.cancelled_at END,
         version = p.version + 1,
         updated_at = now()
   WHERE p.id = p_process_id
  RETURNING * INTO v_row;

  IF v_renamed THEN
    PERFORM private.record_audit_event(
      'ceo', 'process.updated', 'process', v_row.id, v_row.client_id, v_row.id,
      '{"fields":["title"]}'::jsonb
    );
  END IF;
  IF v_cancelling THEN
    PERFORM private.record_audit_event(
      'ceo', 'process.cancelled', 'process', v_row.id, v_row.client_id, v_row.id
    );
  END IF;

  RETURN v_row;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.update_process(uuid, text, boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.update_process(uuid, text, boolean) TO authenticated;
