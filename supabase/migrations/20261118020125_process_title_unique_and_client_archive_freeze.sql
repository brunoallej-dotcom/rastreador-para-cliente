-- Spec: docs/specs/client-delivery-tracker.md §3.7, §3.7.2, §3.7.3, §4.3, E-96 a E-102 — Onda 10.2, duas decisões de
-- produto do usuário (2026-11-17):
--   F-80 (Q-14): título de processo único entre os processos ATIVOS de um mesmo cliente. Antes, um `POST` repetido
--     (duplo clique, retry depois de um 503 já gravado) criava um segundo processo. Agora o banco recusa o segundo
--     título: `PROCESS_TITLE_TAKEN` (`P0001`), que o app mapeia para 409 `CONFLICT`.
--   F-87 (Q-13): cliente arquivado congela os processos. `approve_current_stage` e `update_process` (renomear e
--     cancelar) respondem `CLIENT_ARCHIVED` (`P0001`, 422) para o processo de um cliente arquivado.
-- Mudam três funções: `create_process`, `update_process` e `approve_current_stage` (CREATE OR REPLACE: mesma
-- assinatura, mesmo dono, mesmos privilégios, reafirmados no fim). Os testes estão no pgTAP 022.
--
-- F-80, a chave do título. É a MESMA de `clients_active_name_key` (20261116150822_client_name_unique.sql), com o
-- `client_id` na frente: `lower(normalize(title, NFKC))`, sem as marcas de variação invisíveis (U+034F, U+180B a
-- U+180D, U+180F, U+FE00 a U+FE0F, U+E0100 a U+E01EF) e com cada sequência de espaços reduzida a um. As mesmas razões
-- valem: o NFKC junta as formas de compatibilidade; o `lower` do locale do banco não dobra "ß" e "ss" (o Postgres 17
-- não tem `casefold()`) e só dobra letras fora do ASCII se o locale for Unicode; as funções da expressão são
-- IMMUTABLE; e depois de um upgrade do ICU ou maior do Postgres é preciso `REINDEX INDEX
-- public.processes_client_active_title_key`. O pgTAP 022 confere o `lower()` com letras acentuadas, como o 014.
-- O que o título de outro cliente faz: nada (a chave leva o `client_id`). Um processo `completed` ou `cancelled`
-- sai do índice (predicado `status = 'active'`), então o título dele pode ser reusado.
--
-- Esta migration FALHA se algum banco já tem dois processos ativos de um mesmo cliente com a mesma chave: renomeie
-- ou cancele um deles (pelo app) e aplique de novo. Não existe ambiente hospedado ainda, então é aceitável; o seed
-- local e as fixtures dos testes não repetem título num cliente.

-- Índice único parcial: título de processo único entre os ativos de um cliente. Caso de uso: `create_process`, e
-- `update_process` ao renomear; a violação vira 409 `CONFLICT` (E-96 a E-98). Concluir ou cancelar tira a linha do
-- índice e libera o título.
CREATE UNIQUE INDEX processes_client_active_title_key ON public.processes (
  client_id,
  (regexp_replace(
     regexp_replace(
       lower(normalize(title, NFKC)),
       U&'[\034F\180B-\180F\FE00-\FE0F\+0E0100-\+0E01EF]', '', 'g'),
     U&'[ \1680]+', ' ', 'g'))
) WHERE status = 'active';
COMMENT ON INDEX public.processes_client_active_title_key IS
  'Caso de uso: título de processo único entre os processos ativos de um cliente (create_process, update_process ao renomear; 409 CONFLICT, F-80). Chave: client_id e lower(normalize(title, NFKC)) sem marcas de variação invisíveis e com espaços repetidos reduzidos a um.';

-- Cria o processo e as fases. `p_stages` nulo = template padrão; senão, um array JSON de 1 a 30
-- objetos `{"name": ..., "description": ...}` (nada além dessas duas chaves; `description` pode faltar
-- ou ser `null`). As posições são as do array, de 1 a n (I1); a fase 1 nasce `in_progress` junto com o
-- processo (I2); as demais, `pending`. Evento `process.created`.
-- O cliente é travado com `FOR NO KEY UPDATE`: criar um processo e arquivar o cliente se serializam, então
-- um processo nunca nasce num cliente que acabou de ser arquivado (E-16); `FOR NO KEY UPDATE` não
-- bloqueia quem só referencia o cliente por FK. Duas criações para o mesmo cliente também se serializam aí.
--
-- Título único (F-80): quem decide é o índice, não uma consulta prévia. A violação do NOSSO índice, pelo esquema,
-- pela tabela e pelo nome do constraint, vira `PROCESS_TITLE_TAKEN` (sem DETAIL, HINT nem o texto do erro original,
-- que traz o título normalizado); qualquer outra violação sobe como está (23505 bruto). A recusa vem do `INSERT`,
-- antes das fases e da auditoria, e desfaz a transação inteira: nenhum evento, nenhuma fase.
CREATE OR REPLACE FUNCTION public.create_process(
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
  v_schema     text;
  v_table      text;
  v_constraint text;
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

  BEGIN
    INSERT INTO public.processes (client_id, title)
    VALUES (p_client_id, v_title)
    RETURNING * INTO v_row;
  EXCEPTION WHEN unique_violation THEN
    GET STACKED DIAGNOSTICS v_schema = SCHEMA_NAME, v_table = TABLE_NAME, v_constraint = CONSTRAINT_NAME;
    IF v_schema IS DISTINCT FROM 'public'
       OR v_table IS DISTINCT FROM 'processes'
       OR v_constraint IS DISTINCT FROM 'processes_client_active_title_key' THEN
      RAISE;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'PROCESS_TITLE_TAKEN';
  END;

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
-- título (depois da normalização) devolve a linha como está, e uma chamada assim nunca dá
-- `PROCESS_TITLE_TAKEN`. Renomear e cancelar na mesma chamada grava dois eventos, nessa ordem, e soma 1
-- à versão.
--
-- Cliente arquivado (F-87): o processo dele não muda, nem para renomear nem para cancelar: `CLIENT_ARCHIVED`,
-- sem gravar nada. A precedência é: papel, entrada, processo inexistente (`NOT_FOUND`), cliente arquivado
-- (`CLIENT_ARCHIVED`), processo que não está ativo (`PROCESS_NOT_ACTIVE`) e, no renome, título em uso.
--
-- Ordem de trava, de pai para filho: cliente (`FOR SHARE`), processo (`FOR NO KEY UPDATE`). O `client_id` do
-- processo é lido ANTES, sem trava (nenhuma função o escreve), para o cliente ser travado primeiro:
--   * `FOR SHARE` no cliente conflita com o `FOR NO KEY UPDATE` de `update_client` (arquivar) e de `create_process`,
--     e não com outro `FOR SHARE`. Um arquivamento em andamento faz esta função esperar o COMMIT dele e ler o
--     `archived_at` gravado (READ COMMITTED reavalia a linha travada). Um `JOIN` que lesse o `archived_at` na mesma
--     consulta que trava o processo NÃO fecharia a janela: depois de esperar a trava do processo, a reavaliação só
--     refaz a linha travada, e o cliente seria o do começo da consulta.
--   * É também a convenção única do módulo: de pai para filho (cliente, processo, fase) em toda função de escrita. Não
--     há ciclo de espera: quem segura o cliente em modo EXCLUSIVO (`update_client`, `create_process`, o gatilho do
--     perfil) nunca espera por processo nem por fase, e quem segura o processo já passou pelo cliente. O único ciclo
--     possível é o dos renomes cruzados, abaixo (F-123). Nenhuma função pede `FOR SHARE` e depois `FOR NO KEY UPDATE`
--     na mesma linha de cliente.
-- A trava do cliente que não acha a linha é `NOT_FOUND` (falha fechada: a chave estrangeira é `ON DELETE RESTRICT`, então
-- hoje não acontece, mas um cliente que sumiu nunca é lido como "não arquivado"). A trava do processo confere o
-- `client_id` lido; se o processo sumiu ou trocou de cliente nesse intervalo (nunca acontece pelas funções), é
-- `NOT_FOUND`.
--
-- Título único (F-80): como em `create_process`, a violação do NOSSO índice vira `PROCESS_TITLE_TAKEN` e as outras
-- sobem cruas. O conflito vale pelo estado FINAL da linha: renomear e cancelar na mesma chamada não disputa o título
-- (o processo cancelado sai do índice) e renomear para outra grafia do próprio título não conflita com a própria linha.
-- Dois renomes que se cruzam (P1 para o título do P2 e P2 para o do P1) esperam um pelo índice do outro: o Postgres
-- derruba uma das transações (40P01), que o app responde 503; a outra termina em `PROCESS_TITLE_TAKEN`.
CREATE OR REPLACE FUNCTION public.update_process(
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
  v_title       text;
  v_row         public.processes;
  v_client_id   uuid;
  v_archived_at timestamptz;
  v_renamed     boolean;
  v_cancelling  boolean;
  v_schema      text;
  v_table       text;
  v_constraint  text;
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

  -- 1. O cliente do processo, lido sem trava; processo inexistente: NOT_FOUND.
  SELECT p.client_id
    INTO v_client_id
    FROM public.processes p
   WHERE p.id = p_process_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  -- 2. O cliente, travado ANTES do processo (de pai para filho), e o `archived_at` já com a trava.
  SELECT c.archived_at
    INTO v_archived_at
    FROM public.clients c
   WHERE c.id = v_client_id
     FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  -- 3. O processo, com a mesma trava de `approve_current_stage` (as duas se serializam).
  SELECT p.id, p.client_id, p.title, p.status, p.version, p.created_at, p.updated_at,
         p.completed_at, p.cancelled_at
    INTO v_row
    FROM public.processes p
   WHERE p.id = p_process_id
     AND p.client_id = v_client_id
     FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;
  IF v_archived_at IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'CLIENT_ARCHIVED';
  END IF;
  IF v_row.status <> 'active' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'PROCESS_NOT_ACTIVE';
  END IF;

  v_renamed := v_title IS NOT NULL AND v_title IS DISTINCT FROM v_row.title;
  v_cancelling := p_cancel IS TRUE;

  IF NOT v_renamed AND NOT v_cancelling THEN
    RETURN v_row;
  END IF;

  BEGIN
    UPDATE public.processes p
       SET title = CASE WHEN v_renamed THEN v_title ELSE p.title END,
           status = CASE WHEN v_cancelling THEN 'cancelled'::public.process_status ELSE p.status END,
           cancelled_at = CASE WHEN v_cancelling THEN now() ELSE p.cancelled_at END,
           version = p.version + 1,
           updated_at = now()
     WHERE p.id = p_process_id
    RETURNING * INTO v_row;
  EXCEPTION WHEN unique_violation THEN
    GET STACKED DIAGNOSTICS v_schema = SCHEMA_NAME, v_table = TABLE_NAME, v_constraint = CONSTRAINT_NAME;
    IF v_schema IS DISTINCT FROM 'public'
       OR v_table IS DISTINCT FROM 'processes'
       OR v_constraint IS DISTINCT FROM 'processes_client_active_title_key' THEN
      RAISE;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'PROCESS_TITLE_TAKEN';
  END;

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

-- Conclui a fase atual, grava a aprovação e inicia a próxima fase (ou conclui o processo, se era a última).
-- As regras são as da transição pura `approveCurrentStage` do agregado (`tracking/domain/process.ts`), na
-- mesma ordem de precedência: papel (42501), entrada (`INVALID_INPUT`), processo (`NOT_FOUND`), cliente arquivado
-- (`CLIENT_ARCHIVED`, F-87), `status` (`PROCESS_NOT_ACTIVE`, que vence um `STALE_STAGE`: E-03) e só então a fase
-- esperada (`STALE_STAGE`). O erro `STALE_STAGE` não leva a fase atual no DETAIL: o app a lê de novo (§3.7.3), e a
-- mensagem do banco fica fixa.
--
-- Ordem de trava, de pai para filho: cliente (`FOR SHARE`), processo (`FOR NO KEY UPDATE`), fase em andamento
-- (`FOR NO KEY UPDATE`). A razão está no comentário de `update_process` acima (F-82, T-41, F-87): o processo é a
-- primeira linha que ESTA função escreve a travar (a mesma consulta e o mesmo modo de `update_process`), a fase só
-- vem depois do `status` lido com a trava, e o cliente, que ela só consulta, vem antes dos dois para um arquivamento
-- em andamento ser esperado (e visto) em vez de ultrapassado. Nenhuma escrita vem antes das travas, e nunca
-- `FOR UPDATE` no processo.
--
-- Instantes. A fase concluída, a aprovação, a fase iniciada e o processo usam o MESMO instante `v_at`, o maior
-- entre `now()` e o `started_at` da fase. A auditoria NÃO usa `v_at`: `private.record_audit_event` não recebe
-- instante, e o `occurred_at` dela é o `now()` da transação (o relógio do banco, a fonte forense de T-19), que
-- pode ser alguns milissegundos anterior ao `approved_at`. O `now()` de uma aprovação que esperou a trava é o
-- do COMEÇO da transação, e pode ser anterior ao `started_at` que a aprovação anterior gravou na fase seguinte
-- (um CEO que já conhece o id da fase 2 e a aprova junto com a fase 1); sem o `greatest`, o CHECK
-- `completed_at >= started_at` daria 500. Pelo mesmo motivo o `updated_at` pode andar alguns milissegundos para
-- trás entre uma aprovação e um cancelamento que esperou a trava dela. A ordem dos fatos é a do `id` da
-- auditoria (§3.7.3), não a dos instantes. O `greatest` tem teto: um `started_at` mais de um minuto à frente
-- do relógio não vem de espera de trava (que dura milissegundos, no máximo o `statement_timeout`), e sim de
-- uma linha quebrada; clampar até lá escreveria um instante no futuro.
CREATE OR REPLACE FUNCTION public.approve_current_stage(
  p_process_id        uuid,
  p_expected_stage_id uuid
)
RETURNS public.processes
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_row         public.processes;
  v_client_id   uuid;
  v_archived_at timestamptz;
  v_stage_id    uuid;
  v_position    smallint;
  v_started_at  timestamptz;
  v_at          timestamptz;
  v_is_last     boolean;
  v_rows        integer;
BEGIN
  IF private.is_ceo() IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  IF p_process_id IS NULL OR p_expected_stage_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  -- 1. O cliente do processo, lido sem trava; processo inexistente: NOT_FOUND.
  SELECT p.client_id
    INTO v_client_id
    FROM public.processes p
   WHERE p.id = p_process_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  -- 2. O cliente, travado ANTES do processo (de pai para filho), e o `archived_at` já com a trava (F-87).
  SELECT c.archived_at
    INTO v_archived_at
    FROM public.clients c
   WHERE c.id = v_client_id
     FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  -- 3. O processo, travado ANTES de qualquer fase (F-82). `FOR NO KEY UPDATE`, nunca `FOR UPDATE`.
  SELECT p.id, p.client_id, p.title, p.status, p.version, p.created_at, p.updated_at,
         p.completed_at, p.cancelled_at
    INTO v_row
    FROM public.processes p
   WHERE p.id = p_process_id
     AND p.client_id = v_client_id
     FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;
  -- 4. O cliente arquivado congela o processo (F-87): antes do `status`, para o CEO saber que desarquivar vem primeiro.
  IF v_archived_at IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'CLIENT_ARCHIVED';
  END IF;
  -- 5. O `status`, relido já com a trava: um cancelamento que ganhou a corrida aparece aqui (I4, E-03).
  IF v_row.status <> 'active' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'PROCESS_NOT_ACTIVE';
  END IF;

  -- 6. Só agora a fase em andamento (I2: exatamente uma num processo ativo), também travada.
  SELECT s.id, s.position, s.started_at
    INTO v_stage_id, v_position, v_started_at
    FROM public.process_stages s
   WHERE s.process_id = p_process_id
     AND s.status = 'in_progress'
     FOR NO KEY UPDATE;
  -- Sem fase em andamento num processo ativo quebra I2 (só uma linha feita à mão chega aqui): `STALE_STAGE`
  -- como a transição pura; a releitura do app confere as invariantes e dá 500 com o log.
  IF NOT FOUND OR v_stage_id <> p_expected_stage_id THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'STALE_STAGE';
  END IF;

  -- O teto do relógio (F-104): 1 minuto de tolerância para a espera de trava, e nenhum instante além disso.
  IF v_started_at > now() + interval '1 minute' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVARIANT_VIOLATION';
  END IF;
  v_at := greatest(now(), v_started_at);
  v_is_last := NOT EXISTS (
    SELECT 1
      FROM public.process_stages s
     WHERE s.process_id = p_process_id
       AND s.position > v_position
  );

  -- A atual conclui antes de a próxima iniciar: o índice único parcial admite uma `in_progress` por vez.
  UPDATE public.process_stages s
     SET status = 'completed',
         completed_at = v_at
   WHERE s.id = v_stage_id
     AND s.status = 'in_progress';
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  IF v_rows <> 1 THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVARIANT_VIOLATION';
  END IF;

  INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by, approved_at)
  VALUES (v_stage_id, p_process_id, auth.uid(), v_at);
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  IF v_rows <> 1 THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVARIANT_VIOLATION';
  END IF;

  IF v_is_last THEN
    -- I3: o processo só conclui com todas as fases concluídas. Uma fase anterior ainda aberta (um buraco
    -- que a transição pura nunca produz) não pode ser pulada.
    IF EXISTS (
      SELECT 1
        FROM public.process_stages s
       WHERE s.process_id = p_process_id
         AND s.status <> 'completed'
    ) THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVARIANT_VIOLATION';
    END IF;
  ELSE
    -- A próxima é a de posição seguinte e precisa estar `pending`: posições com buraco (1 e 3) ou uma fase
    -- seguinte que já começou não viram uma aprovação que deixa o processo sem fase em andamento (I2).
    UPDATE public.process_stages s
       SET status = 'in_progress',
           started_at = v_at
     WHERE s.process_id = p_process_id
       AND s.position = v_position + 1
       AND s.status = 'pending';
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows <> 1 THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVARIANT_VIOLATION';
    END IF;
  END IF;

  -- A `version` sobe uma vez por aprovação (I6), a que conclui o processo inclusive.
  UPDATE public.processes p
     SET status = CASE WHEN v_is_last THEN 'completed'::public.process_status ELSE p.status END,
         completed_at = CASE WHEN v_is_last THEN v_at ELSE p.completed_at END,
         version = p.version + 1,
         updated_at = v_at
   WHERE p.id = p_process_id
  RETURNING * INTO v_row;
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  IF v_rows <> 1 THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVARIANT_VIOLATION';
  END IF;

  PERFORM private.record_audit_event(
    'ceo', 'stage.approved', 'stage', v_stage_id, v_row.client_id, v_row.id
  );
  IF v_is_last THEN
    PERFORM private.record_audit_event(
      'ceo', 'process.completed', 'process', v_row.id, v_row.client_id, v_row.id
    );
  END IF;

  RETURN v_row;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.approve_current_stage(uuid, uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.approve_current_stage(uuid, uuid) TO authenticated;
