-- Spec: docs/specs/client-delivery-tracker.md §3.6, §3.7, §3.7.3, §4.1 — o "Ok" do CEO (Onda 9): único caminho
-- de escrita de `public.stage_approvals` para o app, e o que muda o `status` das fases e do processo ao
-- aprovar. As tabelas, as constraints (I1, I2, I5 estruturais) e as policies de leitura são da Onda 2; o
-- `update_process` (que cancela sob a mesma trava) é da Onda 8.
--
-- Ordem de trava (F-82, T-41): a linha do processo é a PRIMEIRA coisa que a função trava, com
-- `FOR NO KEY UPDATE`, o mesmo modo e a mesma linha do `update_process`; só depois ela confere o `status` e
-- trava a fase em andamento (também `FOR NO KEY UPDATE`: o `UPDATE` da fase não muda chave). Quem trava a fase
-- antes do processo, ou usa `FOR UPDATE` no processo (que cruza com o `FOR NO KEY UPDATE` do outro modo),
-- abre deadlock ou conclui uma fase de um processo que acabou de ser cancelado (I4). Como toda escrita do
-- mesmo processo passa por essa trava, nada além dela precisa serializar duas aprovações: a que chega depois
-- relê a fase atual já com a primeira gravada e recebe `STALE_STAGE` (AC-17, E-01).
--
-- A função devolve a linha de `public.processes` (o app lê o detalhe depois, com as fases, as aprovações e o
-- cliente) e grava a auditoria na mesma transação, sem título nem nome nos metadados.
--
-- A função confia no que lê, e por isso confere o que escreve (T-49, F-104, F-105). Um estado que as funções
-- nunca produzem (uma linha feita à mão com a secret key, F-81: posições com buraco, uma fase `in_progress`
-- que começa no futuro, uma fase anterior ainda aberta) não pode virar uma aprovação "bem-sucedida" que deixa
-- o processo quebrado: cada escrita confere `ROW_COUNT = 1`, a última fase confere que todas as outras já
-- estão concluídas, e o relógio da fase tem teto. A recusa é `INVARIANT_VIOLATION`, um código que não está no
-- catálogo: o app o responde com 500 (sem corpo do banco), e a transação inteira se desfaz.

-- Conclui a fase atual, grava a aprovação e inicia a próxima fase (ou conclui o processo, se era a última).
-- As regras são as da transição pura `approveCurrentStage` do agregado (`tracking/domain/process.ts`), na
-- mesma ordem de precedência: papel (42501), entrada (`INVALID_INPUT`), processo (`NOT_FOUND`), `status`
-- (`PROCESS_NOT_ACTIVE`, que vence um `STALE_STAGE`: E-03) e só então a fase esperada (`STALE_STAGE`).
-- O erro `STALE_STAGE` não leva a fase atual no DETAIL: o app a lê de novo (§3.7.3), e a mensagem do banco
-- fica fixa.
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
CREATE FUNCTION public.approve_current_stage(
  p_process_id        uuid,
  p_expected_stage_id uuid
)
RETURNS public.processes
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_row        public.processes;
  v_stage_id   uuid;
  v_position   smallint;
  v_started_at timestamptz;
  v_at         timestamptz;
  v_is_last    boolean;
  v_rows       integer;
BEGIN
  IF private.is_ceo() IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  IF p_process_id IS NULL OR p_expected_stage_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  -- 1. O processo, travado ANTES de qualquer outra coisa (F-82). `FOR NO KEY UPDATE`, nunca `FOR UPDATE`.
  SELECT p.id, p.client_id, p.title, p.status, p.version, p.created_at, p.updated_at,
         p.completed_at, p.cancelled_at
    INTO v_row
    FROM public.processes p
   WHERE p.id = p_process_id
     FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;
  -- 2. O `status`, relido já com a trava: um cancelamento que ganhou a corrida aparece aqui (I4, E-03).
  IF v_row.status <> 'active' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'PROCESS_NOT_ACTIVE';
  END IF;

  -- 3. Só agora a fase em andamento (I2: exatamente uma num processo ativo), também travada.
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

-- Índice: linha do tempo do processo (GET /admin/processes/{id}/events), keyset por `id` (F-106). A leitura filtra
-- `process_id = ?` e `id > ?` e ordena por `id`; o índice `(process_id, occurred_at)` da Onda 2 acha as linhas do
-- processo mas deixa a ordenação para depois, e um processo renomeado muitas vezes (o renome não tem teto) pode ter
-- muitos eventos. Com este, a página é uma varredura do índice, já na ordem.
CREATE INDEX audit_events_process_id_id_idx ON public.audit_events (process_id, id)
  WHERE process_id IS NOT NULL;
