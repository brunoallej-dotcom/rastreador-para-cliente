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

-- Conclui a fase atual, grava a aprovação e inicia a próxima fase (ou conclui o processo, se era a última).
-- As regras são as da transição pura `approveCurrentStage` do agregado (`tracking/domain/process.ts`), na
-- mesma ordem de precedência: papel (42501), entrada (`INVALID_INPUT`), processo (`NOT_FOUND`), `status`
-- (`PROCESS_NOT_ACTIVE`, que vence um `STALE_STAGE`: E-03) e só então a fase esperada (`STALE_STAGE`).
-- O erro `STALE_STAGE` não leva a fase atual no DETAIL: o app a lê de novo (§3.7.3), e a mensagem do banco
-- fica fixa.
-- Um instante só (`v_at`) para a fase concluída, a aprovação, a fase iniciada e o processo, igual ao `now()`
-- da auditoria (o mesmo da transação). `greatest(now(), started_at)` cobre uma aprovação que esperou a trava:
-- o `now()` dela é o do começo da transação, que pode ser anterior ao `started_at` que a aprovação anterior
-- gravou na fase seguinte; sem isso o CHECK `completed_at >= started_at` daria 500 a quem aprova a fase
-- seguinte com o id já conhecido enquanto a anterior ainda não tinha terminado.
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
   WHERE s.id = v_stage_id;

  INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by, approved_at)
  VALUES (v_stage_id, p_process_id, auth.uid(), v_at);

  IF NOT v_is_last THEN
    UPDATE public.process_stages s
       SET status = 'in_progress',
           started_at = v_at
     WHERE s.process_id = p_process_id
       AND s.position = v_position + 1;
  END IF;

  -- A `version` sobe uma vez por aprovação (I6), a que conclui o processo inclusive.
  UPDATE public.processes p
     SET status = CASE WHEN v_is_last THEN 'completed'::public.process_status ELSE p.status END,
         completed_at = CASE WHEN v_is_last THEN v_at ELSE p.completed_at END,
         version = p.version + 1,
         updated_at = v_at
   WHERE p.id = p_process_id
  RETURNING * INTO v_row;

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
