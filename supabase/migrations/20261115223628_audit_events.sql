-- Spec: docs/specs/client-delivery-tracker.md §3.10, §4.1, SEC-16 — trilha de auditoria
-- append-only, gravada pelas funções de escrita na mesma transação da mudança. Só CEO lê.

CREATE TABLE public.audit_events (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at   timestamptz NOT NULL DEFAULT now(),
  actor_id      uuid,  -- sem FK: o histórico sobrevive ao ator
  actor_role    public.app_role,
  action        text NOT NULL CHECK (action ~ '^[a-z_]+(\.[a-z_]+)+$' AND char_length(action) <= 64),
  resource_type text NOT NULL CHECK (resource_type IN ('client', 'account', 'process', 'stage')),
  resource_id   uuid NOT NULL,
  client_id     uuid,
  process_id    uuid,
  request_id    text CHECK (request_id ~ '^[A-Za-z0-9-]{1,64}$'),
  metadata      jsonb NOT NULL DEFAULT '{}'::jsonb
                CHECK (jsonb_typeof(metadata) = 'object' AND pg_column_size(metadata) <= 4096)
);
ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.audit_events FROM anon, authenticated;
-- Nem a secret key grava ou altera auditoria: só as funções SECURITY DEFINER (trilha não forjável).
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.audit_events FROM service_role;
GRANT SELECT ON public.audit_events TO authenticated;

-- Índice: linha do tempo do processo (GET /admin/processes/{id}/events)
CREATE INDEX audit_events_process_id_occurred_at_idx ON public.audit_events (process_id, occurred_at)
  WHERE process_id IS NOT NULL;
-- Índice: auditoria por cliente
CREATE INDEX audit_events_client_id_occurred_at_idx ON public.audit_events (client_id, occurred_at)
  WHERE client_id IS NOT NULL;
-- Índice: retenção (limpeza por data, Onda 11)
CREATE INDEX audit_events_occurred_at_idx ON public.audit_events (occurred_at);
-- Índice: eventos de um recurso por ação (idempotência de account.provisioned)
CREATE INDEX audit_events_resource_id_action_idx ON public.audit_events (resource_id, action);

REVOKE ALL ON SEQUENCE public.audit_events_id_seq FROM anon, authenticated, service_role;

CREATE POLICY audit_events_select_ceo ON public.audit_events
  FOR SELECT TO authenticated
  USING ((SELECT private.is_ceo()));

-- Append-only também para o dono da tabela (AC-24) ---------------------------------------
CREATE FUNCTION private.reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN', DETAIL = 'audit_events is append-only';
END;
$$;
REVOKE EXECUTE ON FUNCTION private.reject_audit_mutation() FROM PUBLIC, anon, authenticated;

CREATE TRIGGER audit_events_reject_update_delete
  BEFORE UPDATE OR DELETE ON public.audit_events
  FOR EACH ROW EXECUTE FUNCTION private.reject_audit_mutation();

CREATE TRIGGER audit_events_reject_truncate
  BEFORE TRUNCATE ON public.audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION private.reject_audit_mutation();

-- Gravação de evento, usada só por outras funções SECURITY DEFINER --------------------------
CREATE FUNCTION private.record_audit_event(
  p_actor_role    public.app_role,
  p_action        text,
  p_resource_type text,
  p_resource_id   uuid,
  p_client_id     uuid,
  p_process_id    uuid,
  p_metadata      jsonb DEFAULT '{}'::jsonb
)
RETURNS void
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $$
  INSERT INTO public.audit_events (
    actor_id, actor_role, action, resource_type, resource_id, client_id, process_id, request_id, metadata
  )
  VALUES (
    auth.uid(), p_actor_role, p_action, p_resource_type, p_resource_id, p_client_id, p_process_id,
    private.request_id(), coalesce(p_metadata, '{}'::jsonb)
  );
$$;
REVOKE EXECUTE ON FUNCTION private.record_audit_event(public.app_role, text, text, uuid, uuid, uuid, jsonb)
  FROM PUBLIC, anon, authenticated;
