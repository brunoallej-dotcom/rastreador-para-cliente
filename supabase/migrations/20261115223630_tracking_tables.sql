-- Spec: docs/specs/client-delivery-tracker.md §3.6, §4.1–§4.3 — processos, fases, aprovações e
-- template padrão. As funções de escrita (create_process, update_process, approve_current_stage)
-- chegam nas Ondas 8 e 9; aqui ficam as tabelas, as invariantes estruturais e a leitura por RLS.
-- service_role mantém DML em clients/processes/process_stages/stage_approvals só para fixtures de
-- teste (Supabase local) e operação manual; o app nunca escreve com a secret key (AGENTS.md, ESLint
-- e hooks restringem o admin client ao gateway de contas e ao rate limiter).

-- Processos ------------------------------------------------------------------------
CREATE TABLE public.processes (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id    uuid NOT NULL REFERENCES public.clients (id) ON DELETE RESTRICT,
  title        text NOT NULL
               CHECK (char_length(btrim(title)) BETWEEN 1 AND 160 AND title !~ '[[:cntrl:]\u00AD\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u180E\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0001\U000E0020-\U000E007F]'),
  status       public.process_status NOT NULL DEFAULT 'active',
  version      integer NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  cancelled_at timestamptz,
  CONSTRAINT processes_completed_at_ck CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
  CONSTRAINT processes_cancelled_at_ck CHECK ((status = 'cancelled') = (cancelled_at IS NOT NULL))
);
ALTER TABLE public.processes ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.processes FROM anon, authenticated;
GRANT SELECT ON public.processes TO authenticated;

-- Índice: aba do cliente no painel de CEO e GET /me/processes (mais recentes primeiro)
CREATE INDEX processes_client_id_created_at_idx ON public.processes (client_id, created_at DESC, id);

-- Fases (só colunas seguras para o cliente) ---------------------------------------------
CREATE TABLE public.process_stages (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  process_id   uuid NOT NULL REFERENCES public.processes (id) ON DELETE CASCADE,
  position     smallint NOT NULL CHECK (position BETWEEN 1 AND 30),
  name         text NOT NULL
               CHECK (char_length(btrim(name)) BETWEEN 1 AND 120 AND name !~ '[[:cntrl:]\u00AD\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u180E\u200B-\u200F\u2028-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0001\U000E0020-\U000E007F]'),
  description  text CHECK (char_length(description) <= 2000),
  status       public.stage_status NOT NULL DEFAULT 'pending',
  started_at   timestamptz,
  completed_at timestamptz,
  CONSTRAINT process_stages_status_timestamps_ck CHECK (
    (status = 'pending' AND started_at IS NULL AND completed_at IS NULL)
    OR (status = 'in_progress' AND started_at IS NOT NULL AND completed_at IS NULL)
    OR (status = 'completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL
        AND completed_at >= started_at)
  ),
  -- Índice único: detalhe do processo (fases em ordem) e posição contígua sem repetição (I1)
  CONSTRAINT process_stages_process_id_position_key UNIQUE (process_id, position),
  -- Índice único: alvo da FK composta de stage_approvals (a aprovação pertence ao processo da fase, I5)
  CONSTRAINT process_stages_id_process_id_key UNIQUE (id, process_id)
);
ALTER TABLE public.process_stages ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.process_stages FROM anon, authenticated;
GRANT SELECT ON public.process_stages TO authenticated;

-- Índice único parcial: fase atual do processo; no máximo uma in_progress (I2)
CREATE UNIQUE INDEX process_stages_one_in_progress_idx ON public.process_stages (process_id)
  WHERE status = 'in_progress';

-- Aprovações ("Ok"), só CEO -----------------------------------------------------------
CREATE TABLE public.stage_approvals (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  process_stage_id uuid NOT NULL UNIQUE,
  process_id       uuid NOT NULL REFERENCES public.processes (id) ON DELETE CASCADE,
  approved_by      uuid NOT NULL REFERENCES public.profiles (id) ON DELETE RESTRICT,
  approved_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT stage_approvals_stage_process_fk FOREIGN KEY (process_stage_id, process_id)
    REFERENCES public.process_stages (id, process_id) ON DELETE CASCADE
);
ALTER TABLE public.stage_approvals ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.stage_approvals FROM anon, authenticated;
GRANT SELECT ON public.stage_approvals TO authenticated;

-- Índice: aprovações no detalhe do processo (painel de CEO)
CREATE INDEX stage_approvals_process_id_idx ON public.stage_approvals (process_id);

-- Template padrão de fases, só CEO; alterado só por migration (Q-01) ---------------------
CREATE TABLE public.default_stage_template (
  position    smallint PRIMARY KEY CHECK (position BETWEEN 1 AND 30),
  name        text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 120),
  description text CHECK (char_length(description) <= 2000)
);
ALTER TABLE public.default_stage_template ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.default_stage_template FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.default_stage_template FROM service_role;
GRANT SELECT ON public.default_stage_template TO authenticated;

-- Placeholder de Q-01 (spec §8) até os CEOs confirmarem os nomes.
INSERT INTO public.default_stage_template (position, name, description) VALUES
  (1, 'Contrato assinado', NULL),
  (2, 'Briefing', NULL),
  (3, 'Planejamento', NULL),
  (4, 'Execução', NULL),
  (5, 'Revisão', NULL),
  (6, 'Entrega final', NULL);

-- Policies (somente leitura) -----------------------------------------------------------
CREATE POLICY processes_select_own_tenant ON public.processes
  FOR SELECT TO authenticated
  USING (client_id = (SELECT private.current_client_id()));

CREATE POLICY processes_select_ceo ON public.processes
  FOR SELECT TO authenticated
  USING ((SELECT private.is_ceo()));

CREATE POLICY process_stages_select_own_tenant ON public.process_stages
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1
        FROM public.processes p
       WHERE p.id = process_stages.process_id
         AND p.client_id = (SELECT private.current_client_id())
    )
  );

CREATE POLICY process_stages_select_ceo ON public.process_stages
  FOR SELECT TO authenticated
  USING ((SELECT private.is_ceo()));

CREATE POLICY stage_approvals_select_ceo ON public.stage_approvals
  FOR SELECT TO authenticated
  USING ((SELECT private.is_ceo()));

CREATE POLICY default_stage_template_select_ceo ON public.default_stage_template
  FOR SELECT TO authenticated
  USING ((SELECT private.is_ceo()));
