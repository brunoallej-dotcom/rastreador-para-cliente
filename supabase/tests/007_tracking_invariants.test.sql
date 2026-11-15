-- Invariantes estruturais das tabelas (Onda 2): spec §3.6 (I1, I2) e §4.1 — checks de tamanho e
-- controle, coerência entre status e datas, índices únicos, chaves estrangeiras e o template padrão
-- de fases (Q-01). Tudo como postgres: as constraints valem para qualquer caminho de escrita.
BEGIN;
SELECT plan(80);

-- arrange (como postgres) ------------------------------------------------------------------------------
INSERT INTO public.clients (id, name) VALUES ('00000000-0000-4000-8000-00000000000a', 'Cliente A');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
INSERT INTO public.processes (id, client_id, title) VALUES
  ('00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-00000000000a', 'Processo 1'),
  ('00000000-0000-4000-8000-0000000001a2', '00000000-0000-4000-8000-00000000000a', 'Processo 2');

SELECT results_eq(
  $$ SELECT status::text, version, completed_at IS NULL, cancelled_at IS NULL
       FROM public.processes WHERE id = '00000000-0000-4000-8000-0000000001a1' $$,
  $$ VALUES ('active', 1, true, true) $$,
  'processes: o padrão é active, version 1, sem completed_at nem cancelled_at'
);

-- I1: position entre 1 e 30, sem repetição -----------------------------------------------------------------
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 0, 'Fase zero') $$,
  '23514', NULL, 'I1: position 0 é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 31, 'Fase 31') $$,
  '23514', NULL, 'I1: position 31 é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001a1', -1, 'Fase negativa') $$,
  '23514', NULL, 'I1: position negativa é rejeitada'
);
SELECT lives_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 1, 'Primeira'),
            ('00000000-0000-4000-8000-0000000001a1', 30, 'Trigésima') $$,
  'I1: position 1 e position 30 (os limites) são aceitas'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 1, 'Primeira de novo') $$,
  '23505', NULL, 'I1: position repetida no mesmo processo é rejeitada'
);
SELECT lives_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001a2', 1, 'Primeira do processo 2') $$,
  'I1: a mesma position em outro processo é aceita'
);

-- I2: no máximo uma fase in_progress por processo --------------------------------------------------------------
SELECT lives_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, status, started_at)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 2, 'Em andamento', 'in_progress', now()) $$,
  'I2: uma fase in_progress é aceita'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, status, started_at)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 3, 'Outra em andamento', 'in_progress', now()) $$,
  '23505', 'duplicate key value violates unique constraint "process_stages_one_in_progress_idx"',
  'I2: duas fases in_progress no mesmo processo são rejeitadas (índice único parcial)'
);
SELECT throws_ok(
  $$ UPDATE public.process_stages
        SET status = 'in_progress', started_at = now()
      WHERE process_id = '00000000-0000-4000-8000-0000000001a1' AND position = 1 $$,
  '23505', NULL, 'I2: promover uma segunda fase a in_progress por UPDATE também é rejeitado'
);
SELECT lives_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, status, started_at)
     VALUES ('00000000-0000-4000-8000-0000000001a2', 2, 'Em andamento do processo 2', 'in_progress', now()) $$,
  'I2: outro processo tem a própria fase in_progress'
);
SELECT lives_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, status, started_at, completed_at)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 4, 'Concluída', 'completed', now() - interval '1 day', now()) $$,
  'I2: fases completed e pending convivem com a in_progress'
);

-- Fases: status coerente com started_at e completed_at --------------------------------------------------------------
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, status, started_at)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 5, 'X', 'pending', now()) $$,
  '23514', NULL, 'stages: pending com started_at é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, status, completed_at)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 5, 'X', 'pending', now()) $$,
  '23514', NULL, 'stages: pending com completed_at é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, status)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 5, 'X', 'in_progress') $$,
  '23514', NULL, 'stages: in_progress sem started_at é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, status, started_at, completed_at)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 5, 'X', 'in_progress', now(), now()) $$,
  '23514', NULL, 'stages: in_progress com completed_at é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, status, started_at)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 5, 'X', 'completed', now()) $$,
  '23514', NULL, 'stages: completed sem completed_at é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, status, completed_at)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 5, 'X', 'completed', now()) $$,
  '23514', NULL, 'stages: completed sem started_at é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, status, started_at, completed_at)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 5, 'X', 'completed', now(), now() - interval '1 hour') $$,
  '23514', NULL, 'stages: completed_at anterior a started_at é rejeitada'
);

-- Fases: nome, descrição e vínculo ----------------------------------------------------------------------------------------
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 6, '') $$,
  '23514', NULL, 'stages: nome vazio é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 6, '   ') $$,
  '23514', NULL, 'stages: nome em branco é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 6, repeat('n', 121)) $$,
  '23514', NULL, 'stages: nome com 121 caracteres é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 6, E'Com\nquebra') $$,
  '23514', NULL, 'stages: nome com caractere de controle é rejeitado'
);
SELECT lives_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, description)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 6, repeat('n', 120), repeat('d', 2000)) $$,
  'stages: nome de 120 e descrição de 2000 caracteres (os limites) são aceitos'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name, description)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 7, 'Fase', repeat('d', 2001)) $$,
  '23514', NULL, 'stages: descrição com 2001 caracteres é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001ff', 7, 'Órfã') $$,
  '23503', NULL, 'stages: fase de processo inexistente é rejeitada (FK)'
);

-- Processos --------------------------------------------------------------------------------------------------------------------
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title) VALUES ('00000000-0000-4000-8000-00000000000a', '') $$,
  '23514', NULL, 'processes: título vazio é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title) VALUES ('00000000-0000-4000-8000-00000000000a', '   ') $$,
  '23514', NULL, 'processes: título em branco é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title)
     VALUES ('00000000-0000-4000-8000-00000000000a', repeat('t', 161)) $$,
  '23514', NULL, 'processes: título com 161 caracteres é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title)
     VALUES ('00000000-0000-4000-8000-00000000000a', E'Com\tTab') $$,
  '23514', NULL, 'processes: título com caractere de controle é rejeitado'
);
SELECT lives_ok(
  $$ INSERT INTO public.processes (client_id, title)
     VALUES ('00000000-0000-4000-8000-00000000000a', repeat('t', 160)) $$,
  'processes: título com exatamente 160 caracteres é aceito'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title, status)
     VALUES ('00000000-0000-4000-8000-00000000000a', 'X', 'completed') $$,
  '23514', NULL, 'processes: completed sem completed_at é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title, completed_at)
     VALUES ('00000000-0000-4000-8000-00000000000a', 'X', now()) $$,
  '23514', NULL, 'processes: active com completed_at é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title, status)
     VALUES ('00000000-0000-4000-8000-00000000000a', 'X', 'cancelled') $$,
  '23514', NULL, 'processes: cancelled sem cancelled_at é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title, cancelled_at)
     VALUES ('00000000-0000-4000-8000-00000000000a', 'X', now()) $$,
  '23514', NULL, 'processes: active com cancelled_at é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title, status, completed_at, cancelled_at)
     VALUES ('00000000-0000-4000-8000-00000000000a', 'X', 'completed', now(), now()) $$,
  '23514', NULL, 'processes: completed com cancelled_at também é rejeitado'
);
SELECT lives_ok(
  $$ INSERT INTO public.processes (client_id, title, status, completed_at)
     VALUES ('00000000-0000-4000-8000-00000000000a', 'Concluído', 'completed', now()) $$,
  'processes: completed com completed_at é aceito'
);
SELECT lives_ok(
  $$ INSERT INTO public.processes (client_id, title, status, cancelled_at)
     VALUES ('00000000-0000-4000-8000-00000000000a', 'Cancelado', 'cancelled', now()) $$,
  'processes: cancelled com cancelled_at é aceito'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title, version)
     VALUES ('00000000-0000-4000-8000-00000000000a', 'X', 0) $$,
  '23514', NULL, 'processes: version 0 é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title) VALUES ('00000000-0000-4000-8000-0000000000ee', 'Órfão') $$,
  '23503', NULL, 'processes: processo de cliente inexistente é rejeitado (FK)'
);

-- Clientes --------------------------------------------------------------------------------------------------------------------------
SELECT throws_ok(
  $$ INSERT INTO public.clients (name) VALUES ('') $$,
  '23514', NULL, 'clients: nome vazio é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.clients (name) VALUES ('   ') $$,
  '23514', NULL, 'clients: nome em branco é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.clients (name) VALUES (repeat('c', 161)) $$,
  '23514', NULL, 'clients: nome com 161 caracteres é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.clients (name) VALUES (E'Com\nquebra') $$,
  '23514', NULL, 'clients: nome com caractere de controle é rejeitado'
);
SELECT lives_ok(
  $$ INSERT INTO public.clients (name) VALUES (repeat('c', 160)) $$,
  'clients: nome com exatamente 160 caracteres é aceito'
);

-- E-30: texto visível recusa caracteres de formatação Unicode (bidi, zero-width, BOM) ------------------------------------------
-- Caracteres sempre montados com chr(): nenhum invisível literal neste arquivo. O helper tenta inserir
-- um cliente com 'A' || chr(n) || 'B' e desfaz o INSERT (a exceção volta o subbloco).
CREATE FUNCTION tests.clients_name_verdict(p_codepoint integer)
RETURNS text
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO public.clients (name) VALUES ('A' || chr(p_codepoint) || 'B');
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'ACCEPTED';
EXCEPTION
  WHEN check_violation THEN
    RETURN 'rejected';
  WHEN raise_exception THEN
    RETURN 'accepted';
END;
$$;

SELECT is(
  tests.clients_name_verdict(10), 'rejected',
  'E-30: controle do helper: quebra de linha (U+000A) é rejeitada'
);
SELECT is(
  tests.clients_name_verdict(233), 'accepted',
  'E-30: controle do helper: letra acentuada (U+00E9) é aceita'
);
SELECT is_empty(
  $$ SELECT f.cp
       FROM (SELECT unnest(ARRAY[173, 1564, 6158, 65279])
             UNION ALL SELECT generate_series(8203, 8207)
             UNION ALL SELECT generate_series(8234, 8238)
             UNION ALL SELECT generate_series(8288, 8292)
             UNION ALL SELECT generate_series(8294, 8297)) f (cp)
      WHERE tests.clients_name_verdict(f.cp) <> 'rejected' $$,
  'E-30: clients.name rejeita U+00AD, U+061C, U+180E, U+200B-200F, U+202A-202E, U+2060-2064, U+2066-2069 e U+FEFF'
);
SELECT is_empty(
  $$ SELECT f.cp
       FROM unnest(ARRAY[172, 174, 1563, 1565, 6157, 6159, 8202, 8208, 8239, 8287]) f (cp)
      WHERE tests.clients_name_verdict(f.cp) <> 'accepted' $$,
  'E-30: clients.name aceita os caracteres vizinhos dos intervalos proibidos (a regra não é larga demais)'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title)
     VALUES ('00000000-0000-4000-8000-00000000000a', 'Título' || chr(8238) || 'invertido') $$,
  '23514', NULL, 'E-30: processes.title rejeita U+202E (bidi override)'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title)
     VALUES ('00000000-0000-4000-8000-00000000000a', 'Título' || chr(8203) || 'invisível') $$,
  '23514', NULL, 'E-30: processes.title rejeita U+200B (zero-width space)'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 8, 'Fase' || chr(8238) || 'invertida') $$,
  '23514', NULL, 'E-30: process_stages.name rejeita U+202E (bidi override)'
);
SELECT throws_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 8, 'Fase' || chr(8203) || 'invisível') $$,
  '23514', NULL, 'E-30: process_stages.name rejeita U+200B (zero-width space)'
);
SELECT lives_ok(
  $$ INSERT INTO public.clients (name) VALUES ('Ação & Cia — Produção') $$,
  'E-30: clients.name aceita texto acentuado comum, com & e travessão'
);
SELECT lives_ok(
  $$ INSERT INTO public.processes (client_id, title)
     VALUES ('00000000-0000-4000-8000-00000000000a', 'Ação & Cia — Produção') $$,
  'E-30: processes.title aceita texto acentuado comum, com & e travessão'
);
SELECT lives_ok(
  $$ INSERT INTO public.process_stages (process_id, position, name)
     VALUES ('00000000-0000-4000-8000-0000000001a1', 8, 'Ação & Cia — Produção') $$,
  'E-30: process_stages.name aceita texto acentuado comum, com & e travessão'
);

-- Aprovações e chaves estrangeiras ----------------------------------------------------------------------------------------------------
SELECT lives_ok(
  $$ INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)
     SELECT s.id, s.process_id, '00000000-0000-4000-8000-0000000000c1'
       FROM public.process_stages s
      WHERE s.process_id = '00000000-0000-4000-8000-0000000001a1' AND s.position = 4 $$,
  'approvals: a fase concluída recebe uma aprovação'
);
SELECT throws_ok(
  $$ INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)
     SELECT s.id, s.process_id, '00000000-0000-4000-8000-0000000000c1'
       FROM public.process_stages s
      WHERE s.process_id = '00000000-0000-4000-8000-0000000001a1' AND s.position = 4 $$,
  '23505', NULL, 'approvals: a mesma fase não recebe uma segunda aprovação (UNIQUE)'
);
-- I5: a aprovação pertence ao processo da própria fase (FK composta).
SELECT throws_ok(
  $$ INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)
     SELECT s.id, '00000000-0000-4000-8000-0000000001a2', '00000000-0000-4000-8000-0000000000c1'
       FROM public.process_stages s
      WHERE s.process_id = '00000000-0000-4000-8000-0000000001a1' AND s.position = 30 $$,
  '23503', 'insert or update on table "stage_approvals" violates foreign key constraint "stage_approvals_stage_process_fk"',
  'I5: aprovação com process_id de outro processo (fase do processo 1, process_id do processo 2) é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)
     SELECT s.id, '00000000-0000-4000-8000-0000000001a1', '00000000-0000-4000-8000-0000000000c1'
       FROM public.process_stages s
      WHERE s.process_id = '00000000-0000-4000-8000-0000000001a2' AND s.position = 1 $$,
  '23503', 'insert or update on table "stage_approvals" violates foreign key constraint "stage_approvals_stage_process_fk"',
  'I5: aprovação com process_id de outro processo (fase do processo 2, process_id do processo 1) é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)
     VALUES ('00000000-0000-4000-8000-0000000009ff', '00000000-0000-4000-8000-0000000001a1',
             '00000000-0000-4000-8000-0000000000c1') $$,
  '23503', NULL, 'I5: aprovação de fase inexistente é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)
     SELECT s.id, s.process_id, '00000000-0000-4000-8000-0000000000ee'
       FROM public.process_stages s
      WHERE s.process_id = '00000000-0000-4000-8000-0000000001a2' AND s.position = 1 $$,
  '23503', NULL, 'approvals: aprovador inexistente é rejeitado (FK)'
);
SELECT throws_ok(
  $$ DELETE FROM public.profiles WHERE id = '00000000-0000-4000-8000-0000000000c1' $$,
  '23503', NULL, 'approvals: o perfil de quem aprovou não pode ser apagado (ON DELETE RESTRICT)'
);
SELECT throws_ok(
  $$ DELETE FROM public.clients WHERE id = '00000000-0000-4000-8000-00000000000a' $$,
  '23503', NULL, 'clients: cliente com processos não pode ser apagado (ON DELETE RESTRICT)'
);
DELETE FROM public.processes WHERE id = '00000000-0000-4000-8000-0000000001a1';
SELECT is_empty(
  $$ SELECT id FROM public.process_stages WHERE process_id = '00000000-0000-4000-8000-0000000001a1' $$,
  'stages: apagar o processo apaga as fases (ON DELETE CASCADE)'
);
SELECT is_empty(
  $$ SELECT id FROM public.stage_approvals WHERE process_id = '00000000-0000-4000-8000-0000000001a1' $$,
  'approvals: apagar o processo apaga as aprovações (ON DELETE CASCADE)'
);

-- Template padrão de fases (Q-01) -------------------------------------------------------------------------------------------------------
SELECT results_eq(
  $$ SELECT position::int, name, description IS NULL FROM public.default_stage_template ORDER BY position $$,
  $$ VALUES (1, 'Contrato assinado', true), (2, 'Briefing', true), (3, 'Planejamento', true),
            (4, 'Execução', true), (5, 'Revisão', true), (6, 'Entrega final', true) $$,
  'Q-01: o template tem as 6 fases placeholder, em ordem'
);
SELECT throws_ok(
  $$ INSERT INTO public.default_stage_template (position, name) VALUES (0, 'Zero') $$,
  '23514', NULL, 'template: position 0 é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.default_stage_template (position, name) VALUES (31, 'Trinta e uma') $$,
  '23514', NULL, 'template: position 31 é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.default_stage_template (position, name) VALUES (1, 'Repetida') $$,
  '23505', NULL, 'template: position repetida é rejeitada (PK)'
);
SELECT throws_ok(
  $$ INSERT INTO public.default_stage_template (position, name) VALUES (7, '   ') $$,
  '23514', NULL, 'template: nome em branco é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.default_stage_template (position, name, description)
     VALUES (7, 'Sétima', repeat('d', 2001)) $$,
  '23514', NULL, 'template: descrição com 2001 caracteres é rejeitada'
);

-- audit_events: formato das colunas -------------------------------------------------------------------------------------------------------------
SELECT lives_ok(
  $$ INSERT INTO public.audit_events (action, resource_type, resource_id, request_id, metadata)
     VALUES ('process.created', 'process', '00000000-0000-4000-8000-0000000001a2', 'req-abc-123', '{"stages": 6}') $$,
  'audit_events: evento com action, resource_type, request_id e metadata válidos é aceito'
);
SELECT throws_ok(
  $$ INSERT INTO public.audit_events (action, resource_type, resource_id)
     VALUES ('Bad Action', 'process', '00000000-0000-4000-8000-0000000001a2') $$,
  '23514', NULL, 'audit_events: action fora do padrão ^[a-z_]+(\.[a-z_]+)+$ é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.audit_events (action, resource_type, resource_id)
     VALUES ('created', 'process', '00000000-0000-4000-8000-0000000001a2') $$,
  '23514', NULL, 'audit_events: action sem ponto é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.audit_events (action, resource_type, resource_id)
     VALUES ('process.' || repeat('a', 60), 'process', '00000000-0000-4000-8000-0000000001a2') $$,
  '23514', NULL, 'audit_events: action com mais de 64 caracteres é rejeitada'
);
SELECT throws_ok(
  $$ INSERT INTO public.audit_events (action, resource_type, resource_id)
     VALUES ('invoice.created', 'invoice', '00000000-0000-4000-8000-0000000001a2') $$,
  '23514', NULL, 'audit_events: resource_type fora de client/account/process/stage é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.audit_events (action, resource_type, resource_id, request_id)
     VALUES ('process.created', 'process', '00000000-0000-4000-8000-0000000001a2', 'com espaço') $$,
  '23514', NULL, 'audit_events: request_id fora de [A-Za-z0-9-] é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.audit_events (action, resource_type, resource_id, metadata)
     VALUES ('process.created', 'process', '00000000-0000-4000-8000-0000000001a2', '[]') $$,
  '23514', NULL, 'audit_events: metadata que não é objeto é rejeitado'
);
SELECT throws_ok(
  $$ INSERT INTO public.audit_events (action, resource_type, resource_id, metadata)
     VALUES ('process.created', 'process', '00000000-0000-4000-8000-0000000001a2',
             jsonb_build_object('k', repeat('x', 5000))) $$,
  '23514', NULL, 'audit_events: metadata acima de 4 KiB é rejeitado'
);

SELECT * FROM finish();
ROLLBACK;
