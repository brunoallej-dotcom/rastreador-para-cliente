// Helpers for the API tests of the process routes (Wave 8 owns this file): the five operations of
// `/admin/clients/{clientId}/processes`, `/admin/processes/{processId}` and
// `/admin/stage-templates/default` invoked through the real route modules, and fixtures made with the
// secret key.
//
//   const session = await loginAsCeoWithMfa();                          // tests/helpers/mfa.ts: aal2 cookies
//   const created = await createProcessViaApi(session.cookies, client.id, { title: 'Site' });
//   const listed = await listProcessesViaApi(session.cookies, client.id, { limit: '2' });
//
// Fixtures write with the secret key, which keeps DML on `processes`, `process_stages` and
// `stage_approvals` for tests (spec §4.2); they are never how a behavior is checked, and they exist for
// what no API route does yet (the "Ok" is Wave 9: `approveStageAsFixture` plays it). Test code only:
// nothing in `src/` may import it.
import { randomUUID } from 'node:crypto';
import {
  GET as listRoute,
  POST as createRoute,
} from '@/app/api/v1/admin/clients/[clientId]/processes/route';
import {
  GET as getRoute,
  PATCH as updateRoute,
} from '@/app/api/v1/admin/processes/[processId]/route';
import { GET as templateRoute } from '@/app/api/v1/admin/stage-templates/default/route';
import { expectToMatchContract } from './contract';
import { adminClient } from './fixtures';
import { bodyOf, invoke, type CookieStore, type InvokeInit } from './http';

export type StageStatusValue = 'pending' | 'in_progress' | 'completed';
export type ProcessStatusValue = 'active' | 'completed' | 'cancelled';

/** `AdminStage` of the contract, as the API answers it. */
export type AdminStageBody = {
  id: string;
  position: number;
  name: string;
  description: string | null;
  status: StageStatusValue;
  startedAt: string | null;
  completedAt: string | null;
  approval: { approvedBy: { id: string; displayName: string }; approvedAt: string } | null;
};

/** `ProcessSummary` of the contract. */
export type ProcessSummaryBody = {
  id: string;
  clientId: string;
  title: string;
  status: ProcessStatusValue;
  currentStage: { id: string; position: number; name: string } | null;
  totalStages: number;
  completedStages: number;
  version: number;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
  cancelledAt: string | null;
};

/** `ProcessDetail` of the contract: the summary plus the client and every stage. */
export type ProcessDetailBody = ProcessSummaryBody & {
  client: { id: string; name: string };
  stages: AdminStageBody[];
};

export type ProcessListBody = { items: ProcessSummaryBody[]; nextCursor: string | null };

export type StageTemplateBody = {
  stages: { position: number; name: string; description: string | null }[];
};

type Session = CookieStore | undefined;
const withCookies = (cookies: Session) => (cookies === undefined ? {} : { cookies });

/** What a test may still change of a request: headers, `Origin`, a raw body, the client IP. */
type RequestExtras = Omit<InvokeInit, 'method' | 'path' | 'params' | 'query' | 'cookies'>;

export const listProcessesViaApi = (
  cookies: Session,
  clientId: string,
  query: Readonly<Record<string, string>> = {},
) =>
  invoke(listRoute, {
    path: `/admin/clients/${clientId}/processes`,
    params: { clientId },
    query,
    ...withCookies(cookies),
  });

export const createProcessViaApi = (
  cookies: Session,
  clientId: string,
  body: unknown,
  extras: RequestExtras = {},
) =>
  invoke(createRoute, {
    method: 'POST',
    path: `/admin/clients/${clientId}/processes`,
    params: { clientId },
    body,
    ...extras,
    ...withCookies(cookies),
  });

export const getProcessViaApi = (cookies: Session, processId: string) =>
  invoke(getRoute, {
    path: `/admin/processes/${processId}`,
    params: { processId },
    ...withCookies(cookies),
  });

export const updateProcessViaApi = (
  cookies: Session,
  processId: string,
  body: unknown,
  extras: RequestExtras = {},
) =>
  invoke(updateRoute, {
    method: 'PATCH',
    path: `/admin/processes/${processId}`,
    params: { processId },
    body,
    ...extras,
    ...withCookies(cookies),
  });

export const getStageTemplateViaApi = (cookies: Session) =>
  invoke(templateRoute, { path: '/admin/stage-templates/default', ...withCookies(cookies) });

/** A title nobody else uses, so a test can find its own process in a database other tests also fill. */
export const uniqueProcessTitle = (label = 'Processo') => `${label} ${randomUUID().slice(0, 8)}`;

/** Creates a process through the API (the way a CEO does) and returns it; fails the helper unless 201. */
export async function createProcessOrFail(
  cookies: CookieStore,
  clientId: string,
  body: unknown = { title: uniqueProcessTitle() },
): Promise<ProcessDetailBody> {
  const response = await createProcessViaApi(cookies, clientId, body);
  if (response.status !== 201) {
    throw new Error(
      `create process fixture failed with ${response.status}: ${await response.text()}`,
    );
  }
  return (await bodyOf(response)) as ProcessDetailBody;
}

/** `n` stages named `Fase 1` to `Fase n`, as a request body carries them. */
export const stageInputs = (count: number) =>
  Array.from({ length: count }, (_value, index) => ({ name: `Fase ${index + 1}` }));

/**
 * Walks `GET /admin/clients/{clientId}/processes` page by page (up to `maxPages`) and returns every
 * summary it finds, checking each page against the contract.
 */
export async function listAllProcesses(
  cookies: CookieStore,
  clientId: string,
  query: Readonly<Record<string, string>> = {},
  options: { maxPages?: number } = {},
): Promise<ProcessSummaryBody[]> {
  const { maxPages = 50 } = options;
  const found: ProcessSummaryBody[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page += 1) {
    const response = await listProcessesViaApi(cookies, clientId, {
      limit: '100',
      ...query,
      ...(cursor === undefined ? {} : { cursor }),
    });
    if (response.status !== 200) {
      throw new Error(`list fixture failed with ${response.status}: ${await response.text()}`);
    }
    const body = (await bodyOf(response)) as ProcessListBody;
    expectToMatchContract('listClientProcesses', response.status, body, response);
    found.push(...body.items);
    if (body.nextCursor === null) return found;
    cursor = body.nextCursor;
  }
  throw new Error('the process list did not end within the page limit');
}

/**
 * Inserts processes that all carry the given creation instant, text with microseconds and an offset
 * (what PostgREST shows), each with one stage in progress (a process with no stage is not one the API
 * can show), so a test can place rows exactly where a hand-made cursor points. Returns them in the
 * order the list shows equals (`id` ascending).
 */
export async function createProcessesAt(
  clientId: string,
  createdAt: string,
  count: number,
): Promise<{ id: string; title: string }[]> {
  const prefix = uniqueProcessTitle('Marcado');
  const rows = Array.from({ length: count }, (_value, index) => ({
    client_id: clientId,
    title: `${prefix} ${index + 1}`,
    created_at: createdAt,
    updated_at: createdAt,
  }));
  const inserted = await adminClient().from('processes').insert(rows).select('id, title');
  if (inserted.error)
    throw new Error(`insert of dated processes failed: ${inserted.error.message}`);

  const stages = inserted.data.map((process) => ({
    process_id: process.id,
    position: 1,
    name: 'Unica',
    status: 'in_progress' as const,
    started_at: createdAt,
  }));
  const stageInsert = await adminClient().from('process_stages').insert(stages);
  if (stageInsert.error) throw new Error(`insert of stages failed: ${stageInsert.error.message}`);
  return inserted.data.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/**
 * Plays the "Ok" that Wave 9 will expose, with the secret key: completes the current stage of an
 * active process with an approval by `approverId`, and starts the next one (or completes the
 * process). It exists only so the read of an approval can be tested before the route exists; it does
 * what `approve_current_stage` will do, and it is not how an approval is ever checked.
 */
export async function approveStageAsFixture(processId: string, approverId: string): Promise<void> {
  const admin = adminClient();
  const stages = await admin
    .from('process_stages')
    .select('id, position, status')
    .eq('process_id', processId)
    .order('position', { ascending: true });
  if (stages.error) throw new Error(`reading stages failed: ${stages.error.message}`);

  const current = stages.data.find((stage) => stage.status === 'in_progress');
  if (current === undefined) throw new Error('approveStageAsFixture: no stage in progress');
  const next = stages.data.find((stage) => stage.position === current.position + 1);
  const now = new Date().toISOString();

  const completed = await admin
    .from('process_stages')
    .update({ status: 'completed', completed_at: now })
    .eq('id', current.id);
  if (completed.error) throw new Error(`completing a stage failed: ${completed.error.message}`);
  const approval = await admin
    .from('stage_approvals')
    .insert({ process_stage_id: current.id, process_id: processId, approved_by: approverId });
  if (approval.error) throw new Error(`inserting the approval failed: ${approval.error.message}`);

  if (next === undefined) {
    const process = await admin
      .from('processes')
      .update({ status: 'completed', completed_at: now })
      .eq('id', processId);
    if (process.error) throw new Error(`completing the process failed: ${process.error.message}`);
    return;
  }
  const started = await admin
    .from('process_stages')
    .update({ status: 'in_progress', started_at: now })
    .eq('id', next.id);
  if (started.error) throw new Error(`starting a stage failed: ${started.error.message}`);
}

/** How many processes the client has, read with the secret key (a fixture, not a behavior). */
export async function processCountOf(clientId: string): Promise<number> {
  const { count, error } = await adminClient()
    .from('processes')
    .select('id', { count: 'exact', head: true })
    .eq('client_id', clientId);
  if (error) throw new Error(`counting processes failed: ${error.message}`);
  return count ?? 0;
}

/** The titles of the client's processes, read with the secret key. */
export async function processTitlesOf(clientId: string): Promise<string[]> {
  const { data, error } = await adminClient()
    .from('processes')
    .select('title')
    .eq('client_id', clientId);
  if (error) throw new Error(`reading processes failed: ${error.message}`);
  return data.map((row) => row.title);
}

/** The process row as the database holds it, read with the secret key. */
export async function processRowOf(processId: string) {
  const { data, error } = await adminClient()
    .from('processes')
    .select(
      'id, client_id, title, status, version, created_at, updated_at, completed_at, cancelled_at',
    )
    .eq('id', processId)
    .single();
  if (error) throw new Error(`reading a process failed: ${error.message}`);
  return data;
}

/** The stages of a process in position order, read with the secret key. */
export async function stageRowsOf(processId: string) {
  const { data, error } = await adminClient()
    .from('process_stages')
    .select('id, position, name, description, status, started_at, completed_at')
    .eq('process_id', processId)
    .order('position', { ascending: true });
  if (error) throw new Error(`reading stages failed: ${error.message}`);
  return data;
}

export type ProcessAuditRow = {
  action: string;
  actor_id: string | null;
  actor_role: string | null;
  resource_type: string;
  resource_id: string;
  client_id: string | null;
  process_id: string | null;
  request_id: string | null;
  metadata: unknown;
};

/** The audit trail of a process, oldest first, read with the secret key (a fixture, not a behavior). */
export async function auditOfProcess(processId: string): Promise<ProcessAuditRow[]> {
  const { data, error } = await adminClient()
    .from('audit_events')
    .select(
      'action, actor_id, actor_role, resource_type, resource_id, client_id, process_id, request_id, metadata',
    )
    .eq('process_id', processId)
    .order('id', { ascending: true });
  if (error) throw new Error(`reading the audit trail failed: ${error.message}`);
  return data;
}
