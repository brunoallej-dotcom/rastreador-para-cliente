// Helpers for the API tests of the client routes (Wave 6 owns this file): the four operations of
// `/admin/clients` invoked through the real route modules, and fixtures made with the secret key.
//
//   const session = await loginAsCeoWithMfa();                    // tests/helpers/mfa.ts: aal2 cookies
//   const created = await createClientViaApi(session.cookies, { name: 'Acme' });
//   const listed = await listClientsViaApi(session.cookies, { limit: '2' });
//
// Fixtures write with the secret key, which keeps DML on `clients` and `processes` for tests
// (spec §4.2); they are never how a behavior is checked. Test code only: nothing in `src/` may
// import it.
import { randomUUID } from 'node:crypto';
import { GET as getRoute, PATCH as updateRoute } from '@/app/api/v1/admin/clients/[clientId]/route';
import { GET as listRoute, POST as createRoute } from '@/app/api/v1/admin/clients/route';
import { expectToMatchContract } from './contract';
import { adminClient } from './fixtures';
import { bodyOf, invoke, type CookieStore, type InvokeInit } from './http';

/** `ClientDetail` of the contract, as the API answers it. */
export type ClientDetailBody = {
  id: string;
  name: string;
  archived: boolean;
  archivedAt: string | null;
  activeProcessCount: number;
  processCount: number;
  createdAt: string;
  updatedAt: string;
};

/** `ClientSummary` of the contract: the detail without the total process count. */
export type ClientSummaryBody = Omit<ClientDetailBody, 'processCount'>;

export type ClientListBody = { items: ClientSummaryBody[]; nextCursor: string | null };

type Session = CookieStore | undefined;
const withCookies = (cookies: Session) => (cookies === undefined ? {} : { cookies });

/** What a test may still change of a request: headers, `Origin`, a raw body, the client IP. */
type RequestExtras = Omit<InvokeInit, 'method' | 'path' | 'params' | 'query' | 'cookies'>;

export const listClientsViaApi = (cookies: Session, query: Readonly<Record<string, string>> = {}) =>
  invoke(listRoute, { path: '/admin/clients', query, ...withCookies(cookies) });

export const createClientViaApi = (cookies: Session, body: unknown, extras: RequestExtras = {}) =>
  invoke(createRoute, {
    method: 'POST',
    path: '/admin/clients',
    body,
    ...extras,
    ...withCookies(cookies),
  });

export const getClientViaApi = (cookies: Session, clientId: string) =>
  invoke(getRoute, {
    path: `/admin/clients/${clientId}`,
    params: { clientId },
    ...withCookies(cookies),
  });

export const updateClientViaApi = (cookies: Session, clientId: string, body: unknown) =>
  invoke(updateRoute, {
    method: 'PATCH',
    path: `/admin/clients/${clientId}`,
    params: { clientId },
    body,
    ...withCookies(cookies),
  });

/** A name nobody else uses, so a test can find its own client in a database other tests also fill. */
export const uniqueClientName = (label = 'Cliente') => `${label} ${randomUUID().slice(0, 8)}`;

/** Creates a client through the API (the way a CEO does) and returns it; fails the helper unless 201. */
export async function createClientOrFail(
  cookies: CookieStore,
  name = uniqueClientName(),
): Promise<ClientDetailBody> {
  const response = await createClientViaApi(cookies, { name });
  if (response.status !== 201) {
    throw new Error(
      `create client fixture failed with ${response.status}: ${await response.text()}`,
    );
  }
  return (await bodyOf(response)) as ClientDetailBody;
}

/**
 * Walks `GET /admin/clients` page by page (up to `maxPages`) until the client shows up; returns it
 * or `undefined`. The database also holds the clients of other tests, so a test cannot assume that
 * its own client is on the first page.
 */
export async function findInClientList(
  cookies: CookieStore,
  clientId: string,
  options: { includeArchived?: boolean; maxPages?: number } = {},
): Promise<ClientSummaryBody | undefined> {
  const { includeArchived = false, maxPages = 50 } = options;
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page += 1) {
    const response = await listClientsViaApi(cookies, {
      limit: '100',
      includeArchived: String(includeArchived),
      ...(cursor === undefined ? {} : { cursor }),
    });
    if (response.status !== 200) {
      throw new Error(`list fixture failed with ${response.status}: ${await response.text()}`);
    }
    const body = (await bodyOf(response)) as ClientListBody;
    expectToMatchContract('listClients', response.status, body, response);
    const found = body.items.find((item) => item.id === clientId);
    if (found !== undefined) return found;
    if (body.nextCursor === null) return undefined;
    cursor = body.nextCursor;
  }
  return undefined;
}

/**
 * Inserts several clients with ONE statement, so they all get the same `created_at` (`now()` is the
 * start of the transaction): the case a keyset on `created_at` alone would get wrong. Returns them in
 * the order the list has to show them (`id` ascending among equals).
 */
export async function createClientsWithSameCreationInstant(
  count: number,
): Promise<{ id: string; name: string }[]> {
  const prefix = uniqueClientName('Empate');
  const rows = Array.from({ length: count }, (_value, index) => ({
    name: `${prefix} ${index + 1}`,
  }));
  const { data, error } = await adminClient().from('clients').insert(rows).select('id, name');
  if (error) throw new Error(`insert of tied clients failed: ${error.message}`);
  return data.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/**
 * Inserts clients that all carry the given creation instant, text with microseconds and an offset
 * (what PostgREST shows), so a test can place rows exactly where a hand-made cursor points.
 * Returns them in the order the list shows equals (`id` ascending).
 */
export async function createClientsAt(
  createdAt: string,
  count: number,
): Promise<{ id: string; name: string }[]> {
  const prefix = uniqueClientName('Marcado');
  const rows = Array.from({ length: count }, (_value, index) => ({
    name: `${prefix} ${index + 1}`,
    created_at: createdAt,
    updated_at: createdAt,
  }));
  const { data, error } = await adminClient().from('clients').insert(rows).select('id, name');
  if (error) throw new Error(`insert of dated clients failed: ${error.message}`);
  return data.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

type ProcessCounts = { active?: number; completed?: number; cancelled?: number };

/**
 * Gives a client processes in the given states, inserted with the secret key (the Wave 8 function
 * that creates processes does not exist yet; counting them is all these tests need).
 */
export async function seedProcesses(clientId: string, counts: ProcessCounts): Promise<void> {
  const now = new Date().toISOString();
  const rows = [
    ...Array.from({ length: counts.active ?? 0 }, (_v, i) => ({
      client_id: clientId,
      title: `Ativo ${i + 1}`,
      status: 'active' as const,
    })),
    ...Array.from({ length: counts.completed ?? 0 }, (_v, i) => ({
      client_id: clientId,
      title: `Concluído ${i + 1}`,
      status: 'completed' as const,
      completed_at: now,
    })),
    ...Array.from({ length: counts.cancelled ?? 0 }, (_v, i) => ({
      client_id: clientId,
      title: `Cancelado ${i + 1}`,
      status: 'cancelled' as const,
      cancelled_at: now,
    })),
  ];
  if (rows.length === 0) return;
  const { error } = await adminClient().from('processes').insert(rows);
  if (error) throw new Error(`insert of processes failed: ${error.message}`);
}

export type ClientAuditRow = {
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

/** The audit trail of a client, oldest first, read with the secret key (a fixture, not a behavior). */
export async function auditOfClient(clientId: string): Promise<ClientAuditRow[]> {
  const { data, error } = await adminClient()
    .from('audit_events')
    .select(
      'action, actor_id, actor_role, resource_type, resource_id, client_id, process_id, request_id, metadata',
    )
    .eq('resource_id', clientId)
    .order('id', { ascending: true });
  if (error) throw new Error(`reading the audit trail failed: ${error.message}`);
  return data;
}
