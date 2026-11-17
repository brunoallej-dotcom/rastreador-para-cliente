// Helpers for the API tests of the approval ("Ok") and of the timeline of a process (Wave 9 owns this
// file): `POST /admin/processes/{processId}/approvals` and `GET /admin/processes/{processId}/events`
// invoked through the real route modules, the rows a test reads back with the secret key, and the
// mapping from an API body to the aggregate, so a test can hold the database function against the pure
// transition of `tracking/domain/process.ts`.
//
//   const session = await loginAsCeoWithMfa();                          // tests/helpers/mfa.ts: aal2 cookies
//   const created = await createProcessOrFail(session.cookies, client.id, { title, stages: stageInputs(3) });
//   const approved = await approveViaApi(session.cookies, created.id, { expectedStageId: created.stages[0].id });
//   const timeline = await listAllEvents(session.cookies, created.id);
//
// Creating a process goes through `tests/helpers/processes.ts` (Wave 8's). Nothing here writes a
// behavior: what the database holds is read to CHECK a response, never to produce one. Test code only:
// nothing in `src/` may import it.
import { POST as approvalsRoute } from '@/app/api/v1/admin/processes/[processId]/approvals/route';
import { GET as eventsRoute } from '@/app/api/v1/admin/processes/[processId]/events/route';
import type { Process } from '@/modules/tracking/domain/process';
import { expectToMatchContract } from './contract';
import { readApprovalRows, readAuditIds } from './db';
import { createCeo } from './fixtures';
import { bodyOf, invoke, type CookieStore, type InvokeInit } from './http';
import { completeFirstAccess, enrollTotp, loginViaApi, verifyTotp, type CeoWithMfa } from './mfa';
import type { ProcessDetailBody } from './processes';

/**
 * Like `loginAsCeoWithMfa` (tests/helpers/mfa.ts), a fresh CEO with an `aal2` session the backend
 * attested, but with a display name the test chooses: the approval and the timeline show WHO acted, so
 * two CEOs of one test must not share a name.
 */
export async function loginAsNamedCeo(displayName: string): Promise<CeoWithMfa> {
  const ceo = await completeFirstAccess(await createCeo({ displayName }));
  const cookies = await loginViaApi(ceo);
  const enrollment = await enrollTotp(cookies);
  await verifyTotp(cookies, enrollment);
  return { ceo, cookies, ...enrollment };
}

/** `ProcessEventDetails` of the contract. */
export type ProcessEventDetailsBody = {
  stageId?: string;
  stagePosition?: number;
  stageName?: string;
  previousTitle?: string;
  newTitle?: string;
};

/** `ProcessEvent` of the contract, as the API answers it. */
export type ProcessEventBody = {
  id: string;
  occurredAt: string;
  action:
    | 'process.created'
    | 'process.updated'
    | 'process.cancelled'
    | 'process.completed'
    | 'stage.approved';
  actor: { id: string; displayName: string } | null;
  details: ProcessEventDetailsBody;
};

export type ProcessEventListBody = { items: ProcessEventBody[]; nextCursor: string | null };

/** What a test may still change of a request: headers, `Origin`, a raw body, the client IP. */
type RequestExtras = Omit<InvokeInit, 'method' | 'path' | 'params' | 'query' | 'cookies'>;

type Session = CookieStore | undefined;
const withCookies = (cookies: Session) => (cookies === undefined ? {} : { cookies });

export const approveViaApi = (
  cookies: Session,
  processId: string,
  body: unknown,
  extras: RequestExtras = {},
) =>
  invoke(approvalsRoute, {
    method: 'POST',
    path: `/admin/processes/${processId}/approvals`,
    params: { processId },
    body,
    ...extras,
    ...withCookies(cookies),
  });

export const listEventsViaApi = (
  cookies: Session,
  processId: string,
  query: Readonly<Record<string, string>> = {},
) =>
  invoke(eventsRoute, {
    path: `/admin/processes/${processId}/events`,
    params: { processId },
    query,
    ...withCookies(cookies),
  });

/**
 * Walks `GET /admin/processes/{processId}/events` page by page (up to `maxPages`) and returns every
 * event it finds, checking each page against the contract.
 */
export async function listAllEvents(
  cookies: CookieStore,
  processId: string,
  query: Readonly<Record<string, string>> = {},
  options: { maxPages?: number } = {},
): Promise<ProcessEventBody[]> {
  const { maxPages = 50 } = options;
  const found: ProcessEventBody[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page += 1) {
    const response = await listEventsViaApi(cookies, processId, {
      limit: '100',
      ...query,
      ...(cursor === undefined ? {} : { cursor }),
    });
    if (response.status !== 200) {
      throw new Error(`timeline fixture failed with ${response.status}: ${await response.text()}`);
    }
    const body = (await bodyOf(response)) as ProcessEventListBody;
    expectToMatchContract('listProcessEvents', response.status, body, response);
    found.push(...body.items);
    if (body.nextCursor === null) return found;
    cursor = body.nextCursor;
  }
  throw new Error('the timeline did not end within the page limit');
}

export type { ApprovalRow } from './db';

/**
 * The approvals of a process, oldest first, read in the database container (`readApprovalRows` in
 * db.ts): a fixture to CHECK a response with, never a way to produce one, and not through the secret
 * key, which may lose its access to `stage_approvals` (Wave 10.1, F-81).
 */
export const approvalRowsOf = readApprovalRows;

/** The audit events of a process with their ids, oldest id first, read in the database container. */
export const auditIdsOfProcess = readAuditIds;

/**
 * An API body as the aggregate: dates become `Date`, the approval of a completed stage becomes the
 * stage's `approval`. The API answers instants in milliseconds, and both sides of a comparison go
 * through this, so they round the same way.
 */
export function toDomainProcess(body: ProcessDetailBody): Process {
  const dateOrNull = (value: string | null) => (value === null ? null : new Date(value));
  return {
    id: body.id,
    clientId: body.clientId,
    client: { id: body.client.id, name: body.client.name },
    title: body.title,
    status: body.status,
    version: body.version,
    createdAt: new Date(body.createdAt),
    updatedAt: new Date(body.updatedAt),
    completedAt: dateOrNull(body.completedAt),
    cancelledAt: dateOrNull(body.cancelledAt),
    stages: body.stages.map((stage) => ({
      id: stage.id,
      position: stage.position,
      name: stage.name,
      description: stage.description,
      status: stage.status,
      startedAt: dateOrNull(stage.startedAt),
      completedAt: dateOrNull(stage.completedAt),
      approval:
        stage.approval === null
          ? null
          : {
              approvedBy: {
                id: stage.approval.approvedBy.id,
                displayName: stage.approval.approvedBy.displayName,
              },
              approvedAt: new Date(stage.approval.approvedAt),
            },
    })),
  };
}
