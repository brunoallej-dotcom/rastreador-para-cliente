// API tests of the client panel (operationIds `listMyProcesses` and `getMyProcess`): the real route
// modules, the real pipeline and wiring (Postgres rate limiter, Supabase resolver), the local Supabase
// (Auth + PostgREST + RLS), and every response checked against the OpenAPI contract, headers included.
//
// This is where tenant isolation is proved end to end: client A never sees client B's processes or
// stages, by id, in a list, with a cursor of B's, with a tenant sent in the query or in a header, or by
// guessing. The fixtures are built the way production builds them (a CEO creates the clients, the
// logins and the processes through the real routes and database functions; the logins change their
// temporary password through `POST /auth/password`); the one thing no route does yet, the "Ok" of Wave 9,
// is played by `tests/helpers/db.ts` (psql as the operator), never with the secret key.
//
// One CEO per group that writes a lot: a CEO has 60 writes a minute, refused ones included.
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  createClientOrFail,
  createClientViaApi,
  getClientViaApi,
  listClientsViaApi,
  updateClientViaApi,
} from '../helpers/clients';
import {
  getMyProcessViaApi,
  listAllMyProcesses,
  listMyProcessesViaApi,
  signedInClientLogin,
  type MyProcessDetailBody,
  type MyProcessListBody,
  type MyProcessSummaryBody,
  type SignedInClientLogin,
} from '../helpers/client-panel';
import {
  listClientUsersViaApi,
  provisionClientUserViaApi,
  provisionOrFail,
  uniqueLoginEmail,
  updateClientUserViaApi,
} from '../helpers/client-users';
import { expectToMatchContract } from '../helpers/contract';
import { POST as logoutRoute } from '@/app/api/v1/auth/logout/route';
import { GET as sessionRoute } from '@/app/api/v1/auth/session/route';
import {
  approveCurrentStageAsFixture,
  deleteProcessFixture,
  insertProcessesAtFixture,
  insertProcessWithoutStagesFixture,
} from '../helpers/db';
import {
  createCookieStore,
  invoke,
  observableHeaders,
  spyOnSupabaseFetch,
  textOf,
  withoutRequestId,
  type CookieStore,
} from '../helpers/http';
import { loginAsCeoWithMfa, type CeoWithMfa } from '../helpers/mfa';
import { publishableClient } from '../helpers/fixtures';
import { changePassword, jarOf, sessionJarFor } from '../helpers/password';
import {
  createProcessOrFail,
  createProcessViaApi,
  getProcessViaApi,
  getStageTemplateViaApi,
  listProcessesViaApi,
  uniqueProcessTitle,
  updateProcessViaApi,
  type ProcessDetailBody,
} from '../helpers/processes';

const UNKNOWN_ID = '00000000-0000-4000-8000-00000000dead';

/** Parses the body, checks it against the contract (headers too) and returns it. */
async function expectContract<T = unknown>(operationId: string, response: Response): Promise<T> {
  const text = await response.clone().text();
  const body: unknown = text === '' ? undefined : JSON.parse(text);
  expectToMatchContract(operationId, response.status, body, response);
  return body as T;
}

type Problem = {
  code: string;
  requestId?: string;
  detail?: string;
  errors?: { path: string; message: string }[];
};

/** Every member name of a JSON value, at any depth. */
function memberNames(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(memberNames);
  if (typeof value !== 'object' || value === null) return [];
  return Object.entries(value).flatMap(([name, inner]) => [name, ...memberNames(inner)]);
}

const SUMMARY_KEYS = [
  'completedAt',
  'completedStages',
  'createdAt',
  'currentStage',
  'id',
  'progressPercent',
  'status',
  'title',
  'totalStages',
  'updatedAt',
];
const DETAIL_KEYS = [...SUMMARY_KEYS, 'stages'].sort();
const STAGE_KEYS = ['completedAt', 'description', 'name', 'position', 'startedAt', 'status'];

/** Members that belong to the CEO's view, to a row or to the audit trail, and never to a client. */
const INTERNAL_MEMBERS = [
  'version',
  'clientId',
  'client_id',
  'client',
  'cancelledAt',
  'cancelled_at',
  'approval',
  'approvedBy',
  'approvedAt',
  'approver',
  'events',
  'actor',
  'actorId',
];

const idsOf = (items: readonly { id: string }[]) => items.map((item) => item.id);

// ------------------------------------------------------------------------------------ fixtures ----

type Tenant = { id: string; name: string };
type Panel = {
  tenant: Tenant;
  login: SignedInClientLogin;
  /** Newest first: how the list shows them. */
  processes: ProcessDetailBody[];
};

let ceo: CeoWithMfa;
/** Client A: two logins and four processes in four states. */
let a: Panel & {
  second: SignedInClientLogin;
  active: string;
  completed: string;
  cancelled: string;
  fresh: string;
};
/** Client B: one login and two processes, one with an approval. */
let b: Panel;
/** Client C: one login and no process at all. */
let empty: Omit<Panel, 'processes'>;

/**
 * Creates a process through the real function with `stageCount` named stages, plays `approvals` "Ok"s on
 * it, and cancels it when asked (the real `update_process`). Returns the id.
 */
async function buildProcess(
  tenantId: string,
  label: string,
  stages: { name: string; description?: string }[],
  options: { approvals?: number; cancel?: boolean } = {},
): Promise<string> {
  const created = await createProcessOrFail(ceo.cookies, tenantId, {
    title: uniqueProcessTitle(label),
    stages,
  });
  for (let done = 0; done < (options.approvals ?? 0); done += 1) {
    await approveCurrentStageAsFixture(created.id, ceo.ceo.id);
  }
  if (options.cancel === true) {
    const cancelled = await updateProcessViaApi(ceo.cookies, created.id, { status: 'cancelled' });
    if (cancelled.status !== 200) throw new Error(`cancel fixture failed with ${cancelled.status}`);
  }
  return created.id;
}

/** The CEO's view of a process: the truth the client panel is compared with. */
async function adminView(processId: string): Promise<ProcessDetailBody> {
  const response = await getProcessViaApi(ceo.cookies, processId);
  return expectContract<ProcessDetailBody>('getProcess', response);
}

const NAMED_STAGES = [
  { name: 'Contrato', description: 'Assinatura do contrato' },
  { name: 'Briefing' },
  { name: 'Planejamento', description: 'Cronograma e escopo' },
  { name: 'Entrega' },
];

beforeAll(async () => {
  ceo = await loginAsCeoWithMfa();

  const tenantA = await createClientOrFail(ceo.cookies);
  const tenantB = await createClientOrFail(ceo.cookies);
  const tenantC = await createClientOrFail(ceo.cookies);

  // Client A: the process in progress (one stage approved), the completed one, the cancelled one (it
  // stopped at stage 2) and the newest, with the default template and nothing approved.
  const active = await buildProcess(tenantA.id, 'A ativo', NAMED_STAGES, { approvals: 1 });
  const completed = await buildProcess(
    tenantA.id,
    'A concluido',
    [{ name: 'Uma' }, { name: 'Duas' }],
    {
      approvals: 2,
    },
  );
  const cancelled = await buildProcess(
    tenantA.id,
    'A cancelado',
    [{ name: 'Ideia' }, { name: 'Prototipo' }, { name: 'Lancamento' }],
    { approvals: 1, cancel: true },
  );
  const freshCreated = await createProcessOrFail(ceo.cookies, tenantA.id, {
    title: uniqueProcessTitle('A novo'),
  });
  const aProcesses = await Promise.all(
    [freshCreated.id, cancelled, completed, active].map((id) => adminView(id)),
  );
  a = {
    tenant: tenantA,
    login: await signedInClientLogin(ceo.cookies, tenantA.id),
    second: await signedInClientLogin(ceo.cookies, tenantA.id),
    processes: aProcesses,
    active,
    completed,
    cancelled,
    fresh: freshCreated.id,
  };

  // Client B: two processes, one with an approval, so its stages and its approval exist for A to want.
  const bFirst = await buildProcess(
    tenantB.id,
    'B primeiro',
    [{ name: 'Fase B1' }, { name: 'Fase B2' }],
    {
      approvals: 1,
    },
  );
  const bSecond = await buildProcess(tenantB.id, 'B segundo', [{ name: 'Fase B3' }]);
  b = {
    tenant: tenantB,
    login: await signedInClientLogin(ceo.cookies, tenantB.id),
    processes: await Promise.all([bSecond, bFirst].map((id) => adminView(id))),
  };

  empty = { tenant: tenantC, login: await signedInClientLogin(ceo.cookies, tenantC.id) };
});

// ------------------------------------------------------------------------------ GET /me/processes ----

describe('GET /me/processes', () => {
  it('AC-20: lists the own processes, newest first, with the current stage and the progress of each, as the contract says', async () => {
    const response = await listMyProcessesViaApi(a.login.cookies);
    const body = await expectContract<MyProcessListBody>('listMyProcesses', response);

    expect(response.status).toBe(200);
    expect(body.nextCursor).toBeNull();
    expect(idsOf(body.items)).toEqual(idsOf(a.processes));

    const byId = new Map(body.items.map((item) => [item.id, item]));
    expect(byId.get(a.fresh)).toMatchObject({
      status: 'active',
      totalStages: 6,
      completedStages: 0,
      progressPercent: 0,
      currentStage: { position: 1 },
      completedAt: null,
    });
    expect(byId.get(a.cancelled)).toMatchObject({
      status: 'cancelled',
      totalStages: 3,
      completedStages: 1,
      progressPercent: 33,
      currentStage: { position: 2, name: 'Prototipo' },
      completedAt: null,
    });
    expect(byId.get(a.completed)).toMatchObject({
      status: 'completed',
      totalStages: 2,
      completedStages: 2,
      progressPercent: 100,
      currentStage: null,
    });
    expect(byId.get(a.completed)?.completedAt).not.toBeNull();
    expect(byId.get(a.active)).toMatchObject({
      status: 'active',
      totalStages: 4,
      completedStages: 1,
      progressPercent: 25,
      currentStage: { position: 2, name: 'Briefing' },
    });
  });

  it('SEC-14: a 200 of the list carries Cache-Control: no-store, so no cache keeps what one client read', async () => {
    const response = await listMyProcessesViaApi(a.login.cookies);
    await expectContract<MyProcessListBody>('listMyProcesses', response);

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
  });

  it('AC-20: the list equals what the CEO sees of the same processes, minus the internal fields', async () => {
    const body = await expectContract<MyProcessListBody>(
      'listMyProcesses',
      await listMyProcessesViaApi(a.login.cookies),
    );

    for (const item of body.items) {
      const admin = a.processes.find((process) => process.id === item.id);
      expect(admin).toBeDefined();
      expect(item).toMatchObject({
        id: admin?.id,
        title: admin?.title,
        status: admin?.status,
        totalStages: admin?.totalStages,
        completedStages: admin?.completedStages,
        createdAt: admin?.createdAt,
        completedAt: admin?.completedAt,
      });
      expect(item.currentStage).toEqual(
        admin?.currentStage === null || admin?.currentStage === undefined
          ? null
          : { position: admin.currentStage.position, name: admin.currentStage.name },
      );
    }
  });

  it('AC-20: a row is exactly MyProcessSummary: no version, client id, stages, approvals or events, and no CEO anywhere in the response', async () => {
    const response = await listMyProcessesViaApi(a.login.cookies);
    const body = await expectContract<MyProcessListBody>('listMyProcesses', response);
    const text = await textOf(response);

    expect(body.items.length).toBeGreaterThanOrEqual(4);
    for (const item of body.items) expect(Object.keys(item).sort()).toEqual(SUMMARY_KEYS);
    expect(Object.keys(body).sort()).toEqual(['items', 'nextCursor']);
    const names = memberNames(body);
    for (const internal of [...INTERNAL_MEMBERS, 'stages']) expect(names).not.toContain(internal);
    // who gave the "Ok" and which client this is are nowhere in the bytes either
    expect(text).not.toContain(ceo.ceo.id);
    expect(text).not.toContain('CEO Teste');
    expect(text).not.toContain(a.tenant.id);
  });

  it('AC-20: the contract check fails a response that has a field more than the schema (additionalProperties: false)', async () => {
    const response = await listMyProcessesViaApi(a.login.cookies);
    const body = await expectContract<MyProcessListBody>('listMyProcesses', response);
    const [first] = body.items;
    if (first === undefined) throw new Error('the client has processes');

    for (const extra of [
      { version: 3 },
      { clientId: a.tenant.id },
      { cancelledAt: null },
      { approvedBy: { id: ceo.ceo.id } },
    ]) {
      const polluted = { ...body, items: [{ ...first, ...extra }, ...body.items.slice(1)] };
      expect(() => expectToMatchContract('listMyProcesses', 200, polluted, response)).toThrow();
    }
    expect(() =>
      expectToMatchContract('listMyProcesses', 200, { ...body, total: 4 }, response),
    ).toThrow();
  });

  it('AC-09: the list of A has nothing of B and the list of B nothing of A, whole pages of the two compared', async () => {
    const ofA = await listAllMyProcesses(a.login.cookies);
    const ofB = await listAllMyProcesses(b.login.cookies);

    expect(idsOf(ofA)).toEqual(idsOf(a.processes));
    expect(idsOf(ofB)).toEqual(idsOf(b.processes));
    expect(idsOf(ofA).filter((id) => idsOf(ofB).includes(id))).toEqual([]);
    const textOfA = JSON.stringify(ofA);
    const textOfB = JSON.stringify(ofB);
    for (const process of b.processes) expect(textOfA).not.toContain(process.title);
    for (const process of a.processes) expect(textOfB).not.toContain(process.title);
  });

  it('AC-09: both logins of a client read the same list: the tenant is the client, not the login', async () => {
    const first = await listAllMyProcesses(a.login.cookies);
    const second = await listAllMyProcesses(a.second.cookies);

    expect(idsOf(second)).toEqual(idsOf(first));
    expect(idsOf(second)).toEqual(idsOf(a.processes));
  });

  it('AC-20: a client that has no process gets an empty page and no cursor', async () => {
    const response = await listMyProcessesViaApi(empty.login.cookies);
    const body = await expectContract<MyProcessListBody>('listMyProcesses', response);

    expect(response.status).toBe(200);
    expect(body).toEqual({ items: [], nextCursor: null });
  });

  it('AC-09: a tenant sent in a header, in the query or as a client id does nothing: the list is the session’s', async () => {
    const withHeaders = await listMyProcessesViaApi(
      a.login.cookies,
      {},
      {
        headers: {
          'x-client-id': b.tenant.id,
          'x-tenant-id': b.tenant.id,
          'x-forwarded-client': b.tenant.id,
        },
      },
    );
    const body = await expectContract<MyProcessListBody>('listMyProcesses', withHeaders);

    expect(withHeaders.status).toBe(200);
    expect(idsOf(body.items)).toEqual(idsOf(a.processes));

    for (const query of [
      { clientId: b.tenant.id },
      { client_id: b.tenant.id },
      { tenant: b.tenant.id },
      { status: 'active' },
    ]) {
      const refused = await listMyProcessesViaApi(a.login.cookies, query);
      const problem = await expectContract<Problem>('listMyProcesses', refused);
      expect(refused.status).toBe(400);
      expect(problem.code).toBe('VALIDATION_ERROR');
      expect(problem.errors?.map((issue) => issue.path)).toEqual([
        `query.${Object.keys(query)[0]}`,
      ]);
    }
  });

  it('E-80: a limit out of range, or not a whole number, is a 400 on the query', async () => {
    for (const limit of ['0', '101', '-1', 'abc', '1e1', '2.5', ' 5']) {
      const response = await listMyProcessesViaApi(a.login.cookies, { limit });
      const problem = await expectContract<Problem>('listMyProcesses', response);

      expect(response.status).toBe(400);
      expect(problem.errors?.map((issue) => issue.path)).toEqual(['query.limit']);
    }
  });

  it('E-80: a cursor that is tampered, truncated, from the CEO’s list or out of the bounds of a timestamp is a 400 on the cursor', async () => {
    const page = await expectContract<MyProcessListBody>(
      'listMyProcesses',
      await listMyProcessesViaApi(a.login.cookies, { limit: '1' }),
    );
    const mine = page.nextCursor ?? '';
    expect(mine).not.toBe('');

    // the CEO's list of the client's processes mints a cursor of ITS kind: not valid here
    const admin = await expectContract<{ nextCursor: string | null }>(
      'listClientProcesses',
      await listProcessesViaApi(ceo.cookies, a.tenant.id, { limit: '1' }),
    );
    const cursors = [
      mine.slice(0, -4),
      `${mine}AAAA`,
      'not-a-cursor',
      admin.nextCursor ?? '',
      'A'.repeat(201),
    ];
    for (const cursor of cursors) {
      const response = await listMyProcessesViaApi(a.login.cookies, { cursor });
      const problem = await expectContract<Problem>('listMyProcesses', response);

      expect(response.status).toBe(400);
      expect(problem.code).toBe('VALIDATION_ERROR');
      expect(problem.errors?.map((issue) => issue.path)).toEqual(['query.cursor']);
    }
  });

  it('AC-09: a cursor minted for A, sent in B’s session, moves inside B’s rows and shows nothing of A', async () => {
    const page = await expectContract<MyProcessListBody>(
      'listMyProcesses',
      await listMyProcessesViaApi(a.login.cookies, { limit: '1' }),
    );
    expect(page.nextCursor).not.toBeNull();

    const forged = await expectContract<MyProcessListBody>(
      'listMyProcesses',
      await listMyProcessesViaApi(b.login.cookies, { cursor: page.nextCursor ?? '' }),
    );

    // whatever the position, B reads only what is B's
    for (const item of forged.items) expect(idsOf(b.processes)).toContain(item.id);
    for (const process of a.processes) expect(idsOf(forged.items)).not.toContain(process.id);
  });
});

// -------------------------------------------------------------------------------- pagination ----

describe('GET /me/processes: pagination', () => {
  const TIE_INSTANT = '2026-01-01T00:00:00.123456+00:00';
  let pagingCeo: CeoWithMfa;
  let paged: { tenant: Tenant; login: SignedInClientLogin; created: string[]; tied: string[] };
  let neighbour: { tenant: Tenant; tied: string[] };

  beforeAll(async () => {
    pagingCeo = await loginAsCeoWithMfa();
    const tenant = await createClientOrFail(pagingCeo.cookies);
    const created: string[] = [];
    for (let index = 1; index <= 5; index += 1) {
      const process = await createProcessOrFail(pagingCeo.cookies, tenant.id, {
        title: uniqueProcessTitle(`Pag ${index}`),
        stages: [{ name: 'Unica' }],
      });
      created.push(process.id);
    }
    const tied = await insertProcessesAtFixture(tenant.id, TIE_INSTANT, 3, 'Empate');

    // another client whose processes carry the SAME instant: they must never show up in a page of `tenant`
    const other = await createClientOrFail(pagingCeo.cookies);
    neighbour = {
      tenant: other,
      tied: await insertProcessesAtFixture(other.id, TIE_INSTANT, 3, 'Vizinho'),
    };
    paged = {
      tenant,
      login: await signedInClientLogin(pagingCeo.cookies, tenant.id),
      created,
      tied,
    };
  });

  it('AC-20: pages of 2 follow newest first, a tie in created_at broken by id, repeating and skipping nothing', async () => {
    const seen: MyProcessSummaryBody[] = [];
    const sizes: number[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 10; page += 1) {
      const response = await listMyProcessesViaApi(paged.login.cookies, {
        limit: '2',
        ...(cursor === undefined ? {} : { cursor }),
      });
      const body = await expectContract<MyProcessListBody>('listMyProcesses', response);
      expect(response.status).toBe(200);
      seen.push(...body.items);
      sizes.push(body.items.length);
      if (body.nextCursor === null) break;
      cursor = body.nextCursor;
    }

    // the five made through the API, the last one first, then the three tied, `id` ascending
    expect(idsOf(seen)).toEqual([...[...paged.created].reverse(), ...paged.tied]);
    expect(sizes).toEqual([2, 2, 2, 2]);
    expect(new Set(idsOf(seen)).size).toBe(seen.length);
  });

  it('AC-09: the neighbour whose processes tie with these ones never appears, in a page of any size', async () => {
    for (const limit of ['1', '2', '3', '100']) {
      const listed = await listAllMyProcesses(paged.login.cookies, { limit });
      expect(idsOf(listed)).toEqual([...[...paged.created].reverse(), ...paged.tied]);
      for (const id of neighbour.tied) expect(idsOf(listed)).not.toContain(id);
    }
  });

  it('AC-20: a limit of 1 walks eight pages and the last one has no cursor', async () => {
    const listed = await listAllMyProcesses(paged.login.cookies, { limit: '1' }, { maxPages: 8 });

    expect(listed).toHaveLength(8);
  });

  it('AC-20: the default page holds everything up to 50 and says there is no more', async () => {
    const response = await listMyProcessesViaApi(paged.login.cookies);
    const body = await expectContract<MyProcessListBody>('listMyProcesses', response);

    expect(body.items).toHaveLength(8);
    expect(body.nextCursor).toBeNull();
  });
});

// ---------------------------------------------------------------------- GET /me/processes/{id} ----

describe('GET /me/processes/{processId}', () => {
  it('AC-20: reads the own process with its stages in position order, as the contract says', async () => {
    const response = await getMyProcessViaApi(a.login.cookies, a.active);
    const body = await expectContract<MyProcessDetailBody>('getMyProcess', response);

    expect(response.status).toBe(200);
    expect(body).toMatchObject({
      id: a.active,
      status: 'active',
      totalStages: 4,
      completedStages: 1,
      progressPercent: 25,
      currentStage: { position: 2, name: 'Briefing' },
      completedAt: null,
    });
    expect(body.stages.map((stage) => [stage.position, stage.name, stage.status])).toEqual([
      [1, 'Contrato', 'completed'],
      [2, 'Briefing', 'in_progress'],
      [3, 'Planejamento', 'pending'],
      [4, 'Entrega', 'pending'],
    ]);
    expect(body.stages.map((stage) => stage.description)).toEqual([
      'Assinatura do contrato',
      null,
      'Cronograma e escopo',
      null,
    ]);
    expect(body.stages[0]?.startedAt).not.toBeNull();
    expect(body.stages[0]?.completedAt).not.toBeNull();
    expect(body.stages[1]?.startedAt).not.toBeNull();
    expect(body.stages[1]?.completedAt).toBeNull();
    expect(body.stages[2]).toMatchObject({ startedAt: null, completedAt: null });
  });

  it('SEC-14: a 200 of the detail carries Cache-Control: no-store, so no cache keeps what one client read', async () => {
    const response = await getMyProcessViaApi(a.login.cookies, a.active);
    await expectContract<MyProcessDetailBody>('getMyProcess', response);

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
  });

  it('AC-20: the detail equals what the CEO sees of the same process, minus the internal fields', async () => {
    for (const process of a.processes) {
      const response = await getMyProcessViaApi(a.login.cookies, process.id);
      const body = await expectContract<MyProcessDetailBody>('getMyProcess', response);
      const admin = await adminView(process.id);

      expect(body).toMatchObject({
        id: admin.id,
        title: admin.title,
        status: admin.status,
        totalStages: admin.totalStages,
        completedStages: admin.completedStages,
        createdAt: admin.createdAt,
        updatedAt: admin.updatedAt,
        completedAt: admin.completedAt,
      });
      expect(body.stages).toEqual(
        admin.stages.map((stage) => ({
          position: stage.position,
          name: stage.name,
          description: stage.description,
          status: stage.status,
          startedAt: stage.startedAt,
          completedAt: stage.completedAt,
        })),
      );
    }
  });

  it('AC-20: the detail has no approvedBy, no CEO id or name, no version, client id, stage id or event, in members or in bytes', async () => {
    const admin = await adminView(a.active);
    // the CEO's view DOES carry them: the checks below are not vacuous
    expect(admin.stages[0]?.approval?.approvedBy.id).toBe(ceo.ceo.id);
    expect(admin.version).toBeGreaterThanOrEqual(1);

    for (const process of [a.active, a.completed, a.cancelled]) {
      const response = await getMyProcessViaApi(a.login.cookies, process);
      const body = await expectContract<MyProcessDetailBody>('getMyProcess', response);
      const text = await textOf(response);

      expect(Object.keys(body).sort()).toEqual(DETAIL_KEYS);
      for (const stage of body.stages) expect(Object.keys(stage).sort()).toEqual(STAGE_KEYS);
      const names = memberNames(body);
      for (const internal of INTERNAL_MEMBERS) expect(names).not.toContain(internal);
      expect(text).not.toContain(ceo.ceo.id);
      expect(text).not.toContain('CEO Teste');
      expect(text).not.toContain(a.tenant.id);
      for (const stage of (await adminView(process)).stages) expect(text).not.toContain(stage.id);
    }
  });

  it('AC-20: the contract check fails a detail with a field more than the schema, in the process or in a stage', async () => {
    const response = await getMyProcessViaApi(a.login.cookies, a.active);
    const body = await expectContract<MyProcessDetailBody>('getMyProcess', response);
    const [firstStage, ...otherStages] = body.stages;
    if (firstStage === undefined) throw new Error('the process has stages');

    const approval = { approvedBy: { id: ceo.ceo.id, displayName: 'CEO Teste' }, approvedAt: 'x' };
    for (const polluted of [
      { ...body, version: 2 },
      { ...body, clientId: a.tenant.id },
      { ...body, events: [] },
      { ...body, stages: [{ ...firstStage, approval }, ...otherStages] },
      { ...body, stages: [{ ...firstStage, id: UNKNOWN_ID }, ...otherStages] },
    ]) {
      expect(() => expectToMatchContract('getMyProcess', 200, polluted, response)).toThrow();
    }
  });

  it('AC-20: a completed process is 100 percent with every stage completed and no current stage, and a cancelled one stays where it stopped', async () => {
    const completed = await expectContract<MyProcessDetailBody>(
      'getMyProcess',
      await getMyProcessViaApi(a.login.cookies, a.completed),
    );
    const cancelled = await expectContract<MyProcessDetailBody>(
      'getMyProcess',
      await getMyProcessViaApi(a.login.cookies, a.cancelled),
    );

    expect(completed).toMatchObject({
      status: 'completed',
      progressPercent: 100,
      currentStage: null,
    });
    expect(completed.completedAt).not.toBeNull();
    expect(completed.stages.map((stage) => stage.status)).toEqual(['completed', 'completed']);
    expect(cancelled).toMatchObject({
      status: 'cancelled',
      completedAt: null,
      progressPercent: 33,
      currentStage: { position: 2, name: 'Prototipo' },
    });
    expect(cancelled.stages.map((stage) => stage.status)).toEqual([
      'completed',
      'in_progress',
      'pending',
    ]);
  });

  it('E-05: the process of another client and a UUID that does not exist are the same 404 NOT_FOUND, answer for answer', async () => {
    const foreign = b.processes[0];
    if (foreign === undefined) throw new Error('B has processes');

    const ofB = await getMyProcessViaApi(a.login.cookies, foreign.id);
    const unknown = await getMyProcessViaApi(a.login.cookies, UNKNOWN_ID);
    const secondLogin = await getMyProcessViaApi(a.second.cookies, foreign.id);

    const [foreignBody, unknownBody, secondBody] = await Promise.all([
      expectContract<Problem>('getMyProcess', ofB),
      expectContract<Problem>('getMyProcess', unknown),
      expectContract<Problem>('getMyProcess', secondLogin),
    ]);
    expect([ofB.status, unknown.status, secondLogin.status]).toEqual([404, 404, 404]);
    expect(foreignBody.code).toBe('NOT_FOUND');
    // nothing but the request id tells the two apart: not the body, not a header
    expect(withoutRequestId(foreignBody)).toEqual(withoutRequestId(unknownBody));
    expect(withoutRequestId(secondBody)).toEqual(withoutRequestId(unknownBody));
    expect(observableHeaders(ofB)).toEqual(observableHeaders(unknown));
    // and the text names no title, client or id of B
    const text = JSON.stringify(foreignBody);
    expect(text).not.toContain(foreign.title);
    expect(text).not.toContain(b.tenant.id);
    expect(text).not.toContain(foreign.id);
  });

  it('AC-09: A reads none of B’s processes, by id, in any spelling of the id, and B still reads each of them', async () => {
    for (const process of b.processes) {
      for (const spelling of [process.id, process.id.toUpperCase()]) {
        const asA = await getMyProcessViaApi(a.login.cookies, spelling);
        const body = await expectContract<Problem>('getMyProcess', asA);
        expect(asA.status).toBe(404);
        expect(body.code).toBe('NOT_FOUND');
      }
      const asB = await getMyProcessViaApi(b.login.cookies, process.id);
      expect(asB.status).toBe(200);
      expect(await expectContract<MyProcessDetailBody>('getMyProcess', asB)).toMatchObject({
        id: process.id,
        title: process.title,
      });
    }
    // and the other way round
    for (const process of a.processes) {
      const asB = await getMyProcessViaApi(b.login.cookies, process.id);
      const body = await expectContract<Problem>('getMyProcess', asB);
      expect(asB.status).toBe(404);
      expect(body.code).toBe('NOT_FOUND');
    }
  });

  it('AC-09: a tenant sent in the query or in a header does not open the process of another client', async () => {
    const foreign = b.processes[0];
    if (foreign === undefined) throw new Error('B has processes');

    for (const extras of [
      { query: { clientId: b.tenant.id } },
      { query: { client_id: b.tenant.id, tenant: b.tenant.id } },
      { headers: { 'x-client-id': b.tenant.id, 'x-tenant-id': b.tenant.id } },
    ]) {
      const response = await getMyProcessViaApi(a.login.cookies, foreign.id, extras);
      expect(response.status).toBe(404);
      expect((await expectContract<Problem>('getMyProcess', response)).code).toBe('NOT_FOUND');
    }
  });

  it('E-06: a malformed processId is a 400 VALIDATION_ERROR that names the id, never a 404', async () => {
    for (const processId of [
      'not-a-uuid',
      '123',
      `${UNKNOWN_ID}0`,
      UNKNOWN_ID.slice(1),
      `${UNKNOWN_ID} `,
      '00000000-0000-0000-0000-000000000000x',
    ]) {
      const response = await getMyProcessViaApi(a.login.cookies, processId);
      const problem = await expectContract<Problem>('getMyProcess', response);

      expect(response.status).toBe(400);
      expect(problem.code).toBe('VALIDATION_ERROR');
      expect(problem.errors?.map((issue) => issue.path)).toEqual(['params.processId']);
    }
  });
});

// ------------------------------------------------------------------------- who may call what ----

describe('who may read the client panel', () => {
  it('AC-21, E-07: a client user in /admin/* is 403 FORBIDDEN, on every operation, and what the CEO keeps is untouched', async () => {
    const cookies = a.login.cookies;
    const before = await adminView(a.active);

    const answers = [
      ['listClients', await listClientsViaApi(cookies)],
      ['getClient', await getClientViaApi(cookies, a.tenant.id)],
      ['createClient', await createClientViaApi(cookies, { name: 'Invasor' })],
      ['listClientProcesses', await listProcessesViaApi(cookies, a.tenant.id)],
      ['createProcess', await createProcessViaApi(cookies, a.tenant.id, { title: 'Invasor' })],
      ['getProcess', await getProcessViaApi(cookies, a.active)],
      ['updateProcess', await updateProcessViaApi(cookies, a.active, { status: 'cancelled' })],
      ['getDefaultStageTemplate', await getStageTemplateViaApi(cookies)],
      ['listClientUsers', await listClientUsersViaApi(cookies, a.tenant.id)],
      [
        'provisionClientUser',
        await provisionClientUserViaApi(cookies, a.tenant.id, {
          email: uniqueLoginEmail('invasor'),
          displayName: 'Invasor',
        }),
      ],
    ] as const;

    for (const [operationId, response] of answers) {
      const body = await expectContract<Problem>(operationId, response);
      expect([operationId, response.status, body.code]).toEqual([operationId, 403, 'FORBIDDEN']);
    }
    expect(await adminView(a.active)).toEqual(before);
  });

  it('AC-21, E-07: a CEO in /me/* is 403 FORBIDDEN, on the list and on the detail, even for the id of a real process', async () => {
    const list = await listMyProcessesViaApi(ceo.cookies);
    const detail = await getMyProcessViaApi(ceo.cookies, a.active);
    const unknown = await getMyProcessViaApi(ceo.cookies, UNKNOWN_ID);

    const [listBody, detailBody, unknownBody] = await Promise.all([
      expectContract<Problem>('listMyProcesses', list),
      expectContract<Problem>('getMyProcess', detail),
      expectContract<Problem>('getMyProcess', unknown),
    ]);
    expect([list.status, detail.status, unknown.status]).toEqual([403, 403, 403]);
    expect([listBody.code, detailBody.code, unknownBody.code]).toEqual([
      'FORBIDDEN',
      'FORBIDDEN',
      'FORBIDDEN',
    ]);
    // a CEO is told the same thing for a real id and a made-up one, and is shown no process
    expect(withoutRequestId(detailBody)).toEqual(withoutRequestId(unknownBody));
  });

  it('SEC-01: without a session, or with a cookie that is not one, both routes are 401 UNAUTHENTICATED', async () => {
    const forged = createCookieStore({ '__Host-rt-session': 'base64-bm90LWEtc2Vzc2lvbg' });

    for (const cookies of [undefined, createCookieStore(), forged]) {
      const list = await listMyProcessesViaApi(cookies);
      const detail = await getMyProcessViaApi(cookies, a.active);

      expect((await expectContract<Problem>('listMyProcesses', list)).code).toBe('UNAUTHENTICATED');
      expect((await expectContract<Problem>('getMyProcess', detail)).code).toBe('UNAUTHENTICATED');
      expect([list.status, detail.status]).toEqual([401, 401]);
    }
  });

  /** `POST /auth/logout` through the real route: how a browser ends its session. */
  const logout = (cookies: CookieStore) =>
    invoke(logoutRoute, { method: 'POST', path: '/auth/logout', cookies });

  it('AC-04: after logout the old cookie is 401 UNAUTHENTICATED on GET /me/processes, with the JWT still valid', async () => {
    const login = await signedInClientLogin(ceo.cookies, a.tenant.id);
    const oldCookie = login.cookies.clone();
    const before = await listMyProcessesViaApi(oldCookie);
    await expectContract<MyProcessListBody>('listMyProcesses', before);
    expect(before.status).toBe(200);

    const loggedOut = await logout(login.cookies);
    expectToMatchContract('logout', 204, undefined, loggedOut);
    expect(loggedOut.status).toBe(204);

    const reused = await listMyProcessesViaApi(oldCookie);
    const body = await expectContract<Problem>('listMyProcesses', reused);
    expect(reused.status).toBe(401);
    expect(body.code).toBe('UNAUTHENTICATED');
  });

  it('AC-04: after logout the old cookie is 401 UNAUTHENTICATED on GET /me/processes/{processId}, with the JWT still valid', async () => {
    const login = await signedInClientLogin(ceo.cookies, a.tenant.id);
    const oldCookie = login.cookies.clone();
    const before = await getMyProcessViaApi(oldCookie, a.active);
    await expectContract<MyProcessDetailBody>('getMyProcess', before);
    expect(before.status).toBe(200);

    const loggedOut = await logout(login.cookies);
    expectToMatchContract('logout', 204, undefined, loggedOut);
    expect(loggedOut.status).toBe(204);

    const reused = await getMyProcessViaApi(oldCookie, a.active);
    const body = await expectContract<Problem>('getMyProcess', reused);
    expect(reused.status).toBe(401);
    expect(body.code).toBe('UNAUTHENTICATED');
  });

  it('E-81: a client that still has the temporary password is 403 PASSWORD_CHANGE_REQUIRED on both routes, and is let in after the change', async () => {
    const created = await provisionOrFail(ceo.cookies, a.tenant.id);
    const jar = await sessionJarFor({
      email: created.user.email,
      password: created.temporaryPassword,
    });

    const list = await listMyProcessesViaApi(jar);
    const detail = await getMyProcessViaApi(jar, a.active);

    expect((await expectContract<Problem>('listMyProcesses', list)).code).toBe(
      'PASSWORD_CHANGE_REQUIRED',
    );
    expect((await expectContract<Problem>('getMyProcess', detail)).code).toBe(
      'PASSWORD_CHANGE_REQUIRED',
    );
    expect([list.status, detail.status]).toEqual([403, 403]);

    const changed = await changePassword(jar, {
      currentPassword: created.temporaryPassword,
      newPassword: `Panel-${randomUUID()}`,
    });
    expect(changed.status).toBe(204);
    const opened = await listMyProcessesViaApi(jar);
    const body = await expectContract<MyProcessListBody>('listMyProcesses', opened);
    expect(opened.status).toBe(200);
    expect(idsOf(body.items)).toEqual(idsOf(a.processes));
  });

  it('F-83: straight through PostgREST, a client that still has the temporary password reads nothing of the tracking tables, its session still shows the client, and the same login reads after the change', async () => {
    const created = await provisionOrFail(ceo.cookies, a.tenant.id);
    const supabase = publishableClient();
    const signIn = await supabase.auth.signInWithPassword({
      email: created.user.email,
      password: created.temporaryPassword,
    });
    if (signIn.error || signIn.data.session === null) throw new Error('sign-in fixture failed');
    const jar = jarOf(signIn.data.session);

    // the BFF still knows the principal and names the client: the first access and the change depend on it
    const session = await invoke(sessionRoute, { path: '/auth/session', cookies: jar });
    const sessionBody = await expectContract<{
      client: { id: string; name: string } | null;
      pendingActions: string[];
    }>('getSession', session);
    expect(session.status).toBe(200);
    expect(sessionBody.client).toEqual({ id: a.tenant.id, name: a.tenant.name });
    expect(sessionBody.pendingActions).toEqual(['CHANGE_PASSWORD']);

    // ...but the same JWT, straight at PostgREST, gets no row of any tracking table, not its own client's
    const processes = await supabase.from('processes').select('id');
    const stages = await supabase.from('process_stages').select('id');
    const clients = await supabase.from('clients').select('id');
    const approvals = await supabase.from('stage_approvals').select('id');
    expect([processes.error, stages.error, clients.error, approvals.error]).toEqual([
      null,
      null,
      null,
      null,
    ]);
    expect([processes.data, stages.data, clients.data, approvals.data]).toEqual([[], [], [], []]);

    const changed = await changePassword(jar, {
      currentPassword: created.temporaryPassword,
      newPassword: `Panel-${randomUUID()}`,
    });
    expect(changed.status).toBe(204);

    // the pending password was the only difference: the same session now reads its own tenant, and only it
    const after = await supabase.from('processes').select('id');
    expect(after.error).toBeNull();
    expect((after.data ?? []).map((row) => row.id).sort()).toEqual(idsOf(a.processes).sort());
    const own = await supabase.from('clients').select('id');
    expect(own.data).toEqual([{ id: a.tenant.id }]);
  });

  it('E-08: a login that a CEO disables is 401 on the next read, with the JWT still valid, and the other login of the client keeps reading', async () => {
    const tenant = await createClientOrFail(ceo.cookies);
    const doomed = await signedInClientLogin(ceo.cookies, tenant.id);
    const keeper = await signedInClientLogin(ceo.cookies, tenant.id);
    const process = await createProcessOrFail(ceo.cookies, tenant.id);
    const before = await listMyProcessesViaApi(doomed.cookies);
    await expectContract<MyProcessListBody>('listMyProcesses', before);
    expect(before.status).toBe(200);

    const disabled = await updateClientUserViaApi(ceo.cookies, tenant.id, doomed.userId, {
      disabled: true,
    });
    await expectContract('updateClientUser', disabled);
    expect(disabled.status).toBe(200);

    for (const [operationId, response] of [
      ['listMyProcesses', await listMyProcessesViaApi(doomed.cookies)],
      ['getMyProcess', await getMyProcessViaApi(doomed.cookies, process.id)],
    ] as const) {
      const body = await expectContract<Problem>(operationId, response);
      expect(response.status).toBe(401);
      expect(body.code).toBe('UNAUTHENTICATED');
    }
    const kept = await getMyProcessViaApi(keeper.cookies, process.id);
    await expectContract<MyProcessDetailBody>('getMyProcess', kept);
    expect(kept.status).toBe(200);
  });

  it('E-83: an archived client keeps reading the processes it already has, on the list and on the detail', async () => {
    const tenant = await createClientOrFail(ceo.cookies);
    const login = await signedInClientLogin(ceo.cookies, tenant.id);
    const process = await createProcessOrFail(ceo.cookies, tenant.id);

    const archived = await updateClientViaApi(ceo.cookies, tenant.id, { archived: true });
    await expectContract('updateClient', archived);
    expect(archived.status).toBe(200);

    const listed = await listMyProcessesViaApi(login.cookies);
    const list = await expectContract<MyProcessListBody>('listMyProcesses', listed);
    const detail = await getMyProcessViaApi(login.cookies, process.id);
    const detailBody = await expectContract<MyProcessDetailBody>('getMyProcess', detail);
    expect(listed.status).toBe(200);
    expect(idsOf(list.items)).toEqual([process.id]);
    expect(detail.status).toBe(200);
    expect(detailBody.id).toBe(process.id);
  });
});

// ----------------------------------------------------------------------------- failure modes ----

describe('the client panel when the data or the database is not healthy', () => {
  /** Processes without stages that the tests below made: removed afterwards, so no corrupt row is left behind. */
  const strayProcessIds: string[] = [];

  afterAll(async () => {
    for (const id of strayProcessIds) await deleteProcessFixture(id);
  });

  it('E-82: a process with no stage fails the read closed (500 INTERNAL_ERROR, nothing of it shown), the list and the detail, and no other client is affected', async () => {
    const tenant = await createClientOrFail(ceo.cookies);
    const login = await signedInClientLogin(ceo.cookies, tenant.id);
    const healthy = await createProcessOrFail(ceo.cookies, tenant.id);
    const brokenId = await insertProcessWithoutStagesFixture(tenant.id, 'Sem fases');
    strayProcessIds.push(brokenId);

    const list = await listMyProcessesViaApi(login.cookies);
    const detail = await getMyProcessViaApi(login.cookies, brokenId);
    const healthyDetail = await getMyProcessViaApi(login.cookies, healthy.id);

    const [listBody, detailBody] = await Promise.all([
      expectContract<Problem>('listMyProcesses', list),
      expectContract<Problem>('getMyProcess', detail),
    ]);
    expect([list.status, detail.status]).toEqual([500, 500]);
    expect([listBody.code, detailBody.code]).toEqual(['INTERNAL_ERROR', 'INTERNAL_ERROR']);
    expect(JSON.stringify([listBody, detailBody])).not.toContain('Sem fases');
    expect(JSON.stringify([listBody, detailBody])).not.toContain(brokenId);
    // the healthy process of the same client is still readable by id, and other clients are untouched
    await expectContract<MyProcessDetailBody>('getMyProcess', healthyDetail);
    expect(healthyDetail.status).toBe(200);
    const others = await listMyProcessesViaApi(a.login.cookies);
    await expectContract<MyProcessListBody>('listMyProcesses', others);
    expect(others.status).toBe(200);

    // the failure is the DATA: once the corrupt row is gone, the same client reads its list again
    expect(await deleteProcessFixture(brokenId)).toBe(true);
    const recovered = await listMyProcessesViaApi(login.cookies);
    const recoveredBody = await expectContract<MyProcessListBody>('listMyProcesses', recovered);
    expect(recovered.status).toBe(200);
    expect(idsOf(recoveredBody.items)).toEqual([healthy.id]);
  });

  it('E-21: both routes answer 503 SERVICE_UNAVAILABLE with a Retry-After, not a 500, when the database cannot be reached', async () => {
    const spy = spyOnSupabaseFetch((url) =>
      url.includes('/rest/v1/processes') ? new TypeError('fetch failed') : undefined,
    );
    try {
      for (const [operationId, response] of [
        ['listMyProcesses', await listMyProcessesViaApi(a.login.cookies)],
        ['getMyProcess', await getMyProcessViaApi(a.login.cookies, a.active)],
      ] as const) {
        const body = await expectContract<Problem>(operationId, response);
        expect(response.status).toBe(503);
        expect(body.code).toBe('SERVICE_UNAVAILABLE');
        expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
      }
    } finally {
      spy.restore();
    }
  });
});

// -------------------------------------------------------------------------------- rate limit ----

describe('the rate limit of the client panel (x-rate-limit: 300 / min per user)', () => {
  const READ_LIMIT = 300;
  const BATCH = 30;
  /** More than two windows of reads: a minute boundary in the middle cannot hide the cap. */
  const MAX_READS = READ_LIMIT * 2 + BATCH;

  it('SEC-09: the read after the 300th in a minute is 429 RATE_LIMITED with a Retry-After, and the budget is the login’s own', async () => {
    const tenant = await createClientOrFail(ceo.cookies);
    const limited = await signedInClientLogin(ceo.cookies, tenant.id);
    const bystander = await signedInClientLogin(ceo.cookies, tenant.id);

    const throttled: Response[] = [];
    let ok = 0;
    for (let sent = 0; sent < MAX_READS && throttled.length === 0; sent += BATCH) {
      const batch = await Promise.all(
        Array.from({ length: BATCH }, () => listMyProcessesViaApi(limited.cookies)),
      );
      for (const response of batch) {
        if (response.status === 429) throttled.push(response);
        else if (response.status === 200) ok += 1;
        else throw new Error(`a read answered ${response.status}, neither 200 nor 429`);
      }
    }

    expect(throttled.length).toBeGreaterThanOrEqual(1);
    expect(ok).toBeGreaterThanOrEqual(1);
    expect(ok).toBeLessThanOrEqual(READ_LIMIT * 2);
    for (const response of throttled) {
      const body = await expectContract<Problem>('listMyProcesses', response);
      expect(body.code).toBe('RATE_LIMITED');
      const retryAfter = Number(response.headers.get('retry-after'));
      expect(retryAfter).toBeGreaterThanOrEqual(1);
      expect(retryAfter).toBeLessThanOrEqual(60);
    }
    // the counter is shared by the two reads of the panel: the detail of the same login is throttled too
    const detail = await getMyProcessViaApi(limited.cookies, UNKNOWN_ID);
    const detailBody = await expectContract<Problem>('getMyProcess', detail);
    expect(detail.status).toBe(429);
    expect(detailBody.code).toBe('RATE_LIMITED');
    const detailRetryAfter = Number(detail.headers.get('retry-after'));
    expect(detailRetryAfter).toBeGreaterThanOrEqual(1);
    expect(detailRetryAfter).toBeLessThanOrEqual(60);
    // another login of the same client has a budget of its own
    const other = await listMyProcessesViaApi(bystander.cookies);
    expect(other.status).toBe(200);
    expect((await expectContract<MyProcessListBody>('listMyProcesses', other)).items).toEqual([]);
  }, 180_000);
});

// ----------------------------------------------------------------------------------- fixtures ----

describe('the psql fixtures of tests/helpers/db.ts, against the database (F-103)', () => {
  it('F-103: the approval fixture refuses a process that is not active, says why, and leaves it exactly as it was', async () => {
    const view = async (processId: string) =>
      expectContract<MyProcessDetailBody>(
        'getMyProcess',
        await getMyProcessViaApi(a.login.cookies, processId),
      );
    const cancelledBefore = await view(a.cancelled);
    const completedBefore = await view(a.completed);

    await expect(approveCurrentStageAsFixture(a.cancelled, ceo.ceo.id)).rejects.toThrow(
      'the fixture was refused: the process is not active',
    );
    await expect(approveCurrentStageAsFixture(a.completed, ceo.ceo.id)).rejects.toThrow(
      'the fixture was refused: the process is not active',
    );

    expect(await view(a.cancelled)).toEqual(cancelledBefore);
    expect(await view(a.completed)).toEqual(completedBefore);
  });

  it('F-103: the approval fixture refuses a process that does not exist, and the delete fixture says there was nothing to delete', async () => {
    await expect(approveCurrentStageAsFixture(UNKNOWN_ID, ceo.ceo.id)).rejects.toThrow(
      'the fixture was refused: the process is not active',
    );
    expect(await deleteProcessFixture(UNKNOWN_ID)).toBe(false);
  });
});
