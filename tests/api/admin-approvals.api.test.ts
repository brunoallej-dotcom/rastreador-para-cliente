// API tests of the "Ok" and of the timeline (operationIds `approveCurrentStage` and `listProcessEvents`):
// the real route modules, the real pipeline and wiring (Postgres rate limiter, Supabase resolver), the
// local Supabase (Auth + PostgREST + the database functions), and every response checked against the
// OpenAPI contract, headers included.
//
// The CEOs are real ones: each changed the temporary password, logged in through the API, enrolled TOTP
// and verified a code, so its cookies are an `aal2` session the backend attested (tests/helpers/mfa.ts).
// A CEO has 60 writes a minute, refused ones included, so each group has CEOs of its own.
//
// The concurrency tests do not hope for an interleaving. They take the process row lock in a second
// database session (tests/helpers/held-transaction.ts), fire the requests, wait until the database says
// every one of them is parked on that lock, and only then let go. What follows is decided by the
// database, and it is the same on every run: that is what makes "exactly one approval wins" (AC-17) and
// the lock order of F-82 provable without a sleep. Files of this project run one at a time and the
// local database is exclusive while they do, which `countLockWaiters` relies on.
import { beforeAll, describe, expect, it, vi } from 'vitest';
import {
  approveCurrentStage as predictApproval,
  type Process,
} from '@/modules/tracking/domain/process';
import { encodeCursor } from '@/shared/http';
import { expectToMatchContract } from '../helpers/contract';
import {
  createClient,
  createClientUser,
  createCeo,
  directAal2Session,
  publishableClient,
} from '../helpers/fixtures';
import { bodyOf, spyOnSupabaseFetch, type CookieStore } from '../helpers/http';
import {
  approvalRowsOf,
  approveViaApi,
  auditIdsOfProcess,
  listAllEvents,
  listEventsViaApi,
  loginAsNamedCeo,
  toDomainProcess,
  type ProcessEventBody,
  type ProcessEventListBody,
} from '../helpers/approvals';
import {
  ceoIdentityOf,
  openHeldTransaction,
  waitForLockWaiters,
} from '../helpers/held-transaction';
import {
  completeFirstAccess,
  loginAsCeoReadyToEnroll,
  loginViaApi,
  signInCeoWithMfa,
  type CeoWithMfa,
} from '../helpers/mfa';
import {
  auditOfProcess,
  createProcessOrFail,
  getProcessViaApi,
  processRowOf,
  stageInputs,
  stageRowsOf,
  uniqueProcessTitle,
  updateProcessViaApi,
  type ProcessDetailBody,
} from '../helpers/processes';

const UNKNOWN_ID = '00000000-0000-4000-8000-00000000dead';
const MAX_BIGINT = '9223372036854775807';

type Problem = {
  code: string;
  requestId?: string;
  detail?: string;
  errors?: { path: string; message: string }[];
  currentStageId?: string | null;
};

/** Parses the body, checks it against the contract (headers too) and returns it. */
async function expectContract<T = unknown>(operationId: string, response: Response): Promise<T> {
  const text = await response.clone().text();
  const body: unknown = text === '' ? undefined : JSON.parse(text);
  expectToMatchContract(operationId, response.status, body, response);
  return body as T;
}

/** The status and the code a refused request answered, for a failure message that says which. */
const outcomeOf = (response: Response, body: Problem) => [response.status, body.code];

/** The stage at `position` (1-based) of a process body; fails the test if there is none. */
function stageAt(process: ProcessDetailBody, position: number) {
  const stage = process.stages[position - 1];
  if (stage === undefined) throw new Error(`the process has no stage at position ${position}`);
  return stage;
}

/** A new active process of `count` stages, for a client of its own, created through the API. */
async function newProcess(cookies: CookieStore, count = 3): Promise<ProcessDetailBody> {
  const tenant = await createClient();
  return createProcessOrFail(cookies, tenant.id, {
    title: uniqueProcessTitle('Aprovar'),
    stages: stageInputs(count),
  });
}

/** The "Ok" for the stage at `position`: expects 200 and returns the process, contract-checked. */
async function approveOk(
  cookies: CookieStore,
  process: ProcessDetailBody,
  position: number,
): Promise<ProcessDetailBody> {
  const response = await approveViaApi(cookies, process.id, {
    expectedStageId: stageAt(process, position).id,
  });
  const body = await expectContract<ProcessDetailBody>('approveCurrentStage', response);
  expect(response.status).toBe(200);
  return body;
}

/** A 409 `STALE_STAGE` that names the stage that is current. */
async function expectStale(response: Response, currentStageId: string | null) {
  const body = await expectContract<Problem>('approveCurrentStage', response);
  expect(outcomeOf(response, body)).toEqual([409, 'STALE_STAGE']);
  expect(body.currentStageId).toBe(currentStageId);
}

/** A 422 `PROCESS_NOT_ACTIVE`. */
async function expectNotActive(response: Response) {
  const body = await expectContract<Problem>('approveCurrentStage', response);
  expect(outcomeOf(response, body)).toEqual([422, 'PROCESS_NOT_ACTIVE']);
}

/** What the database holds of a process: its row, its stages in order and its approvals. */
async function stateOf(processId: string) {
  return {
    row: await processRowOf(processId),
    stages: (await stageRowsOf(processId)).map((stage) => [stage.position, stage.status]),
    approvals: (await approvalRowsOf(processId)).map((row) => row.process_stage_id),
    audit: (await auditOfProcess(processId)).map((row) => row.action),
  };
}

// ----------------------------------------------------------------------------------------- the Ok ----

describe('POST /admin/processes/{processId}/approvals', () => {
  let ana: CeoWithMfa;
  let bia: CeoWithMfa;

  beforeAll(async () => {
    const suffix = uniqueProcessTitle('').trim();
    ana = await loginAsNamedCeo(`Ana ${suffix}`);
    bia = await loginAsNamedCeo(`Bia ${suffix}`);
  });

  describe('approving', () => {
    it('AC-16: the "Ok" completes the current stage and starts the next: 200 with the process, the approval names the CEO, and stage.approved is audited with the request id', async () => {
      const process = await newProcess(ana.cookies);
      const [first, second, third] = [
        stageAt(process, 1),
        stageAt(process, 2),
        stageAt(process, 3),
      ];

      const response = await approveViaApi(ana.cookies, process.id, { expectedStageId: first.id });
      const body = await expectContract<ProcessDetailBody>('approveCurrentStage', response);

      expect(response.status).toBe(200);
      expect(body).toMatchObject({
        id: process.id,
        status: 'active',
        version: 2,
        completedStages: 1,
        totalStages: 3,
        completedAt: null,
        cancelledAt: null,
        currentStage: { id: second.id, position: 2, name: second.name },
      });
      expect(body.stages.map((stage) => stage.status)).toEqual([
        'completed',
        'in_progress',
        'pending',
      ]);
      expect(body.stages[0]?.approval?.approvedBy).toEqual({
        id: ana.ceo.id,
        displayName: ana.ceo.displayName,
      });
      // one instant for the whole "Ok": the approval, the stage that closed, the one that began, the process
      const instant = body.stages[0]?.approval?.approvedAt;
      expect(instant).toBe(body.updatedAt);
      expect(body.stages[0]?.completedAt).toBe(instant);
      expect(body.stages[1]).toMatchObject({
        startedAt: instant,
        completedAt: null,
        approval: null,
      });
      expect(body.stages[2]).toMatchObject({ startedAt: null, completedAt: null, approval: null });
      expect(third.status).toBe('pending');

      // the response is the process as it is now
      const detail = await expectContract<ProcessDetailBody>(
        'getProcess',
        await getProcessViaApi(ana.cookies, process.id),
      );
      expect(detail).toEqual(body);

      const audit = await auditOfProcess(process.id);
      expect(audit.map((row) => row.action)).toEqual(['process.created', 'stage.approved']);
      expect(audit[1]).toEqual({
        action: 'stage.approved',
        actor_id: ana.ceo.id,
        actor_role: 'ceo',
        resource_type: 'stage',
        resource_id: first.id,
        client_id: process.clientId,
        process_id: process.id,
        request_id: response.headers.get('x-request-id'),
        metadata: {},
      });
      expect((await approvalRowsOf(process.id)).map((row) => row.approved_by)).toEqual([
        ana.ceo.id,
      ]);
    });

    it('AC-16: any CEO may give the "Ok": a second CEO approves the next stage, and each approval names its own CEO', async () => {
      const process = await newProcess(ana.cookies);

      const afterFirst = await approveOk(ana.cookies, process, 1);
      const afterSecond = await approveOk(bia.cookies, afterFirst, 2);

      expect(afterSecond).toMatchObject({ status: 'active', version: 3, completedStages: 2 });
      expect(
        afterSecond.stages.map((stage) => stage.approval?.approvedBy.displayName ?? null),
      ).toEqual([ana.ceo.displayName, bia.ceo.displayName, null]);
      expect(afterSecond.stages.map((stage) => stage.approval?.approvedBy.id ?? null)).toEqual([
        ana.ceo.id,
        bia.ceo.id,
        null,
      ]);
      expect(ana.ceo.displayName).not.toBe(bia.ceo.displayName);
      const actors = (await auditOfProcess(process.id)).map((row) => row.actor_id);
      expect(actors).toEqual([ana.ceo.id, ana.ceo.id, bia.ceo.id]);
    });

    it('AC-16, I6: the database function and the aggregate transition agree on every step, to the last approval', async () => {
      const approvers = [ana, bia, ana];
      let current = await newProcess(ana.cookies, 3);

      for (const approver of approvers) {
        const stage = current.stages.find((candidate) => candidate.status === 'in_progress');
        if (stage === undefined) throw new Error('no stage in progress');
        const before: Process = toDomainProcess(current);

        const response = await approveViaApi(approver.cookies, current.id, {
          expectedStageId: stage.id,
        });
        const after = await expectContract<ProcessDetailBody>('approveCurrentStage', response);
        expect(response.status).toBe(200);

        // the pure transition of tracking/domain/process.ts, at the instant the database used
        const predicted = predictApproval(before, {
          expectedStageId: stage.id,
          approver: {
            userId: approver.ceo.id,
            displayName: approver.ceo.displayName,
            role: 'ceo',
            aal: 'aal2',
          },
          at: new Date(after.updatedAt),
        });
        expect(predicted.ok).toBe(true);
        if (!predicted.ok) return;
        expect(predicted.value).toEqual(toDomainProcess(after));
        current = after;
      }
      expect(current).toMatchObject({ status: 'completed', version: 4, currentStage: null });
    });

    it('AC-16, I6: the refusals agree too: a stale stage and a finished process answer what the aggregate answers', async () => {
      const process = await newProcess(ana.cookies, 2);
      const afterFirst = await approveOk(ana.cookies, process, 1);
      const approver = {
        userId: ana.ceo.id,
        displayName: ana.ceo.displayName,
        role: 'ceo' as const,
        aal: 'aal2' as const,
      };
      const at = new Date();

      const staleApi = await approveViaApi(ana.cookies, process.id, {
        expectedStageId: stageAt(process, 1).id,
      });
      const stalePure = predictApproval(toDomainProcess(afterFirst), {
        expectedStageId: stageAt(process, 1).id,
        approver,
        at,
      });
      await expectStale(staleApi, stageAt(process, 2).id);
      expect(stalePure.ok).toBe(false);
      if (!stalePure.ok) {
        expect([stalePure.error.code, stalePure.error.extensions]).toEqual([
          'STALE_STAGE',
          { currentStageId: stageAt(process, 2).id },
        ]);
      }

      const done = await approveOk(ana.cookies, afterFirst, 2);
      const notActiveApi = await approveViaApi(ana.cookies, process.id, {
        expectedStageId: stageAt(process, 2).id,
      });
      const notActivePure = predictApproval(toDomainProcess(done), {
        expectedStageId: stageAt(process, 2).id,
        approver,
        at,
      });
      await expectNotActive(notActiveApi);
      expect(notActivePure.ok === false && notActivePure.error.code).toBe('PROCESS_NOT_ACTIVE');
    });

    it('AC-18: approving the last stage completes the process: completed, completedAt, no current stage, and stage.approved then process.completed are audited', async () => {
      const process = await newProcess(ana.cookies, 3);
      const afterFirst = await approveOk(ana.cookies, process, 1);
      const afterSecond = await approveOk(bia.cookies, afterFirst, 2);

      const response = await approveViaApi(ana.cookies, process.id, {
        expectedStageId: stageAt(process, 3).id,
      });
      const body = await expectContract<ProcessDetailBody>('approveCurrentStage', response);

      expect(response.status).toBe(200);
      expect(afterSecond.status).toBe('active');
      expect(body).toMatchObject({
        status: 'completed',
        version: 4,
        completedStages: 3,
        totalStages: 3,
        currentStage: null,
        cancelledAt: null,
      });
      expect(body.completedAt).toBe(body.updatedAt);
      expect(body.completedAt).toBe(body.stages[2]?.completedAt);
      expect(
        body.stages.every((stage) => stage.status === 'completed' && stage.approval !== null),
      ).toBe(true);
      expect(await stateOf(process.id)).toMatchObject({
        audit: [
          'process.created',
          'stage.approved',
          'stage.approved',
          'stage.approved',
          'process.completed',
        ],
      });
      // the two events of the last approval share the transaction, and so the request id
      const audit = await auditOfProcess(process.id);
      expect(audit.slice(-2).map((row) => [row.action, row.resource_type, row.request_id])).toEqual(
        [
          ['stage.approved', 'stage', response.headers.get('x-request-id')],
          ['process.completed', 'process', response.headers.get('x-request-id')],
        ],
      );
    });

    it('AC-18, E-03, E-02: after the last approval a new one is 422 PROCESS_NOT_ACTIVE, with the last stage or with any other, and changes nothing', async () => {
      const process = await newProcess(ana.cookies, 2);
      const afterFirst = await approveOk(ana.cookies, process, 1);
      await approveOk(ana.cookies, afterFirst, 2);
      const settled = await stateOf(process.id);

      for (const expectedStageId of [stageAt(process, 2).id, stageAt(process, 1).id, UNKNOWN_ID]) {
        await expectNotActive(await approveViaApi(ana.cookies, process.id, { expectedStageId }));
      }

      expect(await stateOf(process.id)).toEqual(settled);
      expect(settled.approvals).toHaveLength(2);
    });

    it('E-04: a process with a single stage is completed by the first approval', async () => {
      const process = await newProcess(ana.cookies, 1);

      const body = await approveOk(ana.cookies, process, 1);

      expect(body).toMatchObject({
        status: 'completed',
        version: 2,
        completedStages: 1,
        totalStages: 1,
        currentStage: null,
      });
      expect(body.completedAt).not.toBeNull();
      expect((await auditOfProcess(process.id)).map((row) => row.action)).toEqual([
        'process.created',
        'stage.approved',
        'process.completed',
      ]);
    });
  });

  describe('refusing what is not the current stage', () => {
    it('E-02: retrying an approval that was saved is 409 STALE_STAGE naming the next stage, and never advances a second stage', async () => {
      const process = await newProcess(ana.cookies, 3);
      const first = await approveOk(ana.cookies, process, 1);

      const retry = await approveViaApi(ana.cookies, process.id, {
        expectedStageId: stageAt(process, 1).id,
      });

      await expectStale(retry, stageAt(process, 2).id);
      const state = await stateOf(process.id);
      expect(state.row.version).toBe(2);
      expect(state.stages).toEqual([
        [1, 'completed'],
        [2, 'in_progress'],
        [3, 'pending'],
      ]);
      expect(state.approvals).toEqual([stageAt(process, 1).id]);
      expect(state.audit).toEqual(['process.created', 'stage.approved']);
      // the detail says the stage was completed, and by whom
      const detail = await expectContract<ProcessDetailBody>(
        'getProcess',
        await getProcessViaApi(bia.cookies, process.id),
      );
      expect(detail).toEqual(first);
      expect(detail.stages[0]?.approval?.approvedBy.id).toBe(ana.ceo.id);
    });

    it('E-01: a stage that is not the current one is 409 STALE_STAGE with the stage that is: a future stage, a completed one, another process and an unknown id', async () => {
      const process = await newProcess(ana.cookies, 3);
      const other = await newProcess(ana.cookies, 2);
      await approveOk(ana.cookies, process, 1);
      const settled = await stateOf(process.id);

      for (const expectedStageId of [
        stageAt(process, 3).id,
        stageAt(process, 1).id,
        stageAt(other, 1).id,
        UNKNOWN_ID,
      ]) {
        await expectStale(
          await approveViaApi(bia.cookies, process.id, { expectedStageId }),
          stageAt(process, 2).id,
        );
      }

      expect(await stateOf(process.id)).toEqual(settled);
      // the other process kept its own stage in progress
      expect((await stateOf(other.id)).stages).toEqual([
        [1, 'in_progress'],
        [2, 'pending'],
      ]);
    });

    it('E-03: approving a cancelled process is 422 PROCESS_NOT_ACTIVE (the stage id does not matter) and the stage stays in progress', async () => {
      const process = await newProcess(ana.cookies, 3);
      const afterFirst = await approveOk(ana.cookies, process, 1);
      const cancelled = await updateProcessViaApi(ana.cookies, process.id, { status: 'cancelled' });
      expect(cancelled.status).toBe(200);
      const settled = await stateOf(process.id);

      for (const expectedStageId of [
        stageAt(afterFirst, 2).id,
        stageAt(afterFirst, 1).id,
        UNKNOWN_ID,
      ]) {
        await expectNotActive(await approveViaApi(bia.cookies, process.id, { expectedStageId }));
      }

      expect(await stateOf(process.id)).toEqual(settled);
      expect(settled.row).toMatchObject({ status: 'cancelled', version: 3 });
      expect(settled.stages).toEqual([
        [1, 'completed'],
        [2, 'in_progress'],
        [3, 'pending'],
      ]);
      expect(settled.audit).toEqual(['process.created', 'stage.approved', 'process.cancelled']);
    });

    it('E-03: a process that was cancelled before any approval is 422 too, with its first stage as the expected one', async () => {
      const process = await newProcess(ana.cookies, 2);
      await updateProcessViaApi(ana.cookies, process.id, { status: 'cancelled' });

      await expectNotActive(
        await approveViaApi(bia.cookies, process.id, { expectedStageId: stageAt(process, 1).id }),
      );

      expect(await stateOf(process.id)).toMatchObject({
        stages: [
          [1, 'in_progress'],
          [2, 'pending'],
        ],
        approvals: [],
      });
    });
  });

  describe('validation', () => {
    it('an unknown process is 404 NOT_FOUND, and nothing is approved anywhere', async () => {
      const response = await approveViaApi(ana.cookies, UNKNOWN_ID, {
        expectedStageId: UNKNOWN_ID,
      });
      const body = await expectContract<Problem>('approveCurrentStage', response);

      expect(outcomeOf(response, body)).toEqual([404, 'NOT_FOUND']);
      expect(body.detail).toBe('Process not found.');
    });

    it('E-06: a malformed processId is 400 VALIDATION_ERROR that names the id', async () => {
      const response = await approveViaApi(ana.cookies, 'not-a-uuid', {
        expectedStageId: UNKNOWN_ID,
      });
      const body = await expectContract<Problem>('approveCurrentStage', response);

      expect(outcomeOf(response, body)).toEqual([400, 'VALIDATION_ERROR']);
      expect(body.errors?.map((issue) => issue.path)).toEqual(['params.processId']);
    });

    it('AC-23: a missing, malformed or unknown body field is 400 VALIDATION_ERROR on the body, and nothing is approved', async () => {
      const process = await newProcess(ana.cookies, 2);
      const settled = await stateOf(process.id);
      const bodies: unknown[] = [
        {},
        { expectedStageId: 'not-a-uuid' },
        { expectedStageId: 42 },
        { expectedStageId: null },
        { expectedStageId: stageAt(process, 1).id, approvedBy: ana.ceo.id },
        { expectedStageId: stageAt(process, 1).id, status: 'completed' },
        { expectedStageId: stageAt(process, 1).id, processId: process.id },
        [stageAt(process, 1).id],
      ];

      for (const body of bodies) {
        const response = await approveViaApi(ana.cookies, process.id, body);
        const problem = await expectContract<Problem>('approveCurrentStage', response);
        expect([JSON.stringify(body), ...outcomeOf(response, problem)]).toEqual([
          JSON.stringify(body),
          400,
          'VALIDATION_ERROR',
        ]);
        for (const issue of problem.errors ?? []) expect(issue.path).toMatch(/^body(\.|\[|$)/);
      }
      expect(await stateOf(process.id)).toEqual(settled);
    });

    it('E-14: a body that is not JSON is 415, one over 16 KiB is 413, and nothing is approved', async () => {
      const process = await newProcess(ana.cookies, 2);
      const settled = await stateOf(process.id);

      const notJson = await approveViaApi(ana.cookies, process.id, undefined, {
        headers: { 'content-type': 'text/plain' },
        rawBody: JSON.stringify({ expectedStageId: stageAt(process, 1).id }),
      });
      const tooBig = await approveViaApi(ana.cookies, process.id, undefined, {
        headers: { 'content-type': 'application/json' },
        rawBody: JSON.stringify({
          expectedStageId: stageAt(process, 1).id,
          pad: 'x'.repeat(17_000),
        }),
      });

      expect(
        outcomeOf(notJson, await expectContract<Problem>('approveCurrentStage', notJson)),
      ).toEqual([415, 'UNSUPPORTED_MEDIA_TYPE']);
      expect(
        outcomeOf(tooBig, await expectContract<Problem>('approveCurrentStage', tooBig)),
      ).toEqual([413, 'PAYLOAD_TOO_LARGE']);
      expect(await stateOf(process.id)).toEqual(settled);
    });
  });
});

// ------------------------------------------------------------------------------------ who may Ok ----

describe('who may give the "Ok"', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await loginAsNamedCeo(`Dani ${uniqueProcessTitle('').trim()}`);
  });

  /** The process a refused caller tries to approve, and what a refusal must leave as it was. */
  async function aProcess() {
    const process = await newProcess(ceo.cookies, 2);
    return { process, settled: await stateOf(process.id) };
  }

  it('SEC-01: without a session the approval is 401 UNAUTHENTICATED and nothing is approved', async () => {
    const { process, settled } = await aProcess();

    const response = await approveViaApi(undefined, process.id, {
      expectedStageId: stageAt(process, 1).id,
    });
    const body = await expectContract<Problem>('approveCurrentStage', response);

    expect(outcomeOf(response, body)).toEqual([401, 'UNAUTHENTICATED']);
    expect(await stateOf(process.id)).toEqual(settled);
  });

  it('AC-21: a client user is 403 FORBIDDEN, on a process of its own tenant too, and nothing is approved', async () => {
    const { process, settled } = await aProcess();
    const user = await completeFirstAccess(await createClientUser({ clientId: process.clientId }));
    const cookies = await loginViaApi(user);

    const response = await approveViaApi(cookies, process.id, {
      expectedStageId: stageAt(process, 1).id,
    });
    const body = await expectContract<Problem>('approveCurrentStage', response);

    expect(outcomeOf(response, body)).toEqual([403, 'FORBIDDEN']);
    expect(await stateOf(process.id)).toEqual(settled);
  });

  it('SEC-11: a CEO whose session is aal1, with a verified factor, is 403 MFA_VERIFICATION_REQUIRED', async () => {
    const { process, settled } = await aProcess();
    const cookies = await signInCeoWithMfa(ceo, { verify: false });

    const response = await approveViaApi(cookies, process.id, {
      expectedStageId: stageAt(process, 1).id,
    });
    const body = await expectContract<Problem>('approveCurrentStage', response);

    expect(outcomeOf(response, body)).toEqual([403, 'MFA_VERIFICATION_REQUIRED']);
    expect(await stateOf(process.id)).toEqual(settled);
  });

  it('SEC-11: a CEO with no TOTP factor is 403 MFA_ENROLLMENT_REQUIRED', async () => {
    const { process, settled } = await aProcess();
    const { cookies } = await loginAsCeoReadyToEnroll();

    const response = await approveViaApi(cookies, process.id, {
      expectedStageId: stageAt(process, 1).id,
    });
    const body = await expectContract<Problem>('approveCurrentStage', response);

    expect(outcomeOf(response, body)).toEqual([403, 'MFA_ENROLLMENT_REQUIRED']);
    expect(await stateOf(process.id)).toEqual(settled);
  });

  it('spec §3.5: a CEO who still has the temporary password is 403 PASSWORD_CHANGE_REQUIRED', async () => {
    const { process, settled } = await aProcess();
    const cookies = await loginViaApi(await createCeo());

    const response = await approveViaApi(cookies, process.id, {
      expectedStageId: stageAt(process, 1).id,
    });
    const body = await expectContract<Problem>('approveCurrentStage', response);

    expect(outcomeOf(response, body)).toEqual([403, 'PASSWORD_CHANGE_REQUIRED']);
    expect(await stateOf(process.id)).toEqual(settled);
  });

  it('AC-23, E-15: an approval without the allowed Origin is 403 ORIGIN_NOT_ALLOWED and nothing is approved', async () => {
    const { process, settled } = await aProcess();

    for (const origin of [null, 'https://evil.example']) {
      const response = await approveViaApi(
        ceo.cookies,
        process.id,
        { expectedStageId: stageAt(process, 1).id },
        { origin },
      );
      const body = await expectContract<Problem>('approveCurrentStage', response);
      expect(outcomeOf(response, body)).toEqual([403, 'ORIGIN_NOT_ALLOWED']);
    }
    expect(await stateOf(process.id)).toEqual(settled);
  });

  it('F-50 b: an aal2 session obtained straight at Auth does not run approve_current_stage, nor write stage_approvals', async () => {
    const { process, settled } = await aProcess();
    const direct = await directAal2Session(await createCeo());

    const call = await direct.supabase.rpc('approve_current_stage', {
      p_process_id: process.id,
      p_expected_stage_id: stageAt(process, 1).id,
    });
    const insert = await direct.supabase.from('stage_approvals').insert({
      process_stage_id: stageAt(process, 1).id,
      process_id: process.id,
      approved_by: ceo.ceo.id,
    });

    expect(call.error).toMatchObject({ code: '42501' });
    expect(insert.error).toMatchObject({ code: '42501' });
    expect(await stateOf(process.id)).toEqual(settled);
  });

  it('SEC-04: a CEO token cannot write the approval tables directly, only through the function', async () => {
    const { process, settled } = await aProcess();
    const supabase = publishableClient();
    const signIn = await supabase.auth.signInWithPassword({
      email: ceo.ceo.email,
      password: ceo.ceo.password,
    });
    expect(signIn.error).toBeNull();

    const insert = await supabase.from('stage_approvals').insert({
      process_stage_id: stageAt(process, 1).id,
      process_id: process.id,
      approved_by: ceo.ceo.id,
    });
    const complete = await supabase
      .from('process_stages')
      .update({ status: 'completed' })
      .eq('id', stageAt(process, 1).id);
    const call = await supabase.rpc('approve_current_stage', {
      p_process_id: process.id,
      p_expected_stage_id: stageAt(process, 1).id,
    });

    expect(insert.error?.code).toBe('42501');
    expect(complete.error?.code).toBe('42501');
    expect(call.error?.code).toBe('42501');
    expect(await stateOf(process.id)).toEqual(settled);
  });
});

describe('the rate limit of the approval (x-rate-limit: 60 / min per CEO)', () => {
  // A CEO of its own: the 60 writes it spends must not come out of the budget of any other test.
  it('SEC-09: the approval after the 60th in a minute is 429 RATE_LIMITED with a Retry-After, and the answer matches the contract', async () => {
    const spender = await loginAsNamedCeo(`Eli ${uniqueProcessTitle('').trim()}`);
    const limit = 60;

    for (let call = 0; call < limit; call += 1) {
      const response = await approveViaApi(spender.cookies, UNKNOWN_ID, {
        expectedStageId: UNKNOWN_ID,
      });
      if (response.status !== 404) throw new Error(`call ${call + 1} answered ${response.status}`);
    }
    const response = await approveViaApi(spender.cookies, UNKNOWN_ID, {
      expectedStageId: UNKNOWN_ID,
    });
    const body = await expectContract<Problem>('approveCurrentStage', response);

    expect(outcomeOf(response, body)).toEqual([429, 'RATE_LIMITED']);
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
  });
});

// -------------------------------------------------------------------------------- concurrency ----

describe('concurrent approvals and cancellations (AC-17, F-82)', () => {
  let creator: CeoWithMfa;
  let ana: CeoWithMfa;
  let bia: CeoWithMfa;

  beforeAll(async () => {
    const suffix = uniqueProcessTitle('').trim();
    creator = await loginAsNamedCeo(`Caio ${suffix}`);
    ana = await loginAsNamedCeo(`Ana ${suffix}`);
    bia = await loginAsNamedCeo(`Bia ${suffix}`);
  });

  it('AC-17: four approvals of the same stage, parked on the lock together, give exactly one 200 and three 409 STALE_STAGE naming the next stage', async () => {
    const process = await newProcess(creator.cookies, 3);
    const sessions = [ana, bia, ana, bia];
    const held = await openHeldTransaction();
    let responses: Response[];
    try {
      await held.lockProcess(process.id);
      const requests = sessions.map((session) =>
        approveViaApi(session.cookies, process.id, { expectedStageId: stageAt(process, 1).id }),
      );
      // every request is inside approve_current_stage, blocked on the row the second session holds
      await waitForLockWaiters('approve_current_stage', sessions.length);
      await held.commit();
      responses = await Promise.all(requests);
    } finally {
      held.abort();
    }

    expect(responses.map((response) => response.status).sort()).toEqual([200, 409, 409, 409]);
    for (const response of responses) {
      if (response.status === 200) {
        const body = await expectContract<ProcessDetailBody>('approveCurrentStage', response);
        expect(body).toMatchObject({ version: 2, completedStages: 1 });
      } else {
        await expectStale(response, stageAt(process, 2).id);
      }
    }
    const state = await stateOf(process.id);
    expect(state.row.version).toBe(2);
    expect(state.stages).toEqual([
      [1, 'completed'],
      [2, 'in_progress'],
      [3, 'pending'],
    ]);
    expect(state.approvals).toEqual([stageAt(process, 1).id]);
    expect(state.audit).toEqual(['process.created', 'stage.approved']);
  });

  it('AC-17: six approvals of the same stage fired at once, with no lock held, still give exactly one 200 and five 409 STALE_STAGE', async () => {
    const process = await newProcess(creator.cookies, 3);

    const responses = await Promise.all(
      [ana, bia, ana, bia, ana, bia].map((session) =>
        approveViaApi(session.cookies, process.id, { expectedStageId: stageAt(process, 1).id }),
      ),
    );

    expect(responses.map((response) => response.status).sort()).toEqual([
      200, 409, 409, 409, 409, 409,
    ]);
    for (const response of responses) {
      if (response.status === 409) await expectStale(response, stageAt(process, 2).id);
      else await expectContract<ProcessDetailBody>('approveCurrentStage', response);
    }
    expect(await stateOf(process.id)).toMatchObject({
      approvals: [stageAt(process, 1).id],
      audit: ['process.created', 'stage.approved'],
    });
  });

  it('F-82, AC-17: an approval parked behind another approval of the same stage is 409 STALE_STAGE naming the next stage, and the stage is approved once', async () => {
    const process = await newProcess(creator.cookies, 3);
    const winner = ceoIdentityOf(ana);
    const held = await openHeldTransaction();
    let response: Response;
    try {
      // the winner's REAL approve_current_stage, not committed: it holds the process lock
      await held.approveStage(winner, process.id, stageAt(process, 1).id);
      const queued = approveViaApi(bia.cookies, process.id, {
        expectedStageId: stageAt(process, 1).id,
      });
      await waitForLockWaiters('approve_current_stage', 1);
      await held.commit();
      response = await queued;
    } finally {
      held.abort();
    }

    await expectStale(response, stageAt(process, 2).id);
    const state = await stateOf(process.id);
    expect(state.approvals).toEqual([stageAt(process, 1).id]);
    expect((await approvalRowsOf(process.id)).map((row) => row.approved_by)).toEqual([ana.ceo.id]);
    expect(state.row.version).toBe(2);
  });

  it('F-82: an approval parked behind a cancellation that holds the lock sees the cancelled process: 422 PROCESS_NOT_ACTIVE, and nothing is approved', async () => {
    const process = await newProcess(creator.cookies, 3);
    const canceller = ceoIdentityOf(bia);
    const held = await openHeldTransaction();
    let response: Response;
    try {
      // the REAL update_process cancelling, not committed: it holds the process lock
      await held.cancelProcess(canceller, process.id);
      const queued = approveViaApi(ana.cookies, process.id, {
        expectedStageId: stageAt(process, 1).id,
      });
      await waitForLockWaiters('approve_current_stage', 1);
      await held.commit();
      response = await queued;
    } finally {
      held.abort();
    }

    // had the approval read the status before taking the lock, it would have completed a stage of a
    // process that was already cancelled (I4)
    await expectNotActive(response);
    const state = await stateOf(process.id);
    expect(state.row).toMatchObject({ status: 'cancelled', version: 2 });
    expect(state.stages).toEqual([
      [1, 'in_progress'],
      [2, 'pending'],
      [3, 'pending'],
    ]);
    expect(state.approvals).toEqual([]);
    expect(state.audit).toEqual(['process.created', 'process.cancelled']);
  });

  it('F-82: a cancellation parked behind an approval that holds the lock cancels afterwards: the stage was approved first, the next one stays in progress, and the trail shows the approval first', async () => {
    const process = await newProcess(creator.cookies, 3);
    const approver = ceoIdentityOf(ana);
    const held = await openHeldTransaction();
    let response: Response;
    try {
      // the REAL approve_current_stage, not committed: it holds the process lock
      await held.approveStage(approver, process.id, stageAt(process, 1).id);
      const queued = updateProcessViaApi(bia.cookies, process.id, { status: 'cancelled' });
      await waitForLockWaiters('update_process', 1);
      await held.commit();
      response = await queued;
    } finally {
      held.abort();
    }

    const body = await expectContract<ProcessDetailBody>('updateProcess', response);
    expect(response.status).toBe(200);
    expect(body).toMatchObject({ status: 'cancelled', version: 3, completedStages: 1 });
    expect(body.stages.map((stage) => stage.status)).toEqual([
      'completed',
      'in_progress',
      'pending',
    ]);
    expect(body.stages[0]?.approval?.approvedBy.id).toBe(ana.ceo.id);
    const state = await stateOf(process.id);
    expect(state.audit).toEqual(['process.created', 'stage.approved', 'process.cancelled']);
    expect(state.approvals).toEqual([stageAt(process, 1).id]);
  });

  it('F-82: approvals and cancellations racing on fresh processes always end in one of the two causal histories: never an approval after the cancellation, never a 500 or a deadlock', async () => {
    const rounds = 8;
    const histories: string[] = [];

    for (let round = 0; round < rounds; round += 1) {
      const process = await newProcess(creator.cookies, 3);
      const [approve, cancel] = await Promise.all([
        approveViaApi(ana.cookies, process.id, { expectedStageId: stageAt(process, 1).id }),
        updateProcessViaApi(bia.cookies, process.id, { status: 'cancelled' }),
      ]);

      // a cancel of an active process always succeeds, before or after the approval
      expect(cancel.status).toBe(200);
      const state = await stateOf(process.id);
      expect(state.row.status).toBe('cancelled');
      if (approve.status === 200) {
        // the approval took the lock first
        histories.push('approved-then-cancelled');
        expect(state.audit).toEqual(['process.created', 'stage.approved', 'process.cancelled']);
        expect(state.row.version).toBe(3);
        expect(state.stages).toEqual([
          [1, 'completed'],
          [2, 'in_progress'],
          [3, 'pending'],
        ]);
        expect(state.approvals).toEqual([stageAt(process, 1).id]);
      } else {
        // the cancellation took the lock first: the approval found a cancelled process
        histories.push('cancelled-then-refused');
        await expectNotActive(approve);
        expect(state.audit).toEqual(['process.created', 'process.cancelled']);
        expect(state.row.version).toBe(2);
        expect(state.stages).toEqual([
          [1, 'in_progress'],
          [2, 'pending'],
          [3, 'pending'],
        ]);
        expect(state.approvals).toEqual([]);
      }
    }
    expect(histories).toHaveLength(rounds);
  });
});

// ------------------------------------------------------------------------------------- timeline ----

describe('GET /admin/processes/{processId}/events', () => {
  let ana: CeoWithMfa;
  let bia: CeoWithMfa;

  beforeAll(async () => {
    const suffix = uniqueProcessTitle('').trim();
    ana = await loginAsNamedCeo(`Ana ${suffix}`);
    bia = await loginAsNamedCeo(`Bia ${suffix}`);
  });

  /** The ids of the events, as numbers a test can compare. */
  const idsOf = (events: ProcessEventBody[]) => events.map((event) => BigInt(event.id));

  const strictlyAscending = (ids: bigint[]) =>
    ids.every((id, index) => index === 0 || (ids[index - 1] ?? id) < id);

  /** A process with a history: created by Ana, renamed by Bia, two approvals (Ana, Bia), cancelled by Ana. */
  async function historyOfFive() {
    const tenant = await createClient();
    const firstTitle = uniqueProcessTitle('Linha do tempo');
    const secondTitle = uniqueProcessTitle('Linha renomeada');
    const created = await createProcessOrFail(ana.cookies, tenant.id, {
      title: firstTitle,
      stages: stageInputs(3),
    });
    expect(
      (await updateProcessViaApi(bia.cookies, created.id, { title: secondTitle })).status,
    ).toBe(200);
    const afterFirst = await approveOk(ana.cookies, created, 1);
    await approveOk(bia.cookies, afterFirst, 2);
    expect(
      (await updateProcessViaApi(ana.cookies, created.id, { status: 'cancelled' })).status,
    ).toBe(200);
    return { created, firstTitle, secondTitle };
  }

  it('AC-28: the timeline lists the events oldest first with the actor (id and name) and the stage of each approval', async () => {
    const { created } = await historyOfFive();

    const events = await listAllEvents(ana.cookies, created.id);

    expect(events.map((event) => event.action)).toEqual([
      'process.created',
      'process.updated',
      'stage.approved',
      'stage.approved',
      'process.cancelled',
    ]);
    expect(strictlyAscending(idsOf(events))).toBe(true);
    expect(events.map((event) => event.actor)).toEqual([
      { id: ana.ceo.id, displayName: ana.ceo.displayName },
      { id: bia.ceo.id, displayName: bia.ceo.displayName },
      { id: ana.ceo.id, displayName: ana.ceo.displayName },
      { id: bia.ceo.id, displayName: bia.ceo.displayName },
      { id: ana.ceo.id, displayName: ana.ceo.displayName },
    ]);
    expect(events.map((event) => event.details)).toEqual([
      {},
      {},
      { stageId: stageAt(created, 1).id, stagePosition: 1, stageName: stageAt(created, 1).name },
      { stageId: stageAt(created, 2).id, stagePosition: 2, stageName: stageAt(created, 2).name },
      {},
    ]);
    for (const event of events) {
      expect(new Date(event.occurredAt).toISOString()).toBe(event.occurredAt);
    }
    const instants = events.map((event) => Date.parse(event.occurredAt));
    expect(instants).toEqual([...instants].sort((a, b) => a - b));
    // the same events the audit trail holds, in the same order
    expect((await auditIdsOfProcess(created.id)).map((row) => String(row.id))).toEqual(
      events.map((event) => event.id),
    );
  });

  it('AC-28: the last approval adds stage.approved and process.completed, one transaction, one instant', async () => {
    const tenant = await createClient();
    const process = await createProcessOrFail(ana.cookies, tenant.id, {
      title: uniqueProcessTitle('Concluir'),
      stages: stageInputs(2),
    });
    const afterFirst = await approveOk(ana.cookies, process, 1);
    await approveOk(bia.cookies, afterFirst, 2);

    const events = await listAllEvents(ana.cookies, process.id);

    expect(events.map((event) => event.action)).toEqual([
      'process.created',
      'stage.approved',
      'stage.approved',
      'process.completed',
    ]);
    const [, , lastApproval, completed] = events;
    expect(lastApproval?.details).toEqual({
      stageId: stageAt(process, 2).id,
      stagePosition: 2,
      stageName: stageAt(process, 2).name,
    });
    expect(completed).toMatchObject({
      actor: { id: bia.ceo.id, displayName: bia.ceo.displayName },
      details: {},
    });
    expect(completed?.occurredAt).toBe(lastApproval?.occurredAt);
    expect(strictlyAscending(idsOf(events))).toBe(true);
  });

  it('SEC-16: the timeline carries no title: a process renamed twice has two process.updated events with empty details, and no title anywhere in the answer', async () => {
    const tenant = await createClient();
    const original = uniqueProcessTitle('Original');
    const first = uniqueProcessTitle('Primeiro');
    const second = uniqueProcessTitle('Segundo');
    const process = await createProcessOrFail(ana.cookies, tenant.id, {
      title: original,
      stages: stageInputs(2),
    });
    await updateProcessViaApi(bia.cookies, process.id, { title: first });
    await updateProcessViaApi(ana.cookies, process.id, { title: second });

    const response = await listEventsViaApi(ana.cookies, process.id);
    const body = await expectContract<ProcessEventListBody>('listProcessEvents', response);

    expect(body.items.map((event) => event.action)).toEqual([
      'process.created',
      'process.updated',
      'process.updated',
    ]);
    expect(body.items.map((event) => event.details)).toEqual([{}, {}, {}]);
    const text = await response.clone().text();
    for (const title of [original, first, second]) expect(text).not.toContain(title);
    expect(text).not.toMatch(/previousTitle|newTitle/);
    // and the audit trail the timeline is made from has none either
    const audit = await auditOfProcess(process.id);
    expect(audit.map((row) => row.metadata)).toEqual([
      {},
      { fields: ['title'] },
      { fields: ['title'] },
    ]);
  });

  it('AC-28: the timeline pages by event id: the cursors chain, the pages together are the whole list, and the last page has no cursor', async () => {
    const { created } = await historyOfFive();
    const everything = await listAllEvents(ana.cookies, created.id);
    expect(everything).toHaveLength(5);

    const seen: string[] = [];
    const sizes: number[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 5; page += 1) {
      const response = await listEventsViaApi(ana.cookies, created.id, {
        limit: '2',
        ...(cursor === undefined ? {} : { cursor }),
      });
      const body = await expectContract<ProcessEventListBody>('listProcessEvents', response);
      sizes.push(body.items.length);
      seen.push(...body.items.map((event) => event.id));
      if (body.nextCursor === null) break;
      // the cursor is of the timeline's own kind and carries the id of the last event of the page
      const envelope = JSON.parse(Buffer.from(body.nextCursor, 'base64url').toString('utf8')) as {
        k: string;
        p: { i: string };
      };
      expect(envelope.k).toBe('admin-process-events');
      expect(envelope.p.i).toBe(body.items.at(-1)?.id);
      cursor = body.nextCursor;
    }

    expect(sizes).toEqual([2, 2, 1]);
    expect(seen).toEqual(everything.map((event) => event.id));

    // a page that is exactly full has no cursor; one short of it has
    const full = await expectContract<ProcessEventListBody>(
      'listProcessEvents',
      await listEventsViaApi(ana.cookies, created.id, { limit: '5' }),
    );
    const short = await expectContract<ProcessEventListBody>(
      'listProcessEvents',
      await listEventsViaApi(ana.cookies, created.id, { limit: '4' }),
    );
    expect(full.nextCursor).toBeNull();
    expect(short.nextCursor).not.toBeNull();
  });

  it('AC-28: the timeline of a process holds only its own events', async () => {
    const mine = await historyOfFive();
    const other = await historyOfFive();

    const events = await listAllEvents(ana.cookies, mine.created.id);
    const otherEvents = await listAllEvents(ana.cookies, other.created.id);

    expect(events).toHaveLength(5);
    expect(otherEvents).toHaveLength(5);
    const otherIds = new Set(otherEvents.map((event) => event.id));
    expect(events.some((event) => otherIds.has(event.id))).toBe(false);
    const ownStages = new Set(mine.created.stages.map((stage) => stage.id));
    for (const event of events) {
      if (event.details.stageId !== undefined)
        expect(ownStages.has(event.details.stageId)).toBe(true);
    }
  });

  it('E-29: a tampered, truncated or foreign cursor is 400 VALIDATION_ERROR that points at the cursor', async () => {
    const { created } = await historyOfFive();
    const good = encodeCursor('admin-process-events', { i: '1' });
    const cursors = [
      good.slice(0, -4),
      `${good}AAAA`,
      'not-a-cursor',
      encodeCursor('admin-client-processes', { i: '1' }),
      encodeCursor('admin-clients', { c: '2026-11-16T11:30:24.984084+00:00', i: UNKNOWN_ID }),
      encodeCursor('admin-process-events', { i: '1', extra: 1 }),
      encodeCursor('admin-process-events', { i: 1 }),
      encodeCursor('admin-process-events', { i: '0' }),
      encodeCursor('admin-process-events', { i: '0001' }),
      // one past the largest bigint: refused here, before the database would answer with a class 22 error
      encodeCursor('admin-process-events', { i: '9223372036854775808' }),
    ];

    for (const cursor of cursors) {
      const response = await listEventsViaApi(ana.cookies, created.id, { cursor });
      const body = await expectContract<Problem>('listProcessEvents', response);
      expect(outcomeOf(response, body)).toEqual([400, 'VALIDATION_ERROR']);
      expect(body.errors?.map((issue) => issue.path)).toEqual(['query.cursor']);
    }
  });

  it('E-29: the largest id a cursor may carry is a valid position: an empty last page, never a 500', async () => {
    const { created } = await historyOfFive();

    const response = await listEventsViaApi(ana.cookies, created.id, {
      cursor: encodeCursor('admin-process-events', { i: MAX_BIGINT }),
    });
    const body = await expectContract<ProcessEventListBody>('listProcessEvents', response);

    expect(response.status).toBe(200);
    expect(body).toEqual({ items: [], nextCursor: null });
  });

  it('AC-28: a bad limit or an unknown query param is 400 on the query', async () => {
    const { created } = await historyOfFive();

    for (const [query, path] of [
      [{ limit: '0' }, 'query.limit'],
      [{ limit: '101' }, 'query.limit'],
      [{ limit: 'abc' }, 'query.limit'],
      [{ status: 'active' }, 'query.status'],
    ] as const) {
      const response = await listEventsViaApi(ana.cookies, created.id, query);
      const body = await expectContract<Problem>('listProcessEvents', response);
      expect(outcomeOf(response, body)).toEqual([400, 'VALIDATION_ERROR']);
      expect(body.errors?.map((issue) => issue.path)).toEqual([path]);
    }
  });

  it('an unknown process is 404 NOT_FOUND and a malformed id is 400 (E-06)', async () => {
    const unknown = await listEventsViaApi(ana.cookies, UNKNOWN_ID);
    const malformed = await listEventsViaApi(ana.cookies, 'not-a-uuid');

    const unknownBody = await expectContract<Problem>('listProcessEvents', unknown);
    const malformedBody = await expectContract<Problem>('listProcessEvents', malformed);

    expect(outcomeOf(unknown, unknownBody)).toEqual([404, 'NOT_FOUND']);
    expect(unknownBody.detail).toBe('Process not found.');
    expect(outcomeOf(malformed, malformedBody)).toEqual([400, 'VALIDATION_ERROR']);
    expect(malformedBody.errors?.map((issue) => issue.path)).toEqual(['params.processId']);
  });

  it('AC-21, SEC-01: a client user is 403 on the timeline of its own process and without a session it is 401', async () => {
    const { created } = await historyOfFive();
    const user = await completeFirstAccess(await createClientUser({ clientId: created.clientId }));
    const cookies = await loginViaApi(user);

    const asClient = await listEventsViaApi(cookies, created.id);
    const anonymous = await listEventsViaApi(undefined, created.id);

    expect(
      outcomeOf(asClient, await expectContract<Problem>('listProcessEvents', asClient)),
    ).toEqual([403, 'FORBIDDEN']);
    expect(
      outcomeOf(anonymous, await expectContract<Problem>('listProcessEvents', anonymous)),
    ).toEqual([401, 'UNAUTHENTICATED']);
  });

  it('AC-21: a CEO session that is only aal1 is 403 MFA_VERIFICATION_REQUIRED on the timeline', async () => {
    const { created } = await historyOfFive();
    const cookies = await signInCeoWithMfa(ana, { verify: false });

    const response = await listEventsViaApi(cookies, created.id);
    const body = await expectContract<Problem>('listProcessEvents', response);

    expect(outcomeOf(response, body)).toEqual([403, 'MFA_VERIFICATION_REQUIRED']);
  });
});

// ------------------------------------------------------------------------------ Supabase failing ----

describe('Supabase failing', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await loginAsNamedCeo(`Fabi ${uniqueProcessTitle('').trim()}`);
  });

  /** Makes the requests whose URL holds `part` fail the way a dead network does. */
  const failing = (part: string) =>
    spyOnSupabaseFetch((url) => (url.includes(part) ? new TypeError('fetch failed') : undefined));

  /**
   * The function runs and COMMITS; what the app never receives is its answer (the case that makes a
   * retry necessary and the one the contract describes for an approval that was saved).
   */
  const losingTheAnswerOf = (part: string) => {
    const realFetch = globalThis.fetch;
    return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input instanceof Request ? input.url : input);
      const answer = await realFetch(input, init);
      if (!url.includes(part)) return answer;
      void answer.body?.cancel();
      throw new TypeError('fetch failed');
    });
  };

  /** 503 `SERVICE_UNAVAILABLE` with a `Retry-After` of at least a second, as the contract documents. */
  async function expectUnavailable(operationId: string, response: Response) {
    const body = await expectContract<Problem>(operationId, response);

    expect(response.status).toBe(503);
    expect(body.code).toBe('SERVICE_UNAVAILABLE');
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
  }

  it('E-21: an approval that cannot reach the database is 503 and approves nothing', async () => {
    const process = await newProcess(ceo.cookies, 2);
    const settled = await stateOf(process.id);
    const spy = failing('/rest/v1/rpc/approve_current_stage');
    try {
      await expectUnavailable(
        'approveCurrentStage',
        await approveViaApi(ceo.cookies, process.id, { expectedStageId: stageAt(process, 1).id }),
      );
    } finally {
      spy.restore();
    }

    expect(await stateOf(process.id)).toEqual(settled);
    // nothing was saved, so the retry is the approval itself
    await approveOk(ceo.cookies, process, 1);
  });

  it('E-21, E-02: an approval whose answer was lost (503) and is repeated is 409 STALE_STAGE naming the next stage: it was saved, the retry approves nothing more', async () => {
    const process = await newProcess(ceo.cookies, 3);
    const spy = losingTheAnswerOf('/rest/v1/rpc/approve_current_stage');
    let lost: Response;
    try {
      lost = await approveViaApi(ceo.cookies, process.id, {
        expectedStageId: stageAt(process, 1).id,
      });
    } finally {
      spy.mockRestore();
    }
    await expectUnavailable('approveCurrentStage', lost);
    const saved = await stateOf(process.id);
    expect(saved.approvals).toEqual([stageAt(process, 1).id]);
    expect(saved.row.version).toBe(2);

    const retried = await approveViaApi(ceo.cookies, process.id, {
      expectedStageId: stageAt(process, 1).id,
    });

    await expectStale(retried, stageAt(process, 2).id);
    expect(await stateOf(process.id)).toEqual(saved);
    // the CEO reads the process to see what the lost answer would have said
    const detail = await expectContract<ProcessDetailBody>(
      'getProcess',
      await getProcessViaApi(ceo.cookies, process.id),
    );
    expect(detail).toMatchObject({ version: 2, completedStages: 1 });
    expect(detail.stages[0]?.approval?.approvedBy.id).toBe(ceo.ceo.id);
  });

  it('E-21, E-02: the last approval whose answer was lost (503) and is repeated is 422 PROCESS_NOT_ACTIVE: the process is completed', async () => {
    const process = await newProcess(ceo.cookies, 1);
    const spy = losingTheAnswerOf('/rest/v1/rpc/approve_current_stage');
    let lost: Response;
    try {
      lost = await approveViaApi(ceo.cookies, process.id, {
        expectedStageId: stageAt(process, 1).id,
      });
    } finally {
      spy.mockRestore();
    }
    await expectUnavailable('approveCurrentStage', lost);
    const saved = await stateOf(process.id);
    expect(saved.row).toMatchObject({ status: 'completed', version: 2 });

    const retried = await approveViaApi(ceo.cookies, process.id, {
      expectedStageId: stageAt(process, 1).id,
    });

    await expectNotActive(retried);
    expect(await stateOf(process.id)).toEqual(saved);
  });

  it('E-21: an approval saved whose read back cannot reach the database is 503, and the retry is 409 STALE_STAGE', async () => {
    const process = await newProcess(ceo.cookies, 3);
    const spy = failing('/rest/v1/processes?');
    try {
      await expectUnavailable(
        'approveCurrentStage',
        await approveViaApi(ceo.cookies, process.id, { expectedStageId: stageAt(process, 1).id }),
      );
    } finally {
      spy.restore();
    }
    const saved = await stateOf(process.id);
    expect(saved.approvals).toEqual([stageAt(process, 1).id]);

    await expectStale(
      await approveViaApi(ceo.cookies, process.id, { expectedStageId: stageAt(process, 1).id }),
      stageAt(process, 2).id,
    );
    expect(await stateOf(process.id)).toEqual(saved);
  });

  it('E-21: a stale approval whose re-read of the process cannot reach the database is 503, not a 500', async () => {
    const process = await newProcess(ceo.cookies, 3);
    await approveOk(ceo.cookies, process, 1);
    const spy = failing('/rest/v1/processes?');
    try {
      await expectUnavailable(
        'approveCurrentStage',
        await approveViaApi(ceo.cookies, process.id, { expectedStageId: stageAt(process, 1).id }),
      );
    } finally {
      spy.restore();
    }
  });

  it('E-21: the timeline that cannot reach the database is 503 on either read', async () => {
    const { id } = await newProcess(ceo.cookies, 2);

    for (const part of ['/rest/v1/processes?', '/rest/v1/audit_events']) {
      const spy = failing(part);
      try {
        await expectUnavailable('listProcessEvents', await listEventsViaApi(ceo.cookies, id));
      } finally {
        spy.restore();
      }
    }
  });

  it('E-21: a bodyOf of the 503 carries no database text', async () => {
    const process = await newProcess(ceo.cookies, 2);
    const spy = failing('/rest/v1/rpc/approve_current_stage');
    let response: Response;
    try {
      response = await approveViaApi(ceo.cookies, process.id, {
        expectedStageId: stageAt(process, 1).id,
      });
    } finally {
      spy.restore();
    }

    const text = JSON.stringify(await bodyOf(response));

    expect(text).not.toMatch(/fetch failed|approve_current_stage|postgres|supabase/i);
    expect(text).not.toContain(process.title);
  });
});
