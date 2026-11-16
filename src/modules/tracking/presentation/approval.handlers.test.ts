import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parse } from 'yaml';
import * as approvalsRoute from '@/app/api/v1/admin/processes/[processId]/approvals/route';
import * as eventsRoute from '@/app/api/v1/admin/processes/[processId]/events/route';
import { encodeCursor } from '@/shared/http';
import type { NextRouteHandler, RuntimePolicy, WithRoute } from '@/shared/http/route-policy';
import { apiRequest, createTestPipeline, principalFixture } from '@/shared/http/testing';
import {
  approveCurrentStageHandler,
  createApproveCurrentStageHandler,
} from './approve-current-stage.handler';
import {
  createListProcessEventsHandler,
  listProcessEventsHandler,
} from './list-process-events.handler';

type ContractOperation = {
  operationId: string;
  'x-auth-policy': { access: string; roles: string[]; allowPending: string[] };
  'x-rate-limit': { scope: string; limit: number; windowSeconds: number }[];
};

type ContractPath = Partial<Record<'get' | 'post' | 'patch', ContractOperation>>;

const contract = parse(
  readFileSync(
    fileURLToPath(new URL('../../../../contracts/openapi.v1.yaml', import.meta.url)),
    'utf8',
  ),
) as { paths: Record<string, ContractPath> };

function operationOf(path: string, method: 'get' | 'post', operationId: string) {
  const operation = contract.paths[path]?.[method];
  if (operation === undefined) throw new Error(`${operationId} is not in the contract`);
  expect(operation.operationId).toBe(operationId);
  return operation;
}

// Obviously fake, lowercase-only values (the secret-detection hook rightly ignores them).
const FAKE_ENV = {
  APP_ORIGIN: 'http://localhost:3000',
  SUPABASE_URL: 'http://127.0.0.1:54321',
  SUPABASE_PUBLISHABLE_KEY: 'fake-publishable-key-for-unit-tests',
  SUPABASE_SECRET_KEY: 'fake-secret-key-for-unit-tests',
  RATE_LIMIT_KEY_SECRET: 'unit-test-only-rate-limit-key-not-a-real-value',
};

beforeEach(() => {
  for (const [name, value] of Object.entries(FAKE_ENV)) vi.stubEnv(name, value);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

/** The policy a handler factory hands to `withRoute`, captured before the pipeline wraps it. */
function policyOf(create: (route: WithRoute) => unknown): RuntimePolicy {
  let captured: RuntimePolicy | undefined;
  const { withRoute } = createTestPipeline();
  const spy = ((policy: RuntimePolicy, handler: never) => {
    captured = policy;
    return (withRoute as unknown as (policy: RuntimePolicy, handler: never) => unknown)(
      policy,
      handler,
    );
  }) as unknown as WithRoute;
  create(spy);
  if (captured === undefined) throw new Error('the factory never called withRoute');
  return captured;
}

/** What reaches Supabase would be a bug of these tests: the use case must not run. */
function forbidOutbound() {
  return vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('no outbound call expected'));
}

const PROCESS_ID = '44444444-4444-4444-8444-444444444444';
const STAGE_ID = '55555555-5555-4555-8555-555555555555';
const PROCESS_PARAMS = { processId: PROCESS_ID };

type PathParams = Readonly<Record<string, string>>;

/** Calls a route handler the way Next does: the request, and the dynamic segments of the path. */
const call = (handler: NextRouteHandler, params: PathParams, request: NextRequest) =>
  handler(request, { params: Promise.resolve({ ...params }) });

type Operation = {
  readonly label: string;
  readonly path: string;
  readonly method: 'get' | 'post';
  readonly operationId: string;
  readonly create: (route: WithRoute) => NextRouteHandler;
  readonly group: 'reads' | 'writes';
  readonly request: () => NextRequest;
  readonly hasBody: boolean;
};

const OPERATIONS: readonly Operation[] = [
  {
    label: 'approveCurrentStage',
    path: '/admin/processes/{processId}/approvals',
    method: 'post',
    operationId: 'approveCurrentStage',
    create: createApproveCurrentStageHandler,
    group: 'writes',
    request: () =>
      apiRequest(`/admin/processes/${PROCESS_ID}/approvals`, {
        method: 'POST',
        json: { expectedStageId: STAGE_ID },
      }),
    hasBody: true,
  },
  {
    label: 'listProcessEvents',
    path: '/admin/processes/{processId}/events',
    method: 'get',
    operationId: 'listProcessEvents',
    create: createListProcessEventsHandler,
    group: 'reads',
    request: () => apiRequest(`/admin/processes/${PROCESS_ID}/events`),
    hasBody: false,
  },
];

describe.each(OPERATIONS)('$label: policy of the contract', (operation) => {
  const contractOperation = () =>
    operationOf(operation.path, operation.method, operation.operationId);

  it('declares the role, the allowed pendings and the rate limit of the contract', () => {
    const policy = policyOf(operation.create);
    const { 'x-auth-policy': auth, 'x-rate-limit': limits } = contractOperation();

    expect(policy.access).toBe(auth.access);
    expect(policy.roles).toEqual(auth.roles);
    expect(policy.roles).toEqual(['ceo']);
    expect(policy.allowPending).toEqual(auth.allowPending);
    expect(policy.allowPending).toEqual([]);
    expect(policy.rateLimit).toEqual(limits.map((limit) => ({ ...limit, group: operation.group })));
    expect(policy.rateLimit).toEqual([
      {
        scope: 'user',
        group: operation.group,
        limit: operation.group === 'reads' ? 300 : 60,
        windowSeconds: 60,
      },
    ]);
  });

  it('validates a body only where the contract documents one, and always the path parameter', () => {
    const policy = policyOf(operation.create);

    expect(policy.body !== undefined).toBe(operation.hasBody);
    expect(policy.params).toBeDefined();
    expect(policy.query !== undefined).toBe(operation.operationId === 'listProcessEvents');
  });
});

describe('the pipeline in front of the approval and timeline routes (spec §3.5)', () => {
  it.each(OPERATIONS)(
    'AC-21: $label answers 403 FORBIDDEN to a client user and the database is never reached',
    async (operation) => {
      const outbound = forbidOutbound();
      const client = principalFixture({
        role: 'client',
        clientId: '22222222-2222-4222-8222-222222222222',
        aal: 'aal1',
        pendingActions: [],
      });
      const { withRoute } = createTestPipeline({ principal: client });

      const response = await call(operation.create(withRoute), PROCESS_PARAMS, operation.request());

      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ code: 'FORBIDDEN' });
      expect(outbound).not.toHaveBeenCalled();
    },
  );

  it.each(OPERATIONS)('SEC-01: $label answers 401 without a session', async (operation) => {
    const outbound = forbidOutbound();
    const { withRoute } = createTestPipeline({ principal: null });

    const response = await call(operation.create(withRoute), PROCESS_PARAMS, operation.request());

    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(outbound).not.toHaveBeenCalled();
  });

  it.each([
    ['CHANGE_PASSWORD', ['CHANGE_PASSWORD', 'ENROLL_MFA'], 'aal1', 'PASSWORD_CHANGE_REQUIRED'],
    ['ENROLL_MFA', ['ENROLL_MFA'], 'aal1', 'MFA_ENROLLMENT_REQUIRED'],
    ['VERIFY_MFA', ['VERIFY_MFA'], 'aal1', 'MFA_VERIFICATION_REQUIRED'],
  ] as const)(
    'SEC-11: a CEO with %s pending is 403 %s on both routes',
    async (_pending, pendingActions, aal, code) => {
      const outbound = forbidOutbound();
      const { withRoute } = createTestPipeline({
        principal: principalFixture({ aal, pendingActions: [...pendingActions] }),
      });

      for (const operation of OPERATIONS) {
        const response = await call(
          operation.create(withRoute),
          PROCESS_PARAMS,
          operation.request(),
        );
        expect(response.status).toBe(403);
        expect(await response.json()).toMatchObject({ code });
      }
      expect(outbound).not.toHaveBeenCalled();
    },
  );

  describe('validation (a CEO aal2, before any use case)', () => {
    const ceo = () => createTestPipeline({ principal: principalFixture() });

    type Problem = { code: string; errors: { path: string }[] };

    it('E-06: a malformed processId is a 400 on both routes, and it is the id that is named', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();
      const bad = { processId: 'not-a-uuid' };

      const responses = await Promise.all([
        call(
          createApproveCurrentStageHandler(withRoute),
          bad,
          apiRequest('/admin/processes/not-a-uuid/approvals', {
            method: 'POST',
            json: { expectedStageId: STAGE_ID },
          }),
        ),
        call(
          createListProcessEventsHandler(withRoute),
          bad,
          apiRequest('/admin/processes/not-a-uuid/events'),
        ),
      ]);

      expect(responses.map((response) => response.status)).toEqual([400, 400]);
      const problems = await Promise.all(
        responses.map((response) => response.json() as Promise<Problem>),
      );
      expect(problems.map((problem) => problem.errors.map((issue) => issue.path))).toEqual([
        ['params.processId'],
        ['params.processId'],
      ]);
      expect(outbound).not.toHaveBeenCalled();
    });

    it('AC-23, E-14: a missing, malformed or unknown body field is a 400 that names the body', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();
      const approve = createApproveCurrentStageHandler(withRoute);
      const post = (json: unknown) =>
        call(
          approve,
          PROCESS_PARAMS,
          apiRequest(`/admin/processes/${PROCESS_ID}/approvals`, { method: 'POST', json }),
        );

      const responses = await Promise.all([
        post({}),
        post({ expectedStageId: 'not-a-uuid' }),
        post({ expectedStageId: 42 }),
        post({ expectedStageId: null }),
        post({ expectedStageId: STAGE_ID, approvedBy: STAGE_ID }),
        post({ expectedStageId: STAGE_ID, status: 'completed' }),
        post({ expectedStageId: STAGE_ID, processId: PROCESS_ID }),
        post([STAGE_ID]),
        post('expectedStageId'),
      ]);

      expect(responses.map((response) => response.status)).toEqual(Array(9).fill(400));
      const problems = await Promise.all(
        responses.map((response) => response.json() as Promise<Problem>),
      );
      for (const problem of problems) {
        expect(problem.code).toBe('VALIDATION_ERROR');
        for (const issue of problem.errors) expect(issue.path).toMatch(/^body(\.|\[|$)/);
      }
      expect(outbound).not.toHaveBeenCalled();
    });

    it('E-29: a tampered, truncated or foreign cursor is a 400 that points at the cursor', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();
      const list = createListProcessEventsHandler(withRoute);
      const good = encodeCursor('admin-process-events', { i: '42' });

      const cursors = [
        good.slice(0, -4),
        `${good}AAAA`,
        'not-a-cursor',
        encodeCursor('admin-client-processes', { i: '42' }),
        encodeCursor('admin-process-events', { i: '42', extra: 1 }),
        encodeCursor('admin-process-events', { i: 42 }),
        encodeCursor('admin-process-events', { i: '0' }),
        // well formed, but an id the database cannot read as a bigint
        encodeCursor('admin-process-events', { i: '9223372036854775808' }),
        encodeCursor('admin-process-events', { i: '0042' }),
        'A'.repeat(201),
      ];

      for (const cursor of cursors) {
        const response = await call(
          list,
          PROCESS_PARAMS,
          apiRequest(`/admin/processes/${PROCESS_ID}/events?cursor=${cursor}`),
        );
        const body = (await response.json()) as Problem;
        expect(response.status).toBe(400);
        expect(body.code).toBe('VALIDATION_ERROR');
        expect(body.errors.map((issue) => issue.path)).toEqual(['query.cursor']);
      }
      expect(outbound).not.toHaveBeenCalled();
    });

    it('AC-28: a bad limit or an unknown query param is a 400 on the query', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();
      const list = createListProcessEventsHandler(withRoute);

      const queries = [
        ['limit=0', 'query.limit'],
        ['limit=101', 'query.limit'],
        ['limit=abc', 'query.limit'],
        ['status=active', 'query.status'],
        ['processId=x', 'query.processId'],
      ] as const;
      for (const [query, path] of queries) {
        const response = await call(
          list,
          PROCESS_PARAMS,
          apiRequest(`/admin/processes/${PROCESS_ID}/events?${query}`),
        );
        const body = (await response.json()) as Problem;
        expect(response.status).toBe(400);
        expect(body.errors.map((issue) => issue.path)).toEqual([path]);
      }
      expect(outbound).not.toHaveBeenCalled();
    });
  });
});

describe('route.ts of the approval and timeline routes', () => {
  it('admin/processes/[processId]/approvals re-exports POST and pins the Node.js runtime', () => {
    expect(Object.keys(approvalsRoute).sort()).toEqual(['POST', 'dynamic', 'runtime']);
    expect(approvalsRoute.POST).toBe(approveCurrentStageHandler);
    expect(approvalsRoute.runtime).toBe('nodejs');
    expect(approvalsRoute.dynamic).toBe('force-dynamic');
  });

  it('admin/processes/[processId]/events re-exports GET and pins the Node.js runtime', () => {
    expect(Object.keys(eventsRoute).sort()).toEqual(['GET', 'dynamic', 'runtime']);
    expect(eventsRoute.GET).toBe(listProcessEventsHandler);
    expect(eventsRoute.runtime).toBe('nodejs');
    expect(eventsRoute.dynamic).toBe('force-dynamic');
  });
});
