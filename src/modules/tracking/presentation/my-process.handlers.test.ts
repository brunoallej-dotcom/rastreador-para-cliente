import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parse } from 'yaml';
import * as myProcessRoute from '@/app/api/v1/me/processes/[processId]/route';
import * as myProcessesRoute from '@/app/api/v1/me/processes/route';
import { encodeCursor } from '@/shared/http';
import type { NextRouteHandler, RuntimePolicy, WithRoute } from '@/shared/http/route-policy';
import { apiRequest, createTestPipeline, principalFixture } from '@/shared/http/testing';
import { createGetMyProcessHandler, getMyProcessHandler } from './get-my-process.handler';
import { createListMyProcessesHandler, listMyProcessesHandler } from './list-my-processes.handler';
import { encodeProcessCursor } from './process.cursor';

type ContractOperation = {
  operationId: string;
  'x-auth-policy': { access: string; roles: string[]; allowPending: string[] };
  'x-rate-limit': { scope: string; limit: number; windowSeconds: number }[];
};

const contract = parse(
  readFileSync(
    fileURLToPath(new URL('../../../../contracts/openapi.v1.yaml', import.meta.url)),
    'utf8',
  ),
) as { paths: Record<string, { get?: ContractOperation }> };

function operationOf(path: string, operationId: string): ContractOperation {
  const operation = contract.paths[path]?.get;
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

const TENANT_ID = '33333333-3333-4333-8333-333333333333';
const PROCESS_ID = '44444444-4444-4444-8444-444444444444';

type PathParams = Readonly<Record<string, string>>;

/** Calls a route handler the way Next does: the request, and the dynamic segments of the path. */
const call = (handler: NextRouteHandler, params: PathParams, request: NextRequest) =>
  handler(request, { params: Promise.resolve({ ...params }) });

type Operation = {
  readonly label: string;
  readonly path: string;
  readonly operationId: string;
  readonly create: (route: WithRoute) => NextRouteHandler;
  readonly params: PathParams;
  readonly request: () => NextRequest;
};

const OPERATIONS: readonly Operation[] = [
  {
    label: 'listMyProcesses',
    path: '/me/processes',
    operationId: 'listMyProcesses',
    create: createListMyProcessesHandler,
    params: {},
    request: () => apiRequest('/me/processes'),
  },
  {
    label: 'getMyProcess',
    path: '/me/processes/{processId}',
    operationId: 'getMyProcess',
    create: createGetMyProcessHandler,
    params: { processId: PROCESS_ID },
    request: () => apiRequest(`/me/processes/${PROCESS_ID}`),
  },
];

const clientSession = (overrides: Parameters<typeof principalFixture>[0] = {}) =>
  principalFixture({
    role: 'client',
    clientId: TENANT_ID,
    userId: '22222222-2222-4222-8222-222222222222',
    aal: 'aal1',
    pendingActions: [],
    ...overrides,
  });

describe.each(OPERATIONS)('$label: policy of the contract', (operation) => {
  const contractOperation = () => operationOf(operation.path, operation.operationId);

  it('declares the role, the allowed pendings and the rate limit of the contract', () => {
    const policy = policyOf(operation.create);
    const { 'x-auth-policy': auth, 'x-rate-limit': limits } = contractOperation();

    expect(policy.access).toBe(auth.access);
    expect(policy.roles).toEqual(auth.roles);
    expect(policy.roles).toEqual(['client']);
    expect(policy.allowPending).toEqual(auth.allowPending);
    expect(policy.allowPending).toEqual([]);
    expect(policy.rateLimit).toEqual(limits.map((limit) => ({ ...limit, group: 'reads' })));
    expect(policy.rateLimit).toEqual([
      { scope: 'user', group: 'reads', limit: 300, windowSeconds: 60 },
    ]);
  });

  it('validates no body, takes the path parameter the contract documents, and the query only on the list', () => {
    const policy = policyOf(operation.create);

    expect(policy.body).toBeUndefined();
    expect(policy.params !== undefined).toBe(operation.path.includes('{'));
    expect(policy.query !== undefined).toBe(operation.operationId === 'listMyProcesses');
  });
});

describe('the contract of the client panel', () => {
  it('takes no client id anywhere: not in the path, not in the query', () => {
    const list = contract.paths['/me/processes']?.get as unknown as {
      parameters: { $ref?: string; name?: string }[];
    };
    const names = list.parameters.map((parameter) => parameter.$ref ?? parameter.name);

    expect(names).toEqual(['#/components/parameters/Limit', '#/components/parameters/Cursor']);
    expect(Object.keys(contract.paths).filter((path) => path.startsWith('/me/'))).toEqual([
      '/me/processes',
      '/me/processes/{processId}',
    ]);
  });
});

describe('the pipeline in front of the client panel routes (spec §3.5)', () => {
  it.each(OPERATIONS)(
    'AC-21, E-07: $label answers 403 FORBIDDEN to a CEO and the database is never reached',
    async (operation) => {
      const outbound = forbidOutbound();
      const { withRoute } = createTestPipeline({ principal: principalFixture() });

      const response = await call(
        operation.create(withRoute),
        operation.params,
        operation.request(),
      );

      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ code: 'FORBIDDEN' });
      expect(outbound).not.toHaveBeenCalled();
    },
  );

  it.each(OPERATIONS)('SEC-01: $label answers 401 without a session', async (operation) => {
    const outbound = forbidOutbound();
    const { withRoute } = createTestPipeline({ principal: null });

    const response = await call(operation.create(withRoute), operation.params, operation.request());

    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(outbound).not.toHaveBeenCalled();
  });

  it.each(OPERATIONS)(
    'E-81: $label answers 403 PASSWORD_CHANGE_REQUIRED to a client that still has the temporary password',
    async (operation) => {
      const outbound = forbidOutbound();
      const { withRoute } = createTestPipeline({
        principal: clientSession({ pendingActions: ['CHANGE_PASSWORD'] }),
      });

      const response = await call(
        operation.create(withRoute),
        operation.params,
        operation.request(),
      );

      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ code: 'PASSWORD_CHANGE_REQUIRED' });
      expect(outbound).not.toHaveBeenCalled();
    },
  );

  describe('validation (a client, before any use case)', () => {
    const client = () => createTestPipeline({ principal: clientSession() });

    type Problem = { code: string; errors: { path: string }[] };

    it('E-06: a malformed processId is a 400 that names the id', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = client();

      for (const processId of ['not-a-uuid', '1', '%20', PROCESS_ID.toUpperCase().slice(1)]) {
        const response = await call(
          createGetMyProcessHandler(withRoute),
          { processId },
          apiRequest(`/me/processes/${processId}`),
        );
        const body = (await response.json()) as Problem;

        expect(response.status).toBe(400);
        expect(body.code).toBe('VALIDATION_ERROR');
        expect(body.errors.map((issue) => issue.path)).toEqual(['params.processId']);
      }
      expect(outbound).not.toHaveBeenCalled();
    });

    it('E-80: a client id in the query, a status or any other unknown param is a 400 on the query', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = client();
      const list = createListMyProcessesHandler(withRoute);

      const queries = [
        [`clientId=${TENANT_ID}`, 'query.clientId'],
        ['client_id=x', 'query.client_id'],
        ['status=active', 'query.status'],
        ['limit=0', 'query.limit'],
        ['limit=101', 'query.limit'],
        ['limit=abc', 'query.limit'],
        ['limit=1e1', 'query.limit'],
      ] as const;
      for (const [query, path] of queries) {
        const response = await call(list, {}, apiRequest(`/me/processes?${query}`));
        const body = (await response.json()) as Problem;
        expect(response.status).toBe(400);
        expect(body.errors.map((issue) => issue.path)).toEqual([path]);
      }
      expect(outbound).not.toHaveBeenCalled();
    });

    it('E-80, E-29: a tampered, truncated or foreign cursor is a 400 that points at the cursor', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = client();
      const list = createListMyProcessesHandler(withRoute);
      const payload = { c: '2026-11-16T10:00:00.123456+00:00', i: PROCESS_ID };
      const good = encodeCursor('my-processes', payload);

      const cursors = [
        good.slice(0, -4),
        `${good}AAAA`,
        'not-a-cursor',
        encodeCursor('admin-clients', payload),
        // the CEO's list of a client's processes: same payload, another kind
        encodeProcessCursor({ createdAt: payload.c, id: payload.i }),
        encodeCursor('my-processes', { ...payload, extra: 1 }),
        encodeCursor('my-processes', { ...payload, t: 'b' }),
        encodeCursor('my-processes', { c: 'yesterday', i: PROCESS_ID }),
        encodeCursor('my-processes', { c: payload.c, i: 'nope' }),
        // well formed, but a timestamp the database cannot read (F-53)
        encodeCursor('my-processes', { c: '0000-01-01T00:00:00.000000+00:00', i: PROCESS_ID }),
        encodeCursor('my-processes', { c: '2026-01-01T00:00:00.000000+23:59', i: PROCESS_ID }),
        'A'.repeat(201),
      ];

      for (const cursor of cursors) {
        const response = await call(list, {}, apiRequest(`/me/processes?cursor=${cursor}`));
        const body = (await response.json()) as Problem;
        expect(response.status).toBe(400);
        expect(body.code).toBe('VALIDATION_ERROR');
        expect(body.errors.map((issue) => issue.path)).toEqual(['query.cursor']);
      }
      expect(outbound).not.toHaveBeenCalled();
    });
  });
});

describe('route.ts of the client panel routes', () => {
  it('me/processes re-exports GET and pins the Node.js runtime', () => {
    expect(Object.keys(myProcessesRoute).sort()).toEqual(['GET', 'dynamic', 'runtime']);
    expect(myProcessesRoute.GET).toBe(listMyProcessesHandler);
    expect(myProcessesRoute.runtime).toBe('nodejs');
    expect(myProcessesRoute.dynamic).toBe('force-dynamic');
  });

  it('me/processes/[processId] re-exports GET and pins the Node.js runtime', () => {
    expect(Object.keys(myProcessRoute).sort()).toEqual(['GET', 'dynamic', 'runtime']);
    expect(myProcessRoute.GET).toBe(getMyProcessHandler);
    expect(myProcessRoute.runtime).toBe('nodejs');
    expect(myProcessRoute.dynamic).toBe('force-dynamic');
  });
});
