import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parse } from 'yaml';
import * as clientProcessesRoute from '@/app/api/v1/admin/clients/[clientId]/processes/route';
import * as processRoute from '@/app/api/v1/admin/processes/[processId]/route';
import * as templateRoute from '@/app/api/v1/admin/stage-templates/default/route';
import { encodeCursor } from '@/shared/http';
import type { NextRouteHandler, RuntimePolicy, WithRoute } from '@/shared/http/route-policy';
import { apiRequest, createTestPipeline, principalFixture } from '@/shared/http/testing';
import { createCreateProcessHandler, createProcessHandler } from './create-process.handler';
import {
  createGetDefaultStageTemplateHandler,
  getDefaultStageTemplateHandler,
} from './get-default-stage-template.handler';
import { createGetProcessHandler, getProcessHandler } from './get-process.handler';
import {
  createListClientProcessesHandler,
  listClientProcessesHandler,
} from './list-client-processes.handler';
import { createUpdateProcessHandler, updateProcessHandler } from './update-process.handler';

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

function operationOf(path: string, method: 'get' | 'post' | 'patch', operationId: string) {
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

const CLIENT_ID = '33333333-3333-4333-8333-333333333333';
const PROCESS_ID = '44444444-4444-4444-8444-444444444444';

type PathParams = Readonly<Record<string, string>>;

/** Calls a route handler the way Next does: the request, and the dynamic segments of the path. */
const call = (handler: NextRouteHandler, params: PathParams, request: NextRequest) =>
  handler(request, { params: Promise.resolve({ ...params }) });

type Operation = {
  readonly label: string;
  readonly path: string;
  readonly method: 'get' | 'post' | 'patch';
  readonly operationId: string;
  readonly create: (route: WithRoute) => NextRouteHandler;
  readonly group: 'reads' | 'writes';
  /** The dynamic segments of the path, as a valid request has them. */
  readonly params: PathParams;
  readonly request: () => NextRequest;
  readonly hasBody: boolean;
};

const CLIENT_PARAMS = { clientId: CLIENT_ID };
const PROCESS_PARAMS = { processId: PROCESS_ID };

const OPERATIONS: readonly Operation[] = [
  {
    label: 'listClientProcesses',
    path: '/admin/clients/{clientId}/processes',
    method: 'get',
    operationId: 'listClientProcesses',
    create: createListClientProcessesHandler,
    group: 'reads',
    params: CLIENT_PARAMS,
    request: () => apiRequest(`/admin/clients/${CLIENT_ID}/processes`),
    hasBody: false,
  },
  {
    label: 'createProcess',
    path: '/admin/clients/{clientId}/processes',
    method: 'post',
    operationId: 'createProcess',
    create: createCreateProcessHandler,
    group: 'writes',
    params: CLIENT_PARAMS,
    request: () =>
      apiRequest(`/admin/clients/${CLIENT_ID}/processes`, {
        method: 'POST',
        json: { title: 'Site novo' },
      }),
    hasBody: true,
  },
  {
    label: 'getProcess',
    path: '/admin/processes/{processId}',
    method: 'get',
    operationId: 'getProcess',
    create: createGetProcessHandler,
    group: 'reads',
    params: PROCESS_PARAMS,
    request: () => apiRequest(`/admin/processes/${PROCESS_ID}`),
    hasBody: false,
  },
  {
    label: 'updateProcess',
    path: '/admin/processes/{processId}',
    method: 'patch',
    operationId: 'updateProcess',
    create: createUpdateProcessHandler,
    group: 'writes',
    params: PROCESS_PARAMS,
    request: () =>
      apiRequest(`/admin/processes/${PROCESS_ID}`, { method: 'PATCH', json: { title: 'Novo' } }),
    hasBody: true,
  },
  {
    label: 'getDefaultStageTemplate',
    path: '/admin/stage-templates/default',
    method: 'get',
    operationId: 'getDefaultStageTemplate',
    create: createGetDefaultStageTemplateHandler,
    group: 'reads',
    params: {},
    request: () => apiRequest('/admin/stage-templates/default'),
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

  it('validates a body only where the contract documents one', () => {
    const policy = policyOf(operation.create);
    expect(policy.body !== undefined).toBe(operation.hasBody);
  });

  it('takes the path parameters the contract documents, and the query only on the list', () => {
    const policy = policyOf(operation.create);
    const hasPathParam = operation.path.includes('{');

    expect(policy.params !== undefined).toBe(hasPathParam);
    expect(policy.query !== undefined).toBe(operation.operationId === 'listClientProcesses');
  });
});

describe('the pipeline in front of the process routes (spec §3.5)', () => {
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

  it.each([
    ['CHANGE_PASSWORD', ['CHANGE_PASSWORD', 'ENROLL_MFA'], 'aal1', 'PASSWORD_CHANGE_REQUIRED'],
    ['ENROLL_MFA', ['ENROLL_MFA'], 'aal1', 'MFA_ENROLLMENT_REQUIRED'],
    ['VERIFY_MFA', ['VERIFY_MFA'], 'aal1', 'MFA_VERIFICATION_REQUIRED'],
  ] as const)(
    'SEC-11: a CEO with %s pending is 403 %s on every process route',
    async (_pending, pendingActions, aal, code) => {
      const outbound = forbidOutbound();
      const { withRoute } = createTestPipeline({
        principal: principalFixture({ aal, pendingActions: [...pendingActions] }),
      });

      for (const operation of OPERATIONS) {
        const response = await call(
          operation.create(withRoute),
          operation.params,
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

    it('E-06: a malformed clientId or processId is a 400 on every route that takes one, and it is the id that is named', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();
      const bad = (name: string) => ({ [name]: 'not-a-uuid' });

      const responses = await Promise.all([
        call(
          createListClientProcessesHandler(withRoute),
          bad('clientId'),
          apiRequest('/admin/clients/not-a-uuid/processes'),
        ),
        call(
          createCreateProcessHandler(withRoute),
          bad('clientId'),
          apiRequest('/admin/clients/not-a-uuid/processes', {
            method: 'POST',
            json: { title: 'Site' },
          }),
        ),
        call(
          createGetProcessHandler(withRoute),
          bad('processId'),
          apiRequest('/admin/processes/not-a-uuid'),
        ),
        call(
          createUpdateProcessHandler(withRoute),
          bad('processId'),
          apiRequest('/admin/processes/not-a-uuid', { method: 'PATCH', json: { title: 'Novo' } }),
        ),
      ]);

      expect(responses.map((response) => response.status)).toEqual([400, 400, 400, 400]);
      const problems = await Promise.all(
        responses.map((response) => response.json() as Promise<Problem>),
      );
      expect(problems.map((problem) => problem.errors.map((issue) => issue.path))).toEqual([
        ['params.clientId'],
        ['params.clientId'],
        ['params.processId'],
        ['params.processId'],
      ]);
      expect(outbound).not.toHaveBeenCalled();
    });

    it('E-20, AC-23: an unknown field, a bad title, a bad stage list or an empty patch is a 400 that names the body', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();
      const create = createCreateProcessHandler(withRoute);
      const update = createUpdateProcessHandler(withRoute);
      const post = (json: unknown) =>
        call(
          create,
          CLIENT_PARAMS,
          apiRequest(`/admin/clients/${CLIENT_ID}/processes`, { method: 'POST', json }),
        );
      const patch = (json: unknown) =>
        call(
          update,
          PROCESS_PARAMS,
          apiRequest(`/admin/processes/${PROCESS_ID}`, { method: 'PATCH', json }),
        );

      const responses = await Promise.all([
        post({ title: 'Site', clientId: CLIENT_ID }),
        post({ title: '' }),
        post({ title: '   ' }),
        post({ title: 'a'.repeat(161) }),
        post({ title: `A${String.fromCharCode(0xd800)}` }),
        post({}),
        post({ title: 'Site', stages: [] }),
        post({ title: 'Site', stages: Array.from({ length: 31 }, () => ({ name: 'F' })) }),
        post({ title: 'Site', stages: [{ name: '   ' }] }),
        patch({}),
        patch({ status: 'completed' }),
        patch({ title: 'Novo', id: PROCESS_ID }),
      ]);

      expect(responses.map((response) => response.status)).toEqual(Array(12).fill(400));
      const problems = await Promise.all(
        responses.map((response) => response.json() as Promise<Problem>),
      );
      for (const problem of problems) {
        expect(problem.code).toBe('VALIDATION_ERROR');
        for (const issue of problem.errors) expect(issue.path).toMatch(/^body(\.|\[|$)/);
      }
      expect(outbound).not.toHaveBeenCalled();
    });

    it('E-20: a bad stage points at its path in the problem', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();

      const response = await call(
        createCreateProcessHandler(withRoute),
        CLIENT_PARAMS,
        apiRequest(`/admin/clients/${CLIENT_ID}/processes`, {
          method: 'POST',
          json: { title: 'Site', stages: [{ name: 'Boa' }, { name: '   ' }] },
        }),
      );
      const body = (await response.json()) as Problem;

      expect(response.status).toBe(400);
      expect(body.errors.map((issue) => issue.path)).toEqual(['body.stages[1].name']);
      expect(outbound).not.toHaveBeenCalled();
    });

    it('E-29: a tampered, truncated or foreign cursor is a 400 that points at the cursor', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();
      const list = createListClientProcessesHandler(withRoute);
      const payload = { c: '2026-11-16T10:00:00.123456+00:00', i: PROCESS_ID };
      const good = encodeCursor('admin-client-processes', payload);

      const cursors = [
        good.slice(0, -4),
        `${good}AAAA`,
        'not-a-cursor',
        encodeCursor('admin-clients', payload),
        encodeCursor('admin-client-processes', { ...payload, extra: 1 }),
        encodeCursor('admin-client-processes', { c: 'yesterday', i: PROCESS_ID }),
        encodeCursor('admin-client-processes', { c: payload.c, i: 'nope' }),
        // well formed, but a timestamp the database cannot read (F-53)
        encodeCursor('admin-client-processes', {
          c: '0000-01-01T00:00:00.000000+00:00',
          i: PROCESS_ID,
        }),
        encodeCursor('admin-client-processes', {
          c: '2026-01-01T00:00:00.000000+23:59',
          i: PROCESS_ID,
        }),
        'A'.repeat(201),
      ];

      for (const cursor of cursors) {
        const response = await call(
          list,
          CLIENT_PARAMS,
          apiRequest(`/admin/clients/${CLIENT_ID}/processes?cursor=${cursor}`),
        );
        const body = (await response.json()) as Problem;
        expect(response.status).toBe(400);
        expect(body.code).toBe('VALIDATION_ERROR');
        expect(body.errors.map((issue) => issue.path)).toEqual(['query.cursor']);
      }
      expect(outbound).not.toHaveBeenCalled();
    });

    it('AC-15: a bad limit, a bad status or an unknown query param is a 400 on the query', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();
      const list = createListClientProcessesHandler(withRoute);

      const queries = [
        ['limit=0', 'query.limit'],
        ['limit=101', 'query.limit'],
        ['limit=abc', 'query.limit'],
        ['status=done', 'query.status'],
        ['status=', 'query.status'],
        ['clientId=x', 'query.clientId'],
      ] as const;
      for (const [query, path] of queries) {
        const response = await call(
          list,
          CLIENT_PARAMS,
          apiRequest(`/admin/clients/${CLIENT_ID}/processes?${query}`),
        );
        const body = (await response.json()) as Problem;
        expect(response.status).toBe(400);
        expect(body.errors.map((issue) => issue.path)).toEqual([path]);
      }
      expect(outbound).not.toHaveBeenCalled();
    });
  });
});

describe('route.ts of the process routes', () => {
  it('admin/clients/[clientId]/processes re-exports GET and POST and pins the Node.js runtime', () => {
    expect(Object.keys(clientProcessesRoute).sort()).toEqual(['GET', 'POST', 'dynamic', 'runtime']);
    expect(clientProcessesRoute.GET).toBe(listClientProcessesHandler);
    expect(clientProcessesRoute.POST).toBe(createProcessHandler);
    expect(clientProcessesRoute.runtime).toBe('nodejs');
    expect(clientProcessesRoute.dynamic).toBe('force-dynamic');
  });

  it('admin/processes/[processId] re-exports GET and PATCH and pins the Node.js runtime', () => {
    expect(Object.keys(processRoute).sort()).toEqual(['GET', 'PATCH', 'dynamic', 'runtime']);
    expect(processRoute.GET).toBe(getProcessHandler);
    expect(processRoute.PATCH).toBe(updateProcessHandler);
    expect(processRoute.runtime).toBe('nodejs');
    expect(processRoute.dynamic).toBe('force-dynamic');
  });

  it('admin/stage-templates/default re-exports GET and pins the Node.js runtime', () => {
    expect(Object.keys(templateRoute).sort()).toEqual(['GET', 'dynamic', 'runtime']);
    expect(templateRoute.GET).toBe(getDefaultStageTemplateHandler);
    expect(templateRoute.runtime).toBe('nodejs');
    expect(templateRoute.dynamic).toBe('force-dynamic');
  });
});
