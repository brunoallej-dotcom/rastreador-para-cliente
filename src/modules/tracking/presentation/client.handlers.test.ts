import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parse } from 'yaml';
import * as clientsRoute from '@/app/api/v1/admin/clients/route';
import * as clientRoute from '@/app/api/v1/admin/clients/[clientId]/route';
import { encodeCursor } from '@/shared/http';
import type { RuntimePolicy, WithRoute } from '@/shared/http/route-policy';
import { apiRequest, createTestPipeline, principalFixture } from '@/shared/http/testing';
import { createCreateClientHandler, createClientHandler } from './create-client.handler';
import { createGetClientHandler, getClientHandler } from './get-client.handler';
import { createListClientsHandler, listClientsHandler } from './list-clients.handler';
import { createUpdateClientHandler, updateClientHandler } from './update-client.handler';

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

type Operation = {
  readonly label: string;
  readonly path: string;
  readonly method: 'get' | 'post' | 'patch';
  readonly operationId: string;
  readonly create: (route: WithRoute) => (request: Request) => Promise<Response>;
  readonly group: 'reads' | 'writes';
  readonly request: () => Request;
  readonly hasBody: boolean;
};

const OPERATIONS: readonly Operation[] = [
  {
    label: 'listClients',
    path: '/admin/clients',
    method: 'get',
    operationId: 'listClients',
    create: createListClientsHandler as Operation['create'],
    group: 'reads',
    request: () => apiRequest('/admin/clients'),
    hasBody: false,
  },
  {
    label: 'createClient',
    path: '/admin/clients',
    method: 'post',
    operationId: 'createClient',
    create: createCreateClientHandler as Operation['create'],
    group: 'writes',
    request: () => apiRequest('/admin/clients', { method: 'POST', json: { name: 'Acme' } }),
    hasBody: true,
  },
  {
    label: 'getClient',
    path: '/admin/clients/{clientId}',
    method: 'get',
    operationId: 'getClient',
    create: createGetClientHandler as Operation['create'],
    group: 'reads',
    request: () => apiRequest(`/admin/clients/${CLIENT_ID}`),
    hasBody: false,
  },
  {
    label: 'updateClient',
    path: '/admin/clients/{clientId}',
    method: 'patch',
    operationId: 'updateClient',
    create: createUpdateClientHandler as Operation['create'],
    group: 'writes',
    request: () =>
      apiRequest(`/admin/clients/${CLIENT_ID}`, { method: 'PATCH', json: { name: 'Acme' } }),
    hasBody: true,
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
});

describe('the pipeline in front of the client routes (spec §3.5)', () => {
  it.each(OPERATIONS)(
    'E-07: $label answers 403 FORBIDDEN to a client user and the database is never reached',
    async (operation) => {
      const outbound = forbidOutbound();
      const client = principalFixture({
        role: 'client',
        clientId: '22222222-2222-4222-8222-222222222222',
        aal: 'aal1',
        pendingActions: [],
      });
      const { withRoute } = createTestPipeline({ principal: client });

      const response = await operation.create(withRoute)(operation.request());

      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ code: 'FORBIDDEN' });
      expect(outbound).not.toHaveBeenCalled();
    },
  );

  it.each(OPERATIONS)('SEC-01: $label answers 401 without a session', async (operation) => {
    const outbound = forbidOutbound();
    const { withRoute } = createTestPipeline({ principal: null });

    const response = await operation.create(withRoute)(operation.request());

    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(outbound).not.toHaveBeenCalled();
  });

  it.each([
    ['CHANGE_PASSWORD', ['CHANGE_PASSWORD', 'ENROLL_MFA'], 'aal1', 'PASSWORD_CHANGE_REQUIRED'],
    ['ENROLL_MFA', ['ENROLL_MFA'], 'aal1', 'MFA_ENROLLMENT_REQUIRED'],
    ['VERIFY_MFA', ['VERIFY_MFA'], 'aal1', 'MFA_VERIFICATION_REQUIRED'],
  ] as const)(
    'SEC-11: a CEO with %s pending is 403 %s on every client route',
    async (_pending, pendingActions, aal, code) => {
      const outbound = forbidOutbound();
      const { withRoute } = createTestPipeline({
        principal: principalFixture({ aal, pendingActions: [...pendingActions] }),
      });

      for (const operation of OPERATIONS) {
        const response = await operation.create(withRoute)(operation.request());
        expect(response.status).toBe(403);
        expect(await response.json()).toMatchObject({ code });
      }
      expect(outbound).not.toHaveBeenCalled();
    },
  );

  describe('validation (a CEO aal2, before any use case)', () => {
    const ceo = () => createTestPipeline({ principal: principalFixture() });

    it('E-06: a malformed clientId is a 400 on getClient and updateClient', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();

      const get = await createGetClientHandler(withRoute)(apiRequest('/admin/clients/not-a-uuid'));
      const patch = await createUpdateClientHandler(withRoute)(
        apiRequest('/admin/clients/not-a-uuid', { method: 'PATCH', json: { name: 'Acme' } }),
      );

      expect([get.status, patch.status]).toEqual([400, 400]);
      expect(await get.json()).toMatchObject({ code: 'VALIDATION_ERROR' });
      expect(outbound).not.toHaveBeenCalled();
    });

    it('AC-11: an unknown field, a bad name or an empty patch is a 400', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();
      const create = createCreateClientHandler(withRoute);
      const update = createUpdateClientHandler(withRoute);
      const post = (json: unknown) =>
        create(apiRequest('/admin/clients', { method: 'POST', json }));
      const patch = (json: unknown) =>
        update(apiRequest(`/admin/clients/${CLIENT_ID}`, { method: 'PATCH', json }));

      const responses = await Promise.all([
        post({ name: 'Acme', clientId: CLIENT_ID }),
        post({ name: '' }),
        post({ name: '   ' }),
        post({ name: 'a'.repeat(161) }),
        post({}),
        patch({}),
        patch({ archived: 'yes' }),
        patch({ name: 'Acme', id: CLIENT_ID }),
      ]);

      expect(responses.map((response) => response.status)).toEqual(Array(8).fill(400));
      expect(outbound).not.toHaveBeenCalled();
    });

    it('E-29: a tampered, truncated or foreign cursor is a 400 that points at the cursor', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();
      const list = createListClientsHandler(withRoute);
      const payload = { c: '2026-11-16T10:00:00.123456+00:00', i: CLIENT_ID };
      const good = encodeCursor('admin-clients', payload);

      const cursors = [
        good.slice(0, -4),
        `${good}AAAA`,
        'not-a-cursor',
        encodeCursor('admin-processes', payload),
        encodeCursor('admin-clients', { ...payload, extra: 1 }),
        encodeCursor('admin-clients', { c: 'yesterday', i: CLIENT_ID }),
        encodeCursor('admin-clients', { c: payload.c, i: 'nope' }),
        'A'.repeat(201),
      ];

      for (const cursor of cursors) {
        const response = await list(apiRequest(`/admin/clients?cursor=${cursor}`));
        const body = (await response.json()) as { code: string; errors: { path: string }[] };
        expect(response.status).toBe(400);
        expect(body.code).toBe('VALIDATION_ERROR');
        expect(body.errors.map((issue) => issue.path)).toEqual(['query.cursor']);
      }
      expect(outbound).not.toHaveBeenCalled();
    });

    it('AC-11: a bad limit, includeArchived or an unknown query param is a 400', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();
      const list = createListClientsHandler(withRoute);

      const queries = ['limit=0', 'limit=101', 'limit=abc', 'includeArchived=yes', 'clientId=x'];
      for (const query of queries) {
        const response = await list(apiRequest(`/admin/clients?${query}`));
        expect(response.status).toBe(400);
      }
      expect(outbound).not.toHaveBeenCalled();
    });
  });
});

describe('route.ts of the client routes', () => {
  it('admin/clients re-exports GET and POST and pins the Node.js runtime', () => {
    expect(Object.keys(clientsRoute).sort()).toEqual(['GET', 'POST', 'dynamic', 'runtime']);
    expect(clientsRoute.GET).toBe(listClientsHandler);
    expect(clientsRoute.POST).toBe(createClientHandler);
    expect(clientsRoute.runtime).toBe('nodejs');
    expect(clientsRoute.dynamic).toBe('force-dynamic');
  });

  it('admin/clients/[clientId] re-exports GET and PATCH and pins the Node.js runtime', () => {
    expect(Object.keys(clientRoute).sort()).toEqual(['GET', 'PATCH', 'dynamic', 'runtime']);
    expect(clientRoute.GET).toBe(getClientHandler);
    expect(clientRoute.PATCH).toBe(updateClientHandler);
    expect(clientRoute.runtime).toBe('nodejs');
    expect(clientRoute.dynamic).toBe('force-dynamic');
  });
});
