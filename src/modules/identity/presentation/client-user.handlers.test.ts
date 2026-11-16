import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parse } from 'yaml';
import * as usersRoute from '@/app/api/v1/admin/clients/[clientId]/users/route';
import * as userRoute from '@/app/api/v1/admin/clients/[clientId]/users/[userId]/route';
import * as resetRoute from '@/app/api/v1/admin/clients/[clientId]/users/[userId]/password-reset/route';
import type { RuntimePolicy, WithRoute } from '@/shared/http/route-policy';
import { apiRequest, createTestPipeline, principalFixture } from '@/shared/http/testing';
import { createListClientUsersHandler, listClientUsersHandler } from './list-client-users.handler';
import {
  createProvisionClientUserHandler,
  provisionClientUserHandler,
} from './provision-client-user.handler';
import {
  createResetClientUserPasswordHandler,
  resetClientUserPasswordHandler,
} from './reset-client-user-password.handler';
import {
  createUpdateClientUserHandler,
  updateClientUserHandler,
} from './update-client-user.handler';

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
const USER_ID = '44444444-4444-4444-8444-444444444444';
const USERS = `/admin/clients/${CLIENT_ID}/users`;
const USER = `${USERS}/${USER_ID}`;

type Handler = (
  request: Request,
  context?: { params: Promise<Record<string, string>> },
) => Promise<Response>;

type Operation = {
  readonly label: string;
  readonly path: string;
  readonly method: 'get' | 'post' | 'patch';
  readonly operationId: string;
  readonly create: (route: WithRoute) => Handler;
  readonly group: 'reads' | 'writes' | 'client-user-admin';
  readonly limit: number;
  readonly windowSeconds: number;
  readonly request: () => Request;
  readonly params: Record<string, string>;
  readonly hasBody: boolean;
};

const OPERATIONS: readonly Operation[] = [
  {
    label: 'listClientUsers',
    path: '/admin/clients/{clientId}/users',
    method: 'get',
    operationId: 'listClientUsers',
    create: createListClientUsersHandler as Operation['create'],
    group: 'reads',
    limit: 300,
    windowSeconds: 60,
    request: () => apiRequest(USERS),
    params: { clientId: CLIENT_ID },
    hasBody: false,
  },
  {
    label: 'provisionClientUser',
    path: '/admin/clients/{clientId}/users',
    method: 'post',
    operationId: 'provisionClientUser',
    create: createProvisionClientUserHandler as Operation['create'],
    group: 'client-user-admin',
    limit: 20,
    windowSeconds: 3600,
    request: () =>
      apiRequest(USERS, {
        method: 'POST',
        json: { email: 'maria@cliente.test', displayName: 'Maria' },
      }),
    params: { clientId: CLIENT_ID },
    hasBody: true,
  },
  {
    label: 'updateClientUser',
    path: '/admin/clients/{clientId}/users/{userId}',
    method: 'patch',
    operationId: 'updateClientUser',
    create: createUpdateClientUserHandler as Operation['create'],
    group: 'writes',
    limit: 60,
    windowSeconds: 60,
    request: () => apiRequest(USER, { method: 'PATCH', json: { disabled: true } }),
    params: { clientId: CLIENT_ID, userId: USER_ID },
    hasBody: true,
  },
  {
    label: 'resetClientUserPassword',
    path: '/admin/clients/{clientId}/users/{userId}/password-reset',
    method: 'post',
    operationId: 'resetClientUserPassword',
    create: createResetClientUserPasswordHandler as Operation['create'],
    group: 'client-user-admin',
    limit: 20,
    windowSeconds: 3600,
    request: () => apiRequest(`${USER}/password-reset`, { method: 'POST' }),
    params: { clientId: CLIENT_ID, userId: USER_ID },
    hasBody: false,
  },
];

const callOf = (operation: Operation, route: WithRoute) =>
  operation.create(route)(operation.request(), { params: Promise.resolve(operation.params) });

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
        limit: operation.limit,
        windowSeconds: operation.windowSeconds,
      },
    ]);
  });

  it('validates a body only where the contract documents one', () => {
    const policy = policyOf(operation.create);
    expect(policy.body !== undefined).toBe(operation.hasBody);
  });

  it('spends no programmatic budget: the contract lists none for it', () => {
    const { 'x-rate-limit': limits } = contractOperation();
    expect(limits.some((limit) => 'programmatic' in limit)).toBe(false);
  });
});

describe('spec §3.9: provisioning and resetting a password share ONE counter', () => {
  it('the two policies carry the same scope, group, limit and window', () => {
    const provision = policyOf(createProvisionClientUserHandler);
    const reset = policyOf(createResetClientUserPasswordHandler);

    expect(provision.rateLimit).toEqual(reset.rateLimit);
    expect(provision.rateLimit?.[0]?.group).toBe('client-user-admin');
  });
});

describe('the pipeline in front of the client login routes (spec §3.5)', () => {
  it.each(OPERATIONS)(
    'E-07: $label answers 403 FORBIDDEN to a client user and the database is never reached',
    async (operation) => {
      const outbound = forbidOutbound();
      const client = principalFixture({
        role: 'client',
        clientId: CLIENT_ID,
        aal: 'aal1',
        pendingActions: [],
      });
      const { withRoute } = createTestPipeline({ principal: client });

      const response = await callOf(operation, withRoute);

      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ code: 'FORBIDDEN' });
      expect(outbound).not.toHaveBeenCalled();
    },
  );

  it.each(OPERATIONS)('SEC-01: $label answers 401 without a session', async (operation) => {
    const outbound = forbidOutbound();
    const { withRoute } = createTestPipeline({ principal: null });

    const response = await callOf(operation, withRoute);

    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(outbound).not.toHaveBeenCalled();
  });

  it.each([
    ['CHANGE_PASSWORD', ['CHANGE_PASSWORD', 'ENROLL_MFA'], 'aal1', 'PASSWORD_CHANGE_REQUIRED'],
    ['ENROLL_MFA', ['ENROLL_MFA'], 'aal1', 'MFA_ENROLLMENT_REQUIRED'],
    ['VERIFY_MFA', ['VERIFY_MFA'], 'aal1', 'MFA_VERIFICATION_REQUIRED'],
  ] as const)(
    'SEC-11: a CEO with %s pending is 403 %s on every client login route',
    async (_pending, pendingActions, aal, code) => {
      const outbound = forbidOutbound();
      const { withRoute } = createTestPipeline({
        principal: principalFixture({ aal, pendingActions: [...pendingActions] }),
      });

      for (const operation of OPERATIONS) {
        const response = await callOf(operation, withRoute);
        expect(response.status).toBe(403);
        expect(await response.json()).toMatchObject({ code });
      }
      expect(outbound).not.toHaveBeenCalled();
    },
  );

  describe('validation (a CEO aal2, before any use case)', () => {
    const ceo = () => createTestPipeline({ principal: principalFixture() });
    const context = (params: Record<string, string>) => ({ params: Promise.resolve(params) });

    it('E-06: a malformed clientId or userId is a 400 on every route', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();

      const responses = await Promise.all([
        createListClientUsersHandler(withRoute)(
          apiRequest('/admin/clients/nope/users'),
          context({ clientId: 'nope' }),
        ),
        createProvisionClientUserHandler(withRoute)(
          apiRequest('/admin/clients/nope/users', {
            method: 'POST',
            json: { email: 'maria@cliente.test', displayName: 'Maria' },
          }),
          context({ clientId: 'nope' }),
        ),
        createUpdateClientUserHandler(withRoute)(
          apiRequest(`${USERS}/nope`, { method: 'PATCH', json: { disabled: true } }),
          context({ clientId: CLIENT_ID, userId: 'nope' }),
        ),
        createResetClientUserPasswordHandler(withRoute)(
          apiRequest(`${USERS}/nope/password-reset`, { method: 'POST' }),
          context({ clientId: CLIENT_ID, userId: 'nope' }),
        ),
      ]);

      expect(responses.map((response) => response.status)).toEqual([400, 400, 400, 400]);
      expect(outbound).not.toHaveBeenCalled();
    });

    it('AC-23: an unknown field in the body (role, clientId, password, id) is a 400', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();
      const provision = createProvisionClientUserHandler(withRoute);
      const update = createUpdateClientUserHandler(withRoute);
      const post = (json: unknown) =>
        provision(apiRequest(USERS, { method: 'POST', json }), context({ clientId: CLIENT_ID }));
      const patch = (json: unknown) =>
        update(
          apiRequest(USER, { method: 'PATCH', json }),
          context({ clientId: CLIENT_ID, userId: USER_ID }),
        );
      const valid = { email: 'maria@cliente.test', displayName: 'Maria' };

      const responses = await Promise.all([
        post({ ...valid, role: 'ceo' }),
        post({ ...valid, clientId: CLIENT_ID }),
        post({ ...valid, password: 'a-password-of-mine' }),
        post({ ...valid, temporaryPassword: 'a-password-of-mine' }),
        patch({ disabled: true, email: 'other@cliente.test' }),
        patch({ disabled: true, id: USER_ID }),
        patch({ displayName: 'Maria', role: 'ceo' }),
      ]);

      expect(responses.map((response) => response.status)).toEqual(Array(7).fill(400));
      expect(outbound).not.toHaveBeenCalled();
    });

    it('AC-12: a bad e-mail, a bad name, a missing field or an empty patch is a 400', async () => {
      const outbound = forbidOutbound();
      const { withRoute } = ceo();
      const provision = createProvisionClientUserHandler(withRoute);
      const update = createUpdateClientUserHandler(withRoute);
      const post = (json: unknown) =>
        provision(apiRequest(USERS, { method: 'POST', json }), context({ clientId: CLIENT_ID }));
      const patch = (json: unknown) =>
        update(
          apiRequest(USER, { method: 'PATCH', json }),
          context({ clientId: CLIENT_ID, userId: USER_ID }),
        );

      const responses = await Promise.all([
        post({ email: 'not-an-email', displayName: 'Maria' }),
        post({ email: `${'a'.repeat(250)}@cliente.test`, displayName: 'Maria' }),
        post({ email: 'maria@cliente.test', displayName: '' }),
        post({ email: 'maria@cliente.test', displayName: '   ' }),
        post({ email: 'maria@cliente.test', displayName: 'a'.repeat(121) }),
        post({ email: 'maria@cliente.test', displayName: `A${String.fromCharCode(0xd800)}` }),
        post({ email: 'maria@cliente.test' }),
        post({ displayName: 'Maria' }),
        patch({}),
        patch({ disabled: 'yes' }),
        patch({ displayName: '' }),
      ]);

      expect(responses.map((response) => response.status)).toEqual(Array(11).fill(400));
      expect(outbound).not.toHaveBeenCalled();
    });
  });
});

describe('route.ts of the client login routes', () => {
  it('admin/clients/[clientId]/users re-exports GET and POST and pins the Node.js runtime', () => {
    expect(Object.keys(usersRoute).sort()).toEqual(['GET', 'POST', 'dynamic', 'runtime']);
    expect(usersRoute.GET).toBe(listClientUsersHandler);
    expect(usersRoute.POST).toBe(provisionClientUserHandler);
    expect(usersRoute.runtime).toBe('nodejs');
    expect(usersRoute.dynamic).toBe('force-dynamic');
  });

  it('.../users/[userId] re-exports PATCH and pins the Node.js runtime', () => {
    expect(Object.keys(userRoute).sort()).toEqual(['PATCH', 'dynamic', 'runtime']);
    expect(userRoute.PATCH).toBe(updateClientUserHandler);
    expect(userRoute.runtime).toBe('nodejs');
  });

  it('.../password-reset re-exports POST and pins the Node.js runtime', () => {
    expect(Object.keys(resetRoute).sort()).toEqual(['POST', 'dynamic', 'runtime']);
    expect(resetRoute.POST).toBe(resetClientUserPasswordHandler);
    expect(resetRoute.runtime).toBe('nodejs');
  });
});
