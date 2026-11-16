import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parse } from 'yaml';
import * as enrollRoute from '@/app/api/v1/auth/mfa/totp/enroll/route';
import * as verifyRoute from '@/app/api/v1/auth/mfa/totp/verify/route';
import type { RuntimePolicy, WithRoute } from '@/shared/http/route-policy';
import { apiRequest, createTestPipeline, principalFixture } from '@/shared/http/testing';
import { createEnrollTotpHandler, enrollTotpHandler } from './enroll-totp.handler';
import { createVerifyTotpHandler, verifyTotpHandler } from './verify-totp.handler';

type ContractOperation = {
  operationId: string;
  'x-auth-policy': { access: string; roles: string[]; allowPending: string[] };
  'x-rate-limit': { scope: string; limit: number; windowSeconds: number; programmatic?: boolean }[];
};

/** The rules of the route policy: the entries the handler spends on top (`programmatic`) are not. */
const policyRules = (limits: ContractOperation['x-rate-limit']) =>
  limits
    .filter(({ programmatic }) => programmatic !== true)
    .map(({ scope, limit, windowSeconds }) => ({ scope, limit, windowSeconds }));

const contract = parse(
  readFileSync(
    fileURLToPath(new URL('../../../../contracts/openapi.v1.yaml', import.meta.url)),
    'utf8',
  ),
) as { paths: Record<string, { post?: ContractOperation }> };

const enrollOperation = contract.paths['/auth/mfa/totp/enroll']?.post;
const verifyOperation = contract.paths['/auth/mfa/totp/verify']?.post;

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

/** Bodies are checked in `tests/api`; here a fetch to Auth would be a bug of the test. */
function forbidOutbound() {
  return vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('no outbound call expected'));
}

describe('POST /auth/mfa/totp/enroll: policy of the contract', () => {
  const operation = () => {
    if (enrollOperation === undefined) throw new Error('enrollTotp is not in the contract');
    return enrollOperation;
  };

  it('is the operation enrollTotp', () => {
    expect(operation().operationId).toBe('enrollTotp');
  });

  it('declares the roles, the allowed pendings and the rate limit of the contract', () => {
    const policy = policyOf(createEnrollTotpHandler);
    const { 'x-auth-policy': auth, 'x-rate-limit': limits } = operation();

    expect(policy.access).toBe(auth.access);
    expect(policy.roles).toEqual(auth.roles);
    expect(policy.allowPending).toEqual(auth.allowPending);
    expect(policy.allowPending).toEqual(['ENROLL_MFA']);
    expect(policy.rateLimit).toEqual(
      policyRules(limits).map((limit) => ({ ...limit, group: 'totp-enroll' })),
    );
    expect(policy.rateLimit).toEqual([
      { scope: 'user', group: 'totp-enroll', limit: 10, windowSeconds: 900 },
    ]);
  });

  it('has no body schema: the contract documents no request body', () => {
    expect(policyOf(createEnrollTotpHandler).body).toBeUndefined();
  });
});

describe('POST /auth/mfa/totp/verify: policy of the contract', () => {
  const operation = () => {
    if (verifyOperation === undefined) throw new Error('verifyTotp is not in the contract');
    return verifyOperation;
  };

  it('is the operation verifyTotp', () => {
    expect(operation().operationId).toBe('verifyTotp');
  });

  it('declares the roles, the allowed pendings and the rate limit of the contract', () => {
    const policy = policyOf(createVerifyTotpHandler);
    const { 'x-auth-policy': auth, 'x-rate-limit': limits } = operation();

    expect(policy.access).toBe(auth.access);
    expect(policy.roles).toEqual(auth.roles);
    expect(policy.allowPending).toEqual(auth.allowPending);
    expect(policy.allowPending).toEqual(['ENROLL_MFA', 'VERIFY_MFA']);
    expect(policy.rateLimit).toEqual(
      policyRules(limits).map((limit) => ({ ...limit, group: 'totp-verify' })),
    );
    expect(policy.rateLimit).toEqual([
      { scope: 'user', group: 'totp-verify', limit: 5, windowSeconds: 300 },
    ]);
  });

  it('validates a body with the contract schema (TotpVerifyRequest)', () => {
    expect(policyOf(createVerifyTotpHandler).body).toBeDefined();
  });
});

describe('the pipeline in front of the MFA routes (spec §3.5)', () => {
  const ceoWith = (
    pendingActions: ('CHANGE_PASSWORD' | 'ENROLL_MFA' | 'VERIFY_MFA')[],
    aal: 'aal1' | 'aal2' = 'aal1',
  ) => principalFixture({ aal, pendingActions });

  const verifyBody = { factorId: '33333333-3333-4333-8333-333333333333', code: '123456' };

  it.each([
    ['enroll', 'CHANGE_PASSWORD', 'PASSWORD_CHANGE_REQUIRED'],
    ['verify', 'CHANGE_PASSWORD', 'PASSWORD_CHANGE_REQUIRED'],
    ['enroll', 'VERIFY_MFA', 'MFA_VERIFICATION_REQUIRED'],
  ] as const)(
    'SEC-11: %s with %s pending is 403 %s and Auth is never called',
    async (which, pending, code) => {
      const outbound = forbidOutbound();
      const { withRoute } = createTestPipeline({
        principal: ceoWith(
          pending === 'CHANGE_PASSWORD' ? ['CHANGE_PASSWORD', 'ENROLL_MFA'] : [pending],
        ),
      });
      const handler =
        which === 'enroll'
          ? createEnrollTotpHandler(withRoute)
          : createVerifyTotpHandler(withRoute);
      const path = which === 'enroll' ? '/auth/mfa/totp/enroll' : '/auth/mfa/totp/verify';

      const response = await handler(
        apiRequest(path, { method: 'POST', ...(which === 'verify' ? { json: verifyBody } : {}) }),
      );

      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ code });
      expect(outbound).not.toHaveBeenCalled();
    },
  );

  it('a client is 403 FORBIDDEN on both routes, whatever it has pending', async () => {
    const outbound = forbidOutbound();
    const client = principalFixture({
      role: 'client',
      clientId: '22222222-2222-4222-8222-222222222222',
      aal: 'aal1',
      pendingActions: [],
    });
    const { withRoute } = createTestPipeline({ principal: client });

    const enroll = await createEnrollTotpHandler(withRoute)(
      apiRequest('/auth/mfa/totp/enroll', { method: 'POST' }),
    );
    const verify = await createVerifyTotpHandler(withRoute)(
      apiRequest('/auth/mfa/totp/verify', { method: 'POST', json: verifyBody }),
    );

    expect(enroll.status).toBe(403);
    expect(verify.status).toBe(403);
    expect(await enroll.json()).toMatchObject({ code: 'FORBIDDEN' });
    expect(await verify.json()).toMatchObject({ code: 'FORBIDDEN' });
    expect(outbound).not.toHaveBeenCalled();
  });

  it('no session is 401 on both routes', async () => {
    const outbound = forbidOutbound();
    const { withRoute } = createTestPipeline({ principal: null });

    const enroll = await createEnrollTotpHandler(withRoute)(
      apiRequest('/auth/mfa/totp/enroll', { method: 'POST' }),
    );
    const verify = await createVerifyTotpHandler(withRoute)(
      apiRequest('/auth/mfa/totp/verify', { method: 'POST', json: verifyBody }),
    );

    expect([enroll.status, verify.status]).toEqual([401, 401]);
    expect(outbound).not.toHaveBeenCalled();
  });

  it('E-14: an unknown field or a malformed code is 400, the code is not echoed and Auth is not called', async () => {
    const outbound = forbidOutbound();
    const { withRoute } = createTestPipeline({ principal: ceoWith(['ENROLL_MFA']) });
    const handler = createVerifyTotpHandler(withRoute);

    const unknownField = await handler(
      apiRequest('/auth/mfa/totp/verify', { method: 'POST', json: { ...verifyBody, extra: 1 } }),
    );
    const shortCode = await handler(
      apiRequest('/auth/mfa/totp/verify', { method: 'POST', json: { ...verifyBody, code: '12' } }),
    );

    expect(unknownField.status).toBe(400);
    expect(shortCode.status).toBe(400);
    expect(JSON.stringify(await shortCode.json())).not.toContain('"12"');
    expect(outbound).not.toHaveBeenCalled();
  });
});

describe('route.ts of the MFA routes', () => {
  it('enroll only re-exports the handler as POST and pins the Node.js runtime', () => {
    expect(Object.keys(enrollRoute).sort()).toEqual(['POST', 'dynamic', 'runtime']);
    expect(enrollRoute.POST).toBe(enrollTotpHandler);
    expect(enrollRoute.runtime).toBe('nodejs');
    expect(enrollRoute.dynamic).toBe('force-dynamic');
  });

  it('verify only re-exports the handler as POST and pins the Node.js runtime', () => {
    expect(Object.keys(verifyRoute).sort()).toEqual(['POST', 'dynamic', 'runtime']);
    expect(verifyRoute.POST).toBe(verifyTotpHandler);
    expect(verifyRoute.runtime).toBe('nodejs');
    expect(verifyRoute.dynamic).toBe('force-dynamic');
  });
});
