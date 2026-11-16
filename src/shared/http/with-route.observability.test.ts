import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { NotFoundError, ServiceUnavailableError } from '@/shared/kernel';
import { json } from './responses';
import {
  apiRequest,
  CEO_POLICY,
  createTestPipeline,
  principalFixture,
  PUBLIC_POLICY,
} from './testing';

const PROCESS_ID = '6f1d5a3e-3b0c-4f43-9a55-0d3f6f6f1a11';

describe('withRoute: access log', () => {
  it('writes one line per request with requestId, route, method, status, durationMs, userId and role', async () => {
    const principal = principalFixture({ userId: '33333333-3333-4333-8333-333333333333' });
    const { withRoute, logs } = createTestPipeline({ principal });
    const route = withRoute(CEO_POLICY, () => json(200, {}));
    const response = await route(apiRequest('/admin/clients'));

    const lines = logs.records().filter((record) => record['msg'] === 'request completed');
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({
      level: 'info',
      requestId: response.headers.get('x-request-id'),
      route: '/api/v1/admin/clients',
      method: 'GET',
      status: 200,
      userId: '33333333-3333-4333-8333-333333333333',
      role: 'ceo',
    });
    expect(typeof lines[0]?.['durationMs']).toBe('number');
    expect(lines[0]?.['durationMs'] as number).toBeGreaterThanOrEqual(0);
  });

  it('omits userId and role for anonymous requests and still logs the failure status', async () => {
    const { withRoute, logs } = createTestPipeline({ principal: null });
    const route = withRoute(CEO_POLICY, () => json(200, {}));
    await route(apiRequest('/admin/clients'));
    const line = logs.records().find((record) => record['msg'] === 'request completed');
    expect(line).toMatchObject({ status: 401 });
    expect(line).not.toHaveProperty('userId');
    expect(line).not.toHaveProperty('role');
  });

  it('logs the route template, not the ids in the path', async () => {
    const { withRoute, logs } = createTestPipeline({ principal: principalFixture() });
    const route = withRoute(
      {
        ...CEO_POLICY,
        params: z.object({ processId: z.uuid() }).strict(),
      },
      () => json(200, {}),
    );
    await route(apiRequest(`/admin/processes/${PROCESS_ID}/approvals`), {
      params: Promise.resolve({ processId: PROCESS_ID }),
    });
    const line = logs.records().find((record) => record['msg'] === 'request completed');
    expect(line?.['route']).toBe('/api/v1/admin/processes/[processId]/approvals');
    expect(logs.lines.join('')).not.toContain(PROCESS_ID);
  });

  it('every line of a request carries its requestId', async () => {
    const { withRoute, logs } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, ({ logger }) => {
      logger.info('inside the handler');
      return json(200, {});
    });
    const response = await route(apiRequest('/x'));
    const id = response.headers.get('x-request-id');
    const records = logs.records();
    expect(records.length).toBeGreaterThanOrEqual(2);
    for (const record of records) expect(record['requestId']).toBe(id);
  });
});

describe('withRoute: security events', () => {
  it('logs authz.denied with the reason for a wrong role, including who was denied', async () => {
    const principal = principalFixture({
      userId: '44444444-4444-4444-8444-444444444444',
      role: 'client',
      clientId: 'c1',
    });
    const { withRoute, logs } = createTestPipeline({ principal });
    const route = withRoute(CEO_POLICY, () => json(200, {}));
    await route(apiRequest('/admin/clients'));
    expect(logs.events('authz.denied')).toEqual([
      expect.objectContaining({
        level: 'warn',
        reason: 'role_not_allowed',
        userId: '44444444-4444-4444-8444-444444444444',
        role: 'client',
      }),
    ]);
  });

  it('logs authz.denied with the pending action that blocked the request', async () => {
    const { withRoute, logs } = createTestPipeline({
      principal: principalFixture({ pendingActions: ['ENROLL_MFA', 'VERIFY_MFA'] }),
    });
    const route = withRoute(CEO_POLICY, () => json(200, {}));
    await route(apiRequest('/admin/clients'));
    expect(logs.events('authz.denied')).toEqual([
      expect.objectContaining({ reason: 'pending_action:ENROLL_MFA' }),
    ]);
  });

  it('logs authz.denied for a refused Origin', async () => {
    const { withRoute, logs } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, () => json(200, {}));
    await route(apiRequest('/x', { method: 'POST', origin: 'https://evil.test' }));
    const [event] = logs.events('authz.denied');
    expect(event).toMatchObject({ reason: 'origin_not_allowed' });
    // the foreign origin is attacker-controlled text: it is not copied into the log
    expect(logs.lines.join('')).not.toContain('evil.test');
  });

  it('logs auth.rate_limited with scope and group, without the IP or the account', async () => {
    const { withRoute, logs } = createTestPipeline();
    const route = withRoute(
      {
        ...PUBLIC_POLICY,
        rateLimit: [{ scope: 'ip', group: 'reads', limit: 1, windowSeconds: 60 }],
      },
      () => json(200, {}),
    );
    const headers = { 'x-real-ip': '203.0.113.77' };
    await route(apiRequest('/x', { headers }));
    await route(apiRequest('/x', { headers }));
    expect(logs.events('auth.rate_limited')).toEqual([
      expect.objectContaining({ level: 'warn', scope: 'ip', group: 'reads' }),
    ]);
    expect(logs.lines.join('')).not.toContain('203.0.113.77');
  });

  it('does not log authz.denied for plain 401s or successful requests', async () => {
    const { withRoute, logs } = createTestPipeline({ principal: null });
    const route = withRoute(CEO_POLICY, () => json(200, {}));
    await route(apiRequest('/x'));
    expect(logs.events('authz.denied')).toHaveLength(0);
  });
});

describe('withRoute: no PII in logs', () => {
  it('never writes e-mail, password, cookies or authorization from the request to the logs', async () => {
    const email = 'maria.silva@cliente.com.br';
    const password = 'correct-horse-battery-staple';
    const cookie = '__Host-rt-session=eyJhbGciOiJFUzI1NiJ9.payload.signature';
    const authorization = 'Bearer eyJhbGciOiJFUzI1NiJ9.payload.signature';
    const { withRoute, logs } = createTestPipeline();
    const route = withRoute(
      {
        access: 'public',
        body: z.object({ email: z.string(), password: z.string() }).strict(),
        rateLimit: [{ scope: 'ip', group: 'reads', limit: 1, windowSeconds: 60 }],
      },
      ({ body, logger }) => {
        // even a careless handler that logs the whole body cannot leak it
        logger.info({ body, headers: { cookie, authorization } }, 'careless log');
        return json(200, {});
      },
    );
    const request = () =>
      apiRequest('/auth/login', {
        method: 'POST',
        json: { email, password },
        headers: { cookie, authorization },
      });
    await route(request());
    await route(request()); // rate limited
    const output = logs.lines.join('');
    for (const secret of [email, password, cookie, authorization, 'eyJhbGciOiJFUzI1NiJ9']) {
      expect(output).not.toContain(secret);
    }
  });
});

describe('withRoute: server errors are logged, client errors are not escalated', () => {
  it('logs an unhandled exception at error level with its stack', async () => {
    const { withRoute, logs } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, () => {
      throw new Error('boom');
    });
    await route(apiRequest('/x'));
    const record = logs.records().find((entry) => entry['level'] === 'error');
    expect(record).toMatchObject({ msg: 'unhandled exception' });
    expect((record?.['err'] as { stack: string }).stack).toContain('boom');
  });

  it('logs a 5xx DomainError (503) at error level, keeping its cause for the on-call engineer', async () => {
    const { withRoute, logs } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, () => {
      throw new ServiceUnavailableError('supabase timed out', { cause: new Error('ETIMEDOUT') });
    });
    const response = await route(apiRequest('/x'));
    expect(response.status).toBe(503);
    const record = logs.records().find((entry) => entry['level'] === 'error');
    expect(JSON.stringify(record)).toContain('ETIMEDOUT');
  });

  it('does not log 4xx domain errors at error level', async () => {
    const { withRoute, logs } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, () => new NotFoundError('nope'));
    await route(apiRequest('/x'));
    expect(logs.records().some((entry) => entry['level'] === 'error')).toBe(false);
  });
});
