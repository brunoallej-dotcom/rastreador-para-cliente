import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { NextRequest } from 'next/server';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { parse } from 'yaml';
import * as healthRoute from '@/app/api/v1/health/route';
import { expectToMatchContract } from '../../../../tests/helpers/contract';
import { healthHandler } from './health.handler';

type HealthOperation = {
  'x-auth-policy': { access: string };
  'x-rate-limit': { scope: string; limit: number; windowSeconds: number }[];
  security: unknown[];
};

const contract = parse(
  readFileSync(
    fileURLToPath(new URL('../../../../contracts/openapi.v1.yaml', import.meta.url)),
    'utf8',
  ),
) as { paths: { '/health': { get: HealthOperation } } };
const healthOperation = contract.paths['/health'].get;

const APP_ORIGIN = 'http://localhost:3000';

const getHealth = (headers: Record<string, string> = {}) =>
  healthHandler(new NextRequest(`${APP_ORIGIN}/api/v1/health`, { headers }), {
    params: Promise.resolve({}),
  });

let ipCounter = 0;
/** Each test gets its own client IP, so the in-memory limiter of the real wiring never interferes. */
const freshIp = () => {
  ipCounter += 1;
  return { 'x-real-ip': `203.0.113.${ipCounter}` };
};

describe('GET /health', () => {
  // The production `withRoute` reads the validated env on first use (lazily, never at import).
  beforeAll(() => {
    vi.stubEnv('APP_ORIGIN', APP_ORIGIN);
    vi.stubEnv('SUPABASE_URL', 'http://127.0.0.1:54321');
    vi.stubEnv('SUPABASE_PUBLISHABLE_KEY', 'test-publishable-key');
    vi.stubEnv('SUPABASE_SECRET_KEY', 'test-secret-key');
    vi.stubEnv('RATE_LIMIT_KEY_SECRET', 'test-only-rate-limit-hmac-key-0123456789');
    vi.stubEnv('LOG_LEVEL', 'error');
  });
  afterAll(() => {
    vi.unstubAllEnvs();
  });

  it('AC-29: answers 200 { "status": "ok" } without a session and with no internal details', async () => {
    const response = await getHealth(freshIp());
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('application/json');
    const body: unknown = await response.json();
    expect(body).toEqual({ status: 'ok' });
    expect(Object.keys(body as object)).toEqual(['status']);
  });

  it('AC-29: needs no authentication: a bogus cookie or Authorization header changes nothing', async () => {
    const response = await getHealth({
      ...freshIp(),
      cookie: '__Host-rt-session=garbage',
      authorization: 'Bearer garbage',
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: 'ok' });
  });

  it('AC-29: leaks no version, dependency or host information in the body or headers', async () => {
    const response = await getHealth(freshIp());
    const text = JSON.stringify([...response.headers]) + (await response.text());
    expect(text).not.toMatch(/version|supabase|postgres|node|next|vercel|uptime|127\.0\.0\.1/i);
  });

  it('AC-26: the response validates against the contract (getHealth 200)', async () => {
    const response = await getHealth(freshIp());
    expectToMatchContract('getHealth', response.status, await response.json());
  });

  it('AC-22: carries the security headers and a server-generated X-Request-Id', async () => {
    const response = await getHealth({ ...freshIp(), 'x-request-id': 'probe-0000-0001' });
    // F-11: the client's id is never the request's own id
    expect(response.headers.get('x-request-id')).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('strict-transport-security')).toContain('max-age=63072000');
  });

  it('declares the policy of the contract: public, ip rate limit 60 per 60 s', async () => {
    expect(healthOperation.security).toEqual([]);
    expect(healthOperation['x-auth-policy']).toEqual({ access: 'public' });
    expect(healthOperation['x-rate-limit']).toEqual([
      { scope: 'ip', limit: 60, windowSeconds: 60 },
    ]);

    const limit = healthOperation['x-rate-limit'][0]?.limit ?? 0;
    expect(limit).toBe(60);
    const headers = freshIp();
    for (let request = 1; request <= limit; request += 1) {
      expect((await getHealth(headers)).status, `request ${request}`).toBe(200);
    }
    const throttled = await getHealth(headers);
    expect(throttled.status).toBe(429);
    expect(Number(throttled.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expectToMatchContract('getHealth', throttled.status, await throttled.json());
    // another client is not affected
    expect((await getHealth(freshIp())).status).toBe(200);
  });
});

describe('route.ts of /health', () => {
  it('only re-exports the handler as GET and pins the Node.js runtime', () => {
    expect(Object.keys(healthRoute).sort()).toEqual(['GET', 'dynamic', 'runtime']);
    expect(healthRoute.GET).toBe(healthHandler);
    expect(healthRoute.runtime).toBe('nodejs');
    expect(healthRoute.dynamic).toBe('force-dynamic');
  });
});
