import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getAdminFacade } from '@/shared/db/admin-client';

// Obviously fake, lowercase-only values (the secret-detection hook rightly ignores them).
const FAKE_ENV = {
  APP_ORIGIN: 'http://localhost:3000',
  SUPABASE_URL: 'http://127.0.0.1:54321',
  SUPABASE_PUBLISHABLE_KEY: 'fake-publishable-key-for-unit-tests',
  SUPABASE_SECRET_KEY: 'fake-secret-key-for-unit-tests',
  RATE_LIMIT_KEY_SECRET: 'unit-test-only-rate-limit-key-not-a-real-value',
};

type Call = { url: string; headers: Headers; body: string };

function stubFetch(answer: () => Response) {
  const calls: Call[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    calls.push({
      url: String(input instanceof Request ? input.url : input),
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? init.body : '',
    });
    return Promise.resolve(answer());
  });
  return calls;
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

beforeEach(() => {
  for (const [name, value] of Object.entries(FAKE_ENV)) vi.stubEnv(name, value);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe('getAdminFacade', () => {
  it('SEC-15: hands out a narrow facade, never the Supabase client: only authAdmin and rateLimitHit', () => {
    const facade = getAdminFacade();

    expect(Object.keys(facade).sort()).toEqual(['authAdmin', 'rateLimitHit']);
    // nothing of a session-bearing or table-reaching client leaks through
    for (const name of ['from', 'rpc', 'auth', 'storage', 'schema', 'signInWithPassword']) {
      expect(facade).not.toHaveProperty(name);
    }
    expect(facade.authAdmin).not.toHaveProperty('signInWithPassword');
    expect(facade.authAdmin).not.toHaveProperty('signUp');
    expect(facade.authAdmin).not.toHaveProperty('getSession');
  });

  it('is frozen and a singleton: nobody can add a method to the shared object', () => {
    const facade = getAdminFacade();
    expect(getAdminFacade()).toBe(facade);
    expect(Object.isFrozen(facade)).toBe(true);
  });

  it('SEC-15: rateLimitHit calls the RPC with the secret key and the typed parameters', async () => {
    const data = [{ allowed: true, retry_after_seconds: 0 }];
    const calls = stubFetch(() => json(data));

    const answer = await getAdminFacade().rateLimitHit({
      bucket: 'ip:login:abc',
      windowSeconds: 900,
      max: 20,
    });

    expect(answer).toEqual(data);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toContain('/rest/v1/rpc/rate_limit_hit');
    expect(calls[0]?.headers.get('apikey')).toBe(FAKE_ENV.SUPABASE_SECRET_KEY);
    expect(JSON.parse(calls[0]?.body ?? '{}')).toEqual({
      p_bucket: 'ip:login:abc',
      p_window_seconds: 900,
      p_max: 20,
    });
  });

  it('E-22: rateLimitHit throws when the RPC fails, without echoing what the database said', async () => {
    stubFetch(() => json({ message: 'internal detail', code: '57P01' }, 500));

    const rejection = getAdminFacade().rateLimitHit({ bucket: 'b', windowSeconds: 1, max: 1 });

    await expect(rejection).rejects.toThrow('rate_limit_hit failed');
    await expect(rejection).rejects.not.toThrow('internal detail');
  });
});
