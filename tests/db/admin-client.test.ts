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
  it('SEC-15: hands out a narrow facade, never the Supabase client: the Auth Admin API and named RPC wrappers only', () => {
    const facade = getAdminFacade();

    expect(Object.keys(facade).sort()).toEqual([
      'attestMfaSession',
      'authAdmin',
      'rateLimitHit',
      'recordBackendMfaChallenge',
      'registerBackendTotpFactor',
    ]);
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

  it.each([
    [
      'registerBackendTotpFactor',
      'register_backend_totp_factor',
      { userId: 'u', factorId: 'f', sessionId: 's' },
      { p_user_id: 'u', p_factor_id: 'f', p_session_id: 's' },
    ],
    [
      'recordBackendMfaChallenge',
      'record_backend_mfa_challenge',
      { userId: 'u', factorId: 'f', challengeId: 'c' },
      { p_user_id: 'u', p_factor_id: 'f', p_challenge_id: 'c' },
    ],
    [
      'attestMfaSession',
      'attest_mfa_session',
      { userId: 'u', sessionId: 's', factorId: 'f', challengeId: 'c' },
      { p_user_id: 'u', p_session_id: 's', p_factor_id: 'f', p_challenge_id: 'c' },
    ],
  ] as const)(
    'F-63: %s calls the %s RPC with the secret key and the typed parameters, and returns the answer',
    async (method, rpcName, input, body) => {
      const calls = stubFetch(() => json('attested'));

      const answer = await getAdminFacade()[method](input as never);

      expect(answer).toEqual({ data: 'attested', error: null, status: 200 });
      expect(calls).toHaveLength(1);
      expect(calls[0]?.url).toContain(`/rest/v1/rpc/${rpcName}`);
      expect(calls[0]?.headers.get('apikey')).toBe(FAKE_ENV.SUPABASE_SECRET_KEY);
      expect(JSON.parse(calls[0]?.body ?? '{}')).toEqual(body);
    },
  );

  it('F-63: an error of an attestation RPC keeps only the SQLSTATE and the message (no details, no hint) and the status', async () => {
    stubFetch(() =>
      json(
        { code: 'P0001', message: 'NOT_FOUND', details: 'internal detail', hint: 'internal hint' },
        400,
      ),
    );

    const answer = await getAdminFacade().recordBackendMfaChallenge({
      userId: 'u',
      factorId: 'f',
      challengeId: 'c',
    });

    expect(answer).toEqual({
      data: null,
      error: { code: 'P0001', message: 'NOT_FOUND' },
      status: 400,
    });
  });

  it('E-21: a transport failure of an attestation RPC is an error answer with status 0, not an exception', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('fetch failed'));

    const answer = await getAdminFacade().attestMfaSession({
      userId: 'u',
      sessionId: 's',
      factorId: 'f',
      challengeId: 'c',
    });

    expect(answer.error).not.toBeNull();
    expect(answer.status).toBe(0);
  });
});
