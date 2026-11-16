import { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createCookieJar } from '@/shared/http/cookies';
import { getRequestSupabase } from './server-client';

// Obviously fake, lowercase-only values (the secret-detection hook rightly ignores them).
const FAKE_ENV = {
  APP_ORIGIN: 'http://localhost:3000',
  SUPABASE_URL: 'http://127.0.0.1:54321',
  SUPABASE_PUBLISHABLE_KEY: 'fake-publishable-key-for-unit-tests',
  SUPABASE_SECRET_KEY: 'fake-secret-key-for-unit-tests',
  RATE_LIMIT_KEY_SECRET: 'unit-test-only-rate-limit-key-not-a-real-value',
};

const requestOf = () => new NextRequest('http://localhost:3000/api/v1/auth/session');

type Call = { url: string; headers: Headers; method: string };

/** Answers every outbound call with `answer(url)` and remembers what was sent. */
function stubFetch(answer: (url: string) => Response) {
  const calls: Call[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = String(input instanceof Request ? input.url : input);
    calls.push({ url, headers: new Headers(init?.headers), method: init?.method ?? 'GET' });
    return Promise.resolve(answer(url));
  });
  return calls;
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

const FAKE_SESSION = {
  access_token: 'header.payload.signature',
  token_type: 'bearer',
  expires_in: 900,
  expires_at: Math.floor(Date.now() / 1000) + 900,
  refresh_token: 'fake-refresh-token',
  user: { id: '11111111-1111-4111-8111-111111111111', aud: 'authenticated', email: 'a@b.test' },
};

beforeEach(() => {
  for (const [name, value] of Object.entries(FAKE_ENV)) vi.stubEnv(name, value);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe('getRequestSupabase', () => {
  it('SEC-07: returns ONE client per request, so the resolver and the handler never refresh twice', () => {
    const request = requestOf();
    const cookies = createCookieJar([]);

    const first = getRequestSupabase({ request, cookies, requestId: 'request-id-1' });
    const second = getRequestSupabase({ request, cookies, requestId: 'request-id-1' });

    expect(second).toBe(first);
  });

  it('never shares a client between two requests', () => {
    const one = getRequestSupabase({
      request: requestOf(),
      cookies: createCookieJar([]),
      requestId: 'request-id-1',
    });
    const other = getRequestSupabase({
      request: requestOf(),
      cookies: createCookieJar([]),
      requestId: 'request-id-2',
    });

    expect(other).not.toBe(one);
  });

  it('refuses a second call that brings ANOTHER cookie jar (it would be silently ignored)', () => {
    const request = requestOf();
    getRequestSupabase({ request, cookies: createCookieJar([]), requestId: 'request-id-1' });

    expect(() =>
      getRequestSupabase({ request, cookies: createCookieJar([]), requestId: 'request-id-1' }),
    ).toThrow('different cookie jar');
  });

  it('forwards x-request-id and the publishable key on every call (SEC-15, RNF-04)', async () => {
    const calls = stubFetch(() => json([]));
    const client = getRequestSupabase({
      request: requestOf(),
      cookies: createCookieJar([]),
      requestId: 'request-id-77',
    });

    await client.from('clients').select('id');

    expect(calls).toHaveLength(1);
    expect(calls[0]?.headers.get('x-request-id')).toBe('request-id-77');
    expect(calls[0]?.headers.get('apikey')).toBe(FAKE_ENV.SUPABASE_PUBLISHABLE_KEY);
  });

  it('SEC-19: every outbound call carries an abort signal (the 5 s timeout)', async () => {
    const seen: (AbortSignal | null | undefined)[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      seen.push(init?.signal);
      return Promise.resolve(json([]));
    });
    const client = getRequestSupabase({
      request: requestOf(),
      cookies: createCookieJar([]),
      requestId: 'request-id-1',
    });

    await client.from('clients').select('id');

    expect(seen[0]).toBeInstanceOf(AbortSignal);
  });

  it('SEC-07: a new session goes into the jar as __Host-rt-session, and a sign-out deletes it', async () => {
    stubFetch((url) =>
      url.includes('/logout') ? new Response(null, { status: 204 }) : json(FAKE_SESSION),
    );
    const cookies = createCookieJar([]);
    const client = getRequestSupabase({ request: requestOf(), cookies, requestId: 'request-id-1' });

    const signedIn = await client.auth.signInWithPassword({ email: 'a@b.test', password: 'x' });

    expect(signedIn.error).toBeNull();
    const names = cookies.getAll().map(({ name }) => name);
    expect(names.length).toBeGreaterThan(0);
    for (const name of names) expect(name).toMatch(/^__Host-rt-session(\.\d+)?$/);

    const headers = new Headers();
    cookies.applyTo(headers);
    for (const cookie of headers.getSetCookie()) {
      expect(cookie).toMatch(/;\s*HttpOnly(;|$)/i);
      expect(cookie).toMatch(/;\s*Secure(;|$)/i);
      expect(cookie).toMatch(/;\s*SameSite=lax(;|$)/i);
      expect(cookie).toMatch(/;\s*Path=\/(;|$)/i);
      expect(cookie).not.toMatch(/Domain=/i);
      expect(cookie).not.toMatch(/Max-Age=0/i);
    }

    await client.auth.signOut({ scope: 'local' });

    expect(cookies.getAll()).toEqual([]);
    const cleared = new Headers();
    cookies.applyTo(cleared);
    expect(cleared.getSetCookie().length).toBeGreaterThan(0);
    for (const cookie of cleared.getSetCookie()) expect(cookie).toMatch(/Max-Age=0/i);
  });
});
