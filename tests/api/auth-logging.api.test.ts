// What login and logout write to the logs (spec §3.10, SEC-16): the events exist, they carry the
// request id and an internal id or an HMAC, and never the e-mail, the password, a token or the
// cookie. The process logger is replaced by one that captures its lines; everything else is real.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type * as LoggerModule from '@/shared/observability/logger';
import { POST as loginRoute } from '@/app/api/v1/auth/login/route';
import { POST as logoutRoute } from '@/app/api/v1/auth/logout/route';
import { sessionIdOfToken } from '@/shared/db/session-cookies';
import { hmacSubject } from '@/shared/http/rate-limit/subject-hmac';
import { timing } from '@/shared/http/response-floor';
import {
  ceoAal2Client,
  createClient,
  createClientUser,
  disableAccount,
  uniqueEmail,
} from '../helpers/fixtures';
import {
  createCookieStore,
  invoke,
  newClientIp,
  readSessionCookie,
  spyOnSupabaseFetch,
} from '../helpers/http';

const logged = vi.hoisted(() => ({ lines: [] as string[] }));

vi.mock('@/shared/observability/logger', async (importOriginal) => {
  const original = await importOriginal<typeof LoggerModule>();
  const logger = original.createLogger({
    level: 'trace',
    destination: {
      write(chunk: string) {
        logged.lines.push(chunk);
      },
    },
  });
  return { ...original, getLogger: () => logger };
});

const records = () => logged.lines.map((line) => JSON.parse(line) as Record<string, unknown>);
const events = (name: string) => records().filter((record) => record['event'] === name);

const login = (email: string, password: string, cookies = createCookieStore()) =>
  invoke(loginRoute, { method: 'POST', path: '/auth/login', body: { email, password }, cookies });

const authAnswers = (status: number, errorCode: string) =>
  Response.json({ code: status, error_code: errorCode, msg: 'simulated by the test' }, { status });

/** A login attempt (unknown e-mail) while the token endpoint of Auth answers `answer()`. */
async function loginWhileAuthAnswers(answer: () => Response | Error): Promise<Response> {
  const spy = spyOnSupabaseFetch((url) => (url.includes('/auth/v1/token') ? answer() : undefined));
  try {
    return await login(uniqueEmail('mapping'), 'any-password-1');
  } finally {
    spy.restore();
  }
}

describe('auth events in the logs', () => {
  beforeEach(() => {
    // a refused login waits for its floor (F-05); these tests do not wait for real
    vi.spyOn(timing, 'sleep').mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('SEC-16: auth.login.failed carries an HMAC of the normalized e-mail and a generic reason, never the e-mail or the password', async () => {
    const email = uniqueEmail('Failing');
    const password = 'Wrong-Password-For-Logs-1';
    logged.lines.length = 0;

    const response = await login(`  ${email.toUpperCase()} `, password);

    expect(response.status).toBe(401);
    const [failed] = events('auth.login.failed');
    expect(failed).toBeDefined();
    expect(failed).toMatchObject({
      level: 'warn',
      reason: 'invalid_credentials',
      requestId: response.headers.get('x-request-id'),
    });
    const secret = process.env.RATE_LIMIT_KEY_SECRET ?? '';
    // the HMAC is over the NORMALIZED e-mail: every spelling of it is the same account...
    const logKey = hmacSubject(secret, 'log-fingerprint-v1');
    expect(failed?.['accountHash']).toBe(hmacSubject(logKey, email.toLowerCase()));
    // ...and it is NOT the value the rate limiter stores in the database for that account
    expect(failed?.['accountHash']).not.toBe(hmacSubject(secret, email.toLowerCase()));
    // F-09: a keyed hash of the client IP, never the IP
    expect(failed?.['ipHash']).toMatch(/^[0-9a-f]{64}$/);

    const everything = logged.lines.join('\n');
    expect(everything).not.toContain(password);
    expect(everything.toLowerCase()).not.toContain(email.toLowerCase());
    expect(everything.toLowerCase()).not.toContain(email.split('@')[0]?.toLowerCase());
  });

  it("F-11: the request id is the server's; a valid X-Request-Id of the client is logged beside it as clientRequestId", async () => {
    logged.lines.length = 0;

    const response = await invoke(loginRoute, {
      method: 'POST',
      path: '/auth/login',
      body: { email: uniqueEmail('trace'), password: 'any-password-1' },
      headers: { 'x-request-id': 'client-trace-0001' },
    });

    const id = response.headers.get('x-request-id');
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect((await response.clone().json()) as { requestId: string }).toMatchObject({
      requestId: id,
    });
    const [failed] = events('auth.login.failed');
    expect(failed).toMatchObject({ requestId: id, clientRequestId: 'client-trace-0001' });
  });

  it('SEC-16: auth.login.failed names the category: invalid_credentials or account_inactive for a refusal of credentials', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });
    const disabled = await createClientUser({ clientId: client.id });
    await disableAccount(await ceoAal2Client(), disabled.id);
    logged.lines.length = 0;

    await login(user.email, `${user.password}-wrong`);
    await login(uniqueEmail('nobody'), user.password);
    await login(disabled.email, disabled.password);
    await loginWhileAuthAnswers(() => authAnswers(403, 'user_banned'));
    await loginWhileAuthAnswers(() => authAnswers(400, 'email_not_confirmed'));

    // the response is the same 401 for all of them; the log tells them apart, with no personal data
    expect(events('auth.login.failed').map((record) => record['reason'])).toEqual([
      'invalid_credentials',
      'invalid_credentials',
      'account_inactive',
      'account_inactive',
      'account_inactive',
    ]);
  });

  it('E-21: auth.login.failed says upstream_unavailable for an outage and upstream_error, with the Auth status and code, for an answer nobody expected', async () => {
    logged.lines.length = 0;

    await loginWhileAuthAnswers(() => Response.json({ msg: 'bad gateway' }, { status: 502 }));
    await loginWhileAuthAnswers(() => authAnswers(429, 'over_request_rate_limit'));
    await loginWhileAuthAnswers(() => new TypeError('fetch failed'));
    await loginWhileAuthAnswers(() => authAnswers(422, 'email_provider_disabled'));

    const failed = events('auth.login.failed');
    expect(failed.map((record) => record['reason'])).toEqual([
      'upstream_unavailable',
      'upstream_unavailable',
      'upstream_unavailable',
      'upstream_error',
    ]);
    expect(failed[3]).toMatchObject({ authStatus: 422, authCode: 'email_provider_disabled' });
    // an outage logs no Auth detail at all
    expect(failed[0]).not.toHaveProperty('authCode');
  });

  it('SEC-16 / F-09: login and logout events carry the user id, the session id and a keyed hash of the IP, and no secrets anywhere', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });
    const jar = createCookieStore();
    const ip = newClientIp();
    // the pipeline aggregates an IPv6 address to its /64: the first four groups
    const subject = `${ip.split(':').slice(0, 4).join(':')}::/64`;
    const secret = process.env.RATE_LIMIT_KEY_SECRET ?? '';
    const expectedIpHash = hmacSubject(hmacSubject(secret, 'log-fingerprint-v1'), subject);
    logged.lines.length = 0;

    const loginResponse = await invoke(loginRoute, {
      method: 'POST',
      path: '/auth/login',
      body: { email: user.email, password: user.password },
      cookies: jar,
      ip,
    });
    const cookieHeader = jar.header() ?? '';
    const sessionId = sessionIdOfToken(readSessionCookie(jar).access_token);
    const logoutResponse = await invoke(logoutRoute, {
      method: 'POST',
      path: '/auth/logout',
      cookies: jar.clone(),
      ip,
    });

    expect(loginResponse.status).toBe(200);
    expect(logoutResponse.status).toBe(204);
    expect(sessionId).toMatch(/^[0-9a-f-]{36}$/);

    const [succeeded] = events('auth.login.succeeded');
    expect(succeeded).toMatchObject({
      level: 'info',
      userId: user.id,
      sessionId,
      ipHash: expectedIpHash,
      requestId: loginResponse.headers.get('x-request-id'),
    });
    expect(Object.keys(succeeded ?? {}).sort()).toEqual(
      ['event', 'ipHash', 'level', 'msg', 'requestId', 'sessionId', 'time', 'userId'].sort(),
    );
    const [loggedOut] = events('auth.logout');
    expect(loggedOut).toMatchObject({
      userId: user.id,
      sessionId,
      ipHash: expectedIpHash,
      requestId: logoutResponse.headers.get('x-request-id'),
    });

    // the IP itself is nowhere, in any form
    expect(logged.lines.join('\n')).not.toContain(ip);
    expect(logged.lines.join('\n')).not.toContain(subject);

    const everything = logged.lines.join('\n');
    expect(everything).not.toContain(user.password);
    expect(everything.toLowerCase()).not.toContain(user.email.toLowerCase());
    expect(everything).not.toContain('__Host-rt-session');
    expect(everything).not.toMatch(/eyJ[\w-]+\.[\w-]+\./);
    // nothing of the session cookie value either
    const cookieValue = cookieHeader.split(';')[0]?.split('=')[1] ?? '';
    expect(cookieValue.length).toBeGreaterThan(20);
    expect(everything).not.toContain(cookieValue.slice(0, 40));
  });
});
