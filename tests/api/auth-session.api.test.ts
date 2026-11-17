// API tests of POST /auth/login, POST /auth/logout and GET /auth/session (operationIds `login`,
// `logout`, `getSession`): the real route modules, the real pipeline and wiring (Postgres rate
// limiter, Supabase resolver), the local Supabase (Auth + PostgREST), and every response checked
// against the OpenAPI contract, headers included.
import { createClient as createSupabaseClient } from '@supabase/supabase-js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { POST as loginRoute } from '@/app/api/v1/auth/login/route';
import { POST as logoutRoute } from '@/app/api/v1/auth/logout/route';
import { GET as sessionRoute } from '@/app/api/v1/auth/session/route';
import type { Database } from '@/shared/db/database.types';
import { timing } from '@/shared/http/response-floor';
import { expectToMatchContract } from '../helpers/contract';
import { markPasswordPendingFixture } from '../helpers/db';
import {
  ceoAal2Client,
  createClient,
  createClientUser,
  createCeo,
  disableAccount,
  uniqueEmail,
  type FixtureUser,
} from '../helpers/fixtures';
import {
  bodyOf,
  createCookieStore,
  invoke,
  newClientIp,
  observableHeaders,
  readSessionCookie,
  spyOnSupabaseFetch,
  textOf,
  withoutRequestId,
  writeSessionCookie,
  type CookieStore,
} from '../helpers/http';
import { verifyTotpViaApi } from '../helpers/mfa';
import { changePassword } from '../helpers/password';

const SESSION_COOKIE = '__Host-rt-session';
/** ADR 0009 and spec SEC-07: a session lives at most 12 hours. */
const SESSION_COOKIE_MAX_AGE_SECONDS = 12 * 60 * 60;

/** `Max-Age` of one `Set-Cookie` line (NaN when it has none, which fails every comparison). */
const maxAgeOf = (setCookie: string): number =>
  Number(/;\s*Max-Age=(\d+)/i.exec(setCookie)?.[1] ?? Number.NaN);

/**
 * A refused login waits for its floor (400 ms and a little jitter, F-05). The tests do not wait for
 * real: `sleep` is replaced by a recorder, and the tests that care about the floor read what it
 * recorded. Every other test just runs faster.
 */
const floorSleeps: number[] = [];

/** Room for the pipeline's own work before the login handler starts its floor (F-05 test). */
const PIPELINE_BEFORE_HANDLER_SLACK_MS = 150;

/**
 * The refusal floor and its jitter as the spec states them (§3.4). Written out on purpose, not
 * imported from the handler: a test that read the handler's own constants could not notice them change.
 */
const REFUSED_LOGIN_FLOOR_MS = 400;
const REFUSED_LOGIN_JITTER_MS = 100;
/** How many times the F-05 test measures one refused path before it says the path outgrew the floor. */
const REFUSAL_ATTEMPTS = 3;

/** The `session-upstream` budget is a fixed window of 15 minutes aligned to the clock (spec §3.9). */
const BUDGET_WINDOW_MS = 15 * 60 * 1000;
/** How far this process's clock and the database's may disagree about where a window starts. */
const WINDOW_CLOCK_SKEW_MS = 2_000;
const BUDGET_WINDOW_ATTEMPTS = 2;

/**
 * A test that spends a fixed-window budget and then checks that it is spent breaks when a window
 * boundary falls in the middle: the counters restart and the budget is whole again. That is the
 * clock, not a defect, so a failure with a boundary somewhere inside the run is tried once more,
 * entirely inside the next window (the body builds its own fixtures and picks a fresh address).
 * A failure with no boundary inside is rethrown as it is, and so is a second one. No sleeps.
 */
function withinOneBudgetWindow<Args extends unknown[]>(
  body: (...args: Args) => Promise<void>,
): (...args: Args) => Promise<void> {
  const windowOf = (instant: number) => Math.floor(instant / BUDGET_WINDOW_MS);
  return async (...args) => {
    for (let attempt = 1; ; attempt += 1) {
      const startedAt = Date.now();
      try {
        await body(...args);
        return;
      } catch (error) {
        const crossedABoundary =
          windowOf(startedAt - WINDOW_CLOCK_SKEW_MS) !==
          windowOf(Date.now() + WINDOW_CLOCK_SKEW_MS);
        if (!crossedABoundary || attempt >= BUDGET_WINDOW_ATTEMPTS) throw error;
      }
    }
  };
}

beforeEach(() => {
  floorSleeps.length = 0;
  vi.spyOn(timing, 'sleep').mockImplementation((ms) => {
    floorSleeps.push(ms);
    return Promise.resolve();
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

const login = (
  body: unknown,
  options: { cookies?: CookieStore; ip?: string; origin?: string | null } = {},
) => invoke(loginRoute, { method: 'POST', path: '/auth/login', body, ...options });

const credentialsOf = (user: FixtureUser) => ({ email: user.email, password: user.password });

/** Logs `user` in and returns the cookies the browser would now hold. */
async function signIn(user: FixtureUser): Promise<CookieStore> {
  const jar = createCookieStore();
  const response = await login(credentialsOf(user), { cookies: jar });
  expect(response.status, 'the login fixture must succeed').toBe(200);
  return jar;
}

const getSession = (cookies?: CookieStore | Record<string, string>) =>
  invoke(sessionRoute, { path: '/auth/session', ...(cookies === undefined ? {} : { cookies }) });

const logout = (cookies?: CookieStore, options: { origin?: string | null } = {}) =>
  invoke(logoutRoute, {
    method: 'POST',
    path: '/auth/logout',
    ...(cookies === undefined ? {} : { cookies }),
    ...options,
  });

/** What the database says about a JWT, asked straight to PostgREST (no pipeline, no Auth server). */
async function principalRowsFor(accessToken: string): Promise<unknown[]> {
  const client = createSupabaseClient<Database>(
    process.env.SUPABASE_URL ?? '',
    process.env.SUPABASE_PUBLISHABLE_KEY ?? '',
    {
      auth: { persistSession: false, autoRefreshToken: false },
      global: { headers: { Authorization: `Bearer ${accessToken}` } },
    },
  );
  const { data, error } = await client.rpc('current_principal');
  if (error) throw new Error(`current_principal failed: ${error.message}`);
  return data;
}

/** Every path of `value` whose key or text looks like a credential. */
function credentialLeaks(value: unknown, path = 'body'): string[] {
  if (typeof value === 'string') {
    return /eyJ[\w-]+\.[\w-]+\./.test(value) || /^(Bearer|Basic) /i.test(value) ? [path] : [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => credentialLeaks(item, `${path}[${index}]`));
  }
  if (typeof value === 'object' && value !== null) {
    return Object.entries(value).flatMap(([key, item]) => [
      ...(/token|jwt|secret|password|cookie|authorization|session_id/i.test(key)
        ? [`${path}.${key}`]
        : []),
      ...credentialLeaks(item, `${path}.${key}`),
    ]);
  }
  return [];
}

describe('POST /api/v1/auth/login', () => {
  it('AC-01: a valid login is 200, sets the HttpOnly Secure SameSite=Lax session cookie and returns no token', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });

    const response = await login(credentialsOf(user));
    const body = await bodyOf(response);

    expect(response.status).toBe(200);
    expectToMatchContract('login', 200, body, response);

    const cookies = response.headers.getSetCookie();
    expect(cookies.length).toBeGreaterThan(0);
    for (const cookie of cookies) {
      expect(cookie).toMatch(/^__Host-rt-session(\.\d+)?=/);
      expect(cookie).toMatch(/;\s*HttpOnly(;|$)/i);
      expect(cookie).toMatch(/;\s*Secure(;|$)/i);
      // Next serializes the attribute value in lowercase
      expect(cookie).toMatch(/;\s*SameSite=Lax(;|$)/i);
      expect(cookie).toMatch(/;\s*Path=\/(;|$)/i);
      expect(cookie).not.toMatch(/;\s*Domain=/i);
      // credentials are ephemeral (ADR 0009): the browser keeps the session cookie at most 12 h
      expect(maxAgeOf(cookie)).toBeGreaterThan(0);
      expect(maxAgeOf(cookie)).toBeLessThanOrEqual(SESSION_COOKIE_MAX_AGE_SECONDS);
    }
    // `__Host-` also needs the cookie to be written WITH the session, not an empty/expired one
    expect(cookies.some((cookie) => !/Max-Age=0/i.test(cookie))).toBe(true);

    expect(credentialLeaks(body)).toEqual([]);
    expect(body).toEqual({
      user: { id: user.id, role: 'client', displayName: user.displayName },
      client: { id: client.id, name: client.name },
      aal: 'aal1',
      pendingActions: ['CHANGE_PASSWORD'],
    });
  });

  it('AC-02: wrong password, unknown e-mail and disabled account are the same 401 INVALID_CREDENTIALS, byte for byte but the requestId', async () => {
    const client = await createClient();
    const target = await createClientUser({ clientId: client.id });
    const disabled = await createClientUser({ clientId: client.id });
    await disableAccount(await ceoAal2Client(), disabled.id);

    const wrongPassword = await login({
      email: target.email,
      password: `${target.password}-wrong`,
    });
    const unknownEmail = await login({ email: uniqueEmail('nobody'), password: target.password });
    // the credentials are RIGHT here: only the account state differs
    const disabledAccount = await login(credentialsOf(disabled));

    const responses = [wrongPassword, unknownEmail, disabledAccount];
    for (const response of responses) {
      expect(response.status).toBe(401);
      expectToMatchContract('login', 401, await bodyOf(response), response);
    }

    const bodies = await Promise.all(responses.map(bodyOf));
    expect(bodies[0]).toMatchObject({ code: 'INVALID_CREDENTIALS', status: 401 });
    const texts = bodies.map((body) => JSON.stringify(withoutRequestId(body)));
    expect(texts[1]).toBe(texts[0]);
    expect(texts[2]).toBe(texts[0]);

    // the observable headers are identical too: no Set-Cookie leaks which of the three it was
    const headers = responses.map(observableHeaders);
    expect(headers[1]).toEqual(headers[0]);
    expect(headers[2]).toEqual(headers[0]);
    for (const response of responses) expect(response.headers.getSetCookie()).toEqual([]);
  });

  it('AC-02: the disabled account has no live session after the refused login either', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });
    await disableAccount(await ceoAal2Client(), user.id);

    const jar = createCookieStore();
    const spy = spyOnSupabaseFetch();
    let refused: Response;
    try {
      refused = await login(credentialsOf(user), { cookies: jar });
    } finally {
      spy.restore();
    }

    expect(refused.status).toBe(401);
    expect(jar.names()).toEqual([]);
    expect((await getSession(jar)).status).toBe(401);
    // The browser never got the cookie, so a 401 on `getSession(jar)` proves nothing about the
    // server: what proves it is that the session the sign-in opened was revoked right after.
    const authCalls = spy.calls.filter((call) => call.includes('/auth/v1/'));
    expect(authCalls).toHaveLength(2);
    expect(authCalls[0]).toMatch(/^POST .*\/auth\/v1\/token\?grant_type=password/);
    expect(authCalls[1]).toMatch(/^POST .*\/auth\/v1\/logout\?scope=local/);
  });

  it('E-11: an e-mail with capitals and spaces logs in', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id, email: uniqueEmail('maria') });

    const response = await login({
      email: `  ${user.email.replace(/^maria/, 'Maria').replace(/cliente\.test$/, 'Cliente.TEST')} `,
      password: user.password,
    });

    const body = await bodyOf(response);
    expect(response.status).toBe(200);
    expect(body).toMatchObject({ user: { id: user.id } });
    expectToMatchContract('login', 200, body, response);
  });

  it('AC-03: the 11th attempt for the same account within the window is 429 with Retry-After', async () => {
    const email = uniqueEmail('rate');
    const attempt = () => login({ email, password: 'any-password-1' }, { ip: newClientIp() });

    for (let n = 1; n <= 10; n += 1) {
      const response = await attempt();
      expect(response.status, `attempt ${n}`).toBe(401);
    }
    const throttled = await attempt();
    const body = await bodyOf(throttled);

    expect(throttled.status).toBe(429);
    expect(body).toMatchObject({ code: 'RATE_LIMITED', status: 429 });
    expect(Number(throttled.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expectToMatchContract('login', 429, body, throttled);

    // the budget is per account: another account is not affected
    expect((await login({ email: uniqueEmail('rate'), password: 'any-password-1' })).status).toBe(
      401,
    );
  });

  it('AC-03: the account budget is shared by every spelling of the e-mail', async () => {
    const base = uniqueEmail('spelling');
    for (let n = 1; n <= 10; n += 1) {
      const spelled = n % 2 === 0 ? base.toUpperCase() : ` ${base} `;
      expect((await login({ email: spelled, password: 'any-password-1' })).status).toBe(401);
    }
    expect((await login({ email: base, password: 'any-password-1' })).status).toBe(429);
  });

  it('AC-03: the 21st attempt from the same IP within the window is 429 with Retry-After', async () => {
    const ip = newClientIp();
    const attempt = () => login({ email: uniqueEmail('ip'), password: 'any-password-1' }, { ip });

    for (let n = 1; n <= 20; n += 1) {
      const response = await attempt();
      expect(response.status, `attempt ${n}`).toBe(401);
    }
    const throttled = await attempt();
    const body = await bodyOf(throttled);

    expect(throttled.status).toBe(429);
    expect(Number(throttled.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expectToMatchContract('login', 429, body, throttled);

    // another IP is not affected
    expect((await login({ email: uniqueEmail('ip'), password: 'any-password-1' })).status).toBe(
      401,
    );
  });

  it('AC-26: login answers the documented 400, 403 and 415, validated against the contract', async () => {
    const credentials = { email: uniqueEmail('shape'), password: 'any-password-1' };
    const cases: { name: string; response: Response; status: number }[] = [
      {
        name: 'unknown field',
        response: await login({ ...credentials, role: 'ceo' }),
        status: 400,
      },
      {
        name: 'empty password',
        response: await login({ ...credentials, password: '' }),
        status: 400,
      },
      {
        name: 'password over 72 bytes',
        response: await login({ ...credentials, password: 'x'.repeat(73) }),
        status: 400,
      },
      {
        name: 'password over 72 bytes in UTF-8 (36 two-byte letters + 1)',
        response: await login({ ...credentials, password: 'é'.repeat(37) }),
        status: 400,
      },
      {
        name: 'not an e-mail',
        response: await login({ ...credentials, email: 'nope' }),
        status: 400,
      },
      {
        name: 'missing e-mail',
        response: await login({ password: 'any-password-1' }),
        status: 400,
      },
      { name: 'no Origin', response: await login(credentials, { origin: null }), status: 403 },
      {
        name: 'foreign Origin',
        response: await login(credentials, { origin: 'https://evil.example' }),
        status: 403,
      },
      {
        name: 'not JSON',
        response: await invoke(loginRoute, {
          method: 'POST',
          path: '/auth/login',
          rawBody: 'email=a&password=b',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
        }),
        status: 415,
      },
    ];

    for (const { name, response, status } of cases) {
      expect(response.status, name).toBe(status);
      expectToMatchContract('login', status, await bodyOf(response), response);
    }
  });

  it('E-12: a password of exactly 72 bytes passes validation (and is then refused as credentials)', async () => {
    const response = await login({ email: uniqueEmail('limit'), password: 'x'.repeat(72) });
    expect(response.status).toBe(401);
    expectToMatchContract('login', 401, await bodyOf(response), response);
  });

  it('F-05: every refused login answers only after the floor, and the disabled-account path fits under it', async () => {
    const client = await createClient();
    const target = await createClientUser({ clientId: client.id });
    const disabled = await createClientUser({ clientId: client.id });
    await disableAccount(await ceoAal2Client(), disabled.id);

    const refusals: [string, () => Promise<Response>][] = [
      ['a wrong password', () => login({ email: target.email, password: `${target.password}-x` })],
      [
        'an unknown e-mail',
        () => login({ email: uniqueEmail('nobody'), password: target.password }),
      ],
      // ~3 calls to Auth: sign in, read the principal, revoke the session
      ['a disabled account (right password)', () => login(credentialsOf(disabled))],
    ];
    for (const [label, refuse] of refusals) {
      // The floor is a MINIMUM: a refusal never answers before it, and a refusal whose work fits
      // under it is padded up to it (plus jitter), so the three paths take the same time. That is
      // the security property, and it is checked on every attempt that can show it. Whether the
      // work of a path fits under 400 ms is a property of the machine the test runs on (the
      // disabled-account path is three calls to Auth; production's p95 is a Wave 11 measurement):
      // on a busy one a single attempt can overshoot, there is nothing left to pad, and that
      // attempt says nothing about the floor. So a path gets a few attempts; one that really is
      // slower than the floor never fits, and fails below.
      const workTimes: number[] = [];
      let fitted = false;
      for (let attempt = 0; attempt < REFUSAL_ATTEMPTS && !fitted; attempt += 1) {
        floorSleeps.length = 0;
        const startedAt = performance.now();
        const response = await refuse();
        const workMs = performance.now() - startedAt; // the waiting itself is replaced by a recorder
        workTimes.push(Math.round(workMs));

        expect(response.status, label).toBe(401);
        if (workMs >= REFUSED_LOGIN_FLOOR_MS) continue; // too slow for this attempt to show the floor

        // the work fits under the floor, so the handler had to wait for the rest of it...
        expect(floorSleeps, label).toHaveLength(1);
        // ...and work plus wait is the floor (400 ms) plus at most its jitter (100 ms). `workMs` is
        // measured from before the request, so it also holds the pipeline's work BEFORE the handler
        // starts the floor (three rate-limit calls to Postgres); that part is real time, and on a busy
        // machine it alone has exceeded 20 ms, so the upper bound leaves it explicit room.
        const totalMs = workMs + (floorSleeps[0] ?? 0);
        expect(totalMs, label).toBeGreaterThanOrEqual(REFUSED_LOGIN_FLOOR_MS);
        expect(totalMs, label).toBeLessThan(
          REFUSED_LOGIN_FLOOR_MS + REFUSED_LOGIN_JITTER_MS + PIPELINE_BEFORE_HANDLER_SLACK_MS,
        );
        fitted = true;
      }
      expect(
        fitted,
        `${label}: the work never fit under the ${REFUSED_LOGIN_FLOOR_MS} ms floor in ${REFUSAL_ATTEMPTS} attempts (${workTimes.join(', ')} ms)`,
      ).toBe(true);
    }
  });

  it('F-05: a login that succeeds, and one that is refused by the rate limit, are not delayed', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });

    expect((await login(credentialsOf(user))).status).toBe(200);
    expect(floorSleeps).toEqual([]);

    const email = uniqueEmail('throttled');
    for (let n = 0; n < 10; n += 1) await login({ email, password: 'any-password-1' });
    floorSleeps.length = 0;
    expect((await login({ email, password: 'any-password-1' })).status).toBe(429);
    expect(floorSleeps).toEqual([]);
  });
});

describe('POST /api/v1/auth/login when the Auth server answers something other than a password check', () => {
  const authAnswers = (status: number, errorCode: string) =>
    Response.json(
      { code: status, error_code: errorCode, msg: 'simulated by the test' },
      { status },
    );
  const atTokenEndpoint =
    (answer: () => Response | Error) =>
    (url: string): Response | Error | undefined =>
      url.includes('/auth/v1/token') ? answer() : undefined;

  /** One login attempt of an unknown user (the token call is intercepted, so nothing else matters). */
  async function loginWhileAuthAnswers(answer: () => Response | Error): Promise<Response> {
    const spy = spyOnSupabaseFetch(atTokenEndpoint(answer));
    try {
      return await login({ email: uniqueEmail('mapping'), password: 'any-password-1' });
    } finally {
      spy.restore();
    }
  }

  it.each([
    ['a 502 from Auth', () => Response.json({ msg: 'bad gateway' }, { status: 502 })],
    ['a 500 from Auth', () => authAnswers(500, 'unexpected_failure')],
    ['Auth throttling (429)', () => authAnswers(429, 'over_request_rate_limit')],
    ['a transport failure', () => new TypeError('fetch failed')],
    ['a timeout', () => new DOMException('The operation timed out', 'TimeoutError')],
    ['an error code nobody knows', () => authAnswers(400, 'some_new_error')],
    ['the email provider being disabled', () => authAnswers(422, 'email_provider_disabled')],
    ['a rejected API key', () => authAnswers(401, 'invalid_api_key')],
    ['a validation failure', () => authAnswers(422, 'validation_failed')],
  ])(
    'E-21: %s is 503 SERVICE_UNAVAILABLE with Retry-After and no Set-Cookie, never a wrong-password 401',
    async (_label, answer) => {
      const response = await loginWhileAuthAnswers(answer);
      const body = await bodyOf(response);

      expect(response.status).toBe(503);
      expect(body).toMatchObject({ code: 'SERVICE_UNAVAILABLE', status: 503 });
      expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
      expect(response.headers.getSetCookie()).toEqual([]);
      expectToMatchContract('login', 503, body, response);
    },
  );

  it.each([
    ['a banned user', () => authAnswers(403, 'user_banned')],
    ['an unconfirmed e-mail', () => authAnswers(400, 'email_not_confirmed')],
  ])(
    'SEC-12: %s is the same 401 INVALID_CREDENTIALS as a wrong password, without a cookie',
    async (_label, answer) => {
      const wrongPassword = await login({
        email: uniqueEmail('nobody'),
        password: 'any-password-1',
      });
      const response = await loginWhileAuthAnswers(answer);

      expect(response.status).toBe(401);
      expectToMatchContract('login', 401, await bodyOf(response), response);
      expect(JSON.stringify(withoutRequestId(await bodyOf(response)))).toBe(
        JSON.stringify(withoutRequestId(await bodyOf(wrongPassword))),
      );
      expect(observableHeaders(response)).toEqual(observableHeaders(wrongPassword));
      expect(response.headers.getSetCookie()).toEqual([]);
    },
  );
});

describe('GET /api/v1/auth/session', () => {
  it('AC-26: a client login sees its tenant and CHANGE_PASSWORD, and the response matches the contract', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id, displayName: 'Maria da Silva' });
    const jar = await signIn(user);

    const response = await getSession(jar);
    const body = await bodyOf(response);

    expect(response.status).toBe(200);
    expectToMatchContract('getSession', 200, body, response);
    expect(body).toEqual({
      user: { id: user.id, role: 'client', displayName: 'Maria da Silva' },
      client: { id: client.id, name: client.name },
      aal: 'aal1',
      pendingActions: ['CHANGE_PASSWORD'],
    });
    expect(credentialLeaks(body)).toEqual([]);
  });

  it('AC-26: a fresh CEO has no client and CHANGE_PASSWORD plus ENROLL_MFA pending', async () => {
    const ceo = await createCeo({ displayName: 'Ana CEO' });
    const jar = await signIn(ceo);

    const response = await getSession(jar);
    const body = await bodyOf(response);

    expect(response.status).toBe(200);
    expectToMatchContract('getSession', 200, body, response);
    expect(body).toEqual({
      user: { id: ceo.id, role: 'ceo', displayName: 'Ana CEO' },
      client: null,
      aal: 'aal1',
      pendingActions: ['CHANGE_PASSWORD', 'ENROLL_MFA'],
    });
  });

  it('AC-26: a CEO with a verified factor on a fresh aal1 login has VERIFY_MFA pending', async () => {
    const { ceo } = await ceoAal2Client();
    const jar = await signIn(ceo); // a new session: aal1, while the factor is verified

    const response = await getSession(jar);
    const body = await bodyOf(response);

    expect(response.status).toBe(200);
    expectToMatchContract('getSession', 200, body, response);
    expect(body).toMatchObject({
      aal: 'aal1',
      client: null,
      // the password was changed at the first access (before the factor, as production requires): the
      // factor is verified but not used yet
      pendingActions: ['VERIFY_MFA'],
    });
  });

  it('AC-26: a CEO that already has a verified factor and gets the temporary password again has CHANGE_PASSWORD and VERIFY_MFA pending, in that priority', async () => {
    const { ceo } = await ceoAal2Client();
    await markPasswordPendingFixture(ceo.id); // what the operator's password reset will do (F-41, Wave 11)
    const jar = await signIn(ceo);

    const response = await getSession(jar);
    const body = await bodyOf(response);

    expect(response.status).toBe(200);
    expectToMatchContract('getSession', 200, body, response);
    expect(body).toMatchObject({
      aal: 'aal1',
      client: null,
      pendingActions: ['CHANGE_PASSWORD', 'VERIFY_MFA'],
    });
  });

  it('F-110: a CEO that has the verified factor and the temporary password again is stuck at the BFF: the verify wants CHANGE_PASSWORD done and the password change wants VERIFY_MFA done', async () => {
    const { ceo } = await ceoAal2Client();
    await markPasswordPendingFixture(ceo.id);
    const jar = await signIn(ceo);

    // the authorization comes before the body is looked at, so a code that is not a real one is enough
    const verify = await verifyTotpViaApi(jar, { code: '000000' });
    const verifyBody = await bodyOf(verify);
    const change = await changePassword(jar, {
      currentPassword: ceo.password,
      newPassword: `Next-${ceo.id}-0123456789`,
    });
    const changeBody = await bodyOf(change);

    expectToMatchContract('verifyTotp', verify.status, verifyBody, verify);
    expect([verify.status, (verifyBody as { code: string }).code]).toEqual([
      403,
      'PASSWORD_CHANGE_REQUIRED',
    ]);
    expect([change.status, (changeBody as { code: string }).code]).toEqual([
      403,
      'MFA_VERIFICATION_REQUIRED',
    ]);
  });

  it('AC-26: without a cookie it is 401 UNAUTHENTICATED, per the contract', async () => {
    const response = await getSession();
    const body = await bodyOf(response);

    expect(response.status).toBe(401);
    expect(body).toMatchObject({ code: 'UNAUTHENTICATED', status: 401 });
    expectToMatchContract('getSession', 401, body, response);
  });

  it('SEC-07: a cookie that carries a forged session is 401', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });
    const jar = await signIn(user);
    const session = readSessionCookie(jar);
    const [header = '', payload = ''] = session.access_token.split('.');
    // same header and payload, a signature nobody made
    writeSessionCookie(jar, { ...session, access_token: `${header}.${payload}.${'A'.repeat(43)}` });

    const response = await getSession(jar);

    expect(response.status).toBe(401);
    expectToMatchContract('getSession', 401, await bodyOf(response), response);
  });

  it(
    'F-01: N forged-cookie requests from one IP make at most 60 calls to Auth, then 401 without touching the cookie',
    withinOneBudgetWindow(async () => {
      const ip = newClientIp();
      const forged = createCookieStore();
      // the cookie of the finding: no real token, only an `expires_at` in the past
      writeSessionCookie(forged, { access_token: 'x', refresh_token: 'y', expires_at: 1 });
      const spy = spyOnSupabaseFetch();

      const responses: Response[] = [];
      try {
        for (let n = 0; n < 75; n += 1) {
          responses.push(
            await invoke(sessionRoute, { path: '/auth/session', cookies: forged.clone(), ip }),
          );
        }
      } finally {
        spy.restore();
      }

      const authCalls = spy.calls.filter((call) => call.includes('/auth/v1/'));
      expect(authCalls.length).toBeGreaterThan(0);
      expect(authCalls.length).toBeLessThanOrEqual(60);
      // every request is the documented 401, forged or over budget
      for (const response of responses) {
        expect(response.status).toBe(401);
        expectToMatchContract('getSession', 401, await bodyOf(response), response);
      }
      // the last ones were refused by the budget: no call to Auth, and no Set-Cookie at all
      for (const response of responses.slice(-10)) {
        expect(response.headers.getSetCookie()).toEqual([]);
      }
    }),
  );

  it('F-01: a forger from one IP does not use up the budget of a legitimate user from another', async () => {
    const forgerIp = newClientIp();
    const forged = createCookieStore();
    writeSessionCookie(forged, { access_token: 'x', refresh_token: 'y', expires_at: 1 });
    for (let n = 0; n < 62; n += 1) {
      await invoke(sessionRoute, { path: '/auth/session', cookies: forged.clone(), ip: forgerIp });
    }

    const client = await createClient();
    const jar = await signIn(await createClientUser({ clientId: client.id }));

    expect((await getSession(jar)).status).toBe(200);
  });

  it(
    'F-01: on an address whose budget a forger used up, even a token that verifies locally is refused (401, cookie kept), and works from a clean address',
    withinOneBudgetWindow(async () => {
      const client = await createClient();
      const user = await createClientUser({ clientId: client.id });
      const ip = newClientIp();
      const legitimate = await signIn(user);
      // the first token of a signing key makes the server fetch the keys; after that it is local
      expect((await getSession(legitimate)).status).toBe(200);
      const forged = createCookieStore();
      writeSessionCookie(forged, { access_token: 'x', refresh_token: 'y', expires_at: 1 });
      for (let n = 0; n < 62; n += 1) {
        await invoke(sessionRoute, { path: '/auth/session', cookies: forged.clone(), ip });
      }
      const spy = spyOnSupabaseFetch();

      let response: Response;
      try {
        response = await invoke(sessionRoute, {
          path: '/auth/session',
          cookies: legitimate.clone(),
          ip,
        });
      } finally {
        spy.restore();
      }

      // The trade-off of the second line of defense: an address the limiter already knows to be over
      // budget is refused even for a token that would not have cost a call. Nothing reaches Auth,
      // and the cookie is not touched.
      expect(response.status).toBe(401);
      expectToMatchContract('getSession', 401, await bodyOf(response), response);
      expect(response.headers.getSetCookie()).toEqual([]);
      expect(spy.calls.filter((call) => call.includes('/auth/v1/'))).toEqual([]);
      // from an address with budget left the very same cookie is fine
      expect((await getSession(legitimate)).status).toBe(200);
    }),
  );

  it(
    'F-01: over budget a browser that needs a token refresh gets a 401 and KEEPS its cookie, then refreshes from a clean address',
    withinOneBudgetWindow(async () => {
      const client = await createClient();
      const user = await createClientUser({ clientId: client.id });
      const ip = newClientIp();
      const forged = createCookieStore();
      writeSessionCookie(forged, { access_token: 'x', refresh_token: 'y', expires_at: 1 });
      for (let n = 0; n < 62; n += 1) {
        await invoke(sessionRoute, { path: '/auth/session', cookies: forged.clone(), ip });
      }
      const legitimate = await signIn(user);
      // its access token has expired: the server would have to call Auth to refresh it
      writeSessionCookie(legitimate, { ...readSessionCookie(legitimate), expires_at: 1 });
      const before = legitimate.clone();

      const response = await invoke(sessionRoute, {
        path: '/auth/session',
        cookies: legitimate,
        ip,
      });

      expect(response.status).toBe(401);
      expectToMatchContract('getSession', 401, await bodyOf(response), response);
      // refused by the budget: no Set-Cookie at all, so nothing was deleted
      expect(response.headers.getSetCookie()).toEqual([]);
      expect(legitimate.names()).toEqual(before.names());
      // and from an address with budget left the very same cookie is refreshed
      expect((await getSession(before)).status).toBe(200);
    }),
  );

  describe('F-01: whatever the cookie looks like, an address over budget never reaches Auth', () => {
    const REQUESTS = 63; // the budget is 60: three more than it can pay for
    const AUTH_BUDGET = 60;
    const FUTURE_S = () => Math.floor(Date.now() / 1000) + 3600;
    const SIGNATURE = 'A'.repeat(43);
    const b64 = (value: unknown) =>
      Buffer.from(typeof value === 'string' ? value : JSON.stringify(value), 'utf8').toString(
        'base64url',
      );
    const fakeJwt = (header: Record<string, unknown>, payload: Record<string, unknown> = {}) =>
      `${b64(header)}.${b64({ sub: 'x', exp: FUTURE_S(), ...payload })}.${SIGNATURE}`;
    const stored = (session: Record<string, unknown>) => `base64-${b64(session)}`;
    const sessionOf = (accessToken: unknown, expiresAt: unknown) => ({
      access_token: accessToken,
      refresh_token: 'y',
      expires_at: expiresAt,
    });
    const one = (value: string): Record<string, string> => ({ [SESSION_COOKIE]: value });
    const authCallsOf = (calls: string[]) => calls.filter((call) => call.includes('/auth/v1/'));

    /** A token whose header carries the kid of the real signing key, with a signature nobody made. */
    let realHeader: Promise<Record<string, unknown>> | undefined;
    const realKidHeader = (): Promise<Record<string, unknown>> =>
      (realHeader ??= loadRealKidHeader());
    async function loadRealKidHeader(): Promise<Record<string, unknown>> {
      const client = await createClient();
      const jar = await signIn(await createClientUser({ clientId: client.id }));
      // verifying one real token teaches the server this signing key: from now on it is local
      expect((await getSession(jar)).status).toBe(200);
      const [header = ''] = readSessionCookie(jar).access_token.split('.');
      return JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as Record<
        string,
        unknown
      >;
    }

    const corpus: [string, (real: Record<string, unknown>) => Record<string, string>][] = [
      ['expires_at in the past', () => one(stored(sessionOf('x', 1)))],
      ['expires_at as the string "1"', () => one(stored(sessionOf('x', '1')))],
      ['expires_at -1', () => one(stored(sessionOf('x', -1)))],
      [
        'expires_at null with an HS256 token',
        () => one(stored(sessionOf(fakeJwt({ alg: 'HS256' }), null))),
      ],
      [
        'expires_at 0 with an HS256 token',
        () => one(stored(sessionOf(fakeJwt({ alg: 'HS256' }), 0))),
      ],
      [
        'expires_at 1e999 (Infinity) with an HS256 token',
        () =>
          one(
            `base64-${b64(
              `{"access_token":"${fakeJwt({ alg: 'HS256' })}","refresh_token":"y","expires_at":1e999}`,
            )}`,
          ),
      ],
      [
        'an unexpired HS256 token',
        () => one(stored(sessionOf(fakeJwt({ alg: 'HS256' }), FUTURE_S()))),
      ],
      [
        'an ES256 token with no kid',
        () => one(stored(sessionOf(fakeJwt({ alg: 'ES256' }), FUTURE_S()))),
      ],
      [
        'an ES256 token with a kid nobody has',
        () => one(stored(sessionOf(fakeJwt({ alg: 'ES256', kid: 'nobody-has-this' }), FUTURE_S()))),
      ],
      [
        'an RS256 token with a kid nobody has',
        () => one(stored(sessionOf(fakeJwt({ alg: 'RS256', kid: 'nobody-has-this' }), FUTURE_S()))),
      ],
      [
        'the real kid with a signature nobody made',
        (real) => one(stored(sessionOf(fakeJwt(real), FUTURE_S()))),
      ],
      [
        'the real kid asking for RS256 (a key that cannot verify it)',
        (real) => one(stored(sessionOf(fakeJwt({ ...real, alg: 'RS256' }), FUTURE_S()))),
      ],
      [
        'an ES384 token with the real kid',
        (real) => one(stored(sessionOf(fakeJwt({ ...real, alg: 'ES384' }), FUTURE_S()))),
      ],
      [
        'an alg that is a number',
        () => one(stored(sessionOf(fakeJwt({ alg: 5, kid: 'k' }), FUTURE_S()))),
      ],
      ['an access token that is not a string', () => one(stored(sessionOf(5, FUTURE_S())))],
      [
        'a header that is not JSON',
        () =>
          one(
            stored(
              sessionOf(`${b64('nope')}.${b64({ exp: FUTURE_S() })}.${SIGNATURE}`, FUTURE_S()),
            ),
          ),
      ],
      [
        'a raw JSON value, without the base64- prefix',
        () => one(JSON.stringify(sessionOf('x', 1))),
      ],
      ['base64- followed by garbage', () => one('base64-@@@')],
      ['plain garbage', () => one('garbage')],
      [
        'an empty whole cookie and a valid expired session in a chunk',
        () => ({ [SESSION_COOKIE]: '', [`${SESSION_COOKIE}.0`]: stored(sessionOf('x', 1)) }),
      ],
      [
        'a chunk with a hole in the sequence',
        () => {
          const value = stored(sessionOf('x', 1));
          return {
            [`${SESSION_COOKIE}.0`]: value.slice(0, 10),
            [`${SESSION_COOKIE}.2`]: value.slice(10),
          };
        },
      ],
      ['a chunk named .abc', () => ({ [`${SESSION_COOKIE}.abc`]: stored(sessionOf('x', 1)) })],
    ];

    it.each(corpus)(
      '%s',
      withinOneBudgetWindow(async (_label, build) => {
        const real = await realKidHeader();
        const cookies = build(real);
        const ip = newClientIp();
        const spy = spyOnSupabaseFetch();

        const statuses: number[] = [];
        let authCallsBeforeLast = 0;
        try {
          for (let n = 0; n < REQUESTS; n += 1) {
            if (n === REQUESTS - 3) authCallsBeforeLast = authCallsOf(spy.calls).length;
            const response = await invoke(sessionRoute, {
              path: '/auth/session',
              cookies: createCookieStore(cookies),
              ip,
            });
            statuses.push(response.status);
            expectToMatchContract('getSession', 401, await bodyOf(response), response);
          }
        } finally {
          spy.restore();
        }

        const authCalls = authCallsOf(spy.calls);
        // the invariant: no more than the budget, whatever the shape of the cookie ...
        expect(authCalls.length).toBeLessThanOrEqual(AUTH_BUDGET);
        // ... and once the address is over budget nothing else reaches Auth
        expect(authCalls.length - authCallsBeforeLast).toBe(0);
        // every request is the documented 401: no variant is a 5xx
        expect(statuses.every((status) => status === 401)).toBe(true);
      }),
    );
  });

  it('F-01: a forged ES384 token is 401, not a 500, and costs no call to Auth', async () => {
    const client = await createClient();
    const jar = await signIn(await createClientUser({ clientId: client.id }));
    const session = readSessionCookie(jar);
    expect((await getSession(jar)).status).toBe(200);
    const [header = '', payload = ''] = session.access_token.split('.');
    const realHeader = JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    const forgedHeader = Buffer.from(
      JSON.stringify({ ...realHeader, alg: 'ES384' }),
      'utf8',
    ).toString('base64url');
    writeSessionCookie(jar, {
      ...session,
      access_token: `${forgedHeader}.${payload}.${'A'.repeat(43)}`,
    });
    const spy = spyOnSupabaseFetch();

    let response: Response;
    try {
      response = await getSession(jar);
    } finally {
      spy.restore();
    }

    expect(response.status).toBe(401);
    expectToMatchContract('getSession', 401, await bodyOf(response), response);
    expect(spy.calls.filter((call) => call.includes('/auth/v1/'))).toEqual([]);
  });

  it('F-01: a forged RS256 token with the real kid is 401 on a process that has not seen the key yet (WebCrypto rejects the import)', async () => {
    // A fresh module registry is a process that has verified nothing yet: the kid is unknown, so the
    // request is charged and goes to the key fetch, where importing an EC key as RS256 throws a
    // DOMException that the library does not wrap. That is a verdict about the token, not a 500.
    vi.resetModules();
    const { GET: freshSessionRoute } = await import('@/app/api/v1/auth/session/route');
    const jwksUrl = `${process.env.SUPABASE_URL ?? ''}/auth/v1/.well-known/jwks.json`;
    const jwks = (await (await fetch(jwksUrl)).json()) as { keys: { kid: string }[] };
    const kid = jwks.keys[0]?.kid;
    const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const token = `${part({ alg: 'RS256', kid, typ: 'JWT' })}.${part({
      sub: 'x',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })}.${'A'.repeat(43)}`;
    const jar = createCookieStore();
    writeSessionCookie(jar, {
      access_token: token,
      refresh_token: 'y',
      expires_at: Math.floor(Date.now() / 1000) + 3600,
    });

    const response = await invoke(freshSessionRoute, { path: '/auth/session', cookies: jar });

    expect(response.status).toBe(401);
    expectToMatchContract('getSession', 401, await bodyOf(response), response);
  });

  it('SEC-07: garbage in the session cookie is 401, not a crash', async () => {
    const response = await getSession({ [SESSION_COOKIE]: 'not-a-session' });
    expect(response.status).toBe(401);
    expectToMatchContract('getSession', 401, await bodyOf(response), response);
  });

  it('SEC-07: an expired access token is renewed inside the request and the new cookies reach the response', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });
    const jar = await signIn(user);
    const before = readSessionCookie(jar);
    // the client library decides to refresh from `expires_at`: make it look expired
    writeSessionCookie(jar, { ...before, expires_at: 1 });

    const response = await getSession(jar);

    expect(response.status).toBe(200);
    expectToMatchContract('getSession', 200, await bodyOf(response), response);
    const cookies = response.headers.getSetCookie();
    expect(cookies.length).toBeGreaterThan(0);
    for (const cookie of cookies) {
      expect(cookie).toMatch(/;\s*HttpOnly(;|$)/i);
      expect(cookie).toMatch(/;\s*Secure(;|$)/i);
      expect(cookie).toMatch(/;\s*SameSite=Lax(;|$)/i);
      // a refresh must not stretch the cookie past the 12 h ceiling either
      expect(maxAgeOf(cookie)).toBeLessThanOrEqual(SESSION_COOKIE_MAX_AGE_SECONDS);
    }
    const after = readSessionCookie(jar);
    expect(after.refresh_token).not.toBe(before.refresh_token);
    expect(after.access_token).not.toBe(before.access_token);
    // a fresh 15-minute token, not the "already expired" one the test planted
    expect(after.expires_at).toBeGreaterThanOrEqual(before.expires_at);

    // and the renewed cookie keeps working
    expect((await getSession(jar)).status).toBe(200);
  });

  it('E-08: a disabled profile with a JWT that is still valid is 401 on the next request', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });
    const jar = await signIn(user);
    const { access_token: accessToken } = readSessionCookie(jar);
    expect((await getSession(jar)).status).toBe(200);
    expect(await principalRowsFor(accessToken)).toHaveLength(1);

    await disableAccount(await ceoAal2Client(), user.id);

    const response = await getSession(jar);
    expect(response.status).toBe(401);
    expect(await bodyOf(response)).toMatchObject({ code: 'UNAUTHENTICATED' });
    expectToMatchContract('getSession', 401, await bodyOf(response), response);
    // The JWT itself did not expire (15 min): it is the DATABASE that no longer knows a principal
    // for it (the session row is gone and the profile is disabled), whatever the Auth server says.
    expect(await principalRowsFor(accessToken)).toEqual([]);
  });
});

describe('POST /api/v1/auth/logout', () => {
  it('AC-04: logout is 204 and clears the cookie; the old cookie is 401 afterwards, even for the database', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id }); // born with CHANGE_PASSWORD
    const jar = await signIn(user);
    const oldCookie = jar.clone();
    const { access_token: accessToken } = readSessionCookie(oldCookie);
    expect((await getSession(jar)).status).toBe(200);
    expect(await principalRowsFor(accessToken)).toHaveLength(1);

    const response = await logout(jar);

    expect(response.status).toBe(204);
    expectToMatchContract('logout', 204, undefined, response);
    const cleared = response.headers.getSetCookie();
    expect(cleared.length).toBeGreaterThan(0);
    for (const cookie of cleared) expect(cookie).toMatch(/Max-Age=0/i);
    expect(jar.names().filter((name) => name.startsWith(SESSION_COOKIE))).toEqual([]);

    // reusing the cookie the browser had before: the session is gone on the server
    const reused = await getSession(oldCookie);
    expect(reused.status).toBe(401);
    expectToMatchContract('getSession', 401, await bodyOf(reused), reused);
    const reusedLogout = await logout(oldCookie);
    expect(reusedLogout.status).toBe(401);
    expectToMatchContract('logout', 401, await bodyOf(reusedLogout), reusedLogout);
    // the access token is still within its 15 minutes, yet the database has no principal for it
    expect(await principalRowsFor(accessToken)).toEqual([]);

    // and the refresh token died with the session: an "expired" copy of the old cookie cannot be
    // renewed into a new one
    writeSessionCookie(oldCookie, { ...readSessionCookie(oldCookie), expires_at: 1 });
    const renewed = await getSession(oldCookie);
    expect(renewed.status).toBe(401);
    expect(oldCookie.names().filter((name) => name.startsWith(SESSION_COOKIE))).toEqual([]);
  });

  it('AC-04: if the Auth server answers 403 to the revocation without revoking anything, logout is NOT 204 and the browser keeps its session', async () => {
    const client = await createClient();
    const jar = await signIn(await createClientUser({ clientId: client.id }));
    const spy = spyOnSupabaseFetch((url) =>
      url.includes('/auth/v1/logout')
        ? Response.json({ code: 403, error_code: 'bad_jwt', msg: 'simulated' }, { status: 403 })
        : undefined,
    );

    let response: Response;
    try {
      response = await logout(jar);
    } finally {
      spy.restore();
    }

    // the Auth client calls that "already signed out" and reports success: the database says no
    expect(response.status).toBe(503);
    expect(await bodyOf(response)).toMatchObject({ code: 'SERVICE_UNAVAILABLE', status: 503 });
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    for (const cookie of response.headers.getSetCookie()) {
      expect(cookie).not.toMatch(/Max-Age=0/i);
    }
    // the session is still alive and the browser still holds it, so the user can try again
    expect((await getSession(jar)).status).toBe(200);
    const retry = await logout(jar);
    expect(retry.status).toBe(204);
    expectToMatchContract('logout', 204, undefined, retry);
    expect((await getSession(jar)).status).toBe(401);
  });

  it('E-21: if the revocation cannot reach the Auth server, logout is 503 and the session cookies stay', async () => {
    const client = await createClient();
    const jar = await signIn(await createClientUser({ clientId: client.id }));
    const spy = spyOnSupabaseFetch((url) =>
      url.includes('/auth/v1/logout') ? new TypeError('fetch failed') : undefined,
    );

    let response: Response;
    try {
      response = await logout(jar);
    } finally {
      spy.restore();
    }

    expect(response.status).toBe(503);
    expect(await bodyOf(response)).toMatchObject({ code: 'SERVICE_UNAVAILABLE' });
    expect((await getSession(jar)).status).toBe(200);
    const retry = await logout(jar);
    expect(retry.status).toBe(204);
    expectToMatchContract('logout', 204, undefined, retry);
  });

  it('AC-26: a CEO with every pending action can log out, and the old cookie is dead', async () => {
    const ceo = await createCeo();
    const jar = await signIn(ceo);
    const oldCookie = jar.clone();
    expect(await bodyOf(await getSession(jar))).toMatchObject({
      pendingActions: ['CHANGE_PASSWORD', 'ENROLL_MFA'],
    });

    const response = await logout(jar);

    expect(response.status).toBe(204);
    expectToMatchContract('logout', 204, undefined, response);
    expect((await getSession(oldCookie)).status).toBe(401);
  });

  it('AC-26: without a session logout is 401 UNAUTHENTICATED', async () => {
    const response = await logout();
    const body = await bodyOf(response);

    expect(response.status).toBe(401);
    expect(body).toMatchObject({ code: 'UNAUTHENTICATED' });
    expectToMatchContract('logout', 401, body, response);
  });

  it('AC-23: logout without a valid Origin is 403 ORIGIN_NOT_ALLOWED, before anything else', async () => {
    const client = await createClient();
    const jar = await signIn(await createClientUser({ clientId: client.id }));

    const response = await logout(jar, { origin: 'https://evil.example' });
    const body = await bodyOf(response);

    expect(response.status).toBe(403);
    expect(body).toMatchObject({ code: 'ORIGIN_NOT_ALLOWED' });
    expectToMatchContract('logout', 403, body, response);
    // and the session was NOT ended by the forged request
    expect((await getSession(jar)).status).toBe(200);
  });

  it('E-09: logging out one device keeps the other sessions of the user', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });
    const laptop = await signIn(user);
    const phone = await signIn(user);
    const laptopBeforeLogout = laptop.clone(); // `logout` empties `laptop`: keep what a thief would hold

    const loggedOut = await logout(laptop);
    expect(loggedOut.status).toBe(204);
    expectToMatchContract('logout', 204, undefined, loggedOut);

    expect((await getSession(phone)).status).toBe(200);
    expect((await getSession(laptopBeforeLogout)).status).toBe(401);
  });

  it('AC-26: the body of a logout is ignored (the contract documents no 400, 413 or 415 for it)', async () => {
    const client = await createClient();
    const jar = await signIn(await createClientUser({ clientId: client.id }));

    const response = await invoke(logoutRoute, {
      method: 'POST',
      path: '/auth/logout',
      cookies: jar,
      rawBody: 'not json at all',
      headers: { 'content-type': 'text/plain' },
    });

    expect(response.status).toBe(204);
    expectToMatchContract('logout', 204, undefined, response);
    expect(await textOf(response)).toBe('');
  });
});
