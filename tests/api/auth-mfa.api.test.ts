// API tests of POST /auth/mfa/totp/enroll and POST /auth/mfa/totp/verify (operationIds `enrollTotp`
// and `verifyTotp`): the real route modules, the real pipeline and wiring (Postgres rate limiter,
// Supabase resolver), the local Supabase (Auth + PostgREST), and every response checked against the
// OpenAPI contract, headers included.
//
// The TOTP codes are computed from the secret the enroll endpoint returns, with `otpauth`. A CEO
// that already changed the temporary password is made by `tests/helpers/mfa.ts`, which clears the
// pending the way production's database function does (Wave 4 owns the real endpoint).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createClient as createSupabaseClient } from '@supabase/supabase-js';
import { afterEach, beforeEach, describe, expect, it, onTestFailed, vi } from 'vitest';
import { POST as enrollRoute } from '@/app/api/v1/auth/mfa/totp/enroll/route';
import { POST as verifyRoute } from '@/app/api/v1/auth/mfa/totp/verify/route';
import { GET as sessionRoute } from '@/app/api/v1/auth/session/route';
import { VERIFY_DAILY_BUDGET } from '@/modules/identity/presentation/rate-limit-budgets';
import type * as LoggerModule from '@/shared/observability/logger';
import type { Database } from '@/shared/db/database.types';
import { json, withRoute } from '@/shared/http';
import { createPostgresRateLimiter } from '@/shared/http/rate-limit/postgres-rate-limiter';
import { timing } from '@/shared/http/response-floor';
import { expectToMatchContract } from '../helpers/contract';
import { createClient, createClientUser, createCeo, publishableClient } from '../helpers/fixtures';
import {
  bodyOf,
  createCookieStore,
  invoke,
  readSessionCookie,
  spyOnSupabaseFetch,
  textOf,
  withoutRequestId,
  type CookieStore,
} from '../helpers/http';
import {
  completeFirstAccess,
  enrollTotp,
  enrollTotpViaApi,
  factorsOf,
  loginAsCeoReadyToEnroll,
  loginAsCeoWithMfa,
  loginViaApi,
  nextTotpCode,
  signInCeoWithMfa,
  verifyTotp,
  verifyTotpViaApi,
  wrongTotpCode,
} from '../helpers/mfa';

// ------------------------------------------------------------------------------ logger ----
// The process logger is replaced by one that captures its lines; everything else is real.

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

/** Every primitive value of a log record, at any depth. */
function valuesOf(value: unknown): unknown[] {
  if (Array.isArray(value)) return value.flatMap(valuesOf);
  if (typeof value === 'object' && value !== null) return Object.values(value).flatMap(valuesOf);
  return [value];
}

// ---------------------------------------------------------------- a stand-in for /admin/* ----

/**
 * AC-07 needs an `/admin/*` route, and the first one (`GET /admin/stage-templates/default`) arrives
 * in Wave 8. A `route.ts` outside the contract is forbidden, so the test builds a handler with the
 * REAL `withRoute` and the policy every admin operation of the contract declares: role ceo,
 * `allowPending: []` (no pending action at all, which is how the pipeline asks for `aal2`: a CEO
 * with a verified factor and an `aal1` session has `VERIFY_MFA` pending, one without a factor has
 * `ENROLL_MFA`), and a `reads` rate limit of 300 / min per user. The real resolver and the real
 * pipeline decide; only the use case is a stub.
 */
const adminProbe = withRoute(
  {
    access: 'authenticated',
    roles: ['ceo'],
    allowPending: [],
    rateLimit: [{ scope: 'user', group: 'reads', limit: 300, windowSeconds: 60 }],
  },
  ({ principal }) => json(200, { aal: principal.aal }),
);

const callAdmin = (cookies?: CookieStore) =>
  invoke(adminProbe, { path: '/admin/probe', ...(cookies === undefined ? {} : { cookies }) });

// --------------------------------------------------------------------------------- helpers ----

const getSession = (cookies: CookieStore) =>
  invoke(sessionRoute, { path: '/auth/session', cookies });

type EnrollmentBody = { factorId: string; uri: string; secret: string; qrCode: string };

/** The claims of a JWT (unverified: for assertions only). */
const claimsOf = (accessToken: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(accessToken.split('.')[1] ?? '', 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;

/** A client that sends `accessToken` to PostgREST: what a browser holding that token could build. */
function clientHolding(accessToken: string) {
  return createSupabaseClient<Database>(
    process.env.SUPABASE_URL ?? '',
    process.env.SUPABASE_PUBLISHABLE_KEY ?? '',
    {
      auth: { persistSession: false, autoRefreshToken: false },
      global: { headers: { Authorization: `Bearer ${accessToken}` } },
    },
  );
}

const SECONDS_IN_FIVE_MINUTES = 300;
const SECONDS_IN_FIFTEEN_MINUTES = 900;
/** F-23: the window in which a pre-verification refresh token still yields the elevated session. */
const MAX_REFRESH_REUSE_INTERVAL_SECONDS = 10;
const VERIFY_LIMIT = 5;
const ENROLL_LIMIT = 10;

beforeEach(() => {
  logged.lines.length = 0;
  // a refused login waits for its floor (F-05); these tests do not wait for real
  vi.spyOn(timing, 'sleep').mockResolvedValue(undefined);
  // The logger is captured, so the reason of a 500 would be invisible: show the server's own error
  // lines (already scrubbed by the logger) when a test fails.
  onTestFailed(() => {
    const errors = logged.lines.filter((line) => line.includes('"level":"error"'));
    if (errors.length > 0)
      process.stderr.write(`server errors of the failed test:\n${errors.join('')}`);
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ------------------------------------------------------------------------------------ AC-07 ----

describe('AC-07: a CEO needs aal2 for /admin/*', () => {
  it('AC-07: a CEO without a factor gets 403 MFA_ENROLLMENT_REQUIRED on /admin/*; after enroll + verify (aal2) it gets 200', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();

    // no factor at all
    const before = await callAdmin(cookies);
    expect(before.status).toBe(403);
    expect(await bodyOf(before)).toMatchObject({ code: 'MFA_ENROLLMENT_REQUIRED', status: 403 });

    // an enrolled but unverified factor is not MFA yet
    const enrolled = await enrollTotpViaApi(cookies);
    const enrollment = (await bodyOf(enrolled)) as EnrollmentBody;
    expect(enrolled.status).toBe(200);
    expectToMatchContract('enrollTotp', 200, enrollment, enrolled);
    const unverified = await callAdmin(cookies);
    expect(unverified.status).toBe(403);
    expect(await bodyOf(unverified)).toMatchObject({ code: 'MFA_ENROLLMENT_REQUIRED' });

    // the right code: the session becomes aal2 and the route opens
    const verified = await verifyTotpViaApi(cookies, {
      factorId: enrollment.factorId,
      code: nextTotpCode(enrollment.secret),
    });
    const session = await bodyOf(verified);
    expect(verified.status).toBe(200);
    expectToMatchContract('verifyTotp', 200, session, verified);
    expect(session).toEqual({
      user: { id: ceo.id, role: 'ceo', displayName: ceo.displayName },
      client: null,
      aal: 'aal2',
      pendingActions: [],
    });

    const after = await callAdmin(cookies);
    expect(after.status).toBe(200);
    expect(await bodyOf(after)).toEqual({ aal: 'aal2' });
  });

  it('AC-07: after the verification the old aal1 access token no longer opens /admin/* nor the CEO functions of the database', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const aal1Cookies = cookies.clone();
    const enrollment = await enrollTotp(cookies);
    await verifyTotp(cookies, enrollment);

    const aal1Token = readSessionCookie(aal1Cookies).access_token;
    const aal2Token = readSessionCookie(cookies).access_token;
    // the verification elevates the SAME session: new tokens, same session id, aal2 in the JWT
    expect(claimsOf(aal1Token)['aal']).toBe('aal1');
    expect(claimsOf(aal2Token)['aal']).toBe('aal2');
    expect(claimsOf(aal2Token)['session_id']).toBe(claimsOf(aal1Token)['session_id']);
    expect(aal2Token).not.toBe(aal1Token);

    // pipeline: the old token is an aal1 session of a CEO with a verified factor: VERIFY_MFA
    const stale = await callAdmin(aal1Cookies);
    expect(stale.status).toBe(403);
    expect(await bodyOf(stale)).toMatchObject({ code: 'MFA_VERIFICATION_REQUIRED' });
    expect((await callAdmin(cookies)).status).toBe(200);

    // database: a CEO function demands aal2 of the JWT itself (SEC-11, layer 2)
    const { id: clientId } = await createClient();
    const asAal1 = await clientHolding(aal1Token).rpc('list_client_users', {
      p_client_id: clientId,
    });
    expect(asAal1.error?.code).toBe('42501');
    const asAal2 = await clientHolding(aal2Token).rpc('list_client_users', {
      p_client_id: clientId,
    });
    expect(asAal2.error).toBeNull();
    expect(asAal2.data).toEqual([]);

    // the principal the database builds from each token
    expect(await getSession(aal1Cookies).then(bodyOf)).toMatchObject({
      user: { id: ceo.id },
      aal: 'aal1',
      pendingActions: ['VERIFY_MFA'],
    });
  });

  it('AC-07: a later login of a CEO with a verified factor is held at VERIFY_MFA until the code is verified, and the first session is untouched', async () => {
    const first = await loginAsCeoWithMfa();

    const second = await signInCeoWithMfa(first, { verify: false });
    const held = await getSession(second);
    expect(await bodyOf(held)).toMatchObject({ aal: 'aal1', pendingActions: ['VERIFY_MFA'] });
    const blocked = await callAdmin(second);
    expect(blocked.status).toBe(403);
    expect(await bodyOf(blocked)).toMatchObject({ code: 'MFA_VERIFICATION_REQUIRED' });

    // VERIFY_MFA is in the allowPending of the verify route: no new enrollment, just the code
    const verified = await verifyTotpViaApi(second, {
      factorId: first.factorId,
      code: nextTotpCode(first.secret),
    });
    expect(verified.status).toBe(200);
    expectToMatchContract('verifyTotp', 200, await bodyOf(verified), verified);
    expect(await bodyOf(verified)).toMatchObject({ aal: 'aal2', pendingActions: [] });
    expect((await callAdmin(second)).status).toBe(200);

    // the CEO's other session was never touched
    expect((await callAdmin(first.cookies)).status).toBe(200);
  });
});

// ------------------------------------------------------------------------ POST .../enroll ----

describe('POST /api/v1/auth/mfa/totp/enroll', () => {
  it('returns the TotpEnrollment of the contract, with a secret that is the one inside the URI, and writes no cookie', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();

    const response = await enrollTotpViaApi(cookies);
    const body = (await bodyOf(response)) as EnrollmentBody;

    expect(response.status).toBe(200);
    expectToMatchContract('enrollTotp', 200, body, response);
    expect(Object.keys(body).sort()).toEqual(['factorId', 'qrCode', 'secret', 'uri']);
    expect(body.uri).toContain(`secret=${body.secret}`);
    expect(body.uri).toContain('issuer=Rastreador');
    expect(response.headers.get('cache-control')).toBe('no-store');
    // enrolling does not change the session
    expect(response.headers.getSetCookie()).toEqual([]);
    // the factor exists, unverified, and is the one the endpoint named
    expect(await factorsOf(ceo.id)).toEqual([
      { id: body.factorId, type: 'totp', status: 'unverified' },
    ]);
  });

  it('E-26: enrolling with a pending unverified factor removes the old one and creates a new one', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const first = await enrollTotp(cookies);
    expect(await factorsOf(ceo.id)).toEqual([
      { id: first.factorId, type: 'totp', status: 'unverified' },
    ]);

    const response = await enrollTotpViaApi(cookies);
    const second = (await bodyOf(response)) as EnrollmentBody;

    expect(response.status).toBe(200);
    expectToMatchContract('enrollTotp', 200, second, response);
    expect(second.factorId).not.toBe(first.factorId);
    expect(second.secret).not.toBe(first.secret);
    // exactly one factor is left: the new one
    expect(await factorsOf(ceo.id)).toEqual([
      { id: second.factorId, type: 'totp', status: 'unverified' },
    ]);

    // the old secret opens nothing: its factor is gone, and the answer is the one of a wrong code
    const stale = await verifyTotpViaApi(cookies, {
      factorId: first.factorId,
      code: nextTotpCode(first.secret),
    });
    expect(stale.status).toBe(422);
    expect(await bodyOf(stale)).toMatchObject({ code: 'INVALID_MFA_CODE' });

    // the new one does
    await verifyTotp(cookies, second);
    expect((await callAdmin(cookies)).status).toBe(200);
  });

  it('E-27: enrolling with an already verified factor is 409 MFA_ALREADY_ENROLLED and the factor survives', async () => {
    const session = await loginAsCeoWithMfa();

    const response = await enrollTotpViaApi(session.cookies);
    const body = await bodyOf(response);

    expect(response.status).toBe(409);
    expectToMatchContract('enrollTotp', 409, body, response);
    expect(body).toMatchObject({ code: 'MFA_ALREADY_ENROLLED', status: 409 });
    expect(await factorsOf(session.ceo.id)).toEqual([
      { id: session.factorId, type: 'totp', status: 'verified' },
    ]);
    // and the CEO is not locked out
    expect((await callAdmin(session.cookies)).status).toBe(200);
  });

  it('E-27: a new aal1 session of a CEO with a verified factor cannot add a factor either: 403 MFA_VERIFICATION_REQUIRED', async () => {
    const session = await loginAsCeoWithMfa();
    const otherDevice = await signInCeoWithMfa(session, { verify: false });

    const response = await enrollTotpViaApi(otherDevice);

    expect(response.status).toBe(403);
    const body = await bodyOf(response);
    expectToMatchContract('enrollTotp', 403, body, response);
    expect(body).toMatchObject({ code: 'MFA_VERIFICATION_REQUIRED' });
    expect(await factorsOf(session.ceo.id)).toEqual([
      { id: session.factorId, type: 'totp', status: 'verified' },
    ]);
  });

  it('SEC-11: a CEO that still has to change the temporary password is 403 PASSWORD_CHANGE_REQUIRED (allowPending is only ENROLL_MFA)', async () => {
    const ceo = await createCeo();
    const cookies = await loginViaApi(ceo);

    const response = await enrollTotpViaApi(cookies);

    expect(response.status).toBe(403);
    const body = await bodyOf(response);
    expectToMatchContract('enrollTotp', 403, body, response);
    expect(body).toMatchObject({ code: 'PASSWORD_CHANGE_REQUIRED' });
    expect(await factorsOf(ceo.id)).toEqual([]);
  });

  it('a client is 403 FORBIDDEN, whatever it has pending', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });
    const cookies = await loginViaApi(user);

    const response = await enrollTotpViaApi(cookies);

    expect(response.status).toBe(403);
    const body = await bodyOf(response);
    expectToMatchContract('enrollTotp', 403, body, response);
    expect(body).toMatchObject({ code: 'FORBIDDEN' });
  });

  it('without a session it is 401 UNAUTHENTICATED', async () => {
    const response = await enrollTotpViaApi(createCookieStore());

    expect(response.status).toBe(401);
    const body = await bodyOf(response);
    expectToMatchContract('enrollTotp', 401, body, response);
    expect(body).toMatchObject({ code: 'UNAUTHENTICATED' });
  });

  it('AC-23: a POST without a valid Origin is 403 ORIGIN_NOT_ALLOWED and nothing is created', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();

    const response = await invoke(enrollRoute, {
      method: 'POST',
      path: '/auth/mfa/totp/enroll',
      cookies,
      origin: 'https://evil.example',
    });

    expect(response.status).toBe(403);
    const body = await bodyOf(response);
    expectToMatchContract('enrollTotp', 403, body, response);
    expect(body).toMatchObject({ code: 'ORIGIN_NOT_ALLOWED' });
    expect(await factorsOf(ceo.id)).toEqual([]);
  });

  it('totp-enroll: the 11th enrollment in 15 minutes is 429 RATE_LIMITED with Retry-After', async () => {
    const { cookies } = await loginAsCeoReadyToEnroll();

    for (let attempt = 1; attempt <= ENROLL_LIMIT; attempt += 1) {
      const response = await enrollTotpViaApi(cookies);
      expect(response.status, `enrollment ${attempt}`).toBe(200);
    }
    const throttled = await enrollTotpViaApi(cookies);

    expect(throttled.status).toBe(429);
    const body = await bodyOf(throttled);
    expectToMatchContract('enrollTotp', 429, body, throttled);
    expect(body).toMatchObject({ code: 'RATE_LIMITED' });
    const retryAfter = Number(throttled.headers.get('retry-after'));
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(SECONDS_IN_FIFTEEN_MINUTES);
  });
});

// ------------------------------------------------------------------------ POST .../verify ----

describe('POST /api/v1/auth/mfa/totp/verify', () => {
  it('the right code activates the factor and rewrites the cookies with an aal2 session, and no token reaches the body', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);
    const before = readSessionCookie(cookies);

    const response = await verifyTotpViaApi(cookies, {
      factorId: enrollment.factorId,
      code: nextTotpCode(enrollment.secret),
    });
    const body = await bodyOf(response);

    expect(response.status).toBe(200);
    expectToMatchContract('verifyTotp', 200, body, response);
    expect(await factorsOf(ceo.id)).toEqual([
      { id: enrollment.factorId, type: 'totp', status: 'verified' },
    ]);

    // new cookies, with the flags of SEC-07, holding an aal2 session
    const setCookies = response.headers.getSetCookie();
    expect(setCookies.length).toBeGreaterThan(0);
    for (const cookie of setCookies) {
      expect(cookie).toMatch(/^__Host-rt-session(\.\d+)?=/);
      expect(cookie).toMatch(/;\s*HttpOnly(;|$)/i);
      expect(cookie).toMatch(/;\s*Secure(;|$)/i);
      expect(cookie).toMatch(/;\s*SameSite=lax(;|$)/i);
      expect(cookie).toMatch(/;\s*Path=\/(;|$)/i);
      expect(cookie).not.toMatch(/;\s*Domain=/i);
    }
    const after = readSessionCookie(cookies);
    expect(claimsOf(after.access_token)['aal']).toBe('aal2');
    expect(after.access_token).not.toBe(before.access_token);

    // the body is the Session and never a token
    const text = await textOf(response);
    expect(text).not.toContain(after.access_token);
    expect(text).not.toContain(after.refresh_token);
    expect(text).not.toMatch(/eyJ[\w-]+\./);
    expect(Object.keys(body as object).sort()).toEqual(['aal', 'client', 'pendingActions', 'user']);

    // and the cookies the response set are the ones that work
    expect(await getSession(cookies).then(bodyOf)).toMatchObject({
      aal: 'aal2',
      pendingActions: [],
    });
  });

  it('E-28: a wrong code is 422 INVALID_MFA_CODE; the factor stays unverified, the session stays aal1 and no cookie is written', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);
    const tokenBefore = readSessionCookie(cookies).access_token;

    const response = await verifyTotpViaApi(cookies, {
      factorId: enrollment.factorId,
      code: wrongTotpCode(enrollment.secret),
    });
    const body = await bodyOf(response);

    expect(response.status).toBe(422);
    expectToMatchContract('verifyTotp', 422, body, response);
    expect(body).toMatchObject({ code: 'INVALID_MFA_CODE', status: 422 });
    expect(response.headers.getSetCookie()).toEqual([]);
    expect(readSessionCookie(cookies).access_token).toBe(tokenBefore);
    expect(await factorsOf(ceo.id)).toEqual([
      { id: enrollment.factorId, type: 'totp', status: 'unverified' },
    ]);
    expect(await getSession(cookies).then(bodyOf)).toMatchObject({
      aal: 'aal1',
      pendingActions: ['ENROLL_MFA'],
    });
    expect((await callAdmin(cookies)).status).toBe(403);
  });

  it('E-28: a wrong code counts against the 5 / 5 min limit: the 6th attempt is 429 with Retry-After, even with the right code', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);

    // each request comes from another client IP (the helper draws one per call): the limit is per
    // USER. Every attempt sends a DIFFERENT wrong code, because a code is burned the first time.
    for (let attempt = 1; attempt <= VERIFY_LIMIT; attempt += 1) {
      const response = await verifyTotpViaApi(cookies, {
        factorId: enrollment.factorId,
        code: wrongTotpCode(enrollment.secret, attempt),
      });
      expect(response.status, `attempt ${attempt}`).toBe(422);
    }
    const throttled = await verifyTotpViaApi(cookies, {
      factorId: enrollment.factorId,
      code: nextTotpCode(enrollment.secret),
    });

    expect(throttled.status).toBe(429);
    const body = await bodyOf(throttled);
    expectToMatchContract('verifyTotp', 429, body, throttled);
    expect(body).toMatchObject({ code: 'RATE_LIMITED' });
    const retryAfter = Number(throttled.headers.get('retry-after'));
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(SECONDS_IN_FIVE_MINUTES);

    // the throttled request never reached Auth: the factor was not activated by it
    expect(await factorsOf(ceo.id)).toEqual([
      { id: enrollment.factorId, type: 'totp', status: 'unverified' },
    ]);
    expect(throttled.headers.getSetCookie()).toEqual([]);
  });

  it("E-28: the limit is the route's: four wrong codes and a right one are five attempts, and the sixth is 429", async () => {
    const { cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);

    for (let attempt = 1; attempt < VERIFY_LIMIT; attempt += 1) {
      const response = await verifyTotpViaApi(cookies, {
        factorId: enrollment.factorId,
        code: wrongTotpCode(enrollment.secret, attempt),
      });
      expect(response.status, `wrong attempt ${attempt}`).toBe(422);
    }
    const right = await verifyTotpViaApi(cookies, {
      factorId: enrollment.factorId,
      code: nextTotpCode(enrollment.secret),
    });
    expect(right.status).toBe(200);
    expectToMatchContract('verifyTotp', 200, await bodyOf(right), right);

    const sixth = await verifyTotpViaApi(cookies, {
      factorId: enrollment.factorId,
      code: nextTotpCode(enrollment.secret),
    });
    expect(sixth.status).toBe(429);
    expectToMatchContract('verifyTotp', 429, await bodyOf(sixth), sixth);
  });

  it('E-28: the factor of ANOTHER CEO answers like a wrong code, and nothing is elevated', async () => {
    const victim = await loginAsCeoWithMfa();
    const { ceo: attacker, cookies } = await loginAsCeoReadyToEnroll();
    await enrollTotp(cookies);

    // the attacker even knows the victim's secret: the factor is not theirs
    const response = await verifyTotpViaApi(cookies, {
      factorId: victim.factorId,
      code: nextTotpCode(victim.secret),
    });
    const body = await bodyOf(response);

    expect(response.status).toBe(422);
    expectToMatchContract('verifyTotp', 422, body, response);
    expect(body).toMatchObject({ code: 'INVALID_MFA_CODE' });
    expect(response.headers.getSetCookie()).toEqual([]);
    expect(await getSession(cookies).then(bodyOf)).toMatchObject({
      user: { id: attacker.id },
      aal: 'aal1',
    });
    expect((await callAdmin(cookies)).status).toBe(403);
    // the victim is untouched
    expect(await factorsOf(victim.ceo.id)).toEqual([
      { id: victim.factorId, type: 'totp', status: 'verified' },
    ]);
  });

  it('E-28: a factor id that does not exist is indistinguishable from a wrong code (no probing of ids)', async () => {
    const { cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);

    const wrongCode = await verifyTotpViaApi(cookies, {
      factorId: enrollment.factorId,
      code: wrongTotpCode(enrollment.secret),
    });
    const unknownFactor = await verifyTotpViaApi(cookies, {
      factorId: '99999999-9999-4999-8999-999999999999',
      code: wrongTotpCode(enrollment.secret, 1),
    });

    expect(wrongCode.status).toBe(422);
    expect(unknownFactor.status).toBe(422);
    const wrongBody = await bodyOf(wrongCode);
    const unknownBody = await bodyOf(unknownFactor);
    expectToMatchContract('verifyTotp', 422, wrongBody, wrongCode);
    expectToMatchContract('verifyTotp', 422, unknownBody, unknownFactor);
    expect(withoutRequestId(unknownBody)).toEqual(withoutRequestId(wrongBody));
  });

  it('SEC-11: a CEO that still has to change the temporary password is 403 PASSWORD_CHANGE_REQUIRED', async () => {
    const ceo = await createCeo();
    const cookies = await loginViaApi(ceo);

    const response = await verifyTotpViaApi(cookies, {
      factorId: '99999999-9999-4999-8999-999999999999',
      code: '123456',
    });

    expect(response.status).toBe(403);
    const body = await bodyOf(response);
    expectToMatchContract('verifyTotp', 403, body, response);
    expect(body).toMatchObject({ code: 'PASSWORD_CHANGE_REQUIRED' });
  });

  it('a client is 403 FORBIDDEN, whatever it has pending', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });
    const cookies = await loginViaApi(user);

    const response = await verifyTotpViaApi(cookies, {
      factorId: '99999999-9999-4999-8999-999999999999',
      code: '123456',
    });

    expect(response.status).toBe(403);
    const body = await bodyOf(response);
    expectToMatchContract('verifyTotp', 403, body, response);
    expect(body).toMatchObject({ code: 'FORBIDDEN' });
  });

  it('without a session it is 401 UNAUTHENTICATED', async () => {
    const response = await verifyTotpViaApi(createCookieStore(), {
      factorId: '99999999-9999-4999-8999-999999999999',
      code: '123456',
    });

    expect(response.status).toBe(401);
    const body = await bodyOf(response);
    expectToMatchContract('verifyTotp', 401, body, response);
    expect(body).toMatchObject({ code: 'UNAUTHENTICATED' });
  });

  it.each([
    [
      'an unknown field',
      { factorId: '99999999-9999-4999-8999-999999999999', code: '123456', x: 1 },
    ],
    ['a code of five digits', { factorId: '99999999-9999-4999-8999-999999999999', code: '12345' }],
    ['a code with letters', { factorId: '99999999-9999-4999-8999-999999999999', code: '12345a' }],
    ['a code that is a number', { factorId: '99999999-9999-4999-8999-999999999999', code: 123456 }],
    ['a factor id that is not a UUID', { factorId: 'abc', code: '123456' }],
    ['no code', { factorId: '99999999-9999-4999-8999-999999999999' }],
    ['a factor id that is null', { factorId: null, code: '123456' }],
  ])('AC-23: %s is 400 VALIDATION_ERROR, and the value is not echoed', async (_label, input) => {
    const { cookies } = await loginAsCeoReadyToEnroll();

    const response = await verifyTotpViaApi(cookies, input as { factorId?: string; code: string });

    expect(response.status).toBe(400);
    const body = await bodyOf(response);
    expectToMatchContract('verifyTotp', 400, body, response);
    expect(body).toMatchObject({ code: 'VALIDATION_ERROR' });
    expect(JSON.stringify(body)).not.toContain('12345a');
  });

  it('AC-23: a body that is not JSON is 415, and one over 16 KiB is 413 (checked before the code is looked at)', async () => {
    const { cookies } = await loginAsCeoReadyToEnroll();
    const wrongType = await invoke(verifyRoute, {
      method: 'POST',
      path: '/auth/mfa/totp/verify',
      cookies,
      rawBody: '{"factorId":"x"}',
      headers: { 'content-type': 'text/plain' },
    });
    const tooLarge = await invoke(verifyRoute, {
      method: 'POST',
      path: '/auth/mfa/totp/verify',
      cookies,
      body: {
        factorId: '99999999-9999-4999-8999-999999999999',
        code: '123456',
        pad: 'x'.repeat(20_000),
      },
    });

    expect(wrongType.status).toBe(415);
    expectToMatchContract('verifyTotp', 415, await bodyOf(wrongType), wrongType);
    expect(tooLarge.status).toBe(413);
    expectToMatchContract('verifyTotp', 413, await bodyOf(tooLarge), tooLarge);
  });

  it('AC-23: a POST without a valid Origin is 403 ORIGIN_NOT_ALLOWED', async () => {
    const { cookies } = await loginAsCeoReadyToEnroll();

    const response = await invoke(verifyRoute, {
      method: 'POST',
      path: '/auth/mfa/totp/verify',
      cookies,
      body: { factorId: '99999999-9999-4999-8999-999999999999', code: '123456' },
      origin: null,
    });

    expect(response.status).toBe(403);
    const body = await bodyOf(response);
    expectToMatchContract('verifyTotp', 403, body, response);
    expect(body).toMatchObject({ code: 'ORIGIN_NOT_ALLOWED' });
  });
});

// ------------------------------------------------------------ replay, hijack, brute force ----

describe('hardening of the verification (F-20 to F-23)', () => {
  it('F-21: the same right code sent twice is 422 INVALID_MFA_CODE the second time, the very answer of a wrong code, and logged as code_reused', async () => {
    const { cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);
    const code = nextTotpCode(enrollment.secret);
    const first = await verifyTotpViaApi(cookies, { factorId: enrollment.factorId, code });
    expect(first.status).toBe(200);
    logged.lines.length = 0;

    const replay = await verifyTotpViaApi(cookies, { factorId: enrollment.factorId, code });
    const wrong = await verifyTotpViaApi(cookies, {
      factorId: enrollment.factorId,
      code: wrongTotpCode(enrollment.secret),
    });

    expect(replay.status).toBe(422);
    const replayBody = await bodyOf(replay);
    const wrongBody = await bodyOf(wrong);
    expectToMatchContract('verifyTotp', 422, replayBody, replay);
    expect(withoutRequestId(replayBody)).toEqual(withoutRequestId(wrongBody));
    expect(replay.headers.getSetCookie()).toEqual([]);
    // the log (not the response) tells them apart
    expect(events('auth.mfa.failed').map((event) => event['reason'])).toEqual([
      'code_reused',
      'invalid_code',
    ]);
  });

  it('F-21: a code the CEO used on one session cannot be replayed on another session of the same CEO', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);
    const code = nextTotpCode(enrollment.secret);
    expect((await verifyTotpViaApi(cookies, { factorId: enrollment.factorId, code })).status).toBe(
      200,
    );

    // someone with the password signs in right after, and sends the code they just watched
    const second = await loginViaApi(ceo);
    const replay = await verifyTotpViaApi(second, { factorId: enrollment.factorId, code });

    expect(replay.status).toBe(422);
    expectToMatchContract('verifyTotp', 422, await bodyOf(replay), replay);
    expect(await getSession(second).then(bodyOf)).toMatchObject({
      aal: 'aal1',
      pendingActions: ['VERIFY_MFA'],
    });
    expect((await callAdmin(second)).status).toBe(403);

    // a code nobody used yet still opens that session
    const fresh = await verifyTotpViaApi(second, {
      factorId: enrollment.factorId,
      code: nextTotpCode(enrollment.secret),
    });
    expect(fresh.status).toBe(200);
    expect((await callAdmin(second)).status).toBe(200);
  });

  it('F-20: the verification that ACTIVATES the first factor signs the CEO out of every other session', async () => {
    const ceo = await completeFirstAccess(await createCeo());
    // a session opened with the password alone (a stolen one, or an old tab) and the CEO's own
    const otherSession = await loginViaApi(ceo);
    const own = await loginViaApi(ceo);
    const enrollment = await enrollTotp(own);
    expect((await getSession(otherSession)).status, 'alive before the activation').toBe(200);
    logged.lines.length = 0;

    const verified = await verifyTotpViaApi(own, {
      factorId: enrollment.factorId,
      code: nextTotpCode(enrollment.secret),
    });

    expect(verified.status).toBe(200);
    const gone = await getSession(otherSession);
    expect(gone.status).toBe(401);
    expectToMatchContract('getSession', 401, await bodyOf(gone), gone);
    expect((await callAdmin(otherSession)).status).toBe(401);
    // the session that activated stays, as aal2
    expect(await getSession(own).then(bodyOf)).toMatchObject({ aal: 'aal2', pendingActions: [] });
    expect((await callAdmin(own)).status).toBe(200);
    expect(events('auth.mfa.verified')).toEqual([expect.objectContaining({ activated: true })]);
    expect(events('auth.mfa.followup_failed')).toEqual([]);
  });

  it("F-20: a later login that only verifies the same factor leaves the CEO's other sessions alone", async () => {
    const first = await loginAsCeoWithMfa();
    const second = await signInCeoWithMfa(first, { verify: false });
    const secondEnrollment = { factorId: first.factorId, secret: first.secret };

    await verifyTotp(second, secondEnrollment);

    expect((await callAdmin(first.cookies)).status).toBe(200);
    expect((await callAdmin(second)).status).toBe(200);
  });

  it('F-20: auth.mfa.failed tells a factor that is gone (factor_not_found) from a wrong code, and auth.mfa.enrolled counts the factors it replaced', async () => {
    const { cookies } = await loginAsCeoReadyToEnroll();
    const first = await enrollTotp(cookies);
    const second = await enrollTotp(cookies);
    logged.lines.length = 0;

    // the first factor was replaced: a stale tab (or whoever holds its secret) finds it gone
    const stale = await verifyTotpViaApi(cookies, {
      factorId: first.factorId,
      code: nextTotpCode(first.secret),
    });
    const wrong = await verifyTotpViaApi(cookies, {
      factorId: second.factorId,
      code: wrongTotpCode(second.secret),
    });

    expect([stale.status, wrong.status]).toEqual([422, 422]);
    expect(withoutRequestId(await bodyOf(stale))).toEqual(withoutRequestId(await bodyOf(wrong)));
    expect(events('auth.mfa.failed').map((event) => event['reason'])).toEqual([
      'factor_not_found',
      'invalid_code',
    ]);
  });

  it('F-20: auth.mfa.enrolled carries replacedFactors, so a replaced candidate leaves a trace', async () => {
    const { cookies } = await loginAsCeoReadyToEnroll();
    await enrollTotp(cookies);
    logged.lines.length = 0;

    const replaced = await enrollTotpViaApi(cookies);

    expect(replaced.status).toBe(200);
    expect(events('auth.mfa.enrolled')).toEqual([expect.objectContaining({ replacedFactors: 1 })]);
  });

  it('F-23 (known residual): the refresh token held BEFORE the verification still opens the elevated session, but only for the reuse interval of Auth', async () => {
    const { cookies } = await loginAsCeoReadyToEnroll();
    const copy = readSessionCookie(cookies);
    const enrollment = await enrollTotp(cookies);
    await verifyTotp(cookies, enrollment);

    // straight at the Auth server, as someone holding a copy of the aal1 cookie would: within the
    // reuse interval it answers with the CURRENT session, which is aal2 by now. Rotating the token
    // once more did not help (tried: the old token still answered), and the app cannot shorten the
    // interval; after it the same call is `refresh_token_already_used` (checked by hand with an
    // 11 s pause: this suite does not sleep).
    const refreshed = await publishableClient().auth.refreshSession({
      refresh_token: copy.refresh_token,
    });
    expect(refreshed.error).toBeNull();
    expect(claimsOf(refreshed.data.session?.access_token ?? '')['aal']).toBe('aal2');

    // so the residual is exactly as long as the configured interval: it must not grow
    const config = readFileSync(
      fileURLToPath(new URL('../../supabase/config.toml', import.meta.url)),
      'utf8',
    );
    const reuseIntervalSeconds = Number(
      /^refresh_token_reuse_interval\s*=\s*(\d+)/m.exec(config)?.[1],
    );
    expect(reuseIntervalSeconds).toBeLessThanOrEqual(MAX_REFRESH_REUSE_INTERVAL_SECONDS);
  });

  it('M2: a session that ends while the code is checked is 401 UNAUTHENTICATED, and the cookies of the elevated session are still on the response', async () => {
    const { cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);
    const before = readSessionCookie(cookies).access_token;

    // the pipeline's own read of the principal passes; the one after the verification finds nobody
    let reads = 0;
    const spy = spyOnSupabaseFetch((url) => {
      if (!url.includes('/rest/v1/rpc/current_principal')) return undefined;
      reads += 1;
      return reads === 1
        ? undefined
        : Response.json({ code: 'PGRST301', message: 'JWT expired' }, { status: 401 });
    });
    let response: Response;
    try {
      response = await verifyTotpViaApi(cookies, {
        factorId: enrollment.factorId,
        code: nextTotpCode(enrollment.secret),
      });
    } finally {
      spy.restore();
    }

    expect(response.status).toBe(401);
    const body = await bodyOf(response);
    expectToMatchContract('verifyTotp', 401, body, response);
    expect(body).toMatchObject({ code: 'UNAUTHENTICATED' });
    // the verification did happen: its cookies are on the response, and they are aal2
    expect(response.headers.getSetCookie().length).toBeGreaterThan(0);
    const after = readSessionCookie(cookies);
    expect(after.access_token).not.toBe(before);
    expect(claimsOf(after.access_token)['aal']).toBe('aal2');
  });
});

describe('POST /api/v1/auth/mfa/totp/verify: the daily cap (F-22)', () => {
  it('F-22: after 20 attempts in a day the next one is 429 RATE_LIMITED with Retry-After, and Auth is not asked', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);
    // the day's counter, spent the way the handler spends it (same limiter, same key), without
    // twenty real attempts (the contract's 5 / 5 min rule would stop them first)
    const limiter = createPostgresRateLimiter();
    for (let spent = 1; spent <= VERIFY_DAILY_BUDGET.limit; spent += 1) {
      const decision = await limiter.consume(
        {
          scope: 'user',
          group: VERIFY_DAILY_BUDGET.group,
          bucket: `user:${VERIFY_DAILY_BUDGET.group}`,
          subject: ceo.id,
        },
        { scope: 'user', ...VERIFY_DAILY_BUDGET },
      );
      expect(decision.allowed, `unit ${spent}`).toBe(true);
    }
    logged.lines.length = 0;

    const response = await verifyTotpViaApi(cookies, {
      factorId: enrollment.factorId,
      code: nextTotpCode(enrollment.secret),
    });

    expect(response.status).toBe(429);
    const body = await bodyOf(response);
    expectToMatchContract('verifyTotp', 429, body, response);
    expect(body).toMatchObject({ code: 'RATE_LIMITED' });
    const retryAfter = Number(response.headers.get('retry-after'));
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(VERIFY_DAILY_BUDGET.windowSeconds);
    // the factor was not activated, the code never reached Auth, and the log names the group
    expect(await factorsOf(ceo.id)).toEqual([
      { id: enrollment.factorId, type: 'totp', status: 'unverified' },
    ]);
    expect(events('auth.rate_limited')).toEqual([
      expect.objectContaining({ scope: 'user', group: 'totp-verify-daily' }),
    ]);
    expect(events('auth.mfa.failed')).toEqual([]);
  });

  it("F-22: the other routes and the other CEOs are not affected by one CEO's spent day", async () => {
    const spent = await loginAsCeoReadyToEnroll();
    const limiter = createPostgresRateLimiter();
    for (let n = 1; n <= VERIFY_DAILY_BUDGET.limit + 1; n += 1) {
      await limiter.consume(
        {
          scope: 'user',
          group: VERIFY_DAILY_BUDGET.group,
          bucket: `user:${VERIFY_DAILY_BUDGET.group}`,
          subject: spent.ceo.id,
        },
        { scope: 'user', ...VERIFY_DAILY_BUDGET },
      );
    }

    // enrolling and reading the session are other counters
    expect((await enrollTotpViaApi(spent.cookies)).status).toBe(200);
    expect((await getSession(spent.cookies)).status).toBe(200);
    // and another CEO verifies as usual
    const other = await loginAsCeoReadyToEnroll();
    await verifyTotp(other.cookies, await enrollTotp(other.cookies));
    expect((await callAdmin(other.cookies)).status).toBe(200);
  });
});

// ----------------------------------------------- the factor of the session (no factorId) ----

describe('POST /api/v1/auth/mfa/totp/verify without a factorId (contract 1.0.0-draft.2)', () => {
  it('AC-07: a new device: a CEO with a verified factor logs in on a fresh session (VERIFY_MFA), sends only the code, and gets aal2', async () => {
    const first = await loginAsCeoWithMfa();
    const fresh = await signInCeoWithMfa(first, { verify: false });
    // the new device never learned the factor id: all it has is the session and the authenticator
    expect(await getSession(fresh).then(bodyOf)).toMatchObject({
      aal: 'aal1',
      pendingActions: ['VERIFY_MFA'],
    });
    expect((await callAdmin(fresh)).status).toBe(403);
    logged.lines.length = 0;

    const response = await verifyTotpViaApi(fresh, { code: nextTotpCode(first.secret) });
    const body = await bodyOf(response);

    expect(response.status).toBe(200);
    expectToMatchContract('verifyTotp', 200, body, response);
    expect(body).toEqual({
      user: { id: first.ceo.id, role: 'ceo', displayName: first.ceo.displayName },
      client: null,
      aal: 'aal2',
      pendingActions: [],
    });
    // the pending is gone for good: the session, the cookies it got and a CEO route all agree
    expect(claimsOf(readSessionCookie(fresh).access_token)['aal']).toBe('aal2');
    expect(await getSession(fresh).then(bodyOf)).toMatchObject({
      aal: 'aal2',
      pendingActions: [],
    });
    expect((await callAdmin(fresh)).status).toBe(200);
    // the factor was the CEO's own, resolved by the server; nothing was activated or revoked
    expect(events('auth.mfa.verified')).toEqual([
      expect.objectContaining({
        userId: first.ceo.id,
        factorId: first.factorId,
        factorSource: 'session',
        activated: false,
      }),
    ]);
    expect((await callAdmin(first.cookies)).status).toBe(200);
    expect(await factorsOf(first.ceo.id)).toEqual([
      { id: first.factorId, type: 'totp', status: 'verified' },
    ]);
  });

  it('AC-07: the first enrollment: enroll, then verify with only the code: the factor is activated, the session is aal2 and the other sessions are signed out (F-20)', async () => {
    const ceo = await completeFirstAccess(await createCeo());
    const otherSession = await loginViaApi(ceo);
    const own = await loginViaApi(ceo);
    const enrollment = await enrollTotp(own);
    logged.lines.length = 0;

    const response = await verifyTotpViaApi(own, { code: nextTotpCode(enrollment.secret) });
    const body = await bodyOf(response);

    expect(response.status).toBe(200);
    expectToMatchContract('verifyTotp', 200, body, response);
    expect(body).toMatchObject({ aal: 'aal2', pendingActions: [] });
    expect(await factorsOf(ceo.id)).toEqual([
      { id: enrollment.factorId, type: 'totp', status: 'verified' },
    ]);
    expect((await callAdmin(own)).status).toBe(200);
    expect((await getSession(otherSession)).status).toBe(401);
    expect(events('auth.mfa.verified')).toEqual([
      expect.objectContaining({
        factorId: enrollment.factorId,
        factorSource: 'session',
        activated: true,
      }),
    ]);
  });

  it('E-28: the factorId of ANOTHER CEO is 422 INVALID_MFA_CODE, even with a code that is right for the caller own factor; and the same code without the id then works', async () => {
    const victim = await loginAsCeoWithMfa();
    const mine = await loginAsCeoWithMfa();
    const code = nextTotpCode(mine.secret);
    const newDevice = await signInCeoWithMfa(mine, { verify: false });
    logged.lines.length = 0;

    const foreign = await verifyTotpViaApi(newDevice, { factorId: victim.factorId, code });
    const foreignBody = await bodyOf(foreign);
    const wrong = await verifyTotpViaApi(newDevice, {
      code: wrongTotpCode(mine.secret),
    });

    expect(foreign.status).toBe(422);
    expectToMatchContract('verifyTotp', 422, foreignBody, foreign);
    expect(withoutRequestId(foreignBody)).toEqual(withoutRequestId(await bodyOf(wrong)));
    expect(foreign.headers.getSetCookie()).toEqual([]);
    expect(await getSession(newDevice).then(bodyOf)).toMatchObject({ aal: 'aal1' });
    expect((await callAdmin(newDevice)).status).toBe(403);
    // the log tells them apart; the response does not
    expect(events('auth.mfa.failed')).toEqual([
      expect.objectContaining({
        reason: 'factor_not_found',
        factorId: victim.factorId,
        factorSource: 'request',
      }),
      expect.objectContaining({
        reason: 'invalid_code',
        factorId: mine.factorId,
        factorSource: 'session',
      }),
    ]);

    // the foreign attempt burned nothing of the caller's: the right code still opens the session
    const ok = await verifyTotpViaApi(newDevice, { code });
    expect(ok.status).toBe(200);
    expect((await callAdmin(newDevice)).status).toBe(200);
    // and the victim was never touched
    expect(await factorsOf(victim.ceo.id)).toEqual([
      { id: victim.factorId, type: 'totp', status: 'verified' },
    ]);
  });

  it('F-21: the replay of a code sent without the factorId is 422 INVALID_MFA_CODE (code_reused), like a wrong code, whichever way the factor is named the second time', async () => {
    const first = await loginAsCeoWithMfa();
    const second = await signInCeoWithMfa(first, { verify: false });
    const code = nextTotpCode(first.secret);
    expect((await verifyTotpViaApi(second, { code })).status).toBe(200);
    // after the success: the Auth server itself ends the aal1 sessions a verification leaves behind
    const third = await signInCeoWithMfa(first, { verify: false });
    logged.lines.length = 0;

    const replay = await verifyTotpViaApi(third, { code });
    const replayWithId = await verifyTotpViaApi(third, { factorId: first.factorId, code });
    const wrong = await verifyTotpViaApi(third, { code: wrongTotpCode(first.secret) });

    expect([replay.status, replayWithId.status]).toEqual([422, 422]);
    const replayBody = await bodyOf(replay);
    expectToMatchContract('verifyTotp', 422, replayBody, replay);
    expectToMatchContract('verifyTotp', 422, await bodyOf(replayWithId), replayWithId);
    expect(withoutRequestId(replayBody)).toEqual(withoutRequestId(await bodyOf(wrong)));
    expect(replay.headers.getSetCookie()).toEqual([]);
    expect(await getSession(third).then(bodyOf)).toMatchObject({
      aal: 'aal1',
      pendingActions: ['VERIFY_MFA'],
    });
    // keyed by the resolved factor: the same one the explicit id names
    expect(events('auth.mfa.failed').map((event) => [event['reason'], event['factorId']])).toEqual([
      ['code_reused', first.factorId],
      ['code_reused', first.factorId],
      ['invalid_code', first.factorId],
    ]);
  });

  it('E-31: a CEO that never enrolled has no factor to resolve: 422 INVALID_MFA_CODE (factor_not_found), the same answer as a wrong code, and nothing changes', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const reference = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(reference.cookies);
    logged.lines.length = 0;

    const response = await verifyTotpViaApi(cookies, { code: '123456' });
    const body = await bodyOf(response);
    const wrong = await verifyTotpViaApi(reference.cookies, {
      code: wrongTotpCode(enrollment.secret),
    });

    expect(response.status).toBe(422);
    expectToMatchContract('verifyTotp', 422, body, response);
    expect(withoutRequestId(body)).toEqual(withoutRequestId(await bodyOf(wrong)));
    expect(response.headers.getSetCookie()).toEqual([]);
    expect(await factorsOf(ceo.id)).toEqual([]);
    expect(await getSession(cookies).then(bodyOf)).toMatchObject({
      aal: 'aal1',
      pendingActions: ['ENROLL_MFA'],
    });
    expect(events('auth.mfa.failed')[0]).toMatchObject({
      reason: 'factor_not_found',
      factorSource: 'session',
    });
    expect(events('auth.mfa.failed')[0]).not.toHaveProperty('factorId');
  });

  it('E-31: two unverified factors and none verified are ambiguous: 422 (factor_ambiguous), no code is tried on either, and naming the factor is the way out', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const first = await enrollTotp(cookies);
    // what the app never does (its enrollment keeps one factor) but Auth allows with a name: a
    // second candidate, created straight at the Auth server with the user's own session
    const direct = publishableClient();
    const signedIn = await direct.auth.signInWithPassword({
      email: ceo.email,
      password: ceo.password,
    });
    expect(signedIn.error).toBeNull();
    const extra = await direct.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'second' });
    expect(extra.error).toBeNull();
    expect(await factorsOf(ceo.id)).toHaveLength(2);
    logged.lines.length = 0;

    const ambiguous = await verifyTotpViaApi(cookies, { code: nextTotpCode(first.secret) });
    const wrong = await verifyTotpViaApi(cookies, { code: wrongTotpCode(first.secret) });

    expect(ambiguous.status).toBe(422);
    expectToMatchContract('verifyTotp', 422, await bodyOf(ambiguous), ambiguous);
    expect(withoutRequestId(await bodyOf(ambiguous))).toEqual(
      withoutRequestId(await bodyOf(wrong)),
    );
    expect(events('auth.mfa.failed').map((event) => event['reason'])).toEqual([
      'factor_ambiguous',
      'factor_ambiguous',
    ]);
    // nothing was tried: both factors are still unverified, the session still aal1
    expect((await factorsOf(ceo.id)).map((factor) => factor.status)).toEqual([
      'unverified',
      'unverified',
    ]);
    expect(await getSession(cookies).then(bodyOf)).toMatchObject({ aal: 'aal1' });

    // the deprecated field is exactly for this: the factor named is the caller's own, and it works
    const named = await verifyTotpViaApi(cookies, {
      factorId: first.factorId,
      code: nextTotpCode(first.secret),
    });
    expect(named.status).toBe(200);
    expect((await callAdmin(cookies)).status).toBe(200);
  });

  it('E-28: the 5 / 5 min limit counts a request without a factorId like any other: the 6th is 429 with Retry-After, even with the right code', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);

    for (let attempt = 1; attempt <= VERIFY_LIMIT; attempt += 1) {
      const response = await verifyTotpViaApi(cookies, {
        code: wrongTotpCode(enrollment.secret, attempt),
      });
      expect(response.status, `attempt ${attempt}`).toBe(422);
    }
    const throttled = await verifyTotpViaApi(cookies, { code: nextTotpCode(enrollment.secret) });

    expect(throttled.status).toBe(429);
    expectToMatchContract('verifyTotp', 429, await bodyOf(throttled), throttled);
    expect(await factorsOf(ceo.id)).toEqual([
      { id: enrollment.factorId, type: 'totp', status: 'unverified' },
    ]);
  });

  it('F-22: the daily cap counts a request without a factorId too: after 20 attempts the next is 429, and neither the factors nor the code reach Auth', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);
    const limiter = createPostgresRateLimiter();
    for (let spent = 1; spent <= VERIFY_DAILY_BUDGET.limit; spent += 1) {
      const decision = await limiter.consume(
        {
          scope: 'user',
          group: VERIFY_DAILY_BUDGET.group,
          bucket: `user:${VERIFY_DAILY_BUDGET.group}`,
          subject: ceo.id,
        },
        { scope: 'user', ...VERIFY_DAILY_BUDGET },
      );
      expect(decision.allowed, `unit ${spent}`).toBe(true);
    }
    logged.lines.length = 0;

    const spy = spyOnSupabaseFetch();
    let response: Response;
    try {
      response = await verifyTotpViaApi(cookies, { code: nextTotpCode(enrollment.secret) });
    } finally {
      spy.restore();
    }

    expect(response.status).toBe(429);
    expectToMatchContract('verifyTotp', 429, await bodyOf(response), response);
    expect(events('auth.rate_limited')).toEqual([
      expect.objectContaining({ scope: 'user', group: 'totp-verify-daily' }),
    ]);
    // the cap decided before the factor was resolved: no listing of factors, no challenge, no verify
    expect(spy.calls.filter((call) => /\/auth\/v1\/(user|factors)/.test(call))).toEqual([]);
    expect(await factorsOf(ceo.id)).toEqual([
      { id: enrollment.factorId, type: 'totp', status: 'unverified' },
    ]);
  });

  it('SEC-16: resolving the factor logs ids only: no code, no secret and no token', async () => {
    const first = await loginAsCeoWithMfa();
    const fresh = await signInCeoWithMfa(first, { verify: false });
    logged.lines.length = 0;
    const right = nextTotpCode(first.secret);
    const wrong = wrongTotpCode(first.secret);

    expect((await verifyTotpViaApi(fresh, { code: wrong })).status).toBe(422);
    expect((await verifyTotpViaApi(fresh, { code: right })).status).toBe(200);

    const values = records().flatMap(valuesOf);
    expect(values).not.toContain(right);
    expect(values).not.toContain(wrong);
    expect(logged.lines.join('\n')).not.toContain(first.secret);
    expect(logged.lines.join('\n')).not.toMatch(/eyJ[\w-]+\./);
    expect(records().flatMap((record) => Object.keys(record))).not.toContain('code');
  });
});

// --------------------------------------------------------------------------------- logs ----

describe('what MFA writes to the logs (spec §3.10, SEC-16)', () => {
  it('SEC-16: auth.mfa.enrolled, auth.mfa.failed and auth.mfa.verified carry ids and an IP hash, never the secret, the URI, a code or a token', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    logged.lines.length = 0;

    const enrolled = await enrollTotpViaApi(cookies);
    const enrollment = (await bodyOf(enrolled)) as EnrollmentBody;
    const wrong = wrongTotpCode(enrollment.secret);
    const refused = await verifyTotpViaApi(cookies, { factorId: enrollment.factorId, code: wrong });
    const right = nextTotpCode(enrollment.secret);
    const verified = await verifyTotpViaApi(cookies, {
      factorId: enrollment.factorId,
      code: right,
    });
    expect([enrolled.status, refused.status, verified.status]).toEqual([200, 422, 200]);

    const [enrolledEvent] = events('auth.mfa.enrolled');
    expect(enrolledEvent).toMatchObject({
      level: 'info',
      requestId: enrolled.headers.get('x-request-id'),
      userId: ceo.id,
      factorId: enrollment.factorId,
      replacedFactors: 0,
    });
    const [failedEvent] = events('auth.mfa.failed');
    expect(failedEvent).toMatchObject({
      level: 'warn',
      requestId: refused.headers.get('x-request-id'),
      userId: ceo.id,
      factorId: enrollment.factorId,
      reason: 'invalid_code',
    });
    const [verifiedEvent] = events('auth.mfa.verified');
    expect(verifiedEvent).toMatchObject({
      level: 'info',
      requestId: verified.headers.get('x-request-id'),
      userId: ceo.id,
      factorId: enrollment.factorId,
      sessionId: claimsOf(readSessionCookie(cookies).access_token)['session_id'],
    });
    // a keyed hash of the client IP, never the IP (F-09)
    for (const event of [enrolledEvent, failedEvent, verifiedEvent]) {
      expect(event?.['ipHash']).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(events('auth.mfa.failed')).toHaveLength(1);

    // nothing secret anywhere in the log: not the secret or the URI, not an e-mail, not a token
    const everything = logged.lines.join('\n');
    expect(everything).not.toContain(enrollment.secret);
    expect(everything).not.toContain(enrollment.uri);
    expect(everything).not.toContain('otpauth://');
    expect(everything).not.toContain('data:image/svg');
    expect(everything.toLowerCase()).not.toContain(ceo.email.toLowerCase());
    expect(everything).not.toMatch(/eyJ[\w-]+\./);
    expect(everything).not.toContain(readSessionCookie(cookies).refresh_token);
    // a code is six digits and can occur inside an id by chance: compare VALUES, not substrings
    const values = records().flatMap(valuesOf);
    expect(values).not.toContain(wrong);
    expect(values).not.toContain(right);
    // and no field is named after the code
    expect(records().flatMap((record) => Object.keys(record))).not.toContain('code');
  });
});
