// API tests of POST /auth/password (operationId `changePassword`): the real route module, the real
// pipeline and wiring (Postgres rate limiter, Supabase resolver), the local Supabase (Auth +
// PostgREST + the database functions), and every response the contract documents checked against it.
//
// Also here, because they are about who may do what with an account: the AC-05 gate (a pending
// password change closes every route but three) and the negative AC-31 tests (no route creates or
// promotes a CEO). The script that DOES create CEOs is tested in tests/int/create-ceo.int.test.ts.
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parse } from 'yaml';
import { POST as loginRoute } from '@/app/api/v1/auth/login/route';
import { POST as logoutRoute } from '@/app/api/v1/auth/logout/route';
import { POST as passwordRoute } from '@/app/api/v1/auth/password/route';
import { GET as sessionRoute } from '@/app/api/v1/auth/session/route';
import { sessionIdOfToken } from '@/shared/db/session-cookies';
import { json, withRoute } from '@/shared/http';
import { timing } from '@/shared/http/response-floor';
import { expectToMatchContract } from '../helpers/contract';
import {
  ceoAal2Client,
  createCeo,
  createClient,
  createClientUser,
  publishableClient,
  type FixtureUser,
} from '../helpers/fixtures';
import {
  bodyOf,
  createCookieStore,
  invoke,
  readSessionCookie,
  writeSessionCookie,
  type CookieStore,
} from '../helpers/http';
import {
  canSignIn,
  changePassword,
  hasLivePrincipal,
  LOSE_ANSWER,
  jarOf,
  mustChangePassword,
  roleOf,
  sessionJarFor,
  whileWatching,
} from '../helpers/password';

// Obviously fake values (the secret-detection hook rightly ignores names without "password").
const FRESH = 'A-brand-new-password-9';
const SECOND = 'Yet-another-password-77';
const WRONG = 'this-is-not-the-current-one';

/** Refused logins wait for their floor (400 ms): the tests that log in wrongly do not wait for real. */
beforeEach(() => {
  vi.spyOn(timing, 'sleep').mockResolvedValue(undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function clientUser(): Promise<FixtureUser> {
  const tenant = await createClient();
  return createClientUser({ clientId: tenant.id });
}

const getSession = (cookies: CookieStore) =>
  invoke(sessionRoute, { path: '/auth/session', cookies });

const logout = (cookies: CookieStore) =>
  invoke(logoutRoute, { method: 'POST', path: '/auth/logout', cookies });

/**
 * Routes shaped like the ones that stay closed while a pendency is open: `/me/*` (clients, no
 * pendency allowed) and `/admin/*` (CEOs, no pendency allowed). They use the REAL `withRoute`, so
 * the pipeline's own rule is what answers; the business routes themselves arrive in later waves.
 */
const READS_RULE = { scope: 'user', group: 'reads', limit: 300, windowSeconds: 60 } as const;
const meProbe = withRoute(
  { access: 'authenticated', roles: ['client'], allowPending: [], rateLimit: [READS_RULE] },
  () => json(200, { reached: 'me' }),
);
const adminProbe = withRoute(
  { access: 'authenticated', roles: ['ceo'], allowPending: [], rateLimit: [READS_RULE] },
  () => json(200, { reached: 'admin' }),
);
const probe = (route: typeof meProbe, cookies: CookieStore) =>
  invoke(route, { path: '/probe', cookies });

type SessionBody = { user: { role: string }; pendingActions: string[] };

describe('AC-05: with CHANGE_PASSWORD pending only session, logout and password answer', () => {
  it('AC-05: a client with CHANGE_PASSWORD pending reaches session, password and logout; any other route is 403 PASSWORD_CHANGE_REQUIRED', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);

    const session = await getSession(jar);
    expect(session.status).toBe(200);
    expect((await bodyOf(session)) as SessionBody).toMatchObject({
      pendingActions: ['CHANGE_PASSWORD'],
    });

    // every other route stays closed, with the code of the pendency
    const closed = await probe(meProbe, jar);
    expect(closed.status).toBe(403);
    expect(await bodyOf(closed)).toMatchObject({ code: 'PASSWORD_CHANGE_REQUIRED', status: 403 });

    // the password route is reachable: it answers about the BODY (422), not about the pendency (403)
    const weak = await changePassword(jar, {
      currentPassword: user.password,
      newPassword: 'short',
    });
    expect(weak.status).toBe(422);

    // and so is logout
    expect((await logout(jar)).status).toBe(204);
  });

  it('AC-05: a CEO with CHANGE_PASSWORD and ENROLL_MFA pending is told about the password first, on every closed route', async () => {
    const ceo = await createCeo();
    const jar = await sessionJarFor(ceo);

    expect(((await bodyOf(await getSession(jar))) as SessionBody).pendingActions).toEqual([
      'CHANGE_PASSWORD',
      'ENROLL_MFA',
    ]);
    const closed = await probe(adminProbe, jar);
    expect(closed.status).toBe(403);
    // CHANGE_PASSWORD > ENROLL_MFA > VERIFY_MFA (spec §3.5)
    expect(await bodyOf(closed)).toMatchObject({ code: 'PASSWORD_CHANGE_REQUIRED' });
    expect(
      (await changePassword(jar, { currentPassword: ceo.password, newPassword: 'short' })).status,
    ).toBe(422);
  });

  it('AC-05: the whole path through the real login route: pending, change, free', async () => {
    const user = await clientUser();
    const jar = createCookieStore();
    const login = await invoke(loginRoute, {
      method: 'POST',
      path: '/auth/login',
      body: { email: user.email, password: user.password },
      cookies: jar,
    });
    expect(login.status).toBe(200);
    expect(((await bodyOf(login)) as SessionBody).pendingActions).toEqual(['CHANGE_PASSWORD']);
    expect((await probe(meProbe, jar)).status).toBe(403);

    const change = await changePassword(jar, {
      currentPassword: user.password,
      newPassword: FRESH,
    });
    expect(change.status).toBe(204);

    expect(((await bodyOf(await getSession(jar))) as SessionBody).pendingActions).toEqual([]);
    expect((await probe(meProbe, jar)).status).toBe(200);
  });

  it('AC-05: after the change a CEO is still held by ENROLL_MFA, with its own code (the flow of Wave 5)', async () => {
    const ceo = await createCeo();
    const jar = await sessionJarFor(ceo);

    expect(
      (await changePassword(jar, { currentPassword: ceo.password, newPassword: FRESH })).status,
    ).toBe(204);

    expect(((await bodyOf(await getSession(jar))) as SessionBody).pendingActions).toEqual([
      'ENROLL_MFA',
    ]);
    const closed = await probe(adminProbe, jar);
    expect(closed.status).toBe(403);
    expect(await bodyOf(closed)).toMatchObject({ code: 'MFA_ENROLLMENT_REQUIRED' });
  });

  it('AC-05: the pendency cannot be cleared by calling mark_password_changed() straight at PostgREST: no new password, no proof (ADR 0007)', async () => {
    const user = await clientUser();
    const supabase = publishableClient();
    await supabase.auth.signInWithPassword({ email: user.email, password: user.password });

    const { error } = await supabase.rpc('mark_password_changed');

    expect(error).toMatchObject({ code: 'P0001', message: 'PASSWORD_UNCHANGED' });
    expect(await mustChangePassword(user.id)).toBe(true);
    const jar = jarOf((await supabase.auth.getSession()).data.session!);
    expect(((await bodyOf(await getSession(jar))) as SessionBody).pendingActions).toEqual([
      'CHANGE_PASSWORD',
    ]);
  });
});

describe('AC-06: the change of password', () => {
  it('AC-06: with the current password and a valid new one it is 204 (contract), clears the pendency and keeps the session', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);
    const before = readSessionCookie(jar);

    const response = await changePassword(jar, {
      currentPassword: user.password,
      newPassword: FRESH,
    });

    expect(response.status).toBe(204);
    expectToMatchContract('changePassword', 204, undefined, response);
    // the CURRENT session survives with the very same tokens, and now has nothing pending
    const after = readSessionCookie(jar);
    expect(after.access_token).toBe(before.access_token);
    expect(after.refresh_token).toBe(before.refresh_token);
    const session = await getSession(jar);
    expect(session.status).toBe(200);
    expect(((await bodyOf(session)) as SessionBody).pendingActions).toEqual([]);
    expect(await mustChangePassword(user.id)).toBe(false);
    // the new password opens a session; the old one no longer does
    expect(await canSignIn(user.email, FRESH)).toBe(true);
    expect(await canSignIn(user.email, user.password)).toBe(false);
  });

  it('AC-06: whatever cookie the response carries is the user session itself, with the forced flags, and nothing else', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);
    const before = readSessionCookie(jar);

    const response = await changePassword(jar, {
      currentPassword: user.password,
      newPassword: FRESH,
    });

    for (const cookie of response.headers.getSetCookie()) {
      expect(cookie).toMatch(/^__Host-rt-session(\.\d+)?=/);
      expect(cookie).toMatch(/;\s*HttpOnly(;|$)/i);
      expect(cookie).toMatch(/;\s*Secure(;|$)/i);
      expect(cookie).toMatch(/;\s*SameSite=lax(;|$)/i);
      expect(cookie).toMatch(/;\s*Path=\/(;|$)/i);
      expect(cookie).not.toMatch(/;\s*Domain=/i);
      // no deletion: the session is kept
      expect(cookie).not.toMatch(/Max-Age=0/i);
    }
    // the session in the jar is the one the request came with (same id), not another one
    expect(sessionIdOfToken(readSessionCookie(jar).access_token)).toBe(
      sessionIdOfToken(before.access_token),
    );
  });

  it('AC-06: when the access token is renewed during the call, the 204 carries the renewed session cookie (Set-Cookie is optional in the contract), and it keeps working', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);
    const before = readSessionCookie(jar);
    // the client library decides to refresh from `expires_at`: make the token look expired
    writeSessionCookie(jar, { ...before, expires_at: 1 });

    const response = await changePassword(jar, {
      currentPassword: user.password,
      newPassword: FRESH,
    });

    expect(response.status).toBe(204);
    // `changePassword` already checked the 204 against the contract, header included
    const cookies = response.headers.getSetCookie();
    expect(cookies.length).toBeGreaterThan(0);
    for (const cookie of cookies) expect(cookie).toMatch(/^__Host-rt-session(\.\d+)?=/);
    const after = readSessionCookie(jar);
    expect(after.refresh_token).not.toBe(before.refresh_token);
    expect(sessionIdOfToken(after.access_token)).toBe(sessionIdOfToken(before.access_token));
    expect(await mustChangePassword(user.id)).toBe(false);
    expect((await getSession(jar)).status).toBe(200);
  });

  it('AC-06: it revokes the OTHER sessions of the user and keeps the current one', async () => {
    const user = await clientUser();
    const current = await sessionJarFor(user);
    const phone = await sessionJarFor(user);
    const laptop = await sessionJarFor(user);
    expect((await getSession(phone)).status).toBe(200);
    expect((await getSession(laptop)).status).toBe(200);
    const phoneToken = readSessionCookie(phone).access_token;

    const response = await changePassword(current, {
      currentPassword: user.password,
      newPassword: FRESH,
    });

    expect(response.status).toBe(204);
    expect((await getSession(current)).status).toBe(200);
    for (const other of [phone, laptop]) {
      expect((await getSession(other)).status).toBe(401);
    }
    // not only the API: the database itself no longer sees a principal behind their tokens
    expect(await hasLivePrincipal(phoneToken)).toBe(false);
    expect(await hasLivePrincipal(readSessionCookie(current).access_token)).toBe(true);
  });

  it('AC-06: it does not touch the sessions of another user', async () => {
    const tenant = await createClient();
    const user = await createClientUser({ clientId: tenant.id });
    const neighbour = await createClientUser({ clientId: tenant.id });
    const jar = await sessionJarFor(user);
    const neighbourJar = await sessionJarFor(neighbour);

    expect(
      (await changePassword(jar, { currentPassword: user.password, newPassword: FRESH })).status,
    ).toBe(204);

    expect((await getSession(neighbourJar)).status).toBe(200);
    expect(await mustChangePassword(neighbour.id)).toBe(true);
  });

  it('AC-06: the current password is required: a wrong one is 422 INVALID_CURRENT_PASSWORD (contract) and changes nothing', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);
    const other = await sessionJarFor(user);
    const before = readSessionCookie(jar);

    const response = await changePassword(jar, { currentPassword: WRONG, newPassword: FRESH });

    expect(response.status).toBe(422);
    const body = await bodyOf(response);
    expect(body).toMatchObject({ code: 'INVALID_CURRENT_PASSWORD', status: 422 });
    expectToMatchContract('changePassword', 422, body, response);
    // nothing changed: the old password still opens, the new one does not, the pendency is set
    expect(await canSignIn(user.email, user.password)).toBe(true);
    expect(await canSignIn(user.email, FRESH)).toBe(false);
    expect(await mustChangePassword(user.id)).toBe(true);
    // no session was touched, and the response did not rewrite the one in use
    expect((await getSession(jar)).status).toBe(200);
    expect((await getSession(other)).status).toBe(200);
    expect(readSessionCookie(jar).access_token).toBe(before.access_token);
  });

  it('AC-06: the answer for a wrong current password does not depend on the account: the same code, detail and headers for any user', async () => {
    const first = await clientUser();
    const second = await clientUser();
    const answers = [];
    for (const user of [first, second]) {
      const jar = await sessionJarFor(user);
      const response = await changePassword(jar, { currentPassword: WRONG, newPassword: FRESH });
      const { requestId: _requestId, ...rest } = (await bodyOf(response)) as Record<
        string,
        unknown
      >;
      answers.push({ status: response.status, body: rest });
    }
    expect(answers[0]).toEqual(answers[1]);
  });

  it('AC-06: the session that proves the current password is revoked, and nothing from it reaches the response', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);
    const before = readSessionCookie(jar);

    const { response, signedInTokens } = await whileWatching(undefined, async (traffic) => ({
      response: await changePassword(jar, { currentPassword: user.password, newPassword: FRESH }),
      signedInTokens: traffic.signedInTokens,
    }));

    expect(response.status).toBe(204);
    // exactly one password sign-in happened: the proof
    expect(signedInTokens).toHaveLength(1);
    const [probeToken = ''] = signedInTokens;
    expect(probeToken).not.toBe(before.access_token);
    expect(await hasLivePrincipal(probeToken)).toBe(false);
    // no cookie of the response carries the proof session
    const probeSession = sessionIdOfToken(probeToken);
    expect(probeSession).toBeDefined();
    for (const cookie of response.headers.getSetCookie()) {
      expect(cookie).not.toContain(probeToken);
    }
    expect(sessionIdOfToken(readSessionCookie(jar).access_token)).not.toBe(probeSession);
  });

  it('AC-06: the proof session is revoked on its own, even when the update then fails (Auth down at the update): nothing is changed', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);

    const { response, calls, signedInTokens } = await whileWatching(
      (method, path) =>
        method === 'PUT' && path.startsWith('/auth/v1/user')
          ? Response.json({ msg: 'simulated outage' }, { status: 502 })
          : undefined,
      async (traffic) => ({
        response: await changePassword(jar, {
          currentPassword: user.password,
          newPassword: FRESH,
        }),
        calls: traffic.calls,
        signedInTokens: traffic.signedInTokens,
      }),
    );

    expect(response.status).toBe(503);
    const problem = (await bodyOf(response)) as { code: string; detail: string };
    expect(problem.code).toBe('SERVICE_UNAVAILABLE');
    // M4: an update that got no usable answer might have been applied, and the guidance says so
    expect(problem.detail).toContain('may already have been changed');
    // the proof was opened, then closed (scope local), before the update was even tried
    expect(signedInTokens).toHaveLength(1);
    const logoutCall = calls.findIndex((call) =>
      call.startsWith('POST /auth/v1/logout?scope=local'),
    );
    const updateCall = calls.findIndex((call) => call.startsWith('PUT /auth/v1/user'));
    expect(logoutCall).toBeGreaterThan(-1);
    expect(logoutCall).toBeLessThan(updateCall);
    expect(await hasLivePrincipal(signedInTokens[0] ?? '')).toBe(false);
    // the real session is alive, and so is the old password
    expect((await getSession(jar)).status).toBe(200);
    expect(await canSignIn(user.email, user.password)).toBe(true);
    expect(await mustChangePassword(user.id)).toBe(true);
  });

  it('AC-06: the new password is stored with the session of the user (a single PUT /auth/v1/user), after the proof and before the database call', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);

    const calls = await whileWatching(undefined, async (traffic) => {
      await changePassword(jar, { currentPassword: user.password, newPassword: FRESH });
      return traffic.calls;
    });

    const step = (prefix: string) => calls.findIndex((call) => call.startsWith(prefix));
    const proof = step('POST /auth/v1/token?grant_type=password');
    const update = step('PUT /auth/v1/user');
    const mark = step('POST /rest/v1/rpc/mark_password_changed');
    expect(proof).toBeGreaterThan(-1);
    expect(update).toBeGreaterThan(proof);
    expect(mark).toBeGreaterThan(update);
    expect(calls.filter((call) => call.startsWith('PUT /auth/v1/user'))).toHaveLength(1);
    expect(
      calls.filter((call) => call.startsWith('POST /auth/v1/token?grant_type=password')),
    ).toHaveLength(1);
  });

  it('AC-06: a CEO with a verified second factor changes the password on an aal2 session, and is then free', async () => {
    const { ceo, supabase } = await ceoAal2Client();
    const { data } = await supabase.auth.getSession();
    const jar = jarOf(data.session!);
    expect(((await bodyOf(await getSession(jar))) as SessionBody).pendingActions).toEqual([
      'CHANGE_PASSWORD',
    ]);

    const response = await changePassword(jar, {
      currentPassword: ceo.password,
      newPassword: FRESH,
    });

    expect(response.status).toBe(204);
    expectToMatchContract('changePassword', 204, undefined, response);
    expect(((await bodyOf(await getSession(jar))) as SessionBody).pendingActions).toEqual([]);
    expect((await probe(adminProbe, jar)).status).toBe(200);
  });

  it('AC-06: a CEO with a verified second factor on an aal1 session is 403 MFA_VERIFICATION_REQUIRED, and the database refuses the function too', async () => {
    const { ceo } = await ceoAal2Client();
    // a new sign-in is aal1 again, while the factor stays verified
    const supabase = publishableClient();
    await supabase.auth.signInWithPassword({ email: ceo.email, password: ceo.password });
    const jar = jarOf((await supabase.auth.getSession()).data.session!);

    const response = await changePassword(jar, {
      currentPassword: ceo.password,
      newPassword: FRESH,
    });

    expect(response.status).toBe(403);
    const body = await bodyOf(response);
    expect(body).toMatchObject({ code: 'MFA_VERIFICATION_REQUIRED' });
    expectToMatchContract('changePassword', 403, body, response);
    expect(await canSignIn(ceo.email, ceo.password)).toBe(true);
    // second layer: the database function itself denies this session (42501)
    const { error } = await supabase.rpc('mark_password_changed');
    expect(error).toMatchObject({ code: '42501' });
  });

  it('M4: an update that WAS applied but whose answer was lost is 503 with the guidance of both states, and following it works', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);

    const response = await whileWatching(
      (method, path) =>
        method === 'PUT' && path.startsWith('/auth/v1/user') ? LOSE_ANSWER : undefined,
      () => changePassword(jar, { currentPassword: user.password, newPassword: FRESH }),
    );

    expect(response.status).toBe(503);
    const problem = (await bodyOf(response)) as { code: string; detail: string };
    expect(problem.code).toBe('SERVICE_UNAVAILABLE');
    expect(problem.detail).toContain('may already have been changed');
    expect(problem.detail).toContain('new password as the current password');
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    // the Auth server DID change it, and the account still says "change it"
    expect(await canSignIn(user.email, FRESH)).toBe(true);
    expect(await mustChangePassword(user.id)).toBe(true);

    // the guidance, step one: repeat the request. The old password is no longer the current one
    const repeated = await changePassword(jar, {
      currentPassword: user.password,
      newPassword: FRESH,
    });
    expect(repeated.status).toBe(422);
    expect(await bodyOf(repeated)).toMatchObject({ code: 'INVALID_CURRENT_PASSWORD' });
    // step two: the new password is the current one
    const finished = await changePassword(jar, { currentPassword: FRESH, newPassword: SECOND });
    expect(finished.status).toBe(204);
    expect(await mustChangePassword(user.id)).toBe(false);
    expect(await canSignIn(user.email, SECOND)).toBe(true);
  });

  it('M4: an update that was NOT applied (the request never arrived) is the same 503, and repeating it with the old password works', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);

    const response = await whileWatching(
      (method, path) =>
        method === 'PUT' && path.startsWith('/auth/v1/user')
          ? new TypeError('fetch failed')
          : undefined,
      () => changePassword(jar, { currentPassword: user.password, newPassword: FRESH }),
    );

    expect(response.status).toBe(503);
    expect(await canSignIn(user.email, user.password)).toBe(true);
    const repeated = await changePassword(jar, {
      currentPassword: user.password,
      newPassword: FRESH,
    });
    expect(repeated.status).toBe(204);
    expect(await canSignIn(user.email, FRESH)).toBe(true);
  });

  it('F-44: the first mark committed and only its answer was lost: the retry gets PASSWORD_UNCHANGED and the change is a 204', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);
    let marks = 0;

    const response = await whileWatching(
      (method, path) => {
        if (method !== 'POST' || !path.startsWith('/rest/v1/rpc/mark_password_changed')) {
          return undefined;
        }
        marks += 1;
        return marks === 1 ? LOSE_ANSWER : undefined;
      },
      () => changePassword(jar, { currentPassword: user.password, newPassword: FRESH }),
    );

    // two calls: the first did the work, the second found nothing left to prove
    expect(marks).toBe(2);
    expect(response.status).toBe(204);
    expect(await mustChangePassword(user.id)).toBe(false);
    expect(((await bodyOf(await getSession(jar))) as SessionBody).pendingActions).toEqual([]);
    expect(await canSignIn(user.email, FRESH)).toBe(true);
  });

  it('a half-done change (the database fails after the Auth server stored the password) is 503, says how to finish, and finishing works', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);

    const response = await whileWatching(
      (method, path) =>
        method === 'POST' && path.startsWith('/rest/v1/rpc/mark_password_changed')
          ? Response.json({ message: 'simulated outage' }, { status: 503 })
          : undefined,
      () => changePassword(jar, { currentPassword: user.password, newPassword: FRESH }),
    );

    expect(response.status).toBe(503);
    const body = (await bodyOf(response)) as { code: string; detail: string };
    expect(body.code).toBe('SERVICE_UNAVAILABLE');
    expect(body.detail).toContain('new password as the current password');
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    // the Auth server DID change it, and the account still says "change it"
    expect(await canSignIn(user.email, FRESH)).toBe(true);
    expect(await canSignIn(user.email, user.password)).toBe(false);
    expect(await mustChangePassword(user.id)).toBe(true);
    // the session survived, still pending
    expect(((await bodyOf(await getSession(jar))) as SessionBody).pendingActions).toEqual([
      'CHANGE_PASSWORD',
    ]);

    // the way out the detail names: repeat it with the new password as the current one
    const retry = await changePassword(jar, { currentPassword: FRESH, newPassword: SECOND });
    expect(retry.status).toBe(204);
    expect(await mustChangePassword(user.id)).toBe(false);
    expect(await canSignIn(user.email, SECOND)).toBe(true);
  });
});

describe('E-12: the new password follows the policy', () => {
  it.each([
    ['11 characters', 'a'.repeat(11)],
    ['73 bytes', 'a'.repeat(73)],
    ['74 bytes in 37 two-byte letters', 'é'.repeat(37)],
    ['an empty password', ''],
    [
      '5000 characters (the contract declares no maximum: it is the policy that refuses)',
      'x'.repeat(5000),
    ],
  ])(
    'E-12: %s is 422 WEAK_PASSWORD (contract), not 400, and Auth is not even called',
    async (_label, newPassword) => {
      const user = await clientUser();
      const jar = await sessionJarFor(user);

      const { response, calls } = await whileWatching(undefined, async (traffic) => ({
        response: await changePassword(jar, { currentPassword: user.password, newPassword }),
        calls: traffic.calls,
      }));

      expect(response.status).toBe(422);
      const body = await bodyOf(response);
      expect(body).toMatchObject({ code: 'WEAK_PASSWORD', status: 422 });
      expectToMatchContract('changePassword', 422, body, response);
      // the refusal is local: no sign-in to prove the password, no update, no database call
      expect(
        calls.filter((call) =>
          /\/auth\/v1\/token|PUT \/auth\/v1\/user|mark_password_changed/.test(call),
        ),
      ).toEqual([]);
      expect(await mustChangePassword(user.id)).toBe(true);
      expect(await canSignIn(user.email, user.password)).toBe(true);
    },
  );

  it('E-12: exactly 12 characters is accepted, and the new password opens a session', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);
    const twelve = 'abcdefghijk1';
    expect(twelve).toHaveLength(12);

    const response = await changePassword(jar, {
      currentPassword: user.password,
      newPassword: twelve,
    });

    expect(response.status).toBe(204);
    expect(await canSignIn(user.email, twelve)).toBe(true);
  });

  it('E-12: exactly 72 bytes is accepted (bcrypt reads all of them), and the new password opens a session', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);
    const seventyTwo = `${'é'.repeat(35)}ab`; // 35 two-byte letters + 2 bytes
    expect(new TextEncoder().encode(seventyTwo)).toHaveLength(72);

    const response = await changePassword(jar, {
      currentPassword: user.password,
      newPassword: seventyTwo,
    });

    expect(response.status).toBe(204);
    expect(await canSignIn(user.email, seventyTwo)).toBe(true);
    expect(await canSignIn(user.email, `${seventyTwo.slice(0, -1)}`)).toBe(false);
  });
});

describe('E-13: the new password differs from the current one', () => {
  it('E-13: the same password is 422 PASSWORD_UNCHANGED (contract), and Auth is not even called', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);

    const { response, calls } = await whileWatching(undefined, async (traffic) => ({
      response: await changePassword(jar, {
        currentPassword: user.password,
        newPassword: user.password,
      }),
      calls: traffic.calls,
    }));

    expect(response.status).toBe(422);
    const body = await bodyOf(response);
    expect(body).toMatchObject({ code: 'PASSWORD_UNCHANGED', status: 422 });
    expectToMatchContract('changePassword', 422, body, response);
    expect(
      calls.filter((call) =>
        /\/auth\/v1\/token|PUT \/auth\/v1\/user|mark_password_changed/.test(call),
      ),
    ).toEqual([]);
    expect(await mustChangePassword(user.id)).toBe(true);
  });

  it('E-13: the answer for "same as the current" does not depend on whether the current password is right (no oracle)', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);

    const withWrong = await changePassword(jar, { currentPassword: WRONG, newPassword: WRONG });
    const withRight = await changePassword(jar, {
      currentPassword: user.password,
      newPassword: user.password,
    });

    for (const response of [withWrong, withRight]) {
      expect(response.status).toBe(422);
      expect(await bodyOf(response)).toMatchObject({ code: 'PASSWORD_UNCHANGED' });
    }
  });
});

describe('POST /auth/password: access, input and limits', () => {
  it('SEC-01: without a session it is 401 (contract), and the body is not even looked at', async () => {
    const response = await changePassword(undefined, {
      currentPassword: WRONG,
      newPassword: FRESH,
    });
    expect(response.status).toBe(401);
    const body = await bodyOf(response);
    expect(body).toMatchObject({ code: 'UNAUTHENTICATED' });
    expectToMatchContract('changePassword', 401, body, response);
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it('SEC-06: a bad body is 400 VALIDATION_ERROR (contract), with the unknown field named, and changes nothing', async () => {
    // one user per case: a request spends the user's budget even when its body is refused (the
    // per-user limit runs before validation), and five is all a user has
    const cases: [string, (user: FixtureUser) => Record<string, unknown>][] = [
      [
        'an unknown field',
        (u) => ({ currentPassword: u.password, newPassword: FRESH, userId: 'x' }),
      ],
      ['a missing new password', (u) => ({ currentPassword: u.password })],
      ['a missing current password', () => ({ newPassword: FRESH })],
      ['an empty current password', () => ({ currentPassword: '', newPassword: FRESH })],
      [
        'a non-string new password',
        (u) => ({ currentPassword: u.password, newPassword: 123456789012 }),
      ],
      [
        'a current password of 73 bytes',
        () => ({ currentPassword: 'x'.repeat(73), newPassword: FRESH }),
      ],
      [
        // 37 characters, so within the schema's `maxLength: 72`, but 74 BYTES: the limit is bytes
        'a current password of 74 bytes in 37 two-byte letters',
        () => ({ currentPassword: 'é'.repeat(37), newPassword: FRESH }),
      ],
    ];

    for (const [label, body] of cases) {
      const user = await clientUser();
      const jar = await sessionJarFor(user);

      const response = await changePassword(jar, body(user));

      expect(response.status, label).toBe(400);
      const problem = await bodyOf(response);
      expect(problem, label).toMatchObject({ code: 'VALIDATION_ERROR' });
      expectToMatchContract('changePassword', 400, problem, response);
      expect(await mustChangePassword(user.id), label).toBe(true);
      expect(await canSignIn(user.email, user.password), label).toBe(true);
    }
  });

  it('a current password of exactly 72 bytes (36 two-byte letters) is NOT a 400: the size is bytes, and a wrong one of that size is 422 INVALID_CURRENT_PASSWORD', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);

    const response = await changePassword(jar, {
      currentPassword: 'é'.repeat(36),
      newPassword: FRESH,
    });

    expect(response.status).toBe(422);
    const body = await bodyOf(response);
    expect(body).toMatchObject({ code: 'INVALID_CURRENT_PASSWORD' });
    expectToMatchContract('changePassword', 422, body, response);
  });

  it('SEC-06: the 400 for an unknown field names the field', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);
    const response = await changePassword(jar, {
      currentPassword: user.password,
      newPassword: FRESH,
      role: 'ceo',
    });
    expect(response.status).toBe(400);
    expect(await bodyOf(response)).toMatchObject({
      errors: [{ path: 'body.role', message: 'Unknown field' }],
    });
  });

  it('a 400 never echoes a password', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);
    const response = await changePassword(jar, {
      currentPassword: 'x'.repeat(80),
      newPassword: FRESH,
    });
    expect(response.status).toBe(400);
    const text = JSON.stringify(await bodyOf(response));
    expect(text).not.toContain('x'.repeat(80));
    expect(text).not.toContain(FRESH);
  });

  it('SEC-17: a body over 16 KiB is 413 PAYLOAD_TOO_LARGE (contract)', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);
    const response = await invoke(passwordRoute, {
      method: 'POST',
      path: '/auth/password',
      cookies: jar,
      headers: { 'content-type': 'application/json' },
      rawBody: JSON.stringify({ currentPassword: user.password, newPassword: 'y'.repeat(20_000) }),
    });
    expect(response.status).toBe(413);
    expectToMatchContract('changePassword', 413, await bodyOf(response), response);
  });

  it('a body that is not JSON is 415 UNSUPPORTED_MEDIA_TYPE (contract)', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);
    const response = await invoke(passwordRoute, {
      method: 'POST',
      path: '/auth/password',
      cookies: jar,
      headers: { 'content-type': 'text/plain' },
      rawBody: JSON.stringify({ currentPassword: user.password, newPassword: FRESH }),
    });
    expect(response.status).toBe(415);
    expectToMatchContract('changePassword', 415, await bodyOf(response), response);
  });

  it('SEC-08: a request from another origin is 403 ORIGIN_NOT_ALLOWED (contract), and nothing changes', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);

    const response = await changePassword(
      jar,
      { currentPassword: user.password, newPassword: FRESH },
      { origin: 'https://evil.example' },
    );

    expect(response.status).toBe(403);
    const body = await bodyOf(response);
    expect(body).toMatchObject({ code: 'ORIGIN_NOT_ALLOWED' });
    expectToMatchContract('changePassword', 403, body, response);
    expect(await mustChangePassword(user.id)).toBe(true);
  });

  it('x-rate-limit: 5 attempts per 15 minutes per user, wrong ones included: the 6th is 429 with Retry-After, even with the right password', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);
    const other = await clientUser();
    const otherJar = await sessionJarFor(other);

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const response = await changePassword(jar, { currentPassword: WRONG, newPassword: FRESH });
      expect(response.status, `attempt ${attempt}`).toBe(422);
    }
    const sixth = await changePassword(jar, { currentPassword: user.password, newPassword: FRESH });

    expect(sixth.status).toBe(429);
    const body = await bodyOf(sixth);
    expect(body).toMatchObject({ code: 'RATE_LIMITED' });
    expectToMatchContract('changePassword', 429, body, sixth);
    expect(Number(sixth.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    // the right password was not even tried: nothing changed
    expect(await mustChangePassword(user.id)).toBe(true);
    expect(await canSignIn(user.email, user.password)).toBe(true);
    // the budget is per user: another user is not affected
    const unaffected = await changePassword(otherJar, {
      currentPassword: other.password,
      newPassword: FRESH,
    });
    expect(unaffected.status).toBe(204);
  });

  it('E-21: Auth unreachable while proving the password is 503, never INVALID_CURRENT_PASSWORD, and changes nothing', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);

    const response = await whileWatching(
      (_method, path) =>
        path.startsWith('/auth/v1/token') ? new TypeError('fetch failed') : undefined,
      () => changePassword(jar, { currentPassword: user.password, newPassword: FRESH }),
    );

    expect(response.status).toBe(503);
    expect(await bodyOf(response)).toMatchObject({ code: 'SERVICE_UNAVAILABLE' });
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expect(await canSignIn(user.email, user.password)).toBe(true);
    expect(await mustChangePassword(user.id)).toBe(true);
  });

  it.each([
    ['Auth throttling (429)', 429, 'over_request_rate_limit'],
    ['an Auth server failure (500)', 500, 'unexpected_failure'],
    ['a misconfigured Auth (email provider off)', 422, 'email_provider_disabled'],
  ])(
    '%s while proving the password is 503: a broken service must not look like a wrong password',
    async (_label, status, errorCode) => {
      const user = await clientUser();
      const jar = await sessionJarFor(user);

      const response = await whileWatching(
        (_method, path) =>
          path.startsWith('/auth/v1/token')
            ? Response.json({ code: status, error_code: errorCode, msg: 'simulated' }, { status })
            : undefined,
        () => changePassword(jar, { currentPassword: user.password, newPassword: FRESH }),
      );

      expect(response.status).toBe(503);
      expect(await mustChangePassword(user.id)).toBe(true);
    },
  );
});

// --------------------------------------------------------------------------------- AC-31 ----

type Contract = {
  paths: Record<string, Record<string, { operationId?: string; requestBody?: unknown }>>;
  components: { schemas: Record<string, unknown> };
};

const contract = parse(
  readFileSync(fileURLToPath(new URL('../../contracts/openapi.v1.yaml', import.meta.url)), 'utf8'),
) as Contract;

/** Every property name that can appear in a request body of an operation, `$ref`s followed. */
function requestPropertyNames(node: unknown, seen = new Set<string>()): string[] {
  if (typeof node !== 'object' || node === null) return [];
  if (Array.isArray(node)) return node.flatMap((item) => requestPropertyNames(item, seen));
  const record = node as Record<string, unknown>;
  const ref = record['$ref'];
  if (typeof ref === 'string') {
    const name = /^#\/components\/schemas\/(.+)$/.exec(ref)?.[1];
    if (name === undefined || seen.has(name)) return [];
    seen.add(name);
    return requestPropertyNames(contract.components.schemas[name], seen);
  }
  const properties = record['properties'];
  const own = typeof properties === 'object' && properties !== null ? Object.keys(properties) : [];
  return [...own, ...Object.values(record).flatMap((value) => requestPropertyNames(value, seen))];
}

describe('AC-31: no route of the API creates or promotes a CEO', () => {
  it('AC-31: no operation of the contract accepts a role, app_metadata or user_metadata in its request body', () => {
    const forbidden = /^(role|roles|app_?metadata|user_?metadata|isCeo|is_ceo|ceo)$/i;
    const offenders: string[] = [];
    for (const [path, item] of Object.entries(contract.paths)) {
      for (const [method, operation] of Object.entries(item)) {
        for (const name of requestPropertyNames(operation.requestBody)) {
          if (forbidden.test(name)) offenders.push(`${method.toUpperCase()} ${path}: ${name}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it('AC-31: no operation of the contract is about creating or promoting a CEO', () => {
    for (const [path, item] of Object.entries(contract.paths)) {
      expect(path.toLowerCase(), path).not.toContain('ceo');
      for (const operation of Object.values(item)) {
        expect(operation.operationId?.toLowerCase() ?? '', `${path}`).not.toMatch(/ceo/);
      }
    }
  });

  it('AC-31: every route of src/app/api/v1 is a path of the contract: nothing exists outside it', () => {
    const root = fileURLToPath(new URL('../../src/app/api/v1', import.meta.url));
    const routes = readdirSync(root, { recursive: true, encoding: 'utf8' })
      .filter((file) => file.endsWith('route.ts'))
      .map((file) =>
        `/${file.replace(/\\/g, '/').replace(/\/?route\.ts$/, '')}`.replace(/\[(\w+)\]/g, '{$1}'),
      );

    expect(routes.length).toBeGreaterThan(0);
    const documented = new Set(Object.keys(contract.paths));
    expect(routes.filter((route) => !documented.has(route))).toEqual([]);
    expect(routes.filter((route) => /ceo/i.test(route))).toEqual([]);
  });

  it('AC-31: a client cannot make itself a CEO through the password route: extra role fields are 400, and a good change leaves the role alone', async () => {
    const user = await clientUser();
    const jar = await sessionJarFor(user);

    for (const extra of [
      { role: 'ceo' },
      { app_metadata: { role: 'ceo' } },
      { user_metadata: { role: 'ceo' } },
    ]) {
      const response = await changePassword(jar, {
        currentPassword: user.password,
        newPassword: FRESH,
        ...extra,
      });
      expect(response.status).toBe(400);
    }
    expect(await roleOf(user.id)).toEqual({ profile: 'client', appMetadata: 'client' });

    expect(
      (await changePassword(jar, { currentPassword: user.password, newPassword: FRESH })).status,
    ).toBe(204);
    expect(await roleOf(user.id)).toEqual({ profile: 'client', appMetadata: 'client' });
  });

  it('AC-31: a role written in user_metadata (which the user can edit) changes nothing: the session is a client and /admin-shaped routes stay closed', async () => {
    const user = await clientUser();
    const supabase = publishableClient();
    await supabase.auth.signInWithPassword({ email: user.email, password: user.password });
    const { error } = await supabase.auth.updateUser({ data: { role: 'ceo', is_ceo: true } });
    expect(error).toBeNull();
    // the change of password clears the pendency, so that only the ROLE can close the admin route
    const jar = jarOf((await supabase.auth.getSession()).data.session!);
    expect(
      (await changePassword(jar, { currentPassword: user.password, newPassword: FRESH })).status,
    ).toBe(204);

    const session = await getSession(jar);
    expect(((await bodyOf(session)) as SessionBody).user.role).toBe('client');
    const closed = await probe(adminProbe, jar);
    expect(closed.status).toBe(403);
    expect(await bodyOf(closed)).toMatchObject({ code: 'FORBIDDEN' });
    expect(await roleOf(user.id)).toEqual({ profile: 'client', appMetadata: 'client' });
  });

  it('AC-31: app_metadata cannot be written with the user own token, straight at the Auth server either', async () => {
    const user = await clientUser();
    const supabase = publishableClient();
    const { data } = await supabase.auth.signInWithPassword({
      email: user.email,
      password: user.password,
    });
    await fetch(`${process.env.SUPABASE_URL}/auth/v1/user`, {
      method: 'PUT',
      headers: {
        'content-type': 'application/json',
        apikey: process.env.SUPABASE_PUBLISHABLE_KEY ?? '',
        authorization: `Bearer ${data.session?.access_token ?? ''}`,
      },
      body: JSON.stringify({ app_metadata: { role: 'ceo' } }),
    });

    expect(await roleOf(user.id)).toEqual({ profile: 'client', appMetadata: 'client' });
  });
});
