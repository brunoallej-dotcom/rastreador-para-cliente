// API tests of the client login operations (operationIds `listClientUsers`, `provisionClientUser`,
// `updateClientUser`, `resetClientUserPassword`): the real route modules, the real pipeline and wiring
// (Postgres rate limiter, Supabase resolver), the local Supabase (Auth + PostgREST + the database
// functions), and every response checked against the OpenAPI contract, headers included.
//
// The CEOs are real ones: each changed the temporary password, logged in through the API, enrolled
// TOTP and verified a code, so its cookies are an attested `aal2` session (tests/helpers/mfa.ts). Every
// group of tests that sends many requests has a CEO of its own: the rate limits are per user, and
// provisioning and resetting share ONE counter of 20 per hour.
import { randomUUID } from 'node:crypto';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { POST as loginRoute } from '@/app/api/v1/auth/login/route';
import { GET as sessionRoute } from '@/app/api/v1/auth/session/route';
import type * as LoggerModule from '@/shared/observability/logger';
import { timing } from '@/shared/http/response-floor';
import {
  archiveClientFixture,
  auditOfAccount,
  authUserOf,
  ceoFixture,
  isBannedInAuth,
  listClientUsersViaApi,
  loginsWithEmail,
  profileOf,
  provisionClientUserViaApi,
  provisionOrFail,
  resetClientUserPasswordViaApi,
  uniqueLoginEmail,
  updateClientUserViaApi,
  type ClientUserBody,
  type ClientUserListBody,
  type ProvisionedBody,
} from '../helpers/client-users';
import { updateClientViaApi } from '../helpers/clients';
import { expectToMatchContract } from '../helpers/contract';
import { agePasswordBaseline } from '../helpers/db';
import {
  adminClient,
  ceoAal2Client,
  createClient,
  createClientUser,
  createCeo,
  publishableClient,
  type FixtureUser,
} from '../helpers/fixtures';
import {
  bodyOf,
  invoke,
  spyOnSupabaseFetch,
  withoutRequestId,
  type CookieStore,
} from '../helpers/http';
import { completeFirstAccess, loginViaApi, type CeoWithMfa } from '../helpers/mfa';
import {
  canSignIn,
  changePassword,
  LOSE_ANSWER,
  sessionJarFor,
  whileWatching,
} from '../helpers/password';

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

const UNKNOWN_CLIENT_ID = '00000000-0000-4000-8000-00000000dead';
const UNKNOWN_USER_ID = '00000000-0000-4000-8000-00000000beef';
const TEMPORARY_PASSWORD_LENGTH = 20;
const BODY_LIMIT_BYTES = 16 * 1024;
const ADMIN_LIMIT_PER_HOUR = 20;

/** A refused login waits for its floor (400 ms): the tests that refuse logins do not wait for real. */
beforeEach(() => {
  vi.spyOn(timing, 'sleep').mockResolvedValue(undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** Parses the body, checks it against the contract (headers too) and returns it. */
async function expectContract<T = unknown>(operationId: string, response: Response): Promise<T> {
  const text = await response.clone().text();
  const body: unknown = text === '' ? undefined : JSON.parse(text);
  expectToMatchContract(operationId, response.status, body, response);
  return body as T;
}

type Problem = { code: string; detail?: string; errors?: { path: string; message: string }[] };

/** 503 `SERVICE_UNAVAILABLE` with a `Retry-After` of at least a second, as the contract documents. */
async function expectUnavailable(operationId: string, response: Response): Promise<Problem> {
  const body = await expectContract<Problem>(operationId, response);

  expect(response.status).toBe(503);
  expect(body.code).toBe('SERVICE_UNAVAILABLE');
  expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
  return body;
}

/** `POST /auth/login` through the real route: the response, not a fixture that insists on a 200. */
const loginResponse = (credentials: { email: string; password: string }) =>
  invoke(loginRoute, { method: 'POST', path: '/auth/login', body: credentials });

/** `GET /auth/session` with a cookie jar: how a test asks "is this session still good?". */
const sessionStatus = async (cookies: CookieStore) =>
  (await invoke(sessionRoute, { path: '/auth/session', cookies })).status;

const newPassword = () => `Next-${randomUUID()}`;

/**
 * What the CEO's operations wrote to the audit trail of an account: the trail without the
 * `account.password_changed` of the first access that the fixture completes (`completeFirstAccess`).
 */
async function managementTrail(userId: string) {
  return (await auditOfAccount(userId)).filter((row) => row.action !== 'account.password_changed');
}

/**
 * A client with one login that already changed its temporary password and is signed in. The session is
 * opened straight at Auth (`sessionJarFor`): a test that is not about the login has no reason to go
 * through the login route (its floor, its rate limits, the pipeline), and a file this size signs in a
 * lot (the global budget of 300 per 5 minutes is cleared before every file, but not within one). The
 * tests that ARE about the login call the route.
 */
async function tenantWithSignedInLogin(label = 'Cliente') {
  const tenant = await createClient(`${label} ${randomUUID().slice(0, 8)}`);
  const login = await completeFirstAccess(await createClientUser({ clientId: tenant.id }));
  const cookies = await sessionJarFor(login);
  return { tenant, login, cookies };
}

/**
 * What a session opened straight at Auth with these credentials is worth to the API, with no spend of
 * the login route's budget: `'refused'` when Auth itself refuses the sign-in (wrong password, banned),
 * otherwise the status of `GET /auth/session` (200, or 401 when the database gives the user no
 * principal: disabled, or a temporary password past its 72 h).
 */
async function statusOfSignIn(email: string, password: string): Promise<number | 'refused'> {
  let jar: CookieStore;
  try {
    jar = await sessionJarFor({ email, password });
  } catch {
    return 'refused';
  }
  return sessionStatus(jar);
}

/** Everything the four operations answer to a caller that must be refused, in one list. */
async function callAll(cookies: CookieStore | undefined, clientId: string, userId: string) {
  return [
    ['listClientUsers', await listClientUsersViaApi(cookies, clientId)],
    [
      'provisionClientUser',
      await provisionClientUserViaApi(cookies, clientId, {
        email: uniqueLoginEmail('negado'),
        displayName: 'Negado',
      }),
    ],
    [
      'updateClientUser',
      await updateClientUserViaApi(cookies, clientId, userId, { disabled: true }),
    ],
    ['resetClientUserPassword', await resetClientUserPasswordViaApi(cookies, clientId, userId)],
  ] as const;
}

describe('POST /admin/clients/{clientId}/users (provisionClientUser)', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await ceoFixture('provisioning');
  });

  it('AC-12: a CEO provisions a login: 201 with the login and a temporary password of 20 characters, returned once', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('maria');
    logged.lines.length = 0;

    const response = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email,
      displayName: '  Maria Souza  ',
    });
    const body = await expectContract<ProvisionedBody>('provisionClientUser', response);

    expect(response.status).toBe(201);
    expect(body.temporaryPassword).toHaveLength(TEMPORARY_PASSWORD_LENGTH);
    expect(body.user).toMatchObject({
      email,
      displayName: 'Maria Souza',
      disabled: false,
      mustChangePassword: true,
      lastSignInAt: null,
    });
    // the password is a secret that only this response carries
    expect(response.headers.get('cache-control')).toBe('no-store');
    const everythingLogged = logged.lines.join('\n');
    expect(everythingLogged).not.toContain(body.temporaryPassword);
    expect(everythingLogged.toLowerCase()).not.toContain(email);
    expect(events('identity.client_user.provisioned')).toHaveLength(1);
    // the 201 shows the login as the list will show it, and the list never shows the password
    const listed = await expectContract<ClientUserListBody>(
      'listClientUsers',
      await listClientUsersViaApi(ceo.cookies, tenant.id),
    );
    expect(listed.items).toEqual([body.user]);
    expect(JSON.stringify(listed)).not.toContain(body.temporaryPassword);
  });

  it('AC-12: the login is a client of the client in the PATH: profile, role and app_metadata, with the CHANGE_PASSWORD pending', async () => {
    const tenant = await createClient();

    const created = await provisionOrFail(ceo.cookies, tenant.id, { displayName: 'Ana' });

    expect(await profileOf(created.user.id)).toMatchObject({
      role: 'client',
      client_id: tenant.id,
      display_name: 'Ana',
      must_change_password: true,
      disabled_at: null,
    });
    const authUser = await authUserOf(created.user.id);
    expect(authUser?.app_metadata).toMatchObject({
      role: 'client',
      client_id: tenant.id,
      display_name: 'Ana',
    });
    // what the user could write about itself is never read, and nothing of the tenant is in it
    expect(authUser?.user_metadata).not.toHaveProperty('role');
    expect(authUser?.user_metadata).not.toHaveProperty('client_id');
  });

  it('AC-12: the user signs in with the temporary password, has CHANGE_PASSWORD pending, and changing it proves the baseline', async () => {
    const tenant = await createClient();
    const created = await provisionOrFail(ceo.cookies, tenant.id);

    const jar = await loginViaApi({
      email: created.user.email,
      password: created.temporaryPassword,
    });
    const session = await invoke(sessionRoute, { path: '/auth/session', cookies: jar });
    expect(await bodyOf(session)).toMatchObject({
      user: { role: 'client' },
      client: { id: tenant.id },
      pendingActions: ['CHANGE_PASSWORD'],
    });

    const changed = await changePassword(jar, {
      currentPassword: created.temporaryPassword,
      newPassword: newPassword(),
    });
    expect(changed.status).toBe(204);
    const listed = await expectContract<ClientUserListBody>(
      'listClientUsers',
      await listClientUsersViaApi(ceo.cookies, tenant.id),
    );
    expect(listed.items[0]).toMatchObject({ mustChangePassword: false });
    expect(listed.items[0]?.lastSignInAt).not.toBeNull();
  });

  it('AC-12: the temporary password of two logins is never the same', async () => {
    const tenant = await createClient();

    const first = await provisionOrFail(ceo.cookies, tenant.id);
    const second = await provisionOrFail(ceo.cookies, tenant.id);

    expect(first.temporaryPassword).not.toBe(second.temporaryPassword);
  });

  it('SEC-16: provisioning is audited in the same transaction, with the CEO, the request id and no PII', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('audit');

    const response = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email,
      displayName: 'Auditada',
    });
    const body = await expectContract<ProvisionedBody>('provisionClientUser', response);

    const trail = await auditOfAccount(body.user.id);
    expect(trail).toHaveLength(1);
    expect(trail[0]).toMatchObject({
      action: 'account.provisioned',
      actor_id: ceo.ceo.id,
      actor_role: 'ceo',
      resource_type: 'account',
      resource_id: body.user.id,
      client_id: tenant.id,
      request_id: response.headers.get('x-request-id'),
    });
    expect(JSON.stringify(trail)).not.toContain(email);
    expect(JSON.stringify(trail)).not.toContain(body.temporaryPassword);
  });

  it('E-11: an e-mail with capitals and spaces is stored normalized, and every spelling of it is the same account', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('normal');

    const created = await provisionOrFail(ceo.cookies, tenant.id, {
      email: `  ${email.toUpperCase()} `,
    });
    const again = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email,
      displayName: 'Outra',
    });
    const problem = await expectContract<Problem>('provisionClientUser', again);

    expect(created.user.email).toBe(email);
    expect([again.status, problem.code]).toEqual([409, 'EMAIL_ALREADY_REGISTERED']);
    expect(await loginsWithEmail(email)).toBe(1);
  });

  it('E-17: an e-mail that already has an account is 409 EMAIL_ALREADY_REGISTERED, for a login of any client and for a CEO, and names nobody', async () => {
    const tenant = await createClient();
    const other = await createClient();
    const otherLogin = await createClientUser({ clientId: other.id });
    const own = await provisionOrFail(ceo.cookies, tenant.id);

    for (const email of [own.user.email, otherLogin.email, ceo.ceo.email]) {
      const response = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
        email,
        displayName: 'Duplicada',
      });
      const body = await expectContract<Problem>('provisionClientUser', response);

      expect([response.status, body.code]).toEqual([409, 'EMAIL_ALREADY_REGISTERED']);
      const text = JSON.stringify(body);
      expect(text).not.toContain(otherLogin.id);
      expect(text).not.toContain(other.id);
      expect(text).not.toContain(own.user.id);
    }
    expect(await loginsWithEmail(otherLogin.email)).toBe(1);
    expect(await loginsWithEmail(ceo.ceo.email)).toBe(1);
  });

  it('E-16: a client archived through the API gets no new login: 422 CLIENT_ARCHIVED, nothing is created or audited', async () => {
    const tenant = await createClient();
    const archive = await updateClientViaApi(ceo.cookies, tenant.id, { archived: true });
    expect(archive.status).toBe(200);
    const email = uniqueLoginEmail('arquivado');

    const response = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email,
      displayName: 'Arquivado',
    });
    const body = await expectContract<Problem>('provisionClientUser', response);

    expect([response.status, body.code]).toEqual([422, 'CLIENT_ARCHIVED']);
    expect(await loginsWithEmail(email)).toBe(0);
  });

  it('E-16: a client archived between the check and the creation is still 422 CLIENT_ARCHIVED (the trigger of the profile decides; F-58)', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('corrida');
    const realFetch = globalThis.fetch;
    let archived = false;
    // the archive happens right before the Auth server would create the account: the use case has
    // already seen an active client
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input instanceof Request ? input.url : input);
      const method = (init?.method ?? 'GET').toUpperCase();
      if (!archived && method === 'POST' && url.endsWith('/auth/v1/admin/users')) {
        archived = true;
        await archiveClientFixture(tenant.id);
      }
      return realFetch(input, init);
    });

    const response = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email,
      displayName: 'Corrida',
    });
    vi.restoreAllMocks();
    const body = await expectContract<Problem>('provisionClientUser', response);

    expect(archived).toBe(true);
    expect([response.status, body.code]).toEqual([422, 'CLIENT_ARCHIVED']);
    expect(await loginsWithEmail(email)).toBe(0);
  });

  it('SEC-03: a client that does not exist is 404', async () => {
    const response = await provisionClientUserViaApi(ceo.cookies, UNKNOWN_CLIENT_ID, {
      email: uniqueLoginEmail('fantasma'),
      displayName: 'Fantasma',
    });
    const body = await expectContract<Problem>('provisionClientUser', response);

    expect([response.status, body.code]).toEqual([404, 'NOT_FOUND']);
  });
});

describe('the limit of 10 logins per client', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await ceoFixture('limit of 10');
  });

  async function clientWithLogins(count: number) {
    const tenant = await createClient();
    for (let index = 0; index < count; index += 1) {
      await createClientUser({ clientId: tenant.id });
    }
    return tenant;
  }

  it('E-18: the tenth login is accepted and the eleventh is 422 USER_LIMIT_REACHED, with nothing created', async () => {
    const tenant = await clientWithLogins(9);
    const tenth = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email: uniqueLoginEmail('decimo'),
      displayName: 'Décimo',
    });
    await expectContract('provisionClientUser', tenth);
    expect(tenth.status).toBe(201);
    const email = uniqueLoginEmail('onze');

    const eleventh = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email,
      displayName: 'Onze',
    });
    const body = await expectContract<Problem>('provisionClientUser', eleventh);

    expect([eleventh.status, body.code]).toEqual([422, 'USER_LIMIT_REACHED']);
    expect(await loginsWithEmail(email)).toBe(0);
    const listed = await expectContract<ClientUserListBody>(
      'listClientUsers',
      await listClientUsersViaApi(ceo.cookies, tenant.id),
    );
    expect(listed.items).toHaveLength(10);
  });

  it('E-18: a disabled login still counts toward the limit', async () => {
    const tenant = await clientWithLogins(10);
    const [first] = (
      await expectContract<ClientUserListBody>(
        'listClientUsers',
        await listClientUsersViaApi(ceo.cookies, tenant.id),
      )
    ).items;
    const disabled = await updateClientUserViaApi(ceo.cookies, tenant.id, first?.id ?? '', {
      disabled: true,
    });
    expect(disabled.status).toBe(200);

    const response = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email: uniqueLoginEmail('extra'),
      displayName: 'Extra',
    });
    const body = await expectContract<Problem>('provisionClientUser', response);

    expect([response.status, body.code]).toEqual([422, 'USER_LIMIT_REACHED']);
  });

  it('E-18: four requests racing for the last two places: exactly two are 201 and two are 422 USER_LIMIT_REACHED, never a 503 (E-52)', async () => {
    const tenant = await clientWithLogins(8);

    const responses = await Promise.all(
      Array.from({ length: 4 }, (_, index) =>
        provisionClientUserViaApi(ceo.cookies, tenant.id, {
          email: uniqueLoginEmail(`disputa${index}`),
          displayName: `Disputa ${index}`,
        }),
      ),
    );

    for (const response of responses) await expectContract('provisionClientUser', response);
    expect(responses.map((response) => response.status).sort()).toEqual([201, 201, 422, 422]);
    const listed = await expectContract<ClientUserListBody>(
      'listClientUsers',
      await listClientUsersViaApi(ceo.cookies, tenant.id),
    );
    expect(listed.items).toHaveLength(10);
  });
});

describe('PATCH /admin/clients/{clientId}/users/{userId} (updateClientUser)', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await ceoFixture('update');
  });

  it('AC-13: disabling a login: the next request of that user is 401, its login fails and the Auth server bans it', async () => {
    const { tenant, login, cookies } = await tenantWithSignedInLogin();
    expect(await sessionStatus(cookies)).toBe(200);

    const response = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
      disabled: true,
    });
    const body = await expectContract<ClientUserBody>('updateClientUser', response);

    expect(response.status).toBe(200);
    expect(body).toMatchObject({ id: login.id, disabled: true });
    expect(await sessionStatus(cookies)).toBe(401);
    const refused = await loginResponse({ email: login.email, password: login.password });
    expect(refused.status).toBe(401);
    expect(await refused.json()).toMatchObject({ code: 'INVALID_CREDENTIALS' });
    expect(await isBannedInAuth(login.id)).toBe(true);
    expect(await profileOf(login.id)).toMatchObject({ disabled_at: expect.any(String) as string });
  });

  it('AC-13: re-enabling the login brings the sign-in back, and lifts the ban in the Auth server', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { disabled: true });

    const response = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
      disabled: false,
    });
    const body = await expectContract<ClientUserBody>('updateClientUser', response);

    expect(body).toMatchObject({ id: login.id, disabled: false });
    expect(await isBannedInAuth(login.id)).toBe(false);
    const signedIn = await loginResponse({ email: login.email, password: login.password });
    expect(signedIn.status).toBe(200);
    expect(await signedIn.json()).toMatchObject({ pendingActions: [] });
  });

  it('AC-13: disabling and enabling are audited once each, with the CEO and the request id, and repeating them is a no-op', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();

    const first = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
      disabled: true,
    });
    const again = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
      disabled: true,
    });
    const enable = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
      disabled: false,
    });

    expect([first.status, again.status, enable.status]).toEqual([200, 200, 200]);
    const trail = await managementTrail(login.id);
    // the database events are written once each; every write to the Auth server records its intent first
    // (F-92 b): the ban of each disable, and the unban of the enable
    expect(trail.map((row) => row.action)).toEqual([
      'account.disabled',
      'account.ban_intent',
      'account.ban_intent',
      'account.unban_intent',
      'account.enabled',
    ]);
    expect(trail[0]).toMatchObject({
      actor_id: ceo.ceo.id,
      actor_role: 'ceo',
      client_id: tenant.id,
      request_id: first.headers.get('x-request-id'),
    });
    expect(JSON.stringify(trail)).not.toContain(login.email);
  });

  it('AC-13: renames a login, with the display name normalized, and audits it as account.updated', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    const name = `  Jos${'e'}${String.fromCodePoint(0x0301)} Silva `;

    const response = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
      displayName: name,
    });
    const body = await expectContract<ClientUserBody>('updateClientUser', response);

    expect(body.displayName).toBe(`Jos${String.fromCodePoint(0x00e9)} Silva`);
    expect(body.disabled).toBe(false);
    expect((await profileOf(login.id))?.display_name).toBe(body.displayName);
    expect((await managementTrail(login.id)).map((row) => row.action)).toEqual(['account.updated']);
  });

  it('AC-13: a rename and a disable in one request both apply', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();

    const response = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
      displayName: 'Nome Novo',
      disabled: true,
    });
    const body = await expectContract<ClientUserBody>('updateClientUser', response);

    expect(body).toMatchObject({ displayName: 'Nome Novo', disabled: true });
    expect(await isBannedInAuth(login.id)).toBe(true);
  });

  it('E-24: a ban that fails after the database disabled the login is still 200, the login is blocked, the failure is logged at error; repeating the PATCH bans it', async () => {
    const { tenant, login, cookies } = await tenantWithSignedInLogin();
    logged.lines.length = 0;
    // the only call to the Auth admin API of this PATCH is the ban (PUT .../admin/users/{id})
    const spy = spyOnSupabaseFetch((url) =>
      url.includes('/auth/v1/admin/users/') ? new TypeError('fetch failed') : undefined,
    );
    let response: Response;
    try {
      response = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
        disabled: true,
      });
    } finally {
      spy.restore();
    }
    const body = await expectContract<ClientUserBody>('updateClientUser', response);

    expect(response.status).toBe(200);
    expect(body.disabled).toBe(true);
    // the database blocks the account: the session is gone and the sign-in is refused...
    expect(await sessionStatus(cookies)).toBe(401);
    expect(await statusOfSignIn(login.email, login.password)).toBe(401);
    // ...even though the Auth server was not told to ban it
    expect(await isBannedInAuth(login.id)).toBe(false);
    const [failure] = events('identity.client_user.ban_failed');
    expect(failure).toMatchObject({
      level: 'error',
      targetUserId: login.id,
      clientId: tenant.id,
      reason: 'unavailable',
    });
    expect(logged.lines.join('\n')).not.toContain(login.email);

    const repeated = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
      disabled: true,
    });
    expect(repeated.status).toBe(200);
    expect(await isBannedInAuth(login.id)).toBe(true);
    // the repeat changed no state in the database: still one `account.disabled`; each try of the ban wrote
    // its own intent (F-92 b)
    expect((await managementTrail(login.id)).map((row) => row.action)).toEqual([
      'account.disabled',
      'account.ban_intent',
      'account.ban_intent',
    ]);
  });

  it('F-94: an unexpected answer of the Auth server to the ban is still 200 (the database blocks the login) and is logged at error as `unexpected`', async () => {
    const { tenant, login, cookies } = await tenantWithSignedInLogin();
    logged.lines.length = 0;
    const spy = spyOnSupabaseFetch((url) =>
      url.includes('/auth/v1/admin/users/')
        ? Response.json(
            { code: 400, error_code: 'validation_failed', msg: login.email },
            { status: 400 },
          )
        : undefined,
    );
    let response: Response;
    try {
      response = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
        disabled: true,
      });
    } finally {
      spy.restore();
    }

    const body = await expectContract<ClientUserBody>('updateClientUser', response);

    expect([response.status, body.disabled]).toEqual([200, true]);
    expect(await sessionStatus(cookies)).toBe(401);
    expect(events('identity.client_user.ban_failed')[0]).toMatchObject({
      level: 'error',
      reason: 'unexpected',
    });
    // what the Auth server said (it echoed the e-mail) is nowhere in the log
    expect(logged.lines.join('\n')).not.toContain(login.email);
  });

  it('E-56: the database step of a re-enable fails after the unban: 503, the ban is put back (the login stays blocked in Auth AND in the database) and it is logged at error', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { disabled: true });
    expect(await isBannedInAuth(login.id)).toBe(true);
    logged.lines.length = 0;
    const spy = spyOnSupabaseFetch((url) =>
      url.includes('/rest/v1/rpc/set_account_disabled') ? new TypeError('fetch failed') : undefined,
    );
    let response: Response;
    try {
      response = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
        disabled: false,
      });
    } finally {
      spy.restore();
    }

    const problem = await expectContract<Problem>('updateClientUser', response);

    expect([response.status, problem.code]).toEqual([503, 'SERVICE_UNAVAILABLE']);
    expect((await profileOf(login.id))?.disabled_at).not.toBeNull();
    expect(await isBannedInAuth(login.id)).toBe(true);
    expect(events('identity.client_user.reban_after_failed_enable')[0]).toMatchObject({
      level: 'error',
      rebanned: true,
      targetUserId: login.id,
    });
    // and repeating the enable works
    const repeated = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
      disabled: false,
    });
    expect(repeated.status).toBe(200);
    expect(await isBannedInAuth(login.id)).toBe(false);
  });

  it('F-92a, M2: a login enabled in the database but still banned in Auth (the worst interleaving of two CEOs) is refused at sign-in; a bare enable is a no-op, and a disable followed by an enable repairs it', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    await adminClient().auth.admin.updateUserById(login.id, { ban_duration: '876000h' });
    expect(await statusOfSignIn(login.email, login.password)).toBe('refused');
    const patch = (disabled: boolean) =>
      updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { disabled });

    const bare = await patch(false);

    await expectContract('updateClientUser', bare);
    expect(bare.status).toBe(200);
    expect(await statusOfSignIn(login.email, login.password)).toBe('refused');
    for (const response of [await patch(true), await patch(false)]) {
      await expectContract('updateClientUser', response);
      expect(response.status).toBe(200);
    }
    expect(await statusOfSignIn(login.email, login.password)).toBe(200);
  });

  it('M2: an enable that fails on a login that is already enabled does not ban it', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    const spy = spyOnSupabaseFetch((url) =>
      url.includes('/rest/v1/rpc/set_account_disabled') ? new TypeError('fetch failed') : undefined,
    );
    let response: Response;
    try {
      response = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
        disabled: false,
      });
    } finally {
      spy.restore();
    }

    await expectContract('updateClientUser', response);

    // nothing was called that could fail: the login was active and it stays active and unbanned
    expect(response.status).toBe(200);
    expect(await isBannedInAuth(login.id)).toBe(false);
    expect(await statusOfSignIn(login.email, login.password)).toBe(200);
  });

  it('no-op: renaming to the name the login already has writes no second account.updated', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    const rename = (displayName: string) =>
      updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { displayName });

    const first = await rename('Nome Único');
    const same = await rename('Nome Único');
    const other = await rename('Outro Nome');

    for (const response of [first, same, other]) {
      await expectContract('updateClientUser', response);
      expect(response.status).toBe(200);
    }
    expect((await managementTrail(login.id)).map((row) => row.action)).toEqual([
      'account.updated',
      'account.updated',
    ]);
  });

  it('E-19: a user that does not belong to the client of the path is 404, identical for another client, a CEO and an unknown id, and nothing changes', async () => {
    const a = await tenantWithSignedInLogin('A');
    const b = await tenantWithSignedInLogin('B');

    const attempts = await Promise.all([
      updateClientUserViaApi(ceo.cookies, a.tenant.id, b.login.id, { disabled: true }),
      updateClientUserViaApi(ceo.cookies, a.tenant.id, ceo.ceo.id, { disabled: true }),
      updateClientUserViaApi(ceo.cookies, a.tenant.id, UNKNOWN_USER_ID, { disabled: true }),
      updateClientUserViaApi(ceo.cookies, UNKNOWN_CLIENT_ID, a.login.id, { disabled: true }),
    ]);

    const bodies: Problem[] = [];
    for (const response of attempts) {
      bodies.push(await expectContract<Problem>('updateClientUser', response));
      expect(response.status).toBe(404);
    }
    expect(bodies.map((body) => body.code)).toEqual(Array<string>(4).fill('NOT_FOUND'));
    const [first, ...rest] = bodies.map((body) => withoutRequestId(body));
    for (const body of rest) expect(body).toEqual(first);
    expect(await profileOf(b.login.id)).toMatchObject({ disabled_at: null });
    expect(await profileOf(ceo.ceo.id)).toMatchObject({ disabled_at: null, role: 'ceo' });
    expect(await profileOf(a.login.id)).toMatchObject({ disabled_at: null });
    expect(await sessionStatus(b.cookies)).toBe(200);
    expect(await isBannedInAuth(b.login.id)).toBe(false);
  });

  it('AC-23: an e-mail, a role, a clientId or any unknown field is 400 and nothing is written', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    const before = await profileOf(login.id);

    for (const extra of [
      { email: uniqueLoginEmail('troca') },
      { role: 'ceo' },
      { clientId: UNKNOWN_CLIENT_ID },
      { password: newPassword() },
    ]) {
      const response = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
        displayName: 'Mudou',
        ...extra,
      });
      const body = await expectContract<Problem>('updateClientUser', response);
      expect([response.status, body.code]).toEqual([400, 'VALIDATION_ERROR']);
    }
    expect(await profileOf(login.id)).toEqual(before);
  });

  it('AC-23: an empty body, a bad display name and a malformed id are 400', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();

    const responses = await Promise.all([
      updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {}),
      updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { disabled: 'yes' }),
      updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { displayName: '   ' }),
      updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { displayName: 'a'.repeat(121) }),
      updateClientUserViaApi(ceo.cookies, tenant.id, 'not-a-uuid', { disabled: true }),
      updateClientUserViaApi(ceo.cookies, 'not-a-uuid', login.id, { disabled: true }),
    ]);

    for (const response of responses) {
      const body = await expectContract<Problem>('updateClientUser', response);
      expect([response.status, body.code]).toEqual([400, 'VALIDATION_ERROR']);
    }
  });

  it('AC-23: a foreign Origin, a wrong Content-Type and a body over 16 KiB are refused before anything is written', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();

    const foreign = await updateClientUserViaApi(
      ceo.cookies,
      tenant.id,
      login.id,
      { disabled: true },
      { origin: 'https://evil.example' },
    );
    const wrongType = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, undefined, {
      rawBody: '{"disabled":true}',
      headers: { 'content-type': 'text/plain' },
    });
    const huge = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
      displayName: 'a'.repeat(BODY_LIMIT_BYTES + 1),
    });

    const codes: string[] = [];
    for (const response of [foreign, wrongType, huge]) {
      codes.push((await expectContract<Problem>('updateClientUser', response)).code);
    }
    expect([foreign.status, wrongType.status, huge.status]).toEqual([403, 415, 413]);
    expect(codes).toEqual(['ORIGIN_NOT_ALLOWED', 'UNSUPPORTED_MEDIA_TYPE', 'PAYLOAD_TOO_LARGE']);
    expect(await profileOf(login.id)).toMatchObject({ disabled_at: null });
  });
});

describe('POST /admin/clients/{clientId}/users/{userId}/password-reset (resetClientUserPassword)', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await ceoFixture('password reset');
  });

  it('AC-14: a reset gives a new temporary password, makes the user change it, and revokes every session', async () => {
    const { tenant, login, cookies } = await tenantWithSignedInLogin();
    const second = await sessionJarFor(login);
    expect([await sessionStatus(cookies), await sessionStatus(second)]).toEqual([200, 200]);
    logged.lines.length = 0;

    const response = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    const body = await expectContract<{ temporaryPassword: string }>(
      'resetClientUserPassword',
      response,
    );

    expect(response.status).toBe(200);
    expect(Object.keys(body)).toEqual(['temporaryPassword']);
    expect(body.temporaryPassword).toHaveLength(TEMPORARY_PASSWORD_LENGTH);
    expect(body.temporaryPassword).not.toBe(login.password);
    expect(response.headers.get('cache-control')).toBe('no-store');
    // sessions revoked: both old cookies are dead
    expect([await sessionStatus(cookies), await sessionStatus(second)]).toEqual([401, 401]);
    // the old password is gone, the new one opens a session with CHANGE_PASSWORD pending
    expect(await canSignIn(login.email, login.password)).toBe(false);
    const signedIn = await loginResponse({
      email: login.email,
      password: body.temporaryPassword,
    });
    expect(signedIn.status).toBe(200);
    expect(await signedIn.json()).toMatchObject({ pendingActions: ['CHANGE_PASSWORD'] });
    const listed = await expectContract<ClientUserListBody>(
      'listClientUsers',
      await listClientUsersViaApi(ceo.cookies, tenant.id),
    );
    expect(listed.items[0]).toMatchObject({ id: login.id, mustChangePassword: true });
    // SEC-16: the password is in no log line
    expect(logged.lines.join('\n')).not.toContain(body.temporaryPassword);
    expect(events('identity.client_user.password_reset')).toHaveLength(1);
  });

  it('AC-14: the reset is audited as account.password_reset, with the CEO and the request id', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();

    const response = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    await expectContract('resetClientUserPassword', response);

    const trail = await managementTrail(login.id);
    // the login was made by a fixture, so it never had `account.provisioned`: the reset registers it, late
    // (F-93), after the intent of the Auth write (F-92 b) and before its own event
    expect(trail.map((row) => row.action)).toEqual([
      'account.password_set_intent',
      'account.provisioned',
      'account.password_reset',
    ]);
    for (const row of trail) {
      expect(row).toMatchObject({
        actor_id: ceo.ceo.id,
        actor_role: 'ceo',
        client_id: tenant.id,
        request_id: response.headers.get('x-request-id'),
      });
    }
    expect(trail[0]?.metadata).toEqual({ action: 'set_password' });
    expect(trail[1]?.metadata).toEqual({ late: true });
    expect(JSON.stringify(trail)).not.toContain(login.email);
  });

  it('AC-14: the user changes the temporary password of a reset with POST /auth/password: the baseline is the new hash (ADR 0007)', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    const reset = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    const { temporaryPassword } = await expectContract<{ temporaryPassword: string }>(
      'resetClientUserPassword',
      reset,
    );
    const jar = await sessionJarFor({ email: login.email, password: temporaryPassword });

    const changed = await changePassword(jar, {
      currentPassword: temporaryPassword,
      newPassword: newPassword(),
    });

    expect(changed.status).toBe(204);
    const listed = await expectContract<ClientUserListBody>(
      'listClientUsers',
      await listClientUsersViaApi(ceo.cookies, tenant.id),
    );
    expect(listed.items[0]).toMatchObject({ mustChangePassword: false });
  });

  it('F-41: a temporary password older than 72 h locks the login out (E-34), and a reset renews the 72 h (E-35)', async () => {
    const tenant = await createClient();
    const created = await provisionOrFail(ceo.cookies, tenant.id);
    await agePasswordBaseline(created.user.id, 100);
    // Auth does not know the 72 h: the sign-in opens a session and the database gives it no principal
    expect(await statusOfSignIn(created.user.email, created.temporaryPassword)).toBe(401);

    const response = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, created.user.id);
    const body = await expectContract<{ temporaryPassword: string }>(
      'resetClientUserPassword',
      response,
    );

    const renewed = await loginResponse({
      email: created.user.email,
      password: body.temporaryPassword,
    });
    expect(renewed.status).toBe(200);
    expect(await renewed.json()).toMatchObject({ pendingActions: ['CHANGE_PASSWORD'] });
  });

  it('E-19: a user that does not belong to the client of the path is 404, identical for another client, a CEO and an unknown id, and no password changes', async () => {
    const a = await tenantWithSignedInLogin('A');
    const b = await tenantWithSignedInLogin('B');

    const attempts = await Promise.all([
      resetClientUserPasswordViaApi(ceo.cookies, a.tenant.id, b.login.id),
      resetClientUserPasswordViaApi(ceo.cookies, a.tenant.id, ceo.ceo.id),
      resetClientUserPasswordViaApi(ceo.cookies, a.tenant.id, UNKNOWN_USER_ID),
      resetClientUserPasswordViaApi(ceo.cookies, UNKNOWN_CLIENT_ID, a.login.id),
    ]);

    const bodies: Problem[] = [];
    for (const response of attempts) {
      bodies.push(await expectContract<Problem>('resetClientUserPassword', response));
      expect(response.status).toBe(404);
    }
    const [first, ...rest] = bodies.map((body) => withoutRequestId(body));
    for (const body of rest) expect(body).toEqual(first);
    // nobody's password changed and nobody's session ended
    expect(await canSignIn(b.login.email, b.login.password)).toBe(true);
    expect(await canSignIn(a.login.email, a.login.password)).toBe(true);
    expect(await canSignIn(ceo.ceo.email, ceo.ceo.password)).toBe(true);
    expect(await sessionStatus(b.cookies)).toBe(200);
    expect(await sessionStatus(a.cookies)).toBe(200);
  });

  it('a body (and a Content-Type) is ignored: the route has none, so a refusal of the user is a 404, not a 415', async () => {
    const response = await resetClientUserPasswordViaApi(
      ceo.cookies,
      UNKNOWN_CLIENT_ID,
      UNKNOWN_USER_ID,
      { rawBody: 'not json at all', headers: { 'content-type': 'text/plain' } },
    );
    const body = await expectContract<Problem>('resetClientUserPassword', response);

    expect([response.status, body.code]).toEqual([404, 'NOT_FOUND']);
  });

  it('SEC-04: a foreign Origin is 403 ORIGIN_NOT_ALLOWED and nothing changes', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();

    const response = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id, {
      origin: 'https://evil.example',
    });
    const body = await expectContract<Problem>('resetClientUserPassword', response);

    expect([response.status, body.code]).toEqual([403, 'ORIGIN_NOT_ALLOWED']);
    expect(await canSignIn(login.email, login.password)).toBe(true);
  });
});

describe('the leftovers of a failure in the middle (E-23, E-50, E-51)', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await ceoFixture('failures in the middle');
  });

  /** Makes the requests whose URL holds `part` fail the way a dead network does. */
  const failing = (part: string) =>
    spyOnSupabaseFetch((url) => (url.includes(part) ? new TypeError('fetch failed') : undefined));

  it('E-23: the record of account.provisioned fails after createUser: the account is deleted, the answer is 503, the failure is logged at error and no password is shown', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('compensa');
    logged.lines.length = 0;
    const spy = failing('/rest/v1/rpc/record_account_provisioned');
    let response: Response;
    try {
      response = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
        email,
        displayName: 'Compensada',
      });
    } finally {
      spy.restore();
    }

    const body = await expectUnavailable('provisionClientUser', response);

    expect(JSON.stringify(body)).not.toContain('temporaryPassword');
    // nothing is left: not the Auth user, not the profile
    expect(await loginsWithEmail(email)).toBe(0);
    const listed = await expectContract<ClientUserListBody>(
      'listClientUsers',
      await listClientUsersViaApi(ceo.cookies, tenant.id),
    );
    expect(listed.items).toEqual([]);
    const [rolledBack] = events('identity.client_user.provision_rolled_back');
    expect(rolledBack).toMatchObject({
      level: 'error',
      clientId: tenant.id,
      reason: 'record_failed',
      targetUserId: expect.stringMatching(/^[0-9a-f-]{36}$/) as string,
    });
    expect(logged.lines.join('\n').toLowerCase()).not.toContain(email);
    // F-93: the account is gone, but its trail says it was taken back (`account.provision_reverted`, recorded
    // BEFORE the deletion), with the CEO, the request id, the reason and no e-mail
    const trail = await auditOfAccount(String(rolledBack?.['targetUserId']));
    expect(trail.map((row) => row.action)).toEqual(['account.provision_reverted']);
    expect(trail[0]).toMatchObject({
      actor_id: ceo.ceo.id,
      actor_role: 'ceo',
      client_id: tenant.id,
      request_id: response.headers.get('x-request-id'),
      metadata: { reason: 'record_failed' },
    });
    expect(JSON.stringify(trail)).not.toContain(email);
    // and the CEO can simply try again
    const retry = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email,
      displayName: 'Compensada',
    });
    expect(retry.status).toBe(201);
  });

  it('E-23: the compensation fails too: 503, an error log with the id of the account left behind, and the CEO recovers it by resetting its password (E-53)', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('orfao');
    logged.lines.length = 0;
    // the record fails, and so does the deletion (the only Auth admin call with a user id here)
    const spy = spyOnSupabaseFetch((url) =>
      url.includes('/rest/v1/rpc/record_account_provisioned') ||
      url.includes('/auth/v1/admin/users/')
        ? new TypeError('fetch failed')
        : undefined,
    );
    let response: Response;
    try {
      response = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
        email,
        displayName: 'Órfã',
      });
    } finally {
      spy.restore();
    }

    await expectUnavailable('provisionClientUser', response);
    const [orphaned] = events('identity.client_user.provision_orphaned');
    // why the deletion failed is in the log as a kind, never as a message
    expect(orphaned).toMatchObject({
      level: 'error',
      clientId: tenant.id,
      deleteFailure: { kind: 'SERVICE_UNAVAILABLE' },
    });
    // the account is there, in the list, born with the temporary password nobody was given...
    const listed = await expectContract<ClientUserListBody>(
      'listClientUsers',
      await listClientUsersViaApi(ceo.cookies, tenant.id),
    );
    expect(listed.items).toHaveLength(1);
    const [orphan] = listed.items;
    expect(orphan).toMatchObject({ email, mustChangePassword: true });
    expect(orphaned?.['targetUserId']).toBe(orphan?.id);
    expect(logged.lines.join('\n').toLowerCase()).not.toContain(email);
    // ...and repeating the provisioning says the address is taken
    const again = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email,
      displayName: 'Órfã',
    });
    const conflict = await expectContract<Problem>('provisionClientUser', again);
    expect([again.status, conflict.code]).toEqual([409, 'EMAIL_ALREADY_REGISTERED']);
    // F-93: the reversal was recorded before the deletion that failed, and the account never got
    // `account.provisioned` (the record failed)
    expect((await auditOfAccount(orphan?.id ?? '')).map((row) => row.action)).toEqual([
      'account.provision_reverted',
    ]);
    // the documented recovery: reset the password, which hands over a usable one
    const reset = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, orphan?.id ?? '');
    const { temporaryPassword } = await expectContract<{ temporaryPassword: string }>(
      'resetClientUserPassword',
      reset,
    );
    expect(await statusOfSignIn(email, temporaryPassword)).toBe(200);
    // F-93: and the reset that delivers the account registers the provisioning that was missing, late,
    // between the intent of the Auth write and the event of the reset
    const recovered = await auditOfAccount(orphan?.id ?? '');
    expect(recovered.map((row) => row.action)).toEqual([
      'account.provision_reverted',
      'account.password_set_intent',
      'account.provisioned',
      'account.password_reset',
    ]);
    expect(recovered[2]?.metadata).toEqual({ late: true });
    expect(recovered[2]?.request_id).toBe(reset.headers.get('x-request-id'));
  });

  /** The creation reaches Auth and WORKS; what the app never gets is the answer. */
  const createAnswerLost = (method: string, path: string) =>
    method === 'POST' && path === '/auth/v1/admin/users' ? LOSE_ANSWER : undefined;

  it('F-90, E-50: a creation whose answer is lost is found in the list of the client and taken back: 503 and nothing left, never a 422 and never a login nobody was given', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('perdida');
    logged.lines.length = 0;

    const lost = await whileWatching(createAnswerLost, () =>
      provisionClientUserViaApi(ceo.cookies, tenant.id, { email, displayName: 'Resposta perdida' }),
    );

    await expectUnavailable('provisionClientUser', lost);
    // the creation HAD worked: the look behind found the login by its e-mail and deleted it
    expect(await loginsWithEmail(email)).toBe(0);
    const [rolledBack] = events('identity.client_user.provision_rolled_back');
    expect(rolledBack).toMatchObject({
      level: 'error',
      reason: 'answer_lost',
      clientId: tenant.id,
      targetUserId: expect.stringMatching(/^[0-9a-f-]{36}$/) as string,
    });
    expect(logged.lines.join('\n').toLowerCase()).not.toContain(email);
    // the CEO simply repeats it
    const repeated = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email,
      displayName: 'Resposta perdida',
    });
    await expectContract('provisionClientUser', repeated);
    expect(repeated.status).toBe(201);
  });

  it('F-90, E-50: a lost answer for the LAST place of a client is still a 503 with the login taken back: the client being full is because of the login, not a refusal', async () => {
    const tenant = await createClient();
    for (let index = 0; index < 9; index += 1) await createClientUser({ clientId: tenant.id });
    const email = uniqueLoginEmail('ultima');

    const lost = await whileWatching(createAnswerLost, () =>
      provisionClientUserViaApi(ceo.cookies, tenant.id, { email, displayName: 'Última vaga' }),
    );

    await expectUnavailable('provisionClientUser', lost);
    expect(await loginsWithEmail(email)).toBe(0);
  });

  it('F-90, E-50: a lost answer and a deletion that fails: 503, `provision_answer_lost` at error with the id and why the deletion failed, the login stays in the list and a reset hands it over', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('perdida2');
    logged.lines.length = 0;

    const lost = await whileWatching(
      (method, path) =>
        method === 'DELETE' && path.startsWith('/auth/v1/admin/users/')
          ? new TypeError('fetch failed')
          : createAnswerLost(method, path),
      () =>
        provisionClientUserViaApi(ceo.cookies, tenant.id, { email, displayName: 'Sem exclusão' }),
    );

    await expectUnavailable('provisionClientUser', lost);
    const listed = await expectContract<ClientUserListBody>(
      'listClientUsers',
      await listClientUsersViaApi(ceo.cookies, tenant.id),
    );
    const [found] = listed.items;
    expect(found).toMatchObject({ email, mustChangePassword: true });
    const [answerLost] = events('identity.client_user.provision_answer_lost');
    expect(answerLost).toMatchObject({
      level: 'error',
      clientId: tenant.id,
      targetUserId: found?.id,
      deleteFailure: { kind: 'SERVICE_UNAVAILABLE' },
    });
    expect(logged.lines.join('\n').toLowerCase()).not.toContain(email);
    // repeating the provisioning says the address is taken; the reset is the recovery
    const again = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email,
      displayName: 'Sem exclusão',
    });
    expect(again.status).toBe(409);
    const reset = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, found?.id ?? '');
    const { temporaryPassword } = await expectContract<{ temporaryPassword: string }>(
      'resetClientUserPassword',
      reset,
    );
    expect(await statusOfSignIn(email, temporaryPassword)).toBe(200);
  });

  /**
   * The Auth server creates the account and answers 200 with a body that has no user (`{}`): what the
   * app gets is an accepted creation it cannot name. `forward` says whether the account really exists.
   */
  function answerCreationWithoutUser(forward: boolean) {
    const realFetch = globalThis.fetch;
    return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input instanceof Request ? input.url : input);
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'POST' && url.endsWith('/auth/v1/admin/users')) {
        if (forward) await (await realFetch(input, init)).arrayBuffer();
        return Response.json({}, { status: 200 });
      }
      return realFetch(input, init);
    });
  }

  it('F-90, E-55: an accepted creation whose answer has no user id: the account is found by its e-mail and taken back, a 503 and not a 500', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('semid');
    logged.lines.length = 0;
    const spy = answerCreationWithoutUser(true);
    let response: Response;
    try {
      response = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
        email,
        displayName: 'Sem identificador',
      });
    } finally {
      spy.mockRestore();
    }

    const body = await expectUnavailable('provisionClientUser', response);

    expect(JSON.stringify(body)).not.toContain('temporaryPassword');
    expect(await loginsWithEmail(email)).toBe(0);
    expect(events('identity.client_user.provision_rolled_back')).toHaveLength(1);
    expect(logged.lines.join('\n').toLowerCase()).not.toContain(email);
  });

  it('F-90, E-55: an answer with no user id and no login in the list: `provision_unconfirmed` at error, with no e-mail and no id, and a 503 that says to look in the list', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('semid2');
    logged.lines.length = 0;
    const spy = answerCreationWithoutUser(false);
    let response: Response;
    try {
      response = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
        email,
        displayName: 'Sem identificador',
      });
    } finally {
      spy.mockRestore();
    }

    const body = await expectUnavailable('provisionClientUser', response);

    expect(body.detail).toMatch(/look for it in the list/i);
    const [unconfirmed] = events('identity.client_user.provision_unconfirmed');
    expect(unconfirmed).toMatchObject({ level: 'error', clientId: tenant.id });
    expect(Object.keys(unconfirmed ?? {})).not.toContain('targetUserId');
    expect(logged.lines.join('\n').toLowerCase()).not.toContain(email);
  });

  it('E-51: the database step of a reset keeps failing after the Auth server stored the password: 503 and an error log; the old password and the sessions are gone but the pending action is not set; repeating the reset finishes it', async () => {
    const { tenant, login, cookies } = await tenantWithSignedInLogin();
    logged.lines.length = 0;
    const spy = failing('/rest/v1/rpc/require_password_change');
    let response: Response;
    try {
      response = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    } finally {
      spy.restore();
    }

    const body = await expectUnavailable('resetClientUserPassword', response);

    expect(JSON.stringify(body)).not.toContain('temporaryPassword');
    expect(events('identity.client_user.reset_incomplete')).toHaveLength(1);
    // what the incomplete state is, as documented: the old password no longer works and the Auth
    // server dropped the sessions when it replaced the password; the database side is what is missing
    // (the pending action, the new baseline, the audit event)
    expect(await canSignIn(login.email, login.password)).toBe(false);
    expect(await sessionStatus(cookies)).toBe(401);
    expect((await profileOf(login.id))?.must_change_password).toBe(false);
    // only the intent of the Auth write is on the trail: it was recorded before the password was stored
    expect((await managementTrail(login.id)).map((row) => row.action)).toEqual([
      'account.password_set_intent',
    ]);

    const repeated = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    const { temporaryPassword } = await expectContract<{ temporaryPassword: string }>(
      'resetClientUserPassword',
      repeated,
    );
    const jar = await sessionJarFor({ email: login.email, password: temporaryPassword });
    const session = await invoke(sessionRoute, { path: '/auth/session', cookies: jar });
    expect(await bodyOf(session)).toMatchObject({ pendingActions: ['CHANGE_PASSWORD'] });
    expect((await managementTrail(login.id)).map((row) => row.action)).toEqual([
      'account.password_set_intent',
      'account.password_set_intent',
      'account.provisioned',
      'account.password_reset',
    ]);
  });

  it('E-51: the database step that fails once is tried again: the reset completes in one request', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    let failures = 0;
    const spy = spyOnSupabaseFetch((url) => {
      if (url.includes('/rest/v1/rpc/require_password_change') && failures === 0) {
        failures += 1;
        return new TypeError('fetch failed');
      }
      return undefined;
    });
    let response: Response;
    try {
      response = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    } finally {
      spy.restore();
    }

    await expectContract('resetClientUserPassword', response);

    expect([response.status, failures]).toEqual([200, 1]);
    expect((await profileOf(login.id))?.must_change_password).toBe(true);
  });
});

describe('F-93: whatever the database says after the password is stored, the reset is incomplete', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await ceoFixture('incomplete reset');
  });

  /** What PostgREST answers when a database function raises `sqlstate` with `message`. */
  const databaseRefuses = (status: number, sqlstate: string, message: string) =>
    spyOnSupabaseFetch((url) =>
      url.includes('/rest/v1/rpc/require_password_change')
        ? Response.json({ code: sqlstate, message, details: null, hint: null }, { status })
        : undefined,
    );

  it('E-51: a refusal of the caller (403: the attestation expired meanwhile) is 503 with `reset_incomplete`, not the 403 that would say the reset did not happen', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    logged.lines.length = 0;
    const spy = databaseRefuses(403, '42501', 'FORBIDDEN');
    let response: Response;
    try {
      response = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    } finally {
      spy.restore();
    }

    const problem = await expectContract<Problem>('resetClientUserPassword', response);

    expect([response.status, problem.code]).toEqual([503, 'SERVICE_UNAVAILABLE']);
    expect(JSON.stringify(problem)).not.toContain('temporaryPassword');
    // the password HAS changed: that is what the answer must not hide
    expect(await canSignIn(login.email, login.password)).toBe(false);
    const [incomplete] = events('identity.client_user.reset_incomplete');
    expect(incomplete).toMatchObject({
      level: 'error',
      targetUserId: login.id,
      failure: { kind: 'FORBIDDEN' },
    });
    // the repeat finishes it
    const repeated = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    const { temporaryPassword } = await expectContract<{ temporaryPassword: string }>(
      'resetClientUserPassword',
      repeated,
    );
    expect(await statusOfSignIn(login.email, temporaryPassword)).toBe(200);
  });

  it('E-51: a login that is gone by now (404) is 503 with `reset_incomplete` too, and the log keeps only the kind', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    logged.lines.length = 0;
    const spy = databaseRefuses(400, 'P0001', 'NOT_FOUND');
    let response: Response;
    try {
      response = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    } finally {
      spy.restore();
    }

    await expectUnavailable('resetClientUserPassword', response);

    expect(events('identity.client_user.reset_incomplete')[0]).toMatchObject({
      failure: { kind: 'NOT_FOUND' },
    });
    expect(logged.lines.join('\n')).not.toContain(login.email);
  });
});

describe('E-21: Supabase failing', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await ceoFixture('Supabase failing');
  });

  const failing = (part: string) =>
    spyOnSupabaseFetch((url) => (url.includes(part) ? new TypeError('fetch failed') : undefined));

  it('E-21: listClientUsers that cannot reach the database is 503, not a 500', async () => {
    const tenant = await createClient();
    const spy = failing('/rest/v1/rpc/list_client_users');
    try {
      await expectUnavailable(
        'listClientUsers',
        await listClientUsersViaApi(ceo.cookies, tenant.id),
      );
    } finally {
      spy.restore();
    }
  });

  it('E-21: provisionClientUser that cannot read the client is 503 and creates nothing', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('fora1');
    const spy = failing('/rest/v1/clients');
    try {
      await expectUnavailable(
        'provisionClientUser',
        await provisionClientUserViaApi(ceo.cookies, tenant.id, { email, displayName: 'Fora' }),
      );
    } finally {
      spy.restore();
    }
    expect(await loginsWithEmail(email)).toBe(0);
  });

  it('E-21: provisionClientUser whose Auth server is down is 503 and creates nothing', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('fora2');
    const spy = spyOnSupabaseFetch((url) =>
      url.endsWith('/auth/v1/admin/users') ? new TypeError('fetch failed') : undefined,
    );
    try {
      await expectUnavailable(
        'provisionClientUser',
        await provisionClientUserViaApi(ceo.cookies, tenant.id, { email, displayName: 'Fora' }),
      );
    } finally {
      spy.restore();
    }
    expect(await loginsWithEmail(email)).toBe(0);
  });

  it('E-21: updateClientUser that cannot reach the database is 503 and changes nothing', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    const spy = failing('/rest/v1/rpc/set_account_disabled');
    try {
      await expectUnavailable(
        'updateClientUser',
        await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { disabled: true }),
      );
    } finally {
      spy.restore();
    }
    expect(await profileOf(login.id)).toMatchObject({ disabled_at: null });
  });

  it('E-21: re-enabling when the Auth server is down is 503 and the login stays disabled', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { disabled: true });
    const spy = failing('/auth/v1/admin/users/');
    try {
      await expectUnavailable(
        'updateClientUser',
        await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { disabled: false }),
      );
    } finally {
      spy.restore();
    }
    expect((await profileOf(login.id))?.disabled_at).not.toBeNull();
    // disabled in the database and still banned in the Auth server: no session at all
    expect(await statusOfSignIn(login.email, login.password)).toBe('refused');
  });

  it('E-21: resetClientUserPassword whose Auth server is down is 503 and nothing changes: the old password and the session stay', async () => {
    const { tenant, login, cookies } = await tenantWithSignedInLogin();
    const spy = failing('/auth/v1/admin/users/');
    try {
      await expectUnavailable(
        'resetClientUserPassword',
        await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id),
      );
    } finally {
      spy.restore();
    }
    expect(await canSignIn(login.email, login.password)).toBe(true);
    expect(await sessionStatus(cookies)).toBe(200);
    expect((await profileOf(login.id))?.must_change_password).toBe(false);
  });
});

describe('GET /admin/clients/{clientId}/users (listClientUsers)', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await ceoFixture('list');
  });

  it('RF-07: lists the logins of the client with e-mail, state and last sign-in, and only those of that client', async () => {
    const a = await tenantWithSignedInLogin('A');
    const b = await tenantWithSignedInLogin('B');
    const extra = await createClientUser({ clientId: a.tenant.id });

    const response = await listClientUsersViaApi(ceo.cookies, a.tenant.id);
    const body = await expectContract<ClientUserListBody>('listClientUsers', response);

    expect(response.status).toBe(200);
    expect(body.items.map((item) => item.id)).toEqual([a.login.id, extra.id]);
    expect(body.items.map((item) => item.id)).not.toContain(b.login.id);
    expect(body.items[0]).toMatchObject({
      email: a.login.email,
      disabled: false,
      mustChangePassword: false,
    });
    expect(body.items[0]?.lastSignInAt).not.toBeNull();
    expect(body.items[1]).toMatchObject({
      email: extra.email,
      mustChangePassword: true,
      lastSignInAt: null,
    });
  });

  it('E-19: a CEO account is never in the list, and a client with no login has an empty one', async () => {
    const tenant = await createClient();

    const body = await expectContract<ClientUserListBody>(
      'listClientUsers',
      await listClientUsersViaApi(ceo.cookies, tenant.id),
    );

    expect(body).toEqual({ items: [] });
  });

  it('SEC-03: an unknown client is 404 and a malformed id is 400', async () => {
    const unknown = await listClientUsersViaApi(ceo.cookies, UNKNOWN_CLIENT_ID);
    const malformed = await listClientUsersViaApi(ceo.cookies, 'not-a-uuid');

    expect((await expectContract<Problem>('listClientUsers', unknown)).code).toBe('NOT_FOUND');
    expect((await expectContract<Problem>('listClientUsers', malformed)).code).toBe(
      'VALIDATION_ERROR',
    );
    expect([unknown.status, malformed.status]).toEqual([404, 400]);
  });
});

describe('an archived client keeps its logins (F-58, Q-08)', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await ceoFixture('archived client');
  });

  it('E-54: archiving does not revoke a login, and a CEO still lists, renames, disables, enables and resets it; only a NEW login is refused (E-16)', async () => {
    const { tenant, login, cookies } = await tenantWithSignedInLogin();
    const archive = await updateClientViaApi(ceo.cookies, tenant.id, { archived: true });
    expect(archive.status).toBe(200);

    // the login keeps working
    expect(await sessionStatus(cookies)).toBe(200);
    expect((await loginResponse({ email: login.email, password: login.password })).status).toBe(
      200,
    );
    // the CEO still manages it
    const listed = await listClientUsersViaApi(ceo.cookies, tenant.id);
    expect(
      (await expectContract<ClientUserListBody>('listClientUsers', listed)).items,
    ).toHaveLength(1);
    const calls = [
      await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { displayName: 'Ainda aqui' }),
      await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { disabled: true }),
      await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { disabled: false }),
    ];
    for (const response of calls) await expectContract('updateClientUser', response);
    expect(calls.map((response) => response.status)).toEqual([200, 200, 200]);
    const reset = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    await expectContract('resetClientUserPassword', reset);
    expect(reset.status).toBe(200);
    // a new one is refused
    const email = uniqueLoginEmail('novo');
    const refused = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email,
      displayName: 'Novo',
    });
    expect((await expectContract<Problem>('provisionClientUser', refused)).code).toBe(
      'CLIENT_ARCHIVED',
    );
  });
});

describe('who may call the client login routes', () => {
  let ceo: CeoWithMfa;
  let tenant: Awaited<ReturnType<typeof createClient>>;
  let login: FixtureUser;

  beforeAll(async () => {
    ceo = await ceoFixture('who may call');
    tenant = await createClient();
    login = await completeFirstAccess(await createClientUser({ clientId: tenant.id }));
  });

  async function expectAllRefused(cookies: CookieStore | undefined, status: number, code: string) {
    for (const [operationId, response] of await callAll(cookies, tenant.id, login.id)) {
      const body = await expectContract<Problem>(operationId, response);
      expect([operationId, response.status, body.code]).toEqual([operationId, status, code]);
    }
    // nothing happened to the login
    expect(await profileOf(login.id)).toMatchObject({
      disabled_at: null,
      must_change_password: false,
    });
    expect(await canSignIn(login.email, login.password)).toBe(true);
  }

  it('SEC-01: without a session every operation is 401 UNAUTHENTICATED', async () => {
    await expectAllRefused(undefined, 401, 'UNAUTHENTICATED');
  });

  it('E-07: a client user is 403 FORBIDDEN on every operation, on its own client too', async () => {
    const cookies = await sessionJarFor(login);

    await expectAllRefused(cookies, 403, 'FORBIDDEN');
  });

  it('SEC-11: a CEO whose session is aal1, with a verified factor, is 403 MFA_VERIFICATION_REQUIRED', async () => {
    // a session opened with the password only: aal1, whatever the CEO has enrolled
    const cookies = await sessionJarFor(ceo.ceo);

    await expectAllRefused(cookies, 403, 'MFA_VERIFICATION_REQUIRED');
  });

  it('SEC-11: a CEO with no TOTP factor is 403 MFA_ENROLLMENT_REQUIRED', async () => {
    const readyToEnroll = await completeFirstAccess(await createCeo());
    const cookies = await sessionJarFor(readyToEnroll);

    await expectAllRefused(cookies, 403, 'MFA_ENROLLMENT_REQUIRED');
  });

  it('spec §3.5: a CEO who still has the temporary password is 403 PASSWORD_CHANGE_REQUIRED', async () => {
    const fresh = await createCeo();
    const cookies = await sessionJarFor(fresh);

    await expectAllRefused(cookies, 403, 'PASSWORD_CHANGE_REQUIRED');
  });
});

describe('the input of provisioning', () => {
  let ceo: CeoWithMfa;
  let tenant: Awaited<ReturnType<typeof createClient>>;

  beforeAll(async () => {
    ceo = await ceoFixture('input');
    tenant = await createClient();
  });

  it('AC-23: a role, a clientId, a password or any unknown field is 400 and no account is created', async () => {
    for (const extra of [
      { role: 'ceo' },
      { clientId: tenant.id },
      { password: newPassword() },
      { temporaryPassword: newPassword() },
      { id: UNKNOWN_USER_ID },
    ]) {
      const email = uniqueLoginEmail('mass');
      const response = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
        email,
        displayName: 'Mass Assignment',
        ...extra,
      });
      const body = await expectContract<Problem>('provisionClientUser', response);

      expect([response.status, body.code]).toEqual([400, 'VALIDATION_ERROR']);
      expect(await loginsWithEmail(email)).toBe(0);
    }
  });

  it('AC-12: a bad e-mail, a bad name or a missing field is 400', async () => {
    const valid = { email: uniqueLoginEmail('ok'), displayName: 'Maria' };
    const responses = await Promise.all([
      provisionClientUserViaApi(ceo.cookies, tenant.id, { ...valid, email: 'not-an-email' }),
      provisionClientUserViaApi(ceo.cookies, tenant.id, {
        ...valid,
        email: `${'a'.repeat(250)}@cliente.test`,
      }),
      provisionClientUserViaApi(ceo.cookies, tenant.id, { ...valid, displayName: '' }),
      provisionClientUserViaApi(ceo.cookies, tenant.id, { ...valid, displayName: 'a'.repeat(121) }),
      provisionClientUserViaApi(ceo.cookies, tenant.id, {
        ...valid,
        displayName: `Ma${String.fromCodePoint(0x200b)}ria`,
      }),
      provisionClientUserViaApi(ceo.cookies, tenant.id, { email: valid.email }),
      provisionClientUserViaApi(ceo.cookies, tenant.id, { displayName: 'Maria' }),
      provisionClientUserViaApi(ceo.cookies, 'not-a-uuid', valid),
    ]);

    for (const response of responses) {
      const body = await expectContract<Problem>('provisionClientUser', response);
      expect([response.status, body.code]).toEqual([400, 'VALIDATION_ERROR']);
    }
    expect(await loginsWithEmail(valid.email)).toBe(0);
  });

  it('AC-23: a foreign Origin, a wrong Content-Type and a body over 16 KiB are refused before anything is created', async () => {
    const email = uniqueLoginEmail('transporte');
    const body = { email, displayName: 'Transporte' };

    const foreign = await provisionClientUserViaApi(ceo.cookies, tenant.id, body, {
      origin: 'https://evil.example',
    });
    const wrongType = await provisionClientUserViaApi(ceo.cookies, tenant.id, undefined, {
      rawBody: JSON.stringify(body),
      headers: { 'content-type': 'text/plain' },
    });
    const huge = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      ...body,
      displayName: 'a'.repeat(BODY_LIMIT_BYTES + 1),
    });

    const codes: string[] = [];
    for (const response of [foreign, wrongType, huge]) {
      codes.push((await expectContract<Problem>('provisionClientUser', response)).code);
    }
    expect([foreign.status, wrongType.status, huge.status]).toEqual([403, 415, 413]);
    expect(codes).toEqual(['ORIGIN_NOT_ALLOWED', 'UNSUPPORTED_MEDIA_TYPE', 'PAYLOAD_TOO_LARGE']);
    expect(await loginsWithEmail(email)).toBe(0);
  });
});

describe('SEC-09: provisioning and resetting share one counter of 20 per hour per CEO', () => {
  it('the 21st request of the two kinds together is 429 RATE_LIMITED with Retry-After, whichever kind it is', async () => {
    const ceo = await ceoFixture('rate limit');
    const provisionBody = { email: uniqueLoginEmail('limite'), displayName: 'Limite' };

    // 404s: they spend the budget (the limit runs before the use case) and change nothing
    for (let sent = 0; sent < ADMIN_LIMIT_PER_HOUR / 2; sent += 1) {
      const reset = await resetClientUserPasswordViaApi(
        ceo.cookies,
        UNKNOWN_CLIENT_ID,
        UNKNOWN_USER_ID,
      );
      expect(reset.status).toBe(404);
      const provision = await provisionClientUserViaApi(
        ceo.cookies,
        UNKNOWN_CLIENT_ID,
        provisionBody,
      );
      expect(provision.status).toBe(404);
    }

    const limited = await resetClientUserPasswordViaApi(
      ceo.cookies,
      UNKNOWN_CLIENT_ID,
      UNKNOWN_USER_ID,
    );
    const body = await expectContract<Problem>('resetClientUserPassword', limited);
    const limitedProvision = await provisionClientUserViaApi(
      ceo.cookies,
      UNKNOWN_CLIENT_ID,
      provisionBody,
    );
    const provisionProblem = await expectContract<Problem>('provisionClientUser', limitedProvision);

    expect([limited.status, body.code]).toEqual([429, 'RATE_LIMITED']);
    expect([limitedProvision.status, provisionProblem.code]).toEqual([429, 'RATE_LIMITED']);
    expect(Number(limited.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    // the update has its own counter (writes, 60 per minute): it is not affected
    const { tenant, login } = await tenantWithSignedInLogin();
    const update = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
      displayName: 'Livre',
    });
    expect(update.status).toBe(200);
  });
});

describe('F-92 b and F-93: the audit of what is written to the Auth server and of the compensation (Wave 10.1)', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await ceoFixture('auth write audit');
  });

  /** Makes the requests whose URL holds `part` fail the way a dead network does. */
  const failing = (part: string) =>
    spyOnSupabaseFetch((url) => (url.includes(part) ? new TypeError('fetch failed') : undefined));

  const authAdminCalls = (calls: readonly string[]) =>
    calls.filter((call) => call.includes('/auth/v1/admin/users/'));

  it('F-92 b: a reset records its intent BEFORE the password reaches the Auth server, with the CEO and the request id, and no secret', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    const spy = spyOnSupabaseFetch();
    let response: Response;
    try {
      response = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    } finally {
      spy.restore();
    }
    const body = await expectContract<{ temporaryPassword: string }>(
      'resetClientUserPassword',
      response,
    );

    const intent = spy.calls.findIndex((call) =>
      call.includes('/rest/v1/rpc/begin_client_login_admin'),
    );
    const write = spy.calls.findIndex((call) => call.includes('/auth/v1/admin/users/'));
    const mark = spy.calls.findIndex((call) =>
      call.includes('/rest/v1/rpc/require_password_change'),
    );
    expect(intent).toBeGreaterThanOrEqual(0);
    expect(intent).toBeLessThan(write);
    expect(write).toBeLessThan(mark);
    const [first] = await managementTrail(login.id);
    expect(first).toMatchObject({
      action: 'account.password_set_intent',
      actor_id: ceo.ceo.id,
      client_id: tenant.id,
      request_id: response.headers.get('x-request-id'),
      metadata: { action: 'set_password' },
    });
    expect(JSON.stringify(await auditOfAccount(login.id))).not.toContain(body.temporaryPassword);
  });

  it('F-92 b: a reset whose intent cannot be recorded does not touch the Auth server: 503, the old password still works, nothing on the trail', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    logged.lines.length = 0;
    const spy = failing('/rest/v1/rpc/begin_client_login_admin');
    let response: Response;
    try {
      response = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    } finally {
      spy.restore();
    }

    const body = await expectUnavailable('resetClientUserPassword', response);

    expect(JSON.stringify(body)).not.toContain('temporaryPassword');
    expect(authAdminCalls(spy.calls)).toEqual([]);
    expect(await canSignIn(login.email, login.password)).toBe(true);
    expect((await profileOf(login.id))?.must_change_password).toBe(false);
    expect((await managementTrail(login.id)).map((row) => row.action)).toEqual([]);
    expect(events('identity.client_user.reset_incomplete')).toHaveLength(0);
  });

  it('F-92 b: disabling records the intent of the ban after the database blocked the login and before the Auth server is told', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    const spy = spyOnSupabaseFetch();
    let response: Response;
    try {
      response = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { disabled: true });
    } finally {
      spy.restore();
    }
    await expectContract('updateClientUser', response);

    const disabled = spy.calls.findIndex((call) =>
      call.includes('/rest/v1/rpc/set_account_disabled'),
    );
    const intent = spy.calls.findIndex((call) =>
      call.includes('/rest/v1/rpc/begin_client_login_admin'),
    );
    const ban = spy.calls.findIndex((call) => call.includes('/auth/v1/admin/users/'));
    expect(disabled).toBeLessThan(intent);
    expect(intent).toBeLessThan(ban);
    expect(await isBannedInAuth(login.id)).toBe(true);
    expect((await managementTrail(login.id)).map((row) => [row.action, row.metadata])).toEqual([
      ['account.disabled', {}],
      ['account.ban_intent', { action: 'ban' }],
    ]);
  });

  it('F-92 b: a disable whose ban intent cannot be recorded is still 200 (the database blocks the login) and the Auth server is NOT called: logged as ban_failed / not_audited', async () => {
    const { tenant, login, cookies } = await tenantWithSignedInLogin();
    logged.lines.length = 0;
    const spy = failing('/rest/v1/rpc/begin_client_login_admin');
    let response: Response;
    try {
      response = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { disabled: true });
    } finally {
      spy.restore();
    }
    const body = await expectContract<ClientUserBody>('updateClientUser', response);

    expect([response.status, body.disabled]).toEqual([200, true]);
    expect(await sessionStatus(cookies)).toBe(401);
    expect(authAdminCalls(spy.calls)).toEqual([]);
    expect(await isBannedInAuth(login.id)).toBe(false);
    expect(events('identity.client_user.ban_failed')[0]).toMatchObject({
      level: 'error',
      targetUserId: login.id,
      reason: 'not_audited',
    });
    expect((await managementTrail(login.id)).map((row) => row.action)).toEqual([
      'account.disabled',
    ]);

    // repeating the disable records the intent and sets the ban
    const repeated = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
      disabled: true,
    });
    expect(repeated.status).toBe(200);
    expect(await isBannedInAuth(login.id)).toBe(true);
  });

  it('F-92 b: an unban whose intent cannot be recorded is 503, the Auth server is not touched, and the login stays disabled and banned', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, { disabled: true });
    const spy = failing('/rest/v1/rpc/begin_client_login_admin');
    let response: Response;
    try {
      response = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
        disabled: false,
      });
    } finally {
      spy.restore();
    }

    await expectUnavailable('updateClientUser', response);

    expect(authAdminCalls(spy.calls)).toEqual([]);
    expect(await isBannedInAuth(login.id)).toBe(true);
    expect((await profileOf(login.id))?.disabled_at).not.toBeNull();
    expect((await managementTrail(login.id)).map((row) => row.action)).toEqual([
      'account.disabled',
      'account.ban_intent',
    ]);
  });

  it('F-92 b: the function straight through PostgREST: the right login is recorded, and another client, a CEO, an unknown action, a client login and anon are refused', async () => {
    const { supabase, ceo: ceoUser } = await ceoAal2Client();
    const mine = await tenantWithSignedInLogin();
    const other = await tenantWithSignedInLogin();
    const call = (clientId: string, userId: string, action: string) =>
      supabase.rpc('begin_client_login_admin', {
        p_client_id: clientId,
        p_user_id: userId,
        p_action: action,
      });

    const recorded = await call(mine.tenant.id, mine.login.id, 'unban');
    expect(recorded.error).toBeNull();
    const [row] = await managementTrail(mine.login.id);
    expect(row).toMatchObject({
      action: 'account.unban_intent',
      actor_id: ceoUser.id,
      client_id: mine.tenant.id,
      metadata: { action: 'unban' },
    });

    // a login of ANOTHER client, a CEO, an unknown id: the same NOT_FOUND
    for (const refused of [
      await call(mine.tenant.id, other.login.id, 'ban'),
      await call(other.tenant.id, mine.login.id, 'ban'),
      await call(mine.tenant.id, ceoUser.id, 'ban'),
      await call(mine.tenant.id, UNKNOWN_USER_ID, 'ban'),
    ]) {
      expect(refused.error).toMatchObject({ code: 'P0001', message: 'NOT_FOUND' });
    }
    // an action outside the list
    for (const action of ['delete', 'create', '', 'BAN', 'ban ']) {
      expect((await call(mine.tenant.id, mine.login.id, action)).error).toMatchObject({
        code: 'P0001',
        message: 'INVALID_INPUT',
      });
    }
    // nothing but the one recorded intent reached the trail of either login
    expect((await managementTrail(mine.login.id)).map((trail) => trail.action)).toEqual([
      'account.unban_intent',
    ]);
    expect((await managementTrail(other.login.id)).map((trail) => trail.action)).toEqual([]);

    // a client login, signed in, is not a CEO; and anon does not even execute it
    const asClient = publishableClient();
    const signIn = await asClient.auth.signInWithPassword({
      email: mine.login.email,
      password: mine.login.password,
    });
    expect(signIn.error).toBeNull();
    const byClient = await asClient.rpc('begin_client_login_admin', {
      p_client_id: mine.tenant.id,
      p_user_id: mine.login.id,
      p_action: 'ban',
    });
    expect(byClient.error).toMatchObject({ code: '42501' });
    const anon = await publishableClient().rpc('begin_client_login_admin', {
      p_client_id: mine.tenant.id,
      p_user_id: mine.login.id,
      p_action: 'ban',
    });
    expect(anon.error).toMatchObject({ code: '42501' });
    expect((await managementTrail(mine.login.id)).map((trail) => trail.action)).toEqual([
      'account.unban_intent',
    ]);
  });

  it('F-93: the 201 of a provisioning comes from the record itself: the list is read once (before the creation), never after', async () => {
    const tenant = await createClient();
    let lists = 0;
    // a second read of the list would fail: it must not even be made
    const spy = spyOnSupabaseFetch((url) => {
      if (!url.includes('/rest/v1/rpc/list_client_users')) return undefined;
      lists += 1;
      return lists > 1 ? new TypeError('fetch failed') : undefined;
    });
    let response: Response;
    try {
      response = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
        email: uniqueLoginEmail('semrelida'),
        displayName: 'Sem releitura',
      });
    } finally {
      spy.restore();
    }

    const body = await expectContract<ProvisionedBody>('provisionClientUser', response);

    expect([response.status, lists]).toEqual([201, 1]);
    // the login in the answer is the one the list shows
    const listed = await expectContract<ClientUserListBody>(
      'listClientUsers',
      await listClientUsersViaApi(ceo.cookies, tenant.id),
    );
    expect(listed.items).toEqual([body.user]);
  });

  it('F-93: the compensation is fail closed: when the reversal cannot be recorded the account is NOT deleted, 503, and the log says why (provision_orphaned)', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('semrastro');
    logged.lines.length = 0;
    const spy = spyOnSupabaseFetch((url) =>
      url.includes('/rest/v1/rpc/record_account_provisioned') ||
      url.includes('/rest/v1/rpc/record_account_provision_reverted')
        ? new TypeError('fetch failed')
        : undefined,
    );
    let response: Response;
    try {
      response = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
        email,
        displayName: 'Sem rastro',
      });
    } finally {
      spy.restore();
    }

    await expectUnavailable('provisionClientUser', response);

    // no deletion was even tried, and the account is where the CEO can recover it
    expect(spy.calls.filter((call) => call.startsWith('DELETE '))).toEqual([]);
    expect(await loginsWithEmail(email)).toBe(1);
    const [orphaned] = events('identity.client_user.provision_orphaned');
    expect(orphaned).toMatchObject({
      level: 'error',
      clientId: tenant.id,
      deleteFailure: { kind: 'SERVICE_UNAVAILABLE' },
    });
    const [orphan] = (
      await expectContract<ClientUserListBody>(
        'listClientUsers',
        await listClientUsersViaApi(ceo.cookies, tenant.id),
      )
    ).items;
    expect(orphan).toMatchObject({ email, mustChangePassword: true });
    // nothing at all on its trail: not provisioned, not reverted
    expect(await auditOfAccount(orphan?.id ?? '')).toEqual([]);
    expect(logged.lines.join('\n').toLowerCase()).not.toContain(email);
  });
});
