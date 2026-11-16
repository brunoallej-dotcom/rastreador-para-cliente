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
import { createClient, createClientUser, createCeo, type FixtureUser } from '../helpers/fixtures';
import {
  bodyOf,
  invoke,
  spyOnSupabaseFetch,
  withoutRequestId,
  type CookieStore,
} from '../helpers/http';
import {
  completeFirstAccess,
  loginAsCeoReadyToEnroll,
  loginAsCeoWithMfa,
  loginViaApi,
  signInCeoWithMfa,
  type CeoWithMfa,
} from '../helpers/mfa';
import { canSignIn, changePassword, LOSE_ANSWER, whileWatching } from '../helpers/password';

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

/** A client with one login that already changed its temporary password and is signed in. */
async function tenantWithSignedInLogin(label = 'Cliente') {
  const tenant = await createClient(`${label} ${randomUUID().slice(0, 8)}`);
  const login = await completeFirstAccess(await createClientUser({ clientId: tenant.id }));
  const cookies = await loginViaApi(login);
  return { tenant, login, cookies };
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
    ceo = await loginAsCeoWithMfa();
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
    ceo = await loginAsCeoWithMfa();
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
    ceo = await loginAsCeoWithMfa();
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
    expect(trail.map((row) => row.action)).toEqual(['account.disabled', 'account.enabled']);
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
    const refused = await loginResponse({ email: login.email, password: login.password });
    expect(refused.status).toBe(401);
    // ...even though the Auth server was not told to ban it
    expect(await isBannedInAuth(login.id)).toBe(false);
    const [failure] = events('identity.client_user.ban_failed');
    expect(failure).toMatchObject({ level: 'error', targetUserId: login.id, clientId: tenant.id });
    expect(logged.lines.join('\n')).not.toContain(login.email);

    const repeated = await updateClientUserViaApi(ceo.cookies, tenant.id, login.id, {
      disabled: true,
    });
    expect(repeated.status).toBe(200);
    expect(await isBannedInAuth(login.id)).toBe(true);
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
    ceo = await loginAsCeoWithMfa();
  });

  it('AC-14: a reset gives a new temporary password, makes the user change it, and revokes every session', async () => {
    const { tenant, login, cookies } = await tenantWithSignedInLogin();
    const second = await loginViaApi(login);
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
    expect((await loginResponse({ email: login.email, password: login.password })).status).toBe(
      401,
    );
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
    expect(trail.map((row) => row.action)).toEqual(['account.password_reset']);
    expect(trail[0]).toMatchObject({
      actor_id: ceo.ceo.id,
      actor_role: 'ceo',
      client_id: tenant.id,
      request_id: response.headers.get('x-request-id'),
    });
  });

  it('AC-14: the user changes the temporary password of a reset with POST /auth/password: the baseline is the new hash (ADR 0007)', async () => {
    const { tenant, login } = await tenantWithSignedInLogin();
    const reset = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    const { temporaryPassword } = await expectContract<{ temporaryPassword: string }>(
      'resetClientUserPassword',
      reset,
    );
    const jar = await loginViaApi({ email: login.email, password: temporaryPassword });

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
    const expired = await loginResponse({
      email: created.user.email,
      password: created.temporaryPassword,
    });
    expect(expired.status).toBe(401);

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
    ceo = await loginAsCeoWithMfa();
  });

  /** Makes the requests whose URL holds `part` fail the way a dead network does. */
  const failing = (part: string) =>
    spyOnSupabaseFetch((url) => (url.includes(part) ? new TypeError('fetch failed') : undefined));

  /** 503 `SERVICE_UNAVAILABLE` with a `Retry-After` of at least a second, as the contract documents. */
  async function expectUnavailable(operationId: string, response: Response) {
    const body = await expectContract<Problem>(operationId, response);

    expect(response.status).toBe(503);
    expect(body.code).toBe('SERVICE_UNAVAILABLE');
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    return body;
  }

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
    expect(rolledBack).toMatchObject({ level: 'error', clientId: tenant.id });
    expect(logged.lines.join('\n').toLowerCase()).not.toContain(email);
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
    expect(orphaned).toMatchObject({ level: 'error', clientId: tenant.id });
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
    expect(again.status).toBe(409);
    // the documented recovery: reset the password, which hands over a usable one
    const reset = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, orphan?.id ?? '');
    const { temporaryPassword } = await expectContract<{ temporaryPassword: string }>(
      'resetClientUserPassword',
      reset,
    );
    expect((await loginResponse({ email, password: temporaryPassword })).status).toBe(200);
  });

  it('E-50: a creation whose answer is lost (503) may have created the login: repeating it is 409, the login is in the list, and a reset hands it over', async () => {
    const tenant = await createClient();
    const email = uniqueLoginEmail('perdida');
    const lost = await whileWatching(
      (method, path) =>
        method === 'POST' && path === '/auth/v1/admin/users' ? LOSE_ANSWER : undefined,
      () =>
        provisionClientUserViaApi(ceo.cookies, tenant.id, {
          email,
          displayName: 'Resposta perdida',
        }),
    );
    await expectUnavailable('provisionClientUser', lost);
    expect(await loginsWithEmail(email)).toBe(1);

    const repeated = await provisionClientUserViaApi(ceo.cookies, tenant.id, {
      email,
      displayName: 'Resposta perdida',
    });
    const conflict = await expectContract<Problem>('provisionClientUser', repeated);
    expect([repeated.status, conflict.code]).toEqual([409, 'EMAIL_ALREADY_REGISTERED']);

    const listed = await expectContract<ClientUserListBody>(
      'listClientUsers',
      await listClientUsersViaApi(ceo.cookies, tenant.id),
    );
    const [found] = listed.items;
    expect(found).toMatchObject({ email, mustChangePassword: true });
    const reset = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, found?.id ?? '');
    const { temporaryPassword } = await expectContract<{ temporaryPassword: string }>(
      'resetClientUserPassword',
      reset,
    );
    expect((await loginResponse({ email, password: temporaryPassword })).status).toBe(200);
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
    expect((await managementTrail(login.id)).map((row) => row.action)).toEqual([]);

    const repeated = await resetClientUserPasswordViaApi(ceo.cookies, tenant.id, login.id);
    const { temporaryPassword } = await expectContract<{ temporaryPassword: string }>(
      'resetClientUserPassword',
      repeated,
    );
    const signedIn = await loginResponse({ email: login.email, password: temporaryPassword });
    expect(await signedIn.json()).toMatchObject({ pendingActions: ['CHANGE_PASSWORD'] });
    expect((await managementTrail(login.id)).map((row) => row.action)).toEqual([
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

describe('E-21: Supabase failing', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await loginAsCeoWithMfa();
  });

  const failing = (part: string) =>
    spyOnSupabaseFetch((url) => (url.includes(part) ? new TypeError('fetch failed') : undefined));

  async function expectUnavailable(operationId: string, response: Response) {
    const body = await expectContract<Problem>(operationId, response);

    expect(response.status).toBe(503);
    expect(body.code).toBe('SERVICE_UNAVAILABLE');
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
  }

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
    expect((await loginResponse({ email: login.email, password: login.password })).status).toBe(
      401,
    );
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
    ceo = await loginAsCeoWithMfa();
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
    ceo = await loginAsCeoWithMfa();
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
    ceo = await loginAsCeoWithMfa();
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
    const cookies = await loginViaApi(login);

    await expectAllRefused(cookies, 403, 'FORBIDDEN');
  });

  it('SEC-11: a CEO whose session is aal1, with a verified factor, is 403 MFA_VERIFICATION_REQUIRED', async () => {
    const cookies = await signInCeoWithMfa(ceo, { verify: false });

    await expectAllRefused(cookies, 403, 'MFA_VERIFICATION_REQUIRED');
  });

  it('SEC-11: a CEO with no TOTP factor is 403 MFA_ENROLLMENT_REQUIRED', async () => {
    const { cookies } = await loginAsCeoReadyToEnroll();

    await expectAllRefused(cookies, 403, 'MFA_ENROLLMENT_REQUIRED');
  });

  it('spec §3.5: a CEO who still has the temporary password is 403 PASSWORD_CHANGE_REQUIRED', async () => {
    const fresh = await createCeo();
    const cookies = await loginViaApi(fresh);

    await expectAllRefused(cookies, 403, 'PASSWORD_CHANGE_REQUIRED');
  });
});

describe('the input of provisioning', () => {
  let ceo: CeoWithMfa;
  let tenant: Awaited<ReturnType<typeof createClient>>;

  beforeAll(async () => {
    ceo = await loginAsCeoWithMfa();
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
    const ceo = await loginAsCeoWithMfa();
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
