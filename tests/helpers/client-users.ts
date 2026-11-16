// Helpers for the API tests of the client logins (Wave 7 owns this file): the four operations of
// `/admin/clients/{clientId}/users` invoked through the real route modules, and the reads a test needs
// to PROVE what happened to an account (Auth, profile, audit trail), made with the secret key.
//
//   const session = await loginAsCeoWithMfa();                          // tests/helpers/mfa.ts: aal2 cookies
//   const created = await provisionOrFail(session.cookies, client.id);  // 201: { user, temporaryPassword }
//   const reset = await resetClientUserPasswordViaApi(session.cookies, client.id, created.user.id);
//
// Reads with the secret key are fixtures, never how a behavior is checked. Test code only: nothing in
// `src/` may import it.
import { randomUUID } from 'node:crypto';
import {
  POST as provisionRoute,
  GET as listRoute,
} from '@/app/api/v1/admin/clients/[clientId]/users/route';
import { POST as resetRoute } from '@/app/api/v1/admin/clients/[clientId]/users/[userId]/password-reset/route';
import { PATCH as updateRoute } from '@/app/api/v1/admin/clients/[clientId]/users/[userId]/route';
import { adminClient } from './fixtures';
import { bodyOf, invoke, type CookieStore, type InvokeInit } from './http';

/** `ClientUser` of the contract, as the API answers it. */
export type ClientUserBody = {
  id: string;
  email: string;
  displayName: string;
  disabled: boolean;
  mustChangePassword: boolean;
  lastSignInAt: string | null;
  createdAt: string;
};

export type ProvisionedBody = { user: ClientUserBody; temporaryPassword: string };
export type ClientUserListBody = { items: ClientUserBody[] };

type Session = CookieStore | undefined;
const withCookies = (cookies: Session) => (cookies === undefined ? {} : { cookies });

/** What a test may still change of a request: headers, `Origin`, a raw body, the client IP. */
type RequestExtras = Omit<InvokeInit, 'method' | 'path' | 'params' | 'query' | 'cookies'>;

const usersPath = (clientId: string) => `/admin/clients/${clientId}/users`;

export const listClientUsersViaApi = (cookies: Session, clientId: string) =>
  invoke(listRoute, {
    path: usersPath(clientId),
    params: { clientId },
    ...withCookies(cookies),
  });

export const provisionClientUserViaApi = (
  cookies: Session,
  clientId: string,
  body: unknown,
  extras: RequestExtras = {},
) =>
  invoke(provisionRoute, {
    method: 'POST',
    path: usersPath(clientId),
    params: { clientId },
    body,
    ...extras,
    ...withCookies(cookies),
  });

export const updateClientUserViaApi = (
  cookies: Session,
  clientId: string,
  userId: string,
  body: unknown,
  extras: RequestExtras = {},
) =>
  invoke(updateRoute, {
    method: 'PATCH',
    path: `${usersPath(clientId)}/${userId}`,
    params: { clientId, userId },
    body,
    ...extras,
    ...withCookies(cookies),
  });

export const resetClientUserPasswordViaApi = (
  cookies: Session,
  clientId: string,
  userId: string,
  extras: RequestExtras = {},
) =>
  invoke(resetRoute, {
    method: 'POST',
    path: `${usersPath(clientId)}/${userId}/password-reset`,
    params: { clientId, userId },
    ...extras,
    ...withCookies(cookies),
  });

/** An e-mail nobody else uses, already in canonical form (lowercase). */
export const uniqueLoginEmail = (label = 'login') =>
  `${label}.${randomUUID().slice(0, 8)}@cliente.test`;

/** Provisions a login through the API and returns it; fails the helper unless 201. */
export async function provisionOrFail(
  cookies: CookieStore,
  clientId: string,
  init: { email?: string; displayName?: string } = {},
): Promise<ProvisionedBody> {
  const response = await provisionClientUserViaApi(cookies, clientId, {
    email: init.email ?? uniqueLoginEmail(),
    displayName: init.displayName ?? 'Login de Teste',
  });
  if (response.status !== 201) {
    // the body of a refusal carries no password; a 201 is never printed
    throw new Error(`provision fixture failed with ${response.status}: ${await response.text()}`);
  }
  return (await bodyOf(response)) as ProvisionedBody;
}

/** The profile of an account, read with the secret key (a fixture, not a behavior). */
export async function profileOf(userId: string) {
  const { data, error } = await adminClient()
    .from('profiles')
    .select('id, role, client_id, display_name, must_change_password, disabled_at')
    .eq('id', userId)
    .maybeSingle();
  if (error) throw new Error(`reading a profile failed: ${error.message}`);
  return data;
}

/** The Auth user, read with the secret key. `null` when the Auth server has no such user. */
export async function authUserOf(userId: string) {
  const { data, error } = await adminClient().auth.admin.getUserById(userId);
  if (error) {
    if (error.status === 404) return null;
    throw new Error(`getUserById failed: ${error.message}`);
  }
  return data.user;
}

/** Is the account banned right now in the Auth server? */
export async function isBannedInAuth(userId: string): Promise<boolean> {
  const user = await authUserOf(userId);
  if (user === null) throw new Error('the Auth server has no such user');
  const until = user.banned_until;
  return until !== undefined && until !== null && Date.parse(until) > Date.now();
}

export type AccountAuditRow = {
  action: string;
  actor_id: string | null;
  actor_role: string | null;
  resource_type: string;
  resource_id: string;
  client_id: string | null;
  request_id: string | null;
  metadata: unknown;
};

/** The audit trail of an account, oldest first, read with the secret key (a fixture, not a behavior). */
export async function auditOfAccount(userId: string): Promise<AccountAuditRow[]> {
  const { data, error } = await adminClient()
    .from('audit_events')
    .select(
      'action, actor_id, actor_role, resource_type, resource_id, client_id, request_id, metadata',
    )
    .eq('resource_id', userId)
    .order('id', { ascending: true });
  if (error) throw new Error(`reading the audit trail failed: ${error.message}`);
  return data;
}

/** The logins of a client with this e-mail, read with the secret key through the Auth Admin API. */
export async function loginsWithEmail(email: string): Promise<number> {
  const perPage = 1000;
  for (let page = 1; ; page += 1) {
    const { data, error } = await adminClient().auth.admin.listUsers({ page, perPage });
    if (error) throw new Error(`listUsers failed: ${error.message}`);
    const found = data.users.filter((user) => user.email === email).length;
    if (found > 0) return found;
    if (data.users.length < perPage) return 0;
  }
}

/** Archives a client with the secret key (a fixture: the API path of it is `PATCH /admin/clients`). */
export async function archiveClientFixture(clientId: string): Promise<void> {
  const { error } = await adminClient()
    .from('clients')
    .update({ archived_at: new Date().toISOString() })
    .eq('id', clientId);
  if (error) throw new Error(`archiving a client failed: ${error.message}`);
}
