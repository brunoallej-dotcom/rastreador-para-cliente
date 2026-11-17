// Helpers for the API tests of the client panel (Wave 10 owns this file): the two operations of
// `/me/processes` invoked through the real route modules, and the fixtures that put a client in front of
// them, made the way production makes them.
//
//   const ceo = await loginAsCeoWithMfa();                                     // tests/helpers/mfa.ts
//   const tenant = await createClientOrFail(ceo.cookies);                      // create_client, as a CEO
//   const login = await signedInClientLogin(ceo.cookies, tenant.id);           // provisioned, first access done
//   const process = await createProcessOrFail(ceo.cookies, tenant.id);         // create_process, as a CEO
//   const listed = await listMyProcessesViaApi(login.cookies);                 // what the client sees
//
// Nothing here writes with the secret key: the client, its login, its processes and their cancellation
// go through the real routes, and what no route does yet (the "Ok", a tie in `created_at`) goes through
// `tests/helpers/db.ts`. Test code only: nothing in `src/` may import it.
import { randomUUID } from 'node:crypto';
import { GET as getRoute } from '@/app/api/v1/me/processes/[processId]/route';
import { GET as listRoute } from '@/app/api/v1/me/processes/route';
import { expectToMatchContract } from './contract';
import { bodyOf, invoke, type CookieStore, type InvokeInit } from './http';
import { provisionOrFail } from './client-users';
import { changePassword, sessionJarFor } from './password';
import type { StageStatusValue, ProcessStatusValue } from './processes';

/** `MyStage` of the contract, as the API answers it. */
export type MyStageBody = {
  position: number;
  name: string;
  description: string | null;
  status: StageStatusValue;
  startedAt: string | null;
  completedAt: string | null;
};

/** `MyProcessSummary` of the contract. */
export type MyProcessSummaryBody = {
  id: string;
  title: string;
  status: ProcessStatusValue;
  currentStage: { position: number; name: string } | null;
  totalStages: number;
  completedStages: number;
  progressPercent: number;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
};

/** `MyProcessDetail` of the contract: the summary plus every stage. */
export type MyProcessDetailBody = MyProcessSummaryBody & { stages: MyStageBody[] };

export type MyProcessListBody = { items: MyProcessSummaryBody[]; nextCursor: string | null };

type Session = CookieStore | undefined;
const withCookies = (cookies: Session) => (cookies === undefined ? {} : { cookies });

/** What a test may still change of a request: headers, a client IP. */
type RequestExtras = Omit<InvokeInit, 'method' | 'path' | 'params' | 'query' | 'cookies'>;

/** The detail takes no query in the contract, so a test sends one only to show that it does nothing. */
type DetailExtras = RequestExtras & { readonly query?: Readonly<Record<string, string>> };

export const listMyProcessesViaApi = (
  cookies: Session,
  query: Readonly<Record<string, string>> = {},
  extras: RequestExtras = {},
) => invoke(listRoute, { path: '/me/processes', query, ...extras, ...withCookies(cookies) });

export const getMyProcessViaApi = (
  cookies: Session,
  processId: string,
  extras: DetailExtras = {},
) =>
  invoke(getRoute, {
    path: `/me/processes/${processId}`,
    params: { processId },
    ...extras,
    ...withCookies(cookies),
  });

export type SignedInClientLogin = {
  readonly userId: string;
  readonly email: string;
  /** The password the login has now (the temporary one is long gone). */
  readonly password: string;
  /** A browser session of that login, `aal1`, with nothing pending. */
  readonly cookies: CookieStore;
};

/** A password that is not the temporary one: past the 12-character minimum, within 72 bytes. */
const freshPassword = () => `Panel-${randomUUID()}`;

/**
 * A login of a client the way production makes one: a CEO provisions it (`POST /admin/clients/{id}/users`,
 * the real function), the person signs in with the temporary password (the session is opened straight at
 * Auth, so the login budget of the app is not spent) and changes it through `POST /auth/password`. The
 * cookies it returns have nothing pending, so `/me/*` is open to them. Costs one CEO write.
 */
export async function signedInClientLogin(
  ceoCookies: CookieStore,
  clientId: string,
): Promise<SignedInClientLogin> {
  const created = await provisionOrFail(ceoCookies, clientId);
  const temporary = await sessionJarFor({
    email: created.user.email,
    password: created.temporaryPassword,
  });
  const password = freshPassword();
  const changed = await changePassword(temporary, {
    currentPassword: created.temporaryPassword,
    newPassword: password,
  });
  if (changed.status !== 204) {
    throw new Error(`first access fixture failed with ${changed.status}: ${await changed.text()}`);
  }
  return {
    userId: created.user.id,
    email: created.user.email,
    password,
    cookies: await sessionJarFor({ email: created.user.email, password }),
  };
}

/**
 * Walks `GET /me/processes` page by page (up to `maxPages`) and returns every summary it finds, checking
 * each page against the contract.
 */
export async function listAllMyProcesses(
  cookies: CookieStore,
  query: Readonly<Record<string, string>> = {},
  options: { maxPages?: number } = {},
): Promise<MyProcessSummaryBody[]> {
  const { maxPages = 50 } = options;
  const found: MyProcessSummaryBody[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page += 1) {
    const response = await listMyProcessesViaApi(cookies, {
      limit: '100',
      ...query,
      ...(cursor === undefined ? {} : { cursor }),
    });
    if (response.status !== 200) {
      throw new Error(`list fixture failed with ${response.status}: ${await response.text()}`);
    }
    const body = (await bodyOf(response)) as MyProcessListBody;
    expectToMatchContract('listMyProcesses', response.status, body, response);
    found.push(...body.items);
    if (body.nextCursor === null) return found;
    cursor = body.nextCursor;
  }
  throw new Error('the process list did not end within the page limit');
}
