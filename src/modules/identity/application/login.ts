import { err, ok, type Result } from '@/shared/kernel';
import { InvalidCredentialsError } from '../domain/errors';
import type { AuthGateway, ClientDirectory, Credentials, PrincipalQuery } from '../domain/ports';
import type { SessionView } from '../domain/session';
import { loadSessionView } from './load-session-view';

export type LoginDeps = {
  readonly auth: AuthGateway;
  readonly principals: PrincipalQuery;
  readonly clients: ClientDirectory;
};

/**
 * `POST /auth/login` (spec §3.4, SEC-12). The input is already normalized and validated.
 *
 * 1. Sign in. Refused credentials → `InvalidCredentialsError`.
 * 2. Read the principal with the session just opened. No principal means the account cannot be
 *    used (a disabled profile): the session is revoked and the answer is the SAME
 *    `InvalidCredentialsError`, so an outsider cannot tell a disabled account from a wrong
 *    password.
 * 3. Add the tenant and return the session view.
 *
 * Whatever goes wrong after step 1 revokes the session before the failure propagates, so a login
 * that does not complete never leaves a live session behind.
 */
export async function login(
  deps: LoginDeps,
  credentials: Credentials,
): Promise<Result<SessionView, InvalidCredentialsError>> {
  const signedIn = await deps.auth.signInWithPassword(credentials);
  if (!signedIn.ok) return signedIn;

  try {
    const principal = await deps.principals.current();
    if (principal === null) {
      await revokeQuietly(deps.auth);
      return err(new InvalidCredentialsError('account_inactive'));
    }
    return ok(await loadSessionView(deps.clients, principal));
  } catch (error) {
    await revokeQuietly(deps.auth);
    throw error;
  }
}

/**
 * Best-effort revocation of a session this login opened and is about to refuse. It must not turn
 * the generic 401 into a different answer, and it cannot hurt when it fails: the tokens were never
 * handed to anyone (the response sets no cookie) and a disabled profile has no principal anyway.
 */
async function revokeQuietly(auth: AuthGateway): Promise<void> {
  try {
    await auth.signOut();
  } catch {
    // see above
  }
}
