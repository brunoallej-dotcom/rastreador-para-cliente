import { ok, type DomainError, type Result } from '@/shared/kernel';
import type { AuthGateway } from '../domain/ports';

export type LogoutDeps = { readonly auth: AuthGateway };

/**
 * `POST /auth/logout`: revokes the session of this request on the server (scope `local`: the
 * user's other devices stay signed in, E-09). From then on the old tokens fail, because the
 * session row is gone (AC-04). Throws `ServiceUnavailableError` when the revocation could not be
 * confirmed, so the caller never reports a logout that did not happen.
 */
export async function logout(deps: LogoutDeps): Promise<Result<void, DomainError>> {
  await deps.auth.signOut();
  return ok(undefined);
}
