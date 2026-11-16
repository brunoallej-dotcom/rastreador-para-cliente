import {
  err,
  ForbiddenError,
  NotFoundError,
  ok,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { ClientUser } from '../domain/client-user';
import type { ClientUserRepository } from '../domain/client-user-ports';

/**
 * The second line of the authorization (the pipeline already checked the role): only a CEO touches the
 * logins of a client. A client user gets `ForbiddenError` here even if a route were ever misconfigured.
 */
export function ceoOnly(principal: Principal): ForbiddenError | null {
  return principal.role === 'ceo'
    ? null
    : new ForbiddenError('only a CEO manages client logins', { detail: 'Access denied.' });
}

/**
 * 404 for a login that is not in the client of the path: a user that does not exist, a user of ANOTHER
 * client and a CEO (E-19) all look exactly alike, and so does a client that does not exist.
 */
export const clientLoginNotFound = () =>
  new NotFoundError('client login not found', { detail: 'Client login not found.' });

/**
 * The login `userId` of the client `clientId`, or 404. The ownership check of spec §3.5: the database
 * functions that act on a login take only the user id, so the use case proves first that the user is one
 * of the logins of the client in the path (the list holds client users only, never a CEO). A profile never
 * changes client, so what is proven here still holds when the function runs.
 */
export async function findClientLogin(
  users: ClientUserRepository,
  clientId: string,
  userId: string,
): Promise<Result<ClientUser, DomainError>> {
  const listed = await users.list(clientId);
  if (!listed.ok) {
    return err(listed.error instanceof NotFoundError ? clientLoginNotFound() : listed.error);
  }
  const found = listed.value.find((user) => user.id === userId);
  return found === undefined ? err(clientLoginNotFound()) : ok(found);
}
