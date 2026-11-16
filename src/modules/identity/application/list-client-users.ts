import { err, type DomainError, type Principal, type Result } from '@/shared/kernel';
import type { ClientUser } from '../domain/client-user';
import type { ClientUserRepository } from '../domain/client-user-ports';
import { ceoOnly } from './client-user-access';

export type ListClientUsersDeps = { readonly users: ClientUserRepository };

/**
 * `GET /admin/clients/{clientId}/users` (RF-07): the logins of one client, with e-mail and last
 * sign-in, at most 10. The client comes from the path and is trusted only because the pipeline already
 * proved the caller is a CEO; a client that does not exist is `NotFoundError` (404).
 */
export async function listClientUsers(
  deps: ListClientUsersDeps,
  principal: Principal,
  input: { readonly clientId: string },
): Promise<Result<readonly ClientUser[], DomainError>> {
  const forbidden = ceoOnly(principal);
  if (forbidden !== null) return err(forbidden);
  return deps.users.list(input.clientId);
}
