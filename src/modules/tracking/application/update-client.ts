import {
  err,
  ForbiddenError,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import { requireChange, type Client, type ClientPatch } from '../domain/client';
import type { ClientRepository } from '../domain/client-repository';

export type UpdateClientDeps = { readonly clients: ClientRepository };

export type UpdateClientInput = {
  readonly clientId: string;
  /** `name` is already validated and normalized; a missing field is left alone. */
  readonly patch: ClientPatch;
};

/**
 * `PATCH /admin/clients/{clientId}` (RF-06, AC-11): renames, archives or unarchives a client.
 * Archiving only stops new processes and new logins; the existing logins keep working (Q-08).
 * A patch that changes nothing is refused (400); a missing client is `NotFoundError` (404).
 */
export async function updateClient(
  deps: UpdateClientDeps,
  principal: Principal,
  input: UpdateClientInput,
): Promise<Result<Client, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO updates clients', { detail: 'Access denied.' }));
  }
  const patch = requireChange(input.patch);
  if (!patch.ok) return patch;
  return deps.clients.update(input.clientId, patch.value);
}
