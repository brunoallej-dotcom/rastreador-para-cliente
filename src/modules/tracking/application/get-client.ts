import {
  err,
  ForbiddenError,
  NotFoundError,
  ok,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { Client } from '../domain/client';
import type { ClientRepository } from '../domain/client-repository';

export type GetClientDeps = { readonly clients: ClientRepository };

export type GetClientInput = { readonly clientId: string };

/**
 * `GET /admin/clients/{clientId}` (RF-06): a CEO reads one client with its process counters. A
 * client that does not exist is `NotFoundError` (404).
 */
export async function getClient(
  deps: GetClientDeps,
  principal: Principal,
  input: GetClientInput,
): Promise<Result<Client, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO reads clients', { detail: 'Access denied.' }));
  }
  const client = await deps.clients.find(input.clientId);
  if (client === null) {
    return err(new NotFoundError('client not found', { detail: 'Client not found.' }));
  }
  return ok(client);
}
