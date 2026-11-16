import {
  err,
  ForbiddenError,
  ok,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { ClientListQuery, ClientPage } from '../domain/client';
import type { ClientRepository } from '../domain/client-repository';

export type ListClientsDeps = { readonly clients: ClientRepository };

/**
 * `GET /admin/clients` (RF-06, AC-11): one page of clients for a CEO, newest first. The limit and
 * the position were validated at the edge (`1..100`, a cursor that decoded to a position).
 */
export async function listClients(
  deps: ListClientsDeps,
  principal: Principal,
  query: ClientListQuery,
): Promise<Result<ClientPage, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO lists clients', { detail: 'Access denied.' }));
  }
  return ok(await deps.clients.list(query));
}
