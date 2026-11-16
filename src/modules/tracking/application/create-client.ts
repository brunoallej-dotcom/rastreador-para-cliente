import {
  err,
  ForbiddenError,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { Client } from '../domain/client';
import type { ClientRepository } from '../domain/client-repository';

export type CreateClientDeps = { readonly clients: ClientRepository };

/** `name` is already validated and normalized (NFC, trimmed, 1 to 160 visible characters). */
export type CreateClientInput = { readonly name: string };

/**
 * `POST /admin/clients` (RF-06, AC-11): a CEO creates an active client. The pipeline already
 * checked the role and `aal2`; the role is checked again here as the rule of the use case, and the
 * database function checks it a third time (spec §3.5).
 */
export async function createClient(
  deps: CreateClientDeps,
  principal: Principal,
  input: CreateClientInput,
): Promise<Result<Client, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO creates clients', { detail: 'Access denied.' }));
  }
  return deps.clients.create(input.name);
}
