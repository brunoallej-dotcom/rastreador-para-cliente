import type { DomainError, Result } from '@/shared/kernel';
import type { Client, ClientListQuery, ClientPage, ClientPatch } from './client';

/**
 * Clients of the CURRENT request's session (the database decides what the session may do: reads by
 * RLS, writes by `SECURITY DEFINER` functions that check the CEO role, `aal2` and the TOTP factor).
 *
 * Every method throws `ServiceUnavailableError` when the database is slow or down (E-21). A refusal
 * by the database comes back as an `err` of the matching domain error (spec §3.7):
 * `ForbiddenError` (42501: the pipeline should have stopped this caller), `NotFoundError` or
 * `ValidationError` (invalid input). `list` throws a `ValidationError` on `query.cursor` when the
 * database cannot read the position it was given.
 */
export interface ClientRepository {
  /** Creates an active client with no processes. `name` is already validated and normalized. */
  create(name: string): Promise<Result<Client, DomainError>>;

  /** `null` when the client does not exist (or the session cannot see it). */
  find(clientId: string): Promise<Client | null>;

  /**
   * Applies the patch and returns the client as it is afterwards. `err(NotFoundError)` when the
   * client does not exist.
   */
  update(clientId: string, patch: ClientPatch): Promise<Result<Client, DomainError>>;

  /**
   * One page, newest client first (`created_at` descending, then `id` ascending). Active clients
   * only, unless `query.includeArchived`.
   */
  list(query: ClientListQuery): Promise<ClientPage>;
}
