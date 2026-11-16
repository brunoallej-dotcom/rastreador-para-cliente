import {
  err,
  ForbiddenError,
  ok,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';

/**
 * The tenant of the client panel, read from the SESSION and from nowhere else (SEC-03): the
 * principal's `clientId`. Only a `client` has one. A CEO is refused (the pipeline already did it,
 * E-07; this is the second line), and so is a client with no tenant, which no healthy profile is
 * (fail closed: a read with no tenant must never run without a filter).
 */
export function requireClientTenant(principal: Principal): Result<string, DomainError> {
  if (principal.role !== 'client' || principal.clientId === null) {
    return err(
      new ForbiddenError('only a client reads its own processes', { detail: 'Access denied.' }),
    );
  }
  return ok(principal.clientId);
}
