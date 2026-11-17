import {
  err,
  ForbiddenError,
  ok,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { Logger } from '@/shared/observability/logger';

/**
 * What the client panel use cases log: a defect signal (`error`) and the trail of what a client read
 * (`info`). The request logger of the handler already stamps the `requestId`, and the access line of the
 * pipeline carries the user, so a line here needs only the process; it never carries a title, a stage
 * name or a client id (SEC-16).
 */
export type PanelLogger = Pick<Logger, 'error' | 'info'>;

/**
 * The tenant of the client panel, read from the SESSION and from nowhere else (SEC-03): the
 * principal's `clientId`. Only a `client` has one. A CEO is refused (the pipeline already did it,
 * E-07; this is the second line), and so is a client with no tenant, which no healthy profile is
 * (fail closed: a read with no tenant must never run without a filter). Reaching this refusal means
 * the pipeline's policy was bypassed or a profile is broken, so it is logged at `error` with the role
 * and whether a tenant was there, and nothing else.
 */
export function requireClientTenant(
  principal: Principal,
  logger: PanelLogger,
): Result<string, DomainError> {
  if (principal.role !== 'client' || principal.clientId === null) {
    logger.error(
      {
        event: 'tracking.client_panel_role_guard',
        role: principal.role,
        hasTenant: principal.clientId !== null,
      },
      'tracking.client_panel_role_guard',
    );
    return err(
      new ForbiddenError('only a client reads its own processes', { detail: 'Access denied.' }),
    );
  }
  return ok(principal.clientId);
}
