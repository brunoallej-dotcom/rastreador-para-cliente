import { ok, type DomainError, type Principal, type Result } from '@/shared/kernel';
import type { ClientDirectory } from '../domain/ports';
import type { SessionView } from '../domain/session';
import { loadSessionView } from './load-session-view';

export type GetSessionDeps = { readonly clients: ClientDirectory };

/**
 * `GET /auth/session`: the principal the pipeline already authenticated, with its tenant. Reachable
 * with any pending action (the client needs it to know what to do next).
 */
export async function getSession(
  deps: GetSessionDeps,
  principal: Principal,
): Promise<Result<SessionView, DomainError>> {
  return ok(await loadSessionView(deps.clients, principal));
}
