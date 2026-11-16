import type { Principal } from '@/shared/kernel';
import type { ClientDirectory } from '../domain/ports';
import type { SessionView } from '../domain/session';

/**
 * Adds the tenant to a principal. The client id comes from the principal (the session), never from
 * a request. A CEO has no tenant. A client user whose tenant row cannot be read is an inconsistent
 * account (the foreign key forbids it, a policy change could cause it): the call fails, nothing is
 * guessed.
 */
export async function loadSessionView(
  clients: ClientDirectory,
  principal: Principal,
): Promise<SessionView> {
  if (principal.clientId === null) return { principal, client: null };

  const client = await clients.find(principal.clientId);
  if (client === null) throw new Error('the tenant of a client user is not readable');
  return { principal, client };
}
