import type { Aal, PendingAction, Role } from '@/shared/kernel';
import type { SessionView } from '../domain/session';

/** `Session` of the contract. Explicit fields: no token, no internal flag, nothing spread. */
export type SessionDto = {
  readonly user: { readonly id: string; readonly role: Role; readonly displayName: string };
  readonly client: { readonly id: string; readonly name: string } | null;
  readonly aal: Aal;
  readonly pendingActions: readonly PendingAction[];
};

export function toSessionDto({ principal, client }: SessionView): SessionDto {
  return {
    user: { id: principal.userId, role: principal.role, displayName: principal.displayName },
    client: client === null ? null : { id: client.id, name: client.name },
    aal: principal.aal,
    pendingActions: [...principal.pendingActions],
  };
}
