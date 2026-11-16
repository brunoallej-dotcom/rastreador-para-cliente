import type { Principal } from '@/shared/kernel';

/** The tenant of a client user, as the session shows it. */
export type ClientSummary = { readonly id: string; readonly name: string };

/** Everything `Session` (the contract's schema) is built from: who, which tenant, which pendings. */
export type SessionView = {
  readonly principal: Principal;
  /** `null` for a CEO. */
  readonly client: ClientSummary | null;
};
