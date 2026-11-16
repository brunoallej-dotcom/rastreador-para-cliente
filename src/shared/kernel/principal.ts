// The authenticated caller, as resolved by the HTTP pipeline (spec §3.4/§3.5).
// Lives in the kernel because identity's domain/ may import only `@/shared/kernel`.

export const ROLES = ['client', 'ceo'] as const;
export type Role = (typeof ROLES)[number];

/** Authenticator assurance level of the session (`aal2` = MFA verified). */
export const AALS = ['aal1', 'aal2'] as const;
export type Aal = (typeof AALS)[number];

/**
 * Things a user must still do before using most of the API. A route is reachable only if EVERY
 * pending action of the principal is in the route's `allowPending` (spec §3.5).
 */
export const PENDING_ACTIONS = ['CHANGE_PASSWORD', 'ENROLL_MFA', 'VERIFY_MFA'] as const;
export type PendingAction = (typeof PENDING_ACTIONS)[number];

/**
 * Highest priority first. When several pending actions are not allowed by a route, the 403 carries
 * the code of the first one in this list: CHANGE_PASSWORD > ENROLL_MFA > VERIFY_MFA.
 */
export const PENDING_ACTION_PRIORITY: readonly PendingAction[] = [
  'CHANGE_PASSWORD',
  'ENROLL_MFA',
  'VERIFY_MFA',
];

export type Principal = {
  readonly userId: string;
  readonly role: Role;
  /** Tenant of a `client` user. `null` for a CEO. Always comes from the session, never from input. */
  readonly clientId: string | null;
  readonly displayName: string;
  readonly aal: Aal;
  readonly pendingActions: readonly PendingAction[];
};
