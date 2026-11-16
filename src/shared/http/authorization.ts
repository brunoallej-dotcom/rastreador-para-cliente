import {
  PENDING_ACTION_PRIORITY,
  type PendingAction,
  type Principal,
  type Role,
} from '@/shared/kernel';
import { AuthorizationDeniedError, type PipelineErrorCode } from './pipeline-errors';

/** Code of the 403 for each pending action (spec §3.5). */
export const PENDING_ACTION_ERROR_CODES: Readonly<Record<PendingAction, PipelineErrorCode>> = {
  CHANGE_PASSWORD: 'PASSWORD_CHANGE_REQUIRED',
  ENROLL_MFA: 'MFA_ENROLLMENT_REQUIRED',
  VERIFY_MFA: 'MFA_VERIFICATION_REQUIRED',
};

export type AuthorizationRequirements = {
  readonly roles: readonly Role[];
  readonly allowPending: readonly PendingAction[];
};

/**
 * Layer 1 authorization (spec §3.5). Throws `AuthorizationDeniedError` (403) when:
 * 1. the role is not in `roles` → `FORBIDDEN`; or
 * 2. the principal has a pending action that the route does not allow. The route is open only if
 *    ALL pending actions are allowed; when several are not, the `code` is the one of the
 *    highest-priority action: CHANGE_PASSWORD > ENROLL_MFA > VERIFY_MFA.
 * The role check goes first, so a client calling `/admin/*` gets `FORBIDDEN` whatever it has pending.
 */
export function assertAuthorized(
  principal: Principal,
  requirements: AuthorizationRequirements,
): void {
  if (!requirements.roles.includes(principal.role)) {
    throw new AuthorizationDeniedError(
      'FORBIDDEN',
      'role_not_allowed',
      'You do not have access to this resource.',
    );
  }

  for (const action of PENDING_ACTION_PRIORITY) {
    if (!principal.pendingActions.includes(action)) continue;
    if (requirements.allowPending.includes(action)) continue;
    throw new AuthorizationDeniedError(
      PENDING_ACTION_ERROR_CODES[action],
      `pending_action:${action}`,
      'A pending account action must be completed first.',
    );
  }

  // Fail closed on a pending action this code does not know (e.g. a resolver ahead of the pipeline).
  const unknown = principal.pendingActions.find(
    (action) =>
      !PENDING_ACTION_PRIORITY.includes(action) && !requirements.allowPending.includes(action),
  );
  if (unknown !== undefined) {
    throw new AuthorizationDeniedError(
      'FORBIDDEN',
      `pending_action:${unknown}`,
      'A pending account action must be completed first.',
    );
  }
}
