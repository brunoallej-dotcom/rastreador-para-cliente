import { PENDING_ACTION_PRIORITY, type Aal, type PendingAction, type Role } from './principal';

export type PendingActionsInput = {
  readonly role: Role;
  readonly mustChangePassword: boolean;
  /** A verified TOTP factor exists (only meaningful for a CEO). */
  readonly hasVerifiedTotp: boolean;
  readonly aal: Aal;
};

/**
 * The pending actions of a user (spec §3.5), highest priority first:
 * - `CHANGE_PASSWORD`: the profile still carries a temporary password;
 * - `ENROLL_MFA`: a CEO without a verified TOTP factor;
 * - `VERIFY_MFA`: a CEO with a verified factor whose session is still `aal1`.
 * A client user never has an MFA pending action (MFA is mandatory for CEOs only, SEC-11).
 *
 * Lives in the kernel because both the HTTP pipeline's principal resolver (`shared/http`) and the
 * identity module need it, and `shared/` may never import a module.
 */
export function computePendingActions(input: PendingActionsInput): PendingAction[] {
  const pending = new Set<PendingAction>();
  if (input.mustChangePassword) pending.add('CHANGE_PASSWORD');
  if (input.role === 'ceo') {
    if (!input.hasVerifiedTotp) pending.add('ENROLL_MFA');
    else if (input.aal !== 'aal2') pending.add('VERIFY_MFA');
  }
  return PENDING_ACTION_PRIORITY.filter((action) => pending.has(action));
}
