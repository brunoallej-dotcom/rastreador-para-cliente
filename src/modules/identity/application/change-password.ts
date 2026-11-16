import { ok, ServiceUnavailableError, type DomainError, type Result } from '@/shared/kernel';
import { PasswordChangeIncompleteError } from '../domain/password-errors';
import type { PasswordGateway } from '../domain/password-ports';
import { checkPasswordChange, type PasswordChange } from '../domain/password-policy';

export type ChangePasswordDeps = { readonly passwords: PasswordGateway };

/** The final step is tried this many times when the database is briefly unavailable. */
const MARK_ATTEMPTS = 2;

/**
 * `POST /auth/password` (spec §3.4, SEC-10). The input is already size-checked by the schema.
 *
 * 1. The new password follows the policy (E-12) and differs from the current one (E-13). Pure: no
 *    call to the backend, and the answer does not depend on whether the current password is right.
 * 2. The current password is verified (AC-06) without touching this request's session.
 * 3. The new password is stored in the Auth server, which also drops the user's other sessions.
 * 4. `mark_password_changed()` proves the change to the database (ADR 0007), clears the pending
 *    `CHANGE_PASSWORD` and revokes the other sessions again (AC-06), keeping this one.
 *
 * Step 3 cannot be undone. If step 4 keeps failing because the database is unavailable, the
 * password is already new and the pendency is still set: that is `PasswordChangeIncompleteError`
 * (503) and not a silent success. A refusal of step 4 (no proof of a change, or a role the function
 * refuses) is returned as the error it is.
 */
export async function changePassword(
  deps: ChangePasswordDeps,
  change: PasswordChange,
): Promise<Result<void, DomainError>> {
  const policy = checkPasswordChange(change);
  if (!policy.ok) return policy;

  const verified = await deps.passwords.verifyCurrentPassword(change.currentPassword);
  if (!verified.ok) return verified;

  const updated = await deps.passwords.updatePassword(change);
  if (!updated.ok) return updated;

  return markChanged(deps.passwords);
}

async function markChanged(passwords: PasswordGateway): Promise<Result<void, DomainError>> {
  let lastFailure: unknown;
  for (let attempt = 1; attempt <= MARK_ATTEMPTS; attempt += 1) {
    try {
      const marked = await passwords.markPasswordChanged();
      return marked.ok ? ok(undefined) : marked;
    } catch (error) {
      // only an outage is worth another try; anything else is a bug or a refusal to report as is
      if (!(error instanceof ServiceUnavailableError)) throw error;
      lastFailure = error;
    }
  }
  throw new PasswordChangeIncompleteError({ cause: lastFailure });
}
