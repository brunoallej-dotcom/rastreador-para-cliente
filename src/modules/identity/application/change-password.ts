import { ok, ServiceUnavailableError, type DomainError, type Result } from '@/shared/kernel';
import { UnexpectedAuthAnswerError } from '../domain/errors';
import {
  PasswordChangeIncompleteError,
  PasswordChangeUncertainError,
  PasswordUnchangedError,
} from '../domain/password-errors';
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
 * Step 3 cannot be undone, and it can fail without saying whether it was applied (the answer may be
 * what was lost): that is `PasswordChangeUncertainError` (503). If step 4 keeps failing because the
 * database is unavailable, the password is already new and the pendency is still set: that is
 * `PasswordChangeIncompleteError` (503), and not a silent success. A refusal of step 4 (no proof of a
 * change, or a role the function refuses) is returned as the error it is.
 */
export async function changePassword(
  deps: ChangePasswordDeps,
  change: PasswordChange,
): Promise<Result<void, DomainError>> {
  const policy = checkPasswordChange(change);
  if (!policy.ok) return policy;

  const verified = await deps.passwords.verifyCurrentPassword(change.currentPassword);
  if (!verified.ok) return verified;

  const updated = await update(deps.passwords, change);
  if (!updated.ok) return updated;

  return markChanged(deps.passwords);
}

async function update(
  passwords: PasswordGateway,
  change: PasswordChange,
): ReturnType<PasswordGateway['updatePassword']> {
  try {
    return await passwords.updatePassword(change);
  } catch (error) {
    // The service did not answer (transport failure, timeout, 5xx, 429): the request may have been
    // applied before the answer was lost, so the state is unknown. A definitive answer of the Auth
    // server, even an unexpected one (`UnexpectedAuthAnswerError`: a 4xx nobody mapped), is not an
    // outage: nothing was applied, and it propagates as it is.
    if (error instanceof ServiceUnavailableError && !(error instanceof UnexpectedAuthAnswerError)) {
      throw new PasswordChangeUncertainError({ cause: error });
    }
    throw error;
  }
}

async function markChanged(passwords: PasswordGateway): Promise<Result<void, DomainError>> {
  let lastFailure: unknown;
  for (let attempt = 1; attempt <= MARK_ATTEMPTS; attempt += 1) {
    try {
      const marked = await passwords.markPasswordChanged();
      if (marked.ok) return ok(undefined);
      // On a RETRY only: `PASSWORD_UNCHANGED` is success. The Auth server has already stored the new
      // password (step 3), so the hash differs from the baseline unless a previous attempt of this
      // very request committed: committing renews the baseline to the current hash, clears the
      // pendency and revokes the other sessions. An earlier attempt that failed with a timeout may
      // have committed with its answer lost; nothing else can make the baseline equal to the hash
      // after a successful update. On the FIRST attempt the same answer is a real refusal.
      if (attempt > 1 && marked.error instanceof PasswordUnchangedError) return ok(undefined);
      return marked;
    } catch (error) {
      // only an outage is worth another try; anything else is a bug or a refusal to report as is
      if (!(error instanceof ServiceUnavailableError)) throw error;
      lastFailure = error;
    }
  }
  throw new PasswordChangeIncompleteError({ cause: lastFailure });
}
