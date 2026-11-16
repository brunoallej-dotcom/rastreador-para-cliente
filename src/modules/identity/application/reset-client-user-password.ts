import {
  err,
  ok,
  ServiceUnavailableError,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import { ClientUserResetIncompleteError } from '../domain/client-user-errors';
import type { AccountAdminGateway, ClientUserRepository } from '../domain/client-user-ports';
import { safeCauseOf } from '../domain/safe-cause';
import { generateTemporaryPassword } from '../domain/temporary-password';
import { ceoOnly, clientLoginNotFound, findClientLogin } from './client-user-access';

export type ResetClientUserPasswordDeps = {
  readonly users: ClientUserRepository;
  readonly accounts: AccountAdminGateway;
  /** Default: `generateTemporaryPassword`. Tests inject one. */
  readonly generatePassword?: () => string;
};

export type ResetClientUserPasswordInput = {
  readonly clientId: string;
  readonly userId: string;
};

/** The database step is tried this many times when the database is briefly unavailable. */
const REQUIRE_CHANGE_ATTEMPTS = 2;

/**
 * `POST /admin/clients/{clientId}/users/{userId}/password-reset` (RF-07, AC-14, E-35, F-41): gives the
 * login a NEW temporary password (20 characters, CSPRNG) and hands it back once. A user that is not a
 * login of THAT client is 404 (E-19).
 *
 * The order is the one of spec §3.4 and it is not negotiable: the password is stored in the Auth server
 * FIRST, and only then does `require_password_change` run, which records the baseline of the NEW hash
 * (restarting the 72 h, F-70), sets `CHANGE_PASSWORD` and deletes every session of the user (AC-14). The
 * other order would leave the old password working until the Auth call, and the baseline would prove a
 * "change" the user never made.
 *
 * What a failure in the middle leaves behind is safe and repeatable:
 * - the Auth call fails: nothing changed (or the new password is set and its answer was lost: nobody
 *   knows it, the old one no longer works). 503, repeat the reset;
 * - the database step fails after the Auth call, for ANY reason (an outage, a refusal of the caller, a
 *   login that is gone): `ClientUserResetIncompleteError` (503, error log). The old
 *   password no longer works, the new one was never shown, and the user's sessions are already gone (the
 *   Auth server drops them when a password is replaced, observed on the local stack). What is missing is
 *   the database side: `CHANGE_PASSWORD`, the new baseline and the audit event. The repeat stores another
 *   password and finishes the job.
 * The temporary password is shown only when BOTH steps worked.
 */
export async function resetClientUserPassword(
  deps: ResetClientUserPasswordDeps,
  principal: Principal,
  input: ResetClientUserPasswordInput,
): Promise<Result<{ readonly temporaryPassword: string }, DomainError>> {
  const forbidden = ceoOnly(principal);
  if (forbidden !== null) return err(forbidden);

  const target = await findClientLogin(deps.users, input.clientId, input.userId);
  if (!target.ok) return target;

  const temporaryPassword = (deps.generatePassword ?? generateTemporaryPassword)();
  const stored = await deps.accounts.setPassword(input.userId, temporaryPassword);
  if (!stored.ok) return err(clientLoginNotFound());

  await requirePasswordChange(deps.users, input.userId);

  return ok({ temporaryPassword });
}

/**
 * The database step, AFTER the password is stored. From here on nothing is an answer about the request
 * any more, because the password has already changed: an outage, a refusal of the caller (an attestation
 * that expired meanwhile, 403), a login that is gone (404), an input the database refuses, even a bug
 * all end the same way, in `ClientUserResetIncompleteError` (503, the error log), with only a code and
 * a status as the cause. Returning a 403 or a 404 here would tell the CEO the reset did not happen.
 *
 * Only an outage is worth another try. A retry is not free of side effects: when the first attempt
 * committed and only its answer was lost, the second one writes a second `account.password_reset` event
 * (the baseline and the pending action end up the same).
 */
async function requirePasswordChange(users: ClientUserRepository, userId: string): Promise<void> {
  let failure: unknown;
  for (let attempt = 1; attempt <= REQUIRE_CHANGE_ATTEMPTS; attempt += 1) {
    try {
      const marked = await users.requirePasswordChange(userId);
      if (marked.ok) return;
      failure = marked.error;
      break;
    } catch (error) {
      failure = error;
      if (!(error instanceof ServiceUnavailableError)) break;
    }
  }
  throw new ClientUserResetIncompleteError(safeCauseOf(failure));
}
