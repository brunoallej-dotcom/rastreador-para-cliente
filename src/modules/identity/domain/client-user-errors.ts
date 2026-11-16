import { DomainError, ServiceUnavailableError, type DomainErrorOptions } from '@/shared/kernel';
import { UnexpectedAuthAnswerError } from './errors';
import type { SafeCause } from './safe-cause';

/**
 * No new login for an archived client (E-16). 422 `CLIENT_ARCHIVED`. Archiving never touches the logins
 * that already exist (F-58, Q-08): they keep signing in, and a CEO can still list, rename, disable and
 * reset them.
 */
export class ClientArchivedError extends DomainError {
  readonly code = 'CLIENT_ARCHIVED';

  constructor(message = 'the client is archived', options?: DomainErrorOptions) {
    super(message, { detail: 'The client is archived: it cannot get new logins.', ...options });
  }
}

/** The client already has the maximum number of logins (E-18). 422 `USER_LIMIT_REACHED`. */
export class UserLimitReachedError extends DomainError {
  readonly code = 'USER_LIMIT_REACHED';

  constructor(
    message = 'the client has the maximum number of logins',
    options?: DomainErrorOptions,
  ) {
    super(message, { detail: 'The client already has the maximum number of logins.', ...options });
  }
}

/**
 * The e-mail already has an account, of any role and of any client (E-17). 409
 * `EMAIL_ALREADY_REGISTERED`. Only a CEO ever reads it, so telling that the address is taken is not an
 * enumeration channel for the public (SEC-12 is about the unauthenticated login).
 */
export class EmailAlreadyRegisteredError extends DomainError {
  readonly code = 'EMAIL_ALREADY_REGISTERED';

  constructor(message = 'the e-mail already has an account', options?: DomainErrorOptions) {
    super(message, { detail: 'An account with this e-mail already exists.', ...options });
  }
}

/**
 * Why a login that was created in the Auth server had to be taken back: the database refused or lost
 * the record of it (`account.provisioned`, E-23) or the creation itself did not answer in a way that
 * says whether it worked and the account turned up in the client's list anyway (E-50).
 */
export type ProvisionTakeBackReason = 'record_failed' | 'answer_lost';

/**
 * The login was created in the Auth server but could not be completed (see `ProvisionTakeBackReason`),
 * and the compensation worked: the account was deleted again, so nothing was left behind and the
 * temporary password was never shown. A 503 so the CEO repeats the request.
 */
export class ClientUserProvisionRolledBackError extends ServiceUnavailableError {
  /** The id of the account that was taken back: for the log, never part of the response. */
  readonly userId: string;
  readonly reason: ProvisionTakeBackReason;

  constructor(userId: string, reason: ProvisionTakeBackReason, options?: DomainErrorOptions) {
    super('the login was created but could not be completed; it was deleted again', {
      detail: 'The login was not created. Try again.',
      ...options,
    });
    this.userId = userId;
    this.reason = reason;
  }
}

/**
 * Like `ClientUserProvisionRolledBackError`, but the compensation failed too: an account exists in the
 * Auth server (and has a profile) that nobody was given the password of. Not a silent state: the log
 * carries an error-level event with the user id and why the deletion failed (a safe status and code,
 * never a message), and the CEO finds the login in the list. The recovery is to reset its password
 * (which hands over a usable one and is audited) or to disable it. The e-mail is taken until then, so
 * a repeat answers 409.
 *
 * `record_failed`: the audit record failed (E-23, log `provision_orphaned`; the account has no
 * `account.provisioned`). `answer_lost`: the creation did not answer but the account exists (E-50, log
 * `provision_answer_lost`).
 */
export class ClientUserProvisionOrphanedError extends ServiceUnavailableError {
  /** The id of the account left behind: for the log and the operator, never part of the response. */
  readonly userId: string;
  readonly reason: ProvisionTakeBackReason;
  /** Why the last deletion failed: a code and a status, for the log. */
  readonly deleteFailure: SafeCause;

  constructor(
    userId: string,
    reason: ProvisionTakeBackReason,
    deleteFailure: SafeCause,
    options?: DomainErrorOptions,
  ) {
    super('the login was created, could not be completed, and could not be deleted again', {
      detail:
        'The login may exist without having been handed over. Look for it in the list of logins ' +
        'and reset its password, or disable it.',
      ...options,
    });
    this.userId = userId;
    this.reason = reason;
    this.deleteFailure = deleteFailure;
  }
}

/**
 * A creation that failed without an answer, and the client's list now shows a new login with the e-mail
 * of the request that the use case will NOT take for its own and delete: more than one candidate, or one
 * created before this attempt started (another CEO may have provisioned the same address a moment
 * earlier, and ITS login must never be deleted, F-90, M1). Fail closed: nothing is destroyed, the answer
 * is a 503, and the log (`provision_answer_lost`, with the id or ids, `deleted: false`) lets a person
 * decide. Repeating the request then answers 409 (the address is taken).
 */
export class ClientUserProvisionAnswerLostError extends ServiceUnavailableError {
  /** The candidates, for the log: never part of the response. */
  readonly userIds: readonly string[];

  constructor(userIds: readonly string[], options?: DomainErrorOptions) {
    super('the creation did not answer and a login with the e-mail exists; nothing was deleted', {
      detail:
        'The login may have been created, by this request or by another one. ' +
        'Look for it in the list of logins before trying again.',
      ...options,
    });
    this.userIds = userIds;
  }
}

/**
 * The Auth server accepted the creation but its answer carries no usable user id (E-55): the account
 * exists and cannot be named. A 503 (an unexpected answer of the service: never a 500, and never a 201
 * without the password having been handed over). The use case looks for the account by e-mail in the
 * client's list and takes it back when it finds it; when it does not (the list is unavailable, or the
 * account is not there), this error reaches the handler, which logs `provision_unconfirmed` (no
 * e-mail, no id) so a person looks.
 */
export class ClientUserProvisionUnconfirmedError extends UnexpectedAuthAnswerError {
  constructor(options?: DomainErrorOptions) {
    super(
      'create the login: the answer carries no user id',
      {},
      {
        detail:
          'The login may have been created. Look for it in the list of logins before trying again.',
        ...options,
      },
    );
  }
}

/**
 * The new password of a reset is stored in the Auth server but the database step that makes the user
 * change it failed: the old password no longer works and the sessions are gone (the Auth server drops
 * them when a password is replaced), but the pending `CHANGE_PASSWORD`, the new baseline of the 72 h and
 * the audit event are not recorded. The temporary password was never shown. Safe to repeat: the repeat
 * stores another password and finishes the job. A 503, with an error-level log event.
 *
 * It is the answer to EVERY way the database step can fail once the password is stored, not only an
 * outage: a refusal of the caller (an attestation that expired meanwhile, 403), a user that is gone
 * (404) or an input the database refuses are not answers about the request any more, because the
 * password has already changed. `cause` is a `SafeCause`: the code and the status, never a message.
 */
export class ClientUserResetIncompleteError extends ServiceUnavailableError {
  /** Why the database step failed, for the log. */
  readonly failure: SafeCause;

  constructor(failure: SafeCause) {
    super('the password was replaced but the account was not marked for a change', {
      detail: 'The reset did not complete. Repeat it.',
      cause: failure,
    });
    this.failure = failure;
  }
}
