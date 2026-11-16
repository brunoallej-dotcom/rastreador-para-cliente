import { DomainError, ServiceUnavailableError, type DomainErrorOptions } from '@/shared/kernel';

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
 * The login was created in the Auth server but the database refused or lost the record of it
 * (`account.provisioned`, E-23), and the compensation worked: the account was deleted again, so nothing
 * was left behind and the temporary password was never shown. A 503 so the CEO repeats the request.
 */
export class ClientUserProvisionRolledBackError extends ServiceUnavailableError {
  constructor(options?: DomainErrorOptions) {
    super('the login was created but could not be recorded; it was deleted again', {
      detail: 'The login was not created. Try again.',
      ...options,
    });
  }
}

/**
 * Like `ClientUserProvisionRolledBackError`, but the compensation failed too: an account exists in the
 * Auth server (and has a profile) that nobody was given the password of and the audit trail does not
 * show. Not a silent state: the log carries an error-level event with the user id, and the CEO finds
 * the login in the list. The recovery is to reset its password (which hands over a usable one and is
 * audited) or to disable it. The e-mail is taken until then, so a repeat answers 409.
 */
export class ClientUserProvisionOrphanedError extends ServiceUnavailableError {
  /** The id of the account left behind: for the log and the operator, never part of the response. */
  readonly userId: string;

  constructor(userId: string, options?: DomainErrorOptions) {
    super('the login was created, could not be recorded, and could not be deleted again', {
      detail:
        'The login may exist without having been handed over. Look for it in the list of logins ' +
        'and reset its password, or disable it.',
      ...options,
    });
    this.userId = userId;
  }
}

/**
 * The new password of a reset is stored in the Auth server but the database step that makes the user
 * change it failed: the old password no longer works and the sessions are gone (the Auth server drops
 * them when a password is replaced), but the pending `CHANGE_PASSWORD`, the new baseline of the 72 h and
 * the audit event are not recorded. The temporary password was never shown. Safe to repeat: the repeat
 * stores another password and finishes the job. A 503, with an error-level log event.
 */
export class ClientUserResetIncompleteError extends ServiceUnavailableError {
  constructor(options?: DomainErrorOptions) {
    super('the password was replaced but the account was not marked for a change', {
      detail: 'The reset did not complete. Repeat it.',
      ...options,
    });
  }
}
