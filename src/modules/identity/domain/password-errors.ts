import { DomainError, ServiceUnavailableError, type DomainErrorOptions } from '@/shared/kernel';

/**
 * The new password breaks the password policy (E-12, SEC-10): fewer than 12 characters or more than
 * 72 bytes of UTF-8. The detail is fixed text: it never echoes the password.
 */
export class WeakPasswordError extends DomainError {
  readonly code = 'WEAK_PASSWORD';

  constructor(message = 'password policy violated', options?: DomainErrorOptions) {
    super(message, {
      detail: 'The new password must have at least 12 characters and at most 72 bytes (UTF-8).',
      ...options,
    });
  }
}

/** The new password is the same as the current one (E-13). */
export class PasswordUnchangedError extends DomainError {
  readonly code = 'PASSWORD_UNCHANGED';

  constructor(message = 'new password equals the current one', options?: DomainErrorOptions) {
    super(message, {
      detail: 'The new password must be different from the current one.',
      ...options,
    });
  }
}

/**
 * The current password given in a password change is wrong. The caller is already authenticated, so
 * this tells them nothing about any other account: it is not an enumeration channel (SEC-12 is about
 * the unauthenticated login).
 */
export class InvalidCurrentPasswordError extends DomainError {
  readonly code = 'INVALID_CURRENT_PASSWORD';

  constructor(message = 'the current password is wrong', options?: DomainErrorOptions) {
    super(message, { detail: 'The current password is incorrect.', ...options });
  }
}

/**
 * The Auth server stored the new password, but the account could not be marked as changed
 * (`mark_password_changed()` kept failing): the pending `CHANGE_PASSWORD` is still there and the old
 * password no longer works. The session of this request survives, so the way out is to repeat the
 * change using the NEW password as the current one. A 503 so a client retries, with a detail that
 * says what to retry with; the log carries an error-level event for it.
 */
export class PasswordChangeIncompleteError extends ServiceUnavailableError {
  constructor(options?: DomainErrorOptions) {
    super('the password was updated but the account was not marked as changed', {
      detail:
        'The password was updated, but the change could not be completed. ' +
        'Repeat the request using the new password as the current password.',
      ...options,
    });
  }
}
