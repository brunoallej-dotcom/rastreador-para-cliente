import { DomainError } from '@/shared/kernel';

/**
 * Sign-in refused. The SAME error for an unknown e-mail, a wrong password and a disabled account
 * (SEC-12): same code, same detail, so the problem bodies are identical except for `requestId`.
 * It never says which of the three happened.
 */
export class InvalidCredentialsError extends DomainError {
  readonly code = 'INVALID_CREDENTIALS';

  constructor() {
    super('invalid credentials', { detail: 'The e-mail or the password is incorrect.' });
  }
}
