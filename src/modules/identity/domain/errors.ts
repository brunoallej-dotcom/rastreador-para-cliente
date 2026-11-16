import { DomainError, ServiceUnavailableError, type DomainErrorOptions } from '@/shared/kernel';

/**
 * Why a sign-in was refused, for the LOG only (`auth.login.failed`). It is never part of the
 * response: the client always gets the same 401.
 * - `invalid_credentials`: the e-mail is unknown or the password is wrong;
 * - `account_inactive`: the credentials are right but the account cannot sign in (banned or
 *   disabled in Auth, e-mail not confirmed, or a profile that is disabled).
 */
export type CredentialsRefusal = 'invalid_credentials' | 'account_inactive';

/**
 * Sign-in refused. The SAME response for an unknown e-mail, a wrong password and an account that
 * cannot sign in (SEC-12): same code, same detail, so the problem bodies are identical except for
 * `requestId`. The response never says which of them happened; `reason` is for the log.
 */
export class InvalidCredentialsError extends DomainError {
  readonly code = 'INVALID_CREDENTIALS';
  readonly reason: CredentialsRefusal;

  constructor(reason: CredentialsRefusal = 'invalid_credentials') {
    super('invalid credentials', { detail: 'The e-mail or the password is incorrect.' });
    this.reason = reason;
  }
}

/**
 * The Auth server answered something that is neither a success nor one of the known refusals of
 * credentials (an unknown error code, a 4xx about the request or the API key, a missing session).
 * It is a problem of the service, not of the credentials, so the response is 503: a misconfigured
 * key must never look like a wrong password. The status and code are for the log (they carry no
 * personal data).
 */
export class UnexpectedAuthAnswerError extends ServiceUnavailableError {
  readonly authStatus: number | undefined;
  readonly authCode: string | undefined;

  constructor(
    message: string,
    answer: { readonly status?: number | undefined; readonly code?: string | undefined },
    options?: DomainErrorOptions,
  ) {
    super(message, options);
    this.authStatus = answer.status;
    this.authCode = answer.code;
  }
}
