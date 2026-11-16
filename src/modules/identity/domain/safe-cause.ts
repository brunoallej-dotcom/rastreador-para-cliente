import { DomainError } from '@/shared/kernel';
import { UnexpectedAuthAnswerError } from './errors';

/**
 * What may be kept of a failure of a dependency when a use case turns it into another error or a log
 * line: the application code of the error (`kind`), the HTTP status, and the SQLSTATE or the Auth error
 * code that came with it (`reason`). Never a message, a detail or a row: those can echo an e-mail, a name
 * or a password (SEC-16).
 *
 * The field is called `kind` and not `code` because the log redactor replaces every value under a key
 * named `code` (it protects the TOTP codes), which would blank exactly what an operator needs to read.
 */
export type SafeCause = {
  readonly kind: string;
  readonly status?: number;
  readonly reason?: string;
};

const asString = (value: unknown): string | undefined =>
  typeof value === 'string' && value !== '' ? value : undefined;
const asNumber = (value: unknown): number | undefined =>
  typeof value === 'number' ? value : undefined;

const parts = (
  kind: string,
  status: number | undefined,
  reason: string | undefined,
): SafeCause => ({
  kind,
  ...(status === undefined ? {} : { status }),
  ...(reason === undefined ? {} : { reason }),
});

/**
 * Reduces whatever a call threw or returned to a `SafeCause`. A `DomainError` keeps its own `code` as
 * `kind`, and the `code` and `status` its `cause` carries (the infrastructure keeps only those two
 * there); an unexpected Auth answer keeps the code and status it was built with; anything else is
 * `UNKNOWN`.
 */
export function safeCauseOf(error: unknown): SafeCause {
  if (error instanceof UnexpectedAuthAnswerError) {
    return parts(error.code, error.authStatus, error.authCode);
  }
  if (error instanceof DomainError) {
    const cause: unknown = error.cause;
    if (typeof cause === 'object' && cause !== null) {
      const { code, status } = cause as { code?: unknown; status?: unknown };
      return parts(error.code, asNumber(status), asString(code));
    }
    return parts(error.code, undefined, undefined);
  }
  if (typeof error === 'object' && error !== null) {
    const { code, status } = error as { code?: unknown; status?: unknown };
    return parts('UNKNOWN', asNumber(status), asString(code));
  }
  return parts('UNKNOWN', undefined, undefined);
}
