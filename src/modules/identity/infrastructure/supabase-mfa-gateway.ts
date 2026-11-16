import { createHash } from 'node:crypto';
import { z } from 'zod';
import { readCurrentPrincipal } from '@/shared/db/current-principal';
import type { RequestSupabase } from '@/shared/db/server-client';
import { upstreamFailure } from '@/shared/db/upstream-errors';
import { ConflictError, err, ok, UnauthenticatedError } from '@/shared/kernel';
import { InvalidMfaCodeError, MfaAlreadyEnrolledError } from '../domain/mfa-errors';
import type { MfaGateway } from '../domain/mfa-ports';
import type { PrincipalQuery } from '../domain/ports';

/** The name an authenticator app shows for the account (the issuer of the `otpauth://` URI). */
const TOTP_ISSUER = 'Rastreador';

const UNAUTHORIZED_STATUS = 401;

/**
 * The Auth server's own error codes this adapter reads (`error.code`), and what each one means for
 * the use case. Anything else an answer can say is NOT about the code or the factors: it is an
 * outage (503, E-21) or an unexpected answer (500), never a 422.
 * - `mfa_verification_failed`: the code is wrong or expired;
 * - `mfa_factor_not_found`: the factor does not exist for this user. It answers like a wrong code
 *   (same 422), so factor ids cannot be probed;
 * - `mfa_factor_name_conflict`: a factor already exists (GoTrue keeps one unnamed factor per user,
 *   which is what we create), so another enrollment raced this one;
 * - `insufficient_aal`: GoTrue wants `aal2` to ADD a factor, which it only asks of a user who has a
 *   verified one.
 */
const FACTOR_NOT_FOUND = 'mfa_factor_not_found';
const VERIFICATION_FAILED = 'mfa_verification_failed';
const FACTOR_NAME_CONFLICT = 'mfa_factor_name_conflict';
const INSUFFICIENT_AAL = 'insufficient_aal';

/**
 * Auth answers that say the SESSION is gone or unusable (revoked, or its user deleted, or a token
 * the server rejects) rather than anything about the MFA call: the pipeline had accepted the
 * session a moment ago, so it ended in between. They are a 401, like a session that was never valid.
 */
const SESSION_GONE_CODES: ReadonlySet<string> = new Set([
  'session_not_found',
  'bad_jwt',
  'user_not_found',
]);

/** `PostgREST` answer of `consume_totp_code`: SQLSTATE `P0001` with the catalog `MESSAGE`. */
const SQL_BUSINESS_RULE = 'P0001';
const SQL_NOT_FOUND = 'NOT_FOUND';
const SQL_INSUFFICIENT_PRIVILEGE = '42501';

/** What the Auth server answers for a factor: only the fields the adapter reads. */
const factorListSchema = z.array(
  z.object({
    id: z.guid(),
    factor_type: z.string(),
    status: z.enum(['verified', 'unverified']),
  }),
);

/**
 * What a new TOTP factor looks like. The shapes are the ones of the contract's `TotpEnrollment`:
 * checking them here keeps a malformed upstream answer from becoming a malformed response.
 */
const enrollmentSchema = z.object({
  id: z.guid(),
  type: z.literal('totp'),
  totp: z.object({
    uri: z.string().startsWith('otpauth://totp/'),
    secret: z.string().regex(/^[A-Za-z2-7]+=*$/),
    qr_code: z.string().startsWith('data:image/svg+xml'),
  }),
});

const challengeSchema = z.object({ id: z.guid() });

const errorCodeOf = (error: unknown): string | undefined => {
  const { code } = error as { code?: unknown };
  return typeof code === 'string' ? code : undefined;
};

/**
 * What the database stores to refuse a replay (F-21): the SHA-256 of `<factorId>:<code>` as a
 * PostgREST `bytea` literal. The code itself never reaches the database or any log.
 */
export function codeDigest(factorId: string, code: string): string {
  return `\\x${createHash('sha256').update(`${factorId}:${code}`).digest('hex')}`;
}

/**
 * The failure to throw when a call to Auth returned an error this adapter has no meaning for:
 * - a session the server says is gone or rejected (`SESSION_GONE_CODES`, an `AuthSessionMissingError`
 *   or an HTTP 401) is a 401: it was revoked after the pipeline checked it;
 * - an outage is a 503 (`upstreamFailure`). That includes a 429 from Auth: the server's own limits
 *   are about the service, never about this caller's code, so they must not look like a refused
 *   code;
 * - anything else is a 500.
 * The message is for logs and never reaches the client.
 */
function failure(operation: string, error: unknown): Error {
  const { status, name } = error as { status?: unknown; name?: unknown };
  const code = errorCodeOf(error);
  if (
    status === UNAUTHORIZED_STATUS ||
    name === 'AuthSessionMissingError' ||
    (code !== undefined && SESSION_GONE_CODES.has(code))
  ) {
    return new UnauthenticatedError(`${operation}: the session was rejected`, {
      cause: error,
      detail: 'Authentication required.',
    });
  }
  return upstreamFailure(operation, error);
}

/** Runs a call; whatever it throws (instead of returning `{ error }`) is an outage or a bug. */
async function attempt<T>(operation: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (cause) {
    throw upstreamFailure(operation, cause);
  }
}

/**
 * Supabase Auth's MFA behind identity's ports, on the request-scoped client: the one the principal
 * resolver used, so the session it has just checked is the one MFA acts on, and the cookies
 * `mfa.verify` rewrites go through the pipeline's jar into the response.
 *
 * It also reads the principal (`current_principal()`), because the use case needs the principal of
 * the NEW session once the code is accepted.
 */
export function createSupabaseMfaGateway(supabase: RequestSupabase): MfaGateway & PrincipalQuery {
  return {
    async listTotpFactors() {
      const { data, error } = await attempt('list the factors', () =>
        supabase.auth.mfa.listFactors(),
      );
      if (error) throw failure('list the factors', error);

      const factors = factorListSchema.safeParse(data.all);
      if (!factors.success) throw new Error('list the factors: an answer that is not understood');
      return factors.data
        .filter((factor) => factor.factor_type === 'totp')
        .map((factor) => ({ id: factor.id, verified: factor.status === 'verified' }));
    },

    async removeUnverifiedTotp(factorId) {
      // The caller lists first and passes only unverified factors; and the Auth server needs `aal2`
      // to delete a verified one, so a mistake here cannot remove the CEO's working factor.
      const { error } = await attempt('remove a factor', () =>
        supabase.auth.mfa.unenroll({ factorId }),
      );
      // A factor that is already gone is the state this call was after. Two tabs enrolling at the
      // same time both list the same candidate and both remove it: the second finds it deleted. The
      // last one to create its factor wins (the other tab's factor is removed, or its creation
      // refused as a name conflict, which is a retryable 409).
      if (error && errorCodeOf(error) !== FACTOR_NOT_FOUND) {
        throw failure('remove a factor', error);
      }
    },

    async enrollTotp() {
      const { data, error } = await attempt('enroll a TOTP factor', () =>
        // No friendly name on purpose: Auth then refuses a second factor for the same user, which
        // keeps a race between two enrollments from leaving two candidates behind.
        supabase.auth.mfa.enroll({ factorType: 'totp', issuer: TOTP_ISSUER }),
      );
      if (error) {
        const code = errorCodeOf(error);
        if (code === INSUFFICIENT_AAL) return err(new MfaAlreadyEnrolledError({ cause: error }));
        if (code === FACTOR_NAME_CONFLICT) {
          return err(
            new ConflictError('enroll a TOTP factor: another enrollment is in progress', {
              cause: error,
              detail: 'Another enrollment is in progress. Try again.',
            }),
          );
        }
        throw failure('enroll a TOTP factor', error);
      }

      const enrolled = enrollmentSchema.safeParse(data);
      if (!enrolled.success) {
        throw new Error('enroll a TOTP factor: an answer that is not understood');
      }
      const { id, totp } = enrolled.data;
      return ok({ factorId: id, uri: totp.uri, secret: totp.secret, qrCode: totp.qr_code });
    },

    async verifyTotp({ factorId, code }) {
      // 1. Burn the code BEFORE the Auth server sees it (F-21): the Auth server accepts the same
      //    code again inside its window, the database does not. A wrong code is burned too, which
      //    costs nothing (a code is single-use whatever its fate). The database also checks that
      //    the factor is a TOTP factor of THIS user, so nobody burns another account's codes.
      const consumed = await attempt(
        'burn a TOTP code',
        async () =>
          await supabase.rpc('consume_totp_code', {
            p_factor_id: factorId,
            p_code_digest: codeDigest(factorId, code),
          }),
      );
      if (consumed.error) {
        const { code: sqlState, message } = consumed.error;
        if (sqlState === SQL_BUSINESS_RULE && message === SQL_NOT_FOUND) {
          return err(
            new InvalidMfaCodeError('factor_not_found', { cause: consumed.error, factorId }),
          );
        }
        // no active principal: the session ended after the pipeline accepted it
        if (sqlState === SQL_INSUFFICIENT_PRIVILEGE) {
          throw new UnauthenticatedError('burn a TOTP code: no active principal', {
            cause: consumed.error,
            detail: 'Authentication required.',
          });
        }
        throw upstreamFailure('burn a TOTP code', consumed.error, consumed.status);
      }
      if (consumed.data === false) return err(new InvalidMfaCodeError('code_reused', { factorId }));
      if (consumed.data !== true) {
        throw new Error('burn a TOTP code: an answer that is not understood');
      }

      // 2. The Auth server's own challenge and verification.
      const challenge = await attempt('challenge a factor', () =>
        supabase.auth.mfa.challenge({ factorId }),
      );
      if (challenge.error) {
        if (errorCodeOf(challenge.error) === FACTOR_NOT_FOUND) {
          return err(
            new InvalidMfaCodeError('factor_not_found', { cause: challenge.error, factorId }),
          );
        }
        throw failure('challenge a factor', challenge.error);
      }
      const challengeId = challengeSchema.safeParse(challenge.data);
      if (!challengeId.success) {
        throw new Error('challenge a factor: an answer that is not understood');
      }

      const verified = await attempt('verify a factor', () =>
        supabase.auth.mfa.verify({ factorId, challengeId: challengeId.data.id, code }),
      );
      if (verified.error) {
        const verifiedCode = errorCodeOf(verified.error);
        if (verifiedCode === FACTOR_NOT_FOUND) {
          return err(
            new InvalidMfaCodeError('factor_not_found', { cause: verified.error, factorId }),
          );
        }
        if (verifiedCode === VERIFICATION_FAILED) {
          return err(new InvalidMfaCodeError('invalid_code', { cause: verified.error, factorId }));
        }
        throw failure('verify a factor', verified.error);
      }
      return ok(undefined);
    },

    async revokeOtherSessions() {
      // `others`: the Auth client leaves the current session (and so the cookies) as it is. It
      // reports success for a 401, 403 or 404 of the Auth server (it takes them for "already signed
      // out"), so a revocation that did not happen for that reason is not visible here.
      const { error } = await attempt('revoke the other sessions', () =>
        supabase.auth.signOut({ scope: 'others' }),
      );
      if (error) throw failure('revoke the other sessions', error);
    },

    current() {
      return readCurrentPrincipal(supabase);
    },
  };
}
