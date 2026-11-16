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

/**
 * What the Auth server answers for the factors of the user. Only the type is read from every entry:
 * the TOTP ones are filtered FIRST and only then parsed strictly (`totpFactorSchema`), so a factor
 * type that does not exist yet (`recovery_code` in a newer auth-js, say) can never turn the list
 * of TOTP factors into a 500 on the login path (F-62).
 */
const factorEnvelopeSchema = z.array(z.looseObject({ factor_type: z.string() }));

/** A TOTP factor, with the only fields the adapter reads. */
const totpFactorSchema = z.object({
  id: z.guid(),
  status: z.enum(['verified', 'unverified']),
});

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

/** `public.list_backend_totp_factors()`: the ids of the factors the backend enrolled for the user. */
const backendFactorsSchema = z.array(z.object({ factor_id: z.guid() }));

/** The `session_id` claim of an access token the client has verified. */
const sessionIdSchema = z.guid();

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

      const envelope = factorEnvelopeSchema.safeParse(data.all);
      if (!envelope.success) throw new Error('list the factors: an answer that is not understood');
      const totp = z
        .array(totpFactorSchema)
        .safeParse(envelope.data.filter((factor) => factor.factor_type === 'totp'));
      if (!totp.success) throw new Error('list the factors: an answer that is not understood');

      // Which of them the backend enrolled (F-60, F-61). The user's own session reads it: the
      // database function answers only for the principal of that session.
      const registry = await attempt(
        'list the backend factors',
        async () => await supabase.rpc('list_backend_totp_factors'),
      );
      if (registry.error) {
        if (registry.status === UNAUTHORIZED_STATUS) {
          throw new UnauthenticatedError('list the backend factors: the session was rejected', {
            cause: registry.error,
            detail: 'Authentication required.',
          });
        }
        throw upstreamFailure('list the backend factors', registry.error, registry.status);
      }
      const enrolled = backendFactorsSchema.safeParse(registry.data);
      if (!enrolled.success) {
        throw new Error('list the backend factors: an answer that is not understood');
      }
      const backendIds = new Set(enrolled.data.map((row) => row.factor_id.toLowerCase()));

      return totp.data.map((factor) => ({
        id: factor.id,
        verified: factor.status === 'verified',
        backendEnrolled: backendIds.has(factor.id.toLowerCase()),
      }));
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

    async verifyTotp({ factorId, code, burnCode, recordChallenge }) {
      // 1. Burn the code BEFORE the Auth server sees it (F-21): the Auth server accepts the same
      //    code again inside its window, the database does not. A wrong code is burned too, which
      //    costs nothing (a code is single-use whatever its fate). The burn is the ADMIN path's, not
      //    this client's (F-65): with the user's own session it was a code oracle at PostgREST. It
      //    also checks that the factor is a TOTP factor of THIS user, so nobody burns another
      //    account's codes. What it receives is the digest, never the code.
      const burned = await burnCode(codeDigest(factorId, code));
      if (!burned.ok) return burned;

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

      // 2b. The backend records the challenge it just made BEFORE the Auth server can verify it:
      //     the attestation tells these challenges from the ones made straight at Auth (F-63). If it
      //     cannot, the code is never tried (a throw is a 503, fail closed).
      const recorded = await recordChallenge(challengeId.data.id);
      if (!recorded.ok) return recorded;

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
      return ok({ challengeId: challengeId.data.id });
    },

    async currentSessionId() {
      // The claims of the access token the client holds NOW (after a verification, the new one),
      // verified against the project's signing keys; the id is not read from an unverified cookie.
      let result: Awaited<ReturnType<typeof supabase.auth.getClaims>>;
      try {
        result = await supabase.auth.getClaims();
      } catch (cause) {
        throw upstreamFailure('read the session claims', cause);
      }
      if (result.error) throw failure('read the session claims', result.error);
      const sessionId = sessionIdSchema.safeParse(result.data?.claims.session_id);
      if (!sessionId.success) {
        throw new Error('read the session claims: no session id in the token');
      }
      return sessionId.data;
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
