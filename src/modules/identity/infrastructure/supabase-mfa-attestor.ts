import { z } from 'zod';
import { getAdminFacade, type AdminFacade, type AdminRpcResult } from '@/shared/db/admin-client';
import { upstreamFailure } from '@/shared/db/upstream-errors';
import { ConflictError, err, ok, UnauthenticatedError } from '@/shared/kernel';
import { InvalidMfaCodeError, MfaReenrollmentRefusedError } from '../domain/mfa-errors';
import { ATTESTATION_REFUSALS, type MfaAttestor } from '../domain/mfa-ports';

/**
 * What the admin path must offer: the `service_role` functions of the attestation and of the replay
 * guard (ADR 0013).
 */
export type MfaAdminApi = Pick<
  AdminFacade,
  'registerBackendTotpFactor' | 'recordBackendMfaChallenge' | 'attestMfaSession' | 'consumeTotpCode'
>;

/** `PostgREST` answer of the functions: SQLSTATE `P0001` with the catalog `MESSAGE` (spec §3.7). */
const SQL_BUSINESS_RULE = 'P0001';
const SQL_NOT_FOUND = 'NOT_FOUND';
/** `insufficient_privilege`: what `consume_totp_code` raises for a user that is gone or disabled. */
const SQL_INSUFFICIENT_PRIVILEGE = '42501';

/**
 * What `public.attest_mfa_session` returns: `attested`, or one of the refusal reasons it knows. A
 * string that is neither is not understood and fails closed (the session stays unattested).
 */
const attestationAnswerSchema = z.union([
  z.literal('attested'),
  z.literal('attested_activated'),
  z.enum(ATTESTATION_REFUSALS),
]);

const isNotFound = (error: NonNullable<AdminRpcResult<unknown>['error']>): boolean =>
  error.code === SQL_BUSINESS_RULE && error.message === SQL_NOT_FOUND;

/**
 * The backend's records of its own MFA work (`MfaAttestor`), written through the ADMIN path: the three
 * functions are executable by the `service_role` only, so the user's own session (and anyone holding
 * the password and the publishable key) can never write them (ADR 0006, ADR 0013). The admin facade
 * is the one the identity infrastructure may use; nothing here reads or writes business data.
 *
 * The database revalidates every id these methods send and trusts none of them. A call that fails or
 * is not understood throws (`ServiceUnavailableError` when Supabase is slow or down, a plain error
 * otherwise): nothing is attested on a failure, and the user stays at `VERIFY_MFA` (fail closed).
 *
 * `admin` is injected by the unit tests; production resolves the shared facade at the first call, so
 * building the attestor costs nothing and reads no key.
 */
export function createSupabaseMfaAttestor(admin?: MfaAdminApi): MfaAttestor {
  const adminPath = (): MfaAdminApi => admin ?? getAdminFacade();

  /** Runs a call; whatever it throws (instead of returning `{ error }`) is an outage or a bug. */
  async function call<T>(operation: string, run: () => Promise<AdminRpcResult<T>>) {
    try {
      return await run();
    } catch (cause) {
      throw upstreamFailure(operation, cause);
    }
  }

  return {
    async registerEnrollment({ userId, factorId, sessionId }) {
      const result = await call('record the enrolled factor', () =>
        adminPath().registerBackendTotpFactor({ userId, factorId, sessionId }),
      );
      if (result.error === null) {
        // F-64: the account already had its first factor activated and that one is gone; the database
        // has deleted every session of the user.
        if (result.data === 'factor_reenrolled') return err(new MfaReenrollmentRefusedError());
        return ok(undefined);
      }
      // The factor was removed between its creation and this record (another enrollment replaced it).
      if (isNotFound(result.error)) {
        return err(
          new ConflictError('record the enrolled factor: the factor is gone', {
            cause: result.error,
            detail: 'Another enrollment is in progress. Try again.',
          }),
        );
      }
      throw upstreamFailure('record the enrolled factor', result.error, result.status);
    },

    async burnCode({ userId, factorId, codeDigest }) {
      const result = await call('burn a TOTP code', () =>
        adminPath().consumeTotpCode({ userId, factorId, codeDigest }),
      );
      if (result.error === null) {
        // `false`: the same code of the same factor was accepted in the last 120 s (a replay, F-21)
        if (result.data === true) return ok(undefined);
        return err(new InvalidMfaCodeError('code_reused', { factorId }));
      }
      // not a TOTP factor of this account: answered like a wrong code, so ids cannot be probed
      if (isNotFound(result.error)) {
        return err(new InvalidMfaCodeError('factor_not_found', { cause: result.error, factorId }));
      }
      // the user is gone or disabled: the session ended after the pipeline accepted it
      if (result.error.code === SQL_INSUFFICIENT_PRIVILEGE) {
        throw new UnauthenticatedError('burn a TOTP code: no active user', {
          cause: result.error,
          detail: 'Authentication required.',
        });
      }
      throw upstreamFailure('burn a TOTP code', result.error, result.status);
    },

    async recordChallenge({ userId, factorId, challengeId }) {
      const result = await call('record the challenge', () =>
        adminPath().recordBackendMfaChallenge({ userId, factorId, challengeId }),
      );
      if (result.error === null) return ok(undefined);
      // The factor or the challenge is not this user's, or is gone: answered like a wrong code.
      if (isNotFound(result.error)) {
        return err(new InvalidMfaCodeError('factor_not_found', { cause: result.error, factorId }));
      }
      throw upstreamFailure('record the challenge', result.error, result.status);
    },

    async attest({ userId, sessionId, factorId, challengeId }) {
      const result = await call('attest the session', () =>
        adminPath().attestMfaSession({ userId, sessionId, factorId, challengeId }),
      );
      if (result.error !== null) {
        throw upstreamFailure('attest the session', result.error, result.status);
      }
      const answer = attestationAnswerSchema.safeParse(result.data);
      if (!answer.success) throw new Error('attest the session: an answer that is not understood');
      if (answer.data === 'attested') return { attested: true, activated: false };
      if (answer.data === 'attested_activated') return { attested: true, activated: true };
      return { attested: false, reason: answer.data };
    },
  };
}
