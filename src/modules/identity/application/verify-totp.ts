import {
  err,
  ForbiddenError,
  ok,
  UnauthenticatedError,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { ClientDirectory, PrincipalQuery } from '../domain/ports';
import { InvalidMfaCodeError } from '../domain/mfa-errors';
import type { MfaGateway } from '../domain/mfa-ports';
import type { SessionView } from '../domain/session';
import { loadSessionView } from './load-session-view';

export type VerifyTotpDeps = {
  readonly mfa: MfaGateway;
  readonly principals: PrincipalQuery;
  readonly clients: ClientDirectory;
};

export type VerifyTotpInput = {
  /**
   * Deprecated in the contract (`TotpVerifyRequest.factorId`). Left out, the factor is the one of
   * the session (see `resolveFactor`); given, it must be the caller's own and the gateway refuses
   * any other.
   */
  readonly factorId?: string | undefined;
  /** Six digits, already validated. */
  readonly code: string;
};

export type VerifyTotpOutcome = {
  readonly session: SessionView;
  /** The factor the code was checked against: the one in the request or the one resolved. */
  readonly factorId: string;
  /** How many TOTP factors the account has; `undefined` when the request named the factor. */
  readonly candidateCount: number | undefined;
  /** This verification activated the FIRST factor of the CEO (it was unverified until now). */
  readonly activated: boolean;
  /**
   * `null`: nothing was asked (only the first activation revokes). `true`: the other sessions of
   * the CEO were signed out. `false`: it was asked and failed (F-20); the verification stands.
   */
  readonly otherSessionsRevoked: boolean | null;
};

/**
 * `POST /auth/mfa/totp/verify` (spec §3.4, §3.5, E-28): proves the factor with a code from the
 * authenticator app. The first success activates the factor; every success replaces the session
 * with an `aal2` one (the gateway rewrites the cookies of the request).
 *
 * 1. Only a CEO has MFA (SEC-11): the role is checked again here, as the rule of the use case.
 * 2. Resolve the factor (`resolveFactor`): the one in the request, or, when it names none, the TOTP
 *    factor of the session's own user. No factor, or an ambiguous one → `InvalidMfaCodeError`.
 * 3. Burn the code, challenge and verify. A refused code (wrong, expired, replayed or aimed at a
 *    factor that is not the CEO's) → `InvalidMfaCodeError`, nothing else changes.
 * 4. Read the principal again with the NEW session: the answer carries `aal: 'aal2'` and no
 *    pending action. No principal at that point means the session was revoked while the code was
 *    being checked: `UnauthenticatedError` (401), the tokens that were just written are useless.
 *    A principal of ANOTHER user is an invariant that broke, and nothing is returned (500).
 * 5. When this verification ACTIVATED the first factor (the CEO had `ENROLL_MFA` pending), the other
 *    sessions of the CEO are signed out, so a session opened with the password alone does not
 *    outlive the moment the account gets its second factor (F-20). It is best effort: a failure
 *    never turns a good verification into an error, and the caller logs it.
 *
 * What this does NOT do (F-23): the refresh token a browser held BEFORE the verification keeps
 * working for the Auth server's reuse interval (`refresh_token_reuse_interval`, 10 s locally) and
 * answers with the current, `aal2`, session. Rotating the token once more does not shorten that (tested:
 * the old token still answered), so nothing is done about it here.
 */
export async function verifyTotp(
  deps: VerifyTotpDeps,
  principal: Principal,
  input: VerifyTotpInput,
): Promise<Result<VerifyTotpOutcome, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO verifies TOTP', { detail: 'Access denied.' }));
  }
  const activated = principal.pendingActions.includes('ENROLL_MFA');

  const factor = await resolveFactor(deps.mfa, input.factorId);
  if (!factor.ok) return factor;
  const { factorId, candidateCount } = factor.value;

  const verified = await deps.mfa.verifyTotp({ factorId, code: input.code });
  if (!verified.ok) return err(withCandidateCount(verified.error, candidateCount));

  const elevated = await deps.principals.current();
  if (elevated === null) {
    return err(
      new UnauthenticatedError('the session ended while the TOTP code was verified', {
        detail: 'Authentication required.',
      }),
    );
  }
  if (elevated.userId !== principal.userId) {
    throw new Error('the principal after the TOTP verification is another user');
  }

  const otherSessionsRevoked = activated
    ? await attempt(() => deps.mfa.revokeOtherSessions())
    : null;

  return ok({
    session: await loadSessionView(deps.clients, elevated),
    factorId,
    candidateCount,
    activated,
    otherSessionsRevoked,
  });
}

/**
 * Which factor a verification is about. Identity comes from the credential, never from a client
 * parameter, so a request that names no factor gets the one of the session's own user (listed with
 * that user's session, no admin client). It is the mirror of what the enrollment guarantees (E-26,
 * E-27): a user has either one verified factor, or one unverified candidate.
 *
 * - a factor id in the request is used as it is; the gateway checks it belongs to the user, and a
 *   foreign or missing one is refused like a wrong code (E-28);
 * - exactly one VERIFIED factor → it (a login on a new device);
 * - none verified and exactly one unverified → it (the first use, right after the enrollment);
 * - no TOTP factor at all → `factor_not_found`;
 * - more than one in the same state → `factor_ambiguous`. The code is never tried on several
 *   factors: that would multiply the guesses a code gets and burn codes of factors nobody chose.
 *
 * Both refusals are the same 422 as a wrong code; only the log tells them apart. When the factors
 * were listed, every outcome carries how many the account has (`candidateCount`): the app keeps one,
 * so a failure on an account with two is how a planted factor shows up in the log (F-60, F-61).
 */
async function resolveFactor(
  mfa: MfaGateway,
  requested: string | undefined,
): Promise<Result<ResolvedFactor, InvalidMfaCodeError>> {
  if (requested !== undefined) return ok({ factorId: requested, candidateCount: undefined });

  const factors = await mfa.listTotpFactors();
  const candidateCount = factors.length;
  const verified = factors.filter((factor) => factor.verified);
  const [only, ...others] = verified.length > 0 ? verified : factors;
  if (only === undefined) {
    return err(new InvalidMfaCodeError('factor_not_found', { candidateCount }));
  }
  if (others.length > 0) {
    return err(new InvalidMfaCodeError('factor_ambiguous', { candidateCount }));
  }
  return ok({ factorId: only.id, candidateCount });
}

type ResolvedFactor = { readonly factorId: string; readonly candidateCount: number | undefined };

/** The refusal of the gateway, with the number of factors the resolution saw (if it listed them). */
function withCandidateCount(
  error: InvalidMfaCodeError,
  candidateCount: number | undefined,
): InvalidMfaCodeError {
  if (candidateCount === undefined) return error;
  return new InvalidMfaCodeError(error.reason, {
    cause: error,
    ...(error.factorId === undefined ? {} : { factorId: error.factorId }),
    candidateCount,
  });
}

/** Runs a best-effort step: `true` when it worked, `false` when it threw (the caller logs it). */
async function attempt(step: () => Promise<void>): Promise<boolean> {
  try {
    await step();
    return true;
  } catch {
    return false;
  }
}
