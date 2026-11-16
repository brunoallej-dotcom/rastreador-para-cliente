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
import type { MfaAttestor, MfaGateway } from '../domain/mfa-ports';
import type { SessionView } from '../domain/session';
import { loadSessionView } from './load-session-view';

export type VerifyTotpDeps = {
  readonly mfa: MfaGateway;
  readonly attestor: MfaAttestor;
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
  /** How many of them the backend did not enroll (F-60, F-61); `undefined` when the request named the factor. */
  readonly foreignFactorCount: number | undefined;
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
 * with an `aal2` one (the gateway rewrites the cookies of the request) AND makes the backend attest
 * it: only an attested `aal2` session is a CEO's (ADR 0013).
 *
 * 1. Only a CEO has MFA (SEC-11): the role is checked again here, as the rule of the use case.
 * 2. Resolve the factor (`resolveFactor`): the one in the request, or, when it names none, the TOTP
 *    factor the backend enrolled for the session's own user. No factor, or an ambiguous one →
 *    `InvalidMfaCodeError`.
 * 3. Burn the code, challenge, RECORD the challenge as the backend's, then verify (the gateway keeps
 *    this order). A refused code (wrong, expired, replayed or aimed at a factor that is not the
 *    CEO's) → `InvalidMfaCodeError`, nothing else changes.
 * 4. Read the principal again with the NEW session. No principal at that point means the session was
 *    revoked while the code was being checked: `UnauthenticatedError` (401), the tokens that were just
 *    written are useless. A principal of ANOTHER user is an invariant that broke, and nothing is
 *    returned (500). Until the attestation the new session reads as `aal1` (`VERIFY_MFA`).
 * 5. Attest the session, with the id of the session the new token names. The database revalidates
 *    session, factor and challenge and refuses an oracle (a code that was also verified straight at
 *    Auth inside the TOTP window), a factor the backend never activated or a challenge it never
 *    recorded. A refusal → `InvalidMfaCodeError` (`attestation_refused`: the same 422 as a wrong
 *    code), and the database has already deleted every session of the user and audited it. Whatever
 *    else goes wrong (the database is down) throws, and the session stays unattested: pending
 *    `VERIFY_MFA`, a 503 (fail closed). The CEO verifies again with the next code.
 * 6. When this verification ACTIVATED the first factor (the CEO had `ENROLL_MFA` pending), the other
 *    sessions of the CEO are signed out, so a session opened with the password alone does not
 *    outlive the moment the account gets its second factor (F-20). It is best effort: a failure
 *    never turns a good verification into an error, and the caller logs it.
 *
 * What this does NOT do (F-23): the refresh token a browser held BEFORE the verification keeps
 * working for the Auth server's reuse interval (`refresh_token_reuse_interval`, 10 s locally) and
 * answers with the current, `aal2`, session. Rotating the token once more does not shorten that (tested:
 * the old token still answered), so nothing is done about it here. The session id is the same, so the
 * attestation covers it too: a residual of the F-23 kind, inside the reuse interval, not a new hole.
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
  const { factorId, candidateCount, foreignFactorCount } = factor.value;
  const withContext = (error: InvalidMfaCodeError) =>
    withListing(error, { candidateCount, foreignFactorCount });

  const verified = await deps.mfa.verifyTotp({
    factorId,
    code: input.code,
    recordChallenge: (challengeId) =>
      deps.attestor.recordChallenge({ userId: principal.userId, factorId, challengeId }),
  });
  if (!verified.ok) return err(withContext(verified.error));
  const { challengeId } = verified.value;

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

  const attestation = await deps.attestor.attest({
    userId: principal.userId,
    sessionId: await deps.mfa.currentSessionId(),
    factorId,
    challengeId,
  });
  if (!attestation.attested) {
    return err(
      withContext(
        new InvalidMfaCodeError('attestation_refused', {
          factorId,
          attestationReason: attestation.reason,
        }),
      ),
    );
  }

  const otherSessionsRevoked = activated
    ? await attempt(() => deps.mfa.revokeOtherSessions())
    : null;

  // The principal read above predates the attestation (it says `aal1`): read it again.
  const attested = await deps.principals.current();
  if (attested === null) {
    return err(
      new UnauthenticatedError('the session ended while it was attested', {
        detail: 'Authentication required.',
      }),
    );
  }
  if (attested.userId !== principal.userId) {
    throw new Error('the principal after the attestation is another user');
  }

  return ok({
    session: await loadSessionView(deps.clients, attested),
    factorId,
    candidateCount,
    foreignFactorCount,
    activated,
    otherSessionsRevoked,
  });
}

/**
 * Which factor a verification is about. Identity comes from the credential, never from a client
 * parameter, so a request that names no factor gets the one of the session's own user (listed with
 * that user's session, no admin client). It is the mirror of what the enrollment guarantees (E-26,
 * E-27): a user has either one verified factor, or one unverified candidate. Only the factors the
 * BACKEND enrolled count (F-60): a factor planted straight at the Auth service by someone holding
 * the password is never the candidate and never makes the choice ambiguous. It is counted
 * (`foreignFactorCount`), so the log can raise the alert.
 *
 * - a factor id in the request is used as it is; the gateway checks it belongs to the user, and a
 *   foreign or missing one is refused like a wrong code (E-28). The attestation still refuses a
 *   factor the backend never activated, whatever the request named (F-61);
 * - exactly one VERIFIED backend factor → it (a login on a new device);
 * - none verified and exactly one unverified backend factor → it (the first use, right after the
 *   enrollment);
 * - no backend TOTP factor at all → `factor_not_found`;
 * - more than one in the same state → `factor_ambiguous`. The code is never tried on several
 *   factors: that would multiply the guesses a code gets and burn codes of factors nobody chose.
 *
 * Both refusals are the same 422 as a wrong code; only the log tells them apart. When the factors
 * were listed, every outcome carries how many the account has (`candidateCount`) and how many of
 * them the backend did not enroll (`foreignFactorCount`).
 */
async function resolveFactor(
  mfa: MfaGateway,
  requested: string | undefined,
): Promise<Result<ResolvedFactor, InvalidMfaCodeError>> {
  if (requested !== undefined) {
    return ok({ factorId: requested, candidateCount: undefined, foreignFactorCount: undefined });
  }

  const factors = await mfa.listTotpFactors();
  const candidateCount = factors.length;
  const ours = factors.filter((factor) => factor.backendEnrolled);
  const foreignFactorCount = candidateCount - ours.length;
  const verified = ours.filter((factor) => factor.verified);
  const [only, ...others] = verified.length > 0 ? verified : ours;
  if (only === undefined) {
    return err(new InvalidMfaCodeError('factor_not_found', { candidateCount, foreignFactorCount }));
  }
  if (others.length > 0) {
    return err(new InvalidMfaCodeError('factor_ambiguous', { candidateCount, foreignFactorCount }));
  }
  return ok({ factorId: only.id, candidateCount, foreignFactorCount });
}

type ResolvedFactor = {
  readonly factorId: string;
  readonly candidateCount: number | undefined;
  readonly foreignFactorCount: number | undefined;
};

/** The refusal of the gateway, with what the resolution saw of the account's factors (if it listed them). */
function withListing(
  error: InvalidMfaCodeError,
  listing: {
    readonly candidateCount: number | undefined;
    readonly foreignFactorCount: number | undefined;
  },
): InvalidMfaCodeError {
  const { candidateCount, foreignFactorCount } = listing;
  if (candidateCount === undefined && foreignFactorCount === undefined) return error;
  return new InvalidMfaCodeError(error.reason, {
    cause: error,
    ...(error.factorId === undefined ? {} : { factorId: error.factorId }),
    ...(error.attestationReason === undefined
      ? {}
      : { attestationReason: error.attestationReason }),
    ...(candidateCount === undefined ? {} : { candidateCount }),
    ...(foreignFactorCount === undefined ? {} : { foreignFactorCount }),
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
