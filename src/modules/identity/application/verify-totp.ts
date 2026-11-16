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
import type { MfaGateway, TotpCodeInput } from '../domain/mfa-ports';
import type { SessionView } from '../domain/session';
import { loadSessionView } from './load-session-view';

export type VerifyTotpDeps = {
  readonly mfa: MfaGateway;
  readonly principals: PrincipalQuery;
  readonly clients: ClientDirectory;
};

export type VerifyTotpOutcome = {
  readonly session: SessionView;
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
 * 2. Burn the code, challenge and verify. A refused code (wrong, expired, replayed or aimed at a
 *    factor that is not the CEO's) → `InvalidMfaCodeError`, nothing else changes.
 * 3. Read the principal again with the NEW session: the answer carries `aal: 'aal2'` and no
 *    pending action. No principal at that point means the session was revoked while the code was
 *    being checked: `UnauthenticatedError` (401), the tokens that were just written are useless.
 *    A principal of ANOTHER user is an invariant that broke, and nothing is returned (500).
 * 4. When this verification ACTIVATED the first factor (the CEO had `ENROLL_MFA` pending), the other
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
  input: TotpCodeInput,
): Promise<Result<VerifyTotpOutcome, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO verifies TOTP', { detail: 'Access denied.' }));
  }
  const activated = principal.pendingActions.includes('ENROLL_MFA');

  const verified = await deps.mfa.verifyTotp(input);
  if (!verified.ok) return verified;

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
    activated,
    otherSessionsRevoked,
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
