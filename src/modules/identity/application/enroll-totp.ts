import {
  err,
  ForbiddenError,
  ok,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import { MfaAlreadyEnrolledError } from '../domain/mfa-errors';
import type { MfaGateway, TotpEnrollment } from '../domain/mfa-ports';

export type EnrollTotpDeps = { readonly mfa: MfaGateway };

export type EnrollTotpOutcome = {
  readonly enrollment: TotpEnrollment;
  /** How many unverified factors this enrollment replaced (E-26), for the log. */
  readonly replacedFactors: number;
};

/**
 * `POST /auth/mfa/totp/enroll` (spec §3.5, E-26, E-27): starts the registration of an authenticator
 * app for a CEO.
 *
 * 1. Only a CEO has MFA (SEC-11). The pipeline already checked the role; the check is repeated
 *    here, as the rule of the use case.
 * 2. A VERIFIED factor already exists → `MfaAlreadyEnrolledError` (409). Nothing is changed: a
 *    second factor must never be added by a session that did not just prove the first.
 * 3. Unverified factors are leftovers of an enrollment that was never finished. They are removed
 *    (E-26), so there is never more than one candidate and the secret the user sees is the only
 *    one that can still be activated.
 * 4. A new factor is created.
 *
 * If step 4 fails after step 3, the CEO simply enrolls again: nothing is left half done that a
 * retry cannot repair.
 */
export async function enrollTotp(
  deps: EnrollTotpDeps,
  principal: Principal,
): Promise<Result<EnrollTotpOutcome, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO enrolls TOTP', { detail: 'Access denied.' }));
  }

  const factors = await deps.mfa.listTotpFactors();
  if (factors.some((factor) => factor.verified)) return err(new MfaAlreadyEnrolledError());

  for (const factor of factors) await deps.mfa.removeUnverifiedTotp(factor.id);

  const enrolled = await deps.mfa.enrollTotp();
  if (!enrolled.ok) return enrolled;
  return ok({ enrollment: enrolled.value, replacedFactors: factors.length });
}
