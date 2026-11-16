import { getRequestSupabase } from '@/shared/db/server-client';
import {
  readAccessToken,
  sessionIdOfToken,
  snapshotSessionCookies,
} from '@/shared/db/session-cookies';
import { clientIpFingerprint, json, withRoute, type WithRoute } from '@/shared/http';
import { verifyTotp } from '../application/verify-totp';
import { InvalidMfaCodeError } from '../domain/mfa-errors';
import { ATTESTATION_ATTACK_SIGNALS } from '../domain/mfa-ports';
import { createSupabaseMfaAttestor } from '../infrastructure/supabase-mfa-attestor';
import { createSupabaseMfaGateway } from '../infrastructure/supabase-mfa-gateway';
import { createTrackingClientDirectory } from '../infrastructure/tracking-client-directory';
import { VERIFY_DAILY_BUDGET } from './rate-limit-budgets';
import { toSessionDto } from './session.dto';
import { verifyTotpBodySchema } from './verify-totp.schema';

/** Where the factor of a verification came from, for the log: lets us see who still sends the id. */
const factorSourceOf = (body: { factorId?: string | undefined }) =>
  body.factorId === undefined ? 'session' : 'request';

const VERIFY_LIMIT = 5;
const FIVE_MINUTES_SECONDS = 5 * 60;

/**
 * `POST /auth/mfa/totp/verify` (operationId `verifyTotp`). Policy equal to the contract: role ceo
 * only, `allowPending: [ENROLL_MFA, VERIFY_MFA]` (the first verification activates the factor; a
 * later login verifies it to reach `aal2`; a pending password change still blocks it), user 5 /
 * 5 min in the `totp-verify` counter.
 *
 * The limit is on the route, so EVERY request spends one unit, a correct code too (E-28: a wrong
 * code is counted, and the sixth request in five minutes is 429 whatever it carries). The
 * pipeline spends it before the code is looked at.
 *
 * On success the session becomes `aal2`: `mfa.verify` issues new tokens, the request's Supabase
 * client (the one the principal resolver used) writes them to the pipeline's jar, and the pipeline
 * puts the cookies on the response. A refused code writes nothing. The old `aal1` access token
 * keeps working as what it is: an `aal1` session, which every CEO route refuses (pending
 * `VERIFY_MFA`; and the database functions of the CEO ask `aal2` of the JWT itself).
 *
 * On top of the contract's rule, every attempt that gets past it also spends the daily cap
 * (`VERIFY_DAILY_BUDGET`, 429 over it). A wrong code, a replayed one (the database refuses a code it
 * already accepted in the last 120 s) and a factor that is not the CEO's all answer the same 422.
 *
 * The body's `factorId` is optional and deprecated: left out, the use case resolves the CEO's TOTP
 * factor from the session itself, with the same request client (no admin client). Both budgets are
 * spent before that, so leaving the field out buys no extra attempt.
 *
 * The session the verification elevates is only a CEO's once the backend ATTESTS it (ADR 0013): the
 * use case records the challenge before the Auth server answers it, and attests the session after.
 * A refused attestation (a code that was also verified straight at Auth inside the TOTP window, or a
 * factor the backend never activated) is the same 422 as a wrong code, deletes every session of the
 * CEO in the database and is an ALERT in the log (`auth.mfa.attestation_refused`, error level, with the
 * reason and no PII). A failure to record or attest is a 503 and the session stays at `VERIFY_MFA`.
 *
 * When the verification activated the FIRST factor, the database signs the CEO out of their other
 * sessions inside the attestation (F-20, F-74): nothing is asked of the Auth server for it.
 *
 * The log carries ids and a reason, never the code, the secret or a token.
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createVerifyTotpHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: ['ENROLL_MFA', 'VERIFY_MFA'],
      rateLimit: [
        {
          scope: 'user',
          group: 'totp-verify',
          limit: VERIFY_LIMIT,
          windowSeconds: FIVE_MINUTES_SECONDS,
        },
      ],
      body: verifyTotpBodySchema,
    },
    async ({ request, requestId, cookies, logger, principal, body, consumeUserBudget }) => {
      // After the contract's rule (spent by the pipeline), before the code is looked at.
      await consumeUserBudget(VERIFY_DAILY_BUDGET);

      const supabase = getRequestSupabase({ request, cookies, requestId });
      const gateway = createSupabaseMfaGateway(supabase);

      const result = await verifyTotp(
        {
          mfa: gateway,
          attestor: createSupabaseMfaAttestor(),
          principals: gateway,
          clients: createTrackingClientDirectory(supabase),
        },
        principal,
        body,
      );

      if (!result.ok) {
        if (result.error instanceof InvalidMfaCodeError) {
          const details = {
            userId: principal.userId,
            factorId: result.error.factorId,
            factorSource: factorSourceOf(body),
            candidateCount: result.error.candidateCount,
            foreignFactorCount: result.error.foreignFactorCount,
            ipHash: clientIpFingerprint(request),
          };
          logger.warn(
            { event: 'auth.mfa.failed', ...details, reason: result.error.reason },
            'auth.mfa.failed',
          );
          // The app keeps ONE TOTP factor per CEO: more than one the backend enrolled is a state it
          // never produces. A stable event name, at error level, so an alert can be built on it.
          if (result.error.reason === 'factor_ambiguous') {
            logger.error(
              { event: 'auth.mfa.factor_ambiguous', ...details },
              'auth.mfa.factor_ambiguous',
            );
          }
          // A TOTP factor the backend did not enroll exists on this account: someone with the
          // password planted it straight at the Auth server (F-60, F-61). The app never makes one.
          if ((result.error.foreignFactorCount ?? 0) > 0) {
            logger.error(
              { event: 'auth.mfa.foreign_factor', ...details },
              'auth.mfa.foreign_factor',
            );
          }
          // The Auth server took the code and the database refused to attest the session: the
          // password and a valid code are with someone else (F-50 b), or a factor the backend never
          // activated was used (F-61). Every session of the CEO is already gone. The response is the
          // same 422; this line is how the people find out.
          if (result.error.reason === 'attestation_refused') {
            // a race or an inconsistency (F-66) refuses without revoking and is a warning; a sign of
            // an attack, which deleted every session, is an alert. The ALERT also comes from the audit
            // trail (`auth.mfa_attestation_refused`), which survives a 503 after the COMMIT (F-68).
            const sign =
              result.error.attestationReason !== undefined &&
              ATTESTATION_ATTACK_SIGNALS.has(result.error.attestationReason);
            logger[sign ? 'error' : 'warn'](
              {
                event: 'auth.mfa.attestation_refused',
                userId: principal.userId,
                factorId: result.error.factorId,
                factorSource: factorSourceOf(body),
                attestationReason: result.error.attestationReason,
                ipHash: clientIpFingerprint(request),
              },
              'auth.mfa.attestation_refused',
            );
          }
        }
        return result.error;
      }

      const { session, activated, foreignFactorCount } = result.value;

      // The id of the session the verification elevated: the same one as before, with new tokens.
      const accessToken = readAccessToken(snapshotSessionCookies(cookies));
      logger.info(
        {
          event: 'auth.mfa.verified',
          userId: principal.userId,
          factorId: result.value.factorId,
          factorSource: factorSourceOf(body),
          candidateCount: result.value.candidateCount,
          foreignFactorCount,
          sessionId: accessToken === undefined ? undefined : sessionIdOfToken(accessToken),
          activated,
          ipHash: clientIpFingerprint(request),
        },
        'auth.mfa.verified',
      );
      if ((foreignFactorCount ?? 0) > 0) {
        logger.error(
          {
            event: 'auth.mfa.foreign_factor',
            userId: principal.userId,
            factorId: result.value.factorId,
            foreignFactorCount,
          },
          'auth.mfa.foreign_factor',
        );
      }
      return json(200, toSessionDto(session));
    },
  );
}

export const verifyTotpHandler = createVerifyTotpHandler();
