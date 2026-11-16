// In-memory fake of identity's MFA port, for the unit tests of the use cases. Imported by tests only.
import {
  ConflictError,
  err,
  ok,
  ServiceUnavailableError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import { InvalidMfaCodeError, type MfaAlreadyEnrolledError } from '../domain/mfa-errors';
import type { MfaGateway, TotpCodeInput, TotpEnrollment, TotpFactor } from '../domain/mfa-ports';
import type { PrincipalQuery } from '../domain/ports';

/** The one code every fake factor accepts. */
export const FAKE_VALID_CODE = '123456';

export type FakeMfaOptions = {
  readonly factors?: readonly TotpFactor[];
  /** What `current()` answers: the principal of the elevated session, or `null` for none. */
  readonly principalAfterVerify?: Principal | null;
};

export type FakeMfa = MfaGateway &
  PrincipalQuery & {
    /** The factors the "Auth service" holds right now. */
    factors(): readonly TotpFactor[];
    readonly calls: string[];
    /** Has a verification succeeded (a session was elevated)? */
    elevated(): boolean;
    /** How many times the other sessions were revoked. */
    revocations(): number;
    /** Makes the next calls of that method throw `ServiceUnavailableError`. */
    failWith(method: 'list' | 'remove' | 'enroll' | 'verify' | 'current' | 'revoke'): void;
    /** The next `enrollTotp` answers as if another enrollment had raced this one. */
    conflictOnNextEnroll(error: ConflictError | MfaAlreadyEnrolledError): void;
  };

export function createFakeMfa(options: FakeMfaOptions = {}): FakeMfa {
  let factors: TotpFactor[] = [...(options.factors ?? [])];
  let nextId = 1;
  let elevated = false;
  let revocations = 0;
  /** `factorId:code` of every code a verification already burned (accepted or refused). */
  const burned = new Set<string>();
  let enrollError: ConflictError | MfaAlreadyEnrolledError | undefined;
  const calls: string[] = [];
  const failing = new Set<string>();

  const unavailable = (method: string) => {
    if (failing.has(method)) throw new ServiceUnavailableError(`${method} unavailable`);
  };

  return {
    calls,
    factors: () => factors,
    elevated: () => elevated,
    revocations: () => revocations,
    failWith: (method) => void failing.add(method),
    conflictOnNextEnroll: (error) => {
      enrollError = error;
    },

    listTotpFactors() {
      calls.push('list');
      unavailable('list');
      return Promise.resolve([...factors]);
    },

    removeUnverifiedTotp(factorId) {
      calls.push(`remove:${factorId}`);
      unavailable('remove');
      const target = factors.find((factor) => factor.id === factorId);
      if (target?.verified === true)
        throw new Error('the fake refuses to remove a verified factor');
      factors = factors.filter((factor) => factor.id !== factorId);
      return Promise.resolve();
    },

    enrollTotp(): Promise<Result<TotpEnrollment, MfaAlreadyEnrolledError | ConflictError>> {
      calls.push('enroll');
      unavailable('enroll');
      if (enrollError !== undefined) return Promise.resolve(err(enrollError));
      // like the Auth service: one unnamed factor per user, any other attempt is a name conflict
      if (factors.length > 0) return Promise.resolve(err(new ConflictError('a factor exists')));
      const factorId = `00000000-0000-4000-8000-${String(nextId).padStart(12, '0')}`;
      nextId += 1;
      factors = [{ id: factorId, verified: false }];
      return Promise.resolve(
        ok({
          factorId,
          uri: 'otpauth://totp/Rastreador:fake?secret=FAKESECRET',
          secret: 'FAKESECRET',
          qrCode: 'data:image/svg+xml;utf-8,<svg/>',
        }),
      );
    },

    verifyTotp({ factorId, code }: TotpCodeInput) {
      calls.push(`verify:${factorId}`);
      unavailable('verify');
      if (!factors.some((factor) => factor.id === factorId)) {
        return Promise.resolve(err(new InvalidMfaCodeError('factor_not_found', { factorId })));
      }
      // like the database: a code is burned the first time it is sent, right or wrong
      const use = `${factorId}:${code}`;
      if (burned.has(use)) {
        return Promise.resolve(err(new InvalidMfaCodeError('code_reused', { factorId })));
      }
      burned.add(use);
      if (code !== FAKE_VALID_CODE) {
        return Promise.resolve(err(new InvalidMfaCodeError('invalid_code', { factorId })));
      }
      factors = factors.map((factor) =>
        factor.id === factorId ? { ...factor, verified: true } : factor,
      );
      elevated = true;
      return Promise.resolve(ok(undefined));
    },

    revokeOtherSessions() {
      calls.push('revoke');
      unavailable('revoke');
      revocations += 1;
      return Promise.resolve();
    },

    current() {
      calls.push('current');
      unavailable('current');
      return Promise.resolve(options.principalAfterVerify ?? null);
    },
  };
}
