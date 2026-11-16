// In-memory fakes of identity's MFA ports (the gateway and the attestor), for the unit tests of the
// use cases. Imported by tests only. The two share one state, like the Auth service and the database
// do in production: a factor the attestor registers is the one the gateway then lists as the backend's.
import {
  ConflictError,
  err,
  ok,
  ServiceUnavailableError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import {
  InvalidMfaCodeError,
  MfaReenrollmentRefusedError,
  type MfaAlreadyEnrolledError,
} from '../domain/mfa-errors';
import type {
  AttestationOutcome,
  AttestationRefusal,
  MfaAttestor,
  MfaGateway,
  TotpCodeInput,
  TotpEnrollment,
  TotpFactor,
} from '../domain/mfa-ports';
import type { PrincipalQuery } from '../domain/ports';

/** The one code every fake factor accepts. */
export const FAKE_VALID_CODE = '123456';

/** The session every fake request runs in (the one the claims of its token name). */
export const FAKE_SESSION_ID = '99999999-9999-4999-8999-999999999999';

/**
 * A factor as the tests describe it. `backendEnrolled` is `true` unless the test says otherwise, and
 * `activated` (the database has attested a verification of it as the backend's, F-72) follows
 * `verified`: a factor that is already verified is taken for one the backend activated.
 */
export type FakeFactor = {
  readonly id: string;
  readonly verified: boolean;
  readonly backendEnrolled?: boolean;
  readonly activated?: boolean;
};

type StoredFactor = TotpFactor & { readonly activated: boolean };

export type FakeMfaOptions = {
  readonly factors?: readonly FakeFactor[];
  /** What `current()` answers: the principal of the elevated session, or `null` for none. */
  readonly principalAfterVerify?: Principal | null;
};

export type FakeAttestor = MfaAttestor & {
  /** The factors the backend registered, in order. */
  registrations(): readonly string[];
  /** `factorId:challengeId` of every challenge recorded. */
  recordedChallenges(): readonly string[];
  /** The ids of every attestation asked for. */
  attestations(): readonly {
    readonly userId: string;
    readonly sessionId: string;
    readonly factorId: string;
    readonly challengeId: string;
  }[];
  /** The next `attest` is refused with this reason (the database would also delete the sessions). */
  refuseNextAttestationWith(reason: AttestationRefusal): void;
  /** The next `recordChallenge` is refused as if the database did not know the factor or challenge. */
  refuseNextChallengeRecord(): void;
  /** The next `registerEnrollment` finds the factor already gone (a parallel enrollment). */
  conflictOnNextRegistration(): void;
  /** The next `registerEnrollment` is refused: the user already had a first factor activated (F-64). */
  refuseNextRegistrationAsReenrollment(): void;
  /** `factorId:digest` of every code burned, in order (the replay guard, F-21). */
  burnedCodes(): readonly string[];
  /** Makes the next calls of that method throw `ServiceUnavailableError`. */
  failWith(method: 'register' | 'record' | 'attest' | 'burn'): void;
};

export type FakeMfa = MfaGateway &
  PrincipalQuery & {
    /** The factors the "Auth service" holds right now (id and state only). */
    factors(): readonly { readonly id: string; readonly verified: boolean }[];
    /** The ids of the factors the backend enrolled. */
    backendFactors(): readonly string[];
    /** Adds a factor made straight at the Auth service (not by the backend): F-60, F-61. */
    plant(factor: { readonly id: string; readonly verified: boolean }): void;
    readonly calls: string[];
    /** Has a verification succeeded (a session was elevated)? */
    elevated(): boolean;
    /** Makes the next calls of that method throw `ServiceUnavailableError`. */
    failWith(method: 'list' | 'remove' | 'enroll' | 'verify' | 'current' | 'session'): void;
    /** The next `enrollTotp` answers as if another enrollment had raced this one. */
    conflictOnNextEnroll(error: ConflictError | MfaAlreadyEnrolledError): void;
    /** The attestor sharing this state; its calls go to the same `calls` log. */
    readonly attestor: FakeAttestor;
  };

export function createFakeMfa(options: FakeMfaOptions = {}): FakeMfa {
  let factors: StoredFactor[] = (options.factors ?? []).map((factor) => ({
    id: factor.id,
    verified: factor.verified,
    backendEnrolled: factor.backendEnrolled ?? true,
    activated: factor.activated ?? factor.verified,
  }));
  let nextId = 1;
  let nextChallenge = 1;
  let elevated = false;
  /** `factorId:digest` of every code the replay guard already burned (accepted or refused). */
  const burned = new Set<string>();
  const burnLog: string[] = [];
  let enrollError: ConflictError | MfaAlreadyEnrolledError | undefined;
  const calls: string[] = [];
  const failing = new Set<string>();

  const unavailable = (method: string) => {
    if (failing.has(method)) throw new ServiceUnavailableError(`${method} unavailable`);
  };

  // --- the attestor: the database's records, over the same factors ---
  const registrations: string[] = [];
  const recorded: string[] = [];
  const attestations: {
    userId: string;
    sessionId: string;
    factorId: string;
    challengeId: string;
  }[] = [];
  let nextRefusal: AttestationRefusal | undefined;
  let refuseNextRecord = false;
  let conflictNextRegistration = false;
  let reenrollNextRegistration = false;

  const attestor: FakeAttestor = {
    registrations: () => registrations,
    recordedChallenges: () => recorded,
    attestations: () => attestations,
    refuseNextAttestationWith: (reason) => {
      nextRefusal = reason;
    },
    refuseNextChallengeRecord: () => {
      refuseNextRecord = true;
    },
    conflictOnNextRegistration: () => {
      conflictNextRegistration = true;
    },
    refuseNextRegistrationAsReenrollment: () => {
      reenrollNextRegistration = true;
    },
    burnedCodes: () => burnLog,
    failWith: (method) => void failing.add(`attestor:${method}`),

    registerEnrollment({ factorId }) {
      calls.push(`register:${factorId}`);
      unavailable('attestor:register');
      if (reenrollNextRegistration) {
        reenrollNextRegistration = false;
        return Promise.resolve(err(new MfaReenrollmentRefusedError()));
      }
      if (conflictNextRegistration) {
        conflictNextRegistration = false;
        return Promise.resolve(err(new ConflictError('the factor is gone')));
      }
      registrations.push(factorId);
      factors = factors.map((factor) =>
        factor.id === factorId ? { ...factor, backendEnrolled: true } : factor,
      );
      return Promise.resolve(ok(undefined));
    },

    burnCode({ factorId, codeDigest }) {
      calls.push(`burn:${factorId}`);
      unavailable('attestor:burn');
      // like the database: a factor that is not the user's is unknown, a code is burned the first time
      // it is sent (right or wrong), and a second time is a replay
      if (!factors.some((factor) => factor.id === factorId)) {
        return Promise.resolve(err(new InvalidMfaCodeError('factor_not_found', { factorId })));
      }
      const use = `${factorId}:${codeDigest}`;
      if (burned.has(use)) {
        return Promise.resolve(err(new InvalidMfaCodeError('code_reused', { factorId })));
      }
      burned.add(use);
      burnLog.push(use);
      return Promise.resolve(ok(undefined));
    },

    recordChallenge({ factorId, challengeId }) {
      calls.push(`record:${factorId}:${challengeId}`);
      unavailable('attestor:record');
      if (refuseNextRecord) {
        refuseNextRecord = false;
        return Promise.resolve(err(new InvalidMfaCodeError('factor_not_found', { factorId })));
      }
      recorded.push(`${factorId}:${challengeId}`);
      return Promise.resolve(ok(undefined));
    },

    attest(input) {
      calls.push(`attest:${input.sessionId}:${input.factorId}:${input.challengeId}`);
      unavailable('attestor:attest');
      attestations.push(input);
      const refusal =
        nextRefusal ??
        (factors.some((factor) => factor.id === input.factorId && factor.backendEnrolled)
          ? undefined
          : 'factor_not_backend');
      nextRefusal = undefined;
      if (refusal !== undefined) {
        const refused: AttestationOutcome = { attested: false, reason: refusal };
        return Promise.resolve(refused);
      }
      // the database derives the activation: the first attestation of a factor activates it
      const activated = factors.some((factor) => factor.id === input.factorId && !factor.activated);
      factors = factors.map((factor) =>
        factor.id === input.factorId ? { ...factor, activated: true } : factor,
      );
      const outcome: AttestationOutcome = { attested: true, activated };
      return Promise.resolve(outcome);
    },
  };

  return {
    calls,
    attestor,
    factors: () => factors.map(({ id, verified }) => ({ id, verified })),
    backendFactors: () => factors.filter((factor) => factor.backendEnrolled).map(({ id }) => id),
    plant: (factor) => {
      factors = [...factors, { ...factor, backendEnrolled: false, activated: false }];
    },
    elevated: () => elevated,
    failWith: (method) => void failing.add(method),
    conflictOnNextEnroll: (error) => {
      enrollError = error;
    },

    listTotpFactors() {
      calls.push('list');
      unavailable('list');
      return Promise.resolve(
        factors.map(({ id, verified, backendEnrolled }) => ({ id, verified, backendEnrolled })),
      );
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
      // not the backend's until the attestor registers it, like the database
      factors = [{ id: factorId, verified: false, backendEnrolled: false, activated: false }];
      return Promise.resolve(
        ok({
          factorId,
          uri: 'otpauth://totp/Rastreador:fake?secret=FAKESECRET',
          secret: 'FAKESECRET',
          qrCode: 'data:image/svg+xml;utf-8,<svg/>',
        }),
      );
    },

    async verifyTotp({
      factorId,
      code,
      burnCode,
      recordChallenge,
    }: TotpCodeInput & {
      readonly burnCode: (codeDigest: string) => Promise<Result<void, InvalidMfaCodeError>>;
      readonly recordChallenge: (challengeId: string) => Promise<Result<void, InvalidMfaCodeError>>;
    }) {
      calls.push(`verify:${factorId}`);
      unavailable('verify');
      // like the gateway: the code is burned FIRST, through the replay guard (the digest, never the code)
      // an opaque stand-in for the digest: the characters of the code shifted, so it never contains the code
      const digest = [...code].map((char) => String.fromCharCode(char.charCodeAt(0) + 17)).join('');
      const burnedNow = await burnCode(digest);
      if (!burnedNow.ok) return burnedNow;
      // like the gateway: the challenge is recorded BEFORE the Auth service answers it
      const challengeId = `challenge-${nextChallenge}`;
      nextChallenge += 1;
      const stored = await recordChallenge(challengeId);
      if (!stored.ok) return stored;
      if (code !== FAKE_VALID_CODE) {
        return err(new InvalidMfaCodeError('invalid_code', { factorId }));
      }
      factors = factors.map((factor) =>
        factor.id === factorId ? { ...factor, verified: true } : factor,
      );
      elevated = true;
      return ok({ challengeId });
    },

    currentSessionId() {
      calls.push('session');
      unavailable('session');
      return Promise.resolve(FAKE_SESSION_ID);
    },

    current() {
      calls.push('current');
      unavailable('current');
      return Promise.resolve(options.principalAfterVerify ?? null);
    },
  };
}
