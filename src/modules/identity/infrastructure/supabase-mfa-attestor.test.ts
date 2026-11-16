import { describe, expect, it, vi } from 'vitest';
import type { AdminRpcResult } from '@/shared/db/admin-client';
import { ConflictError, ServiceUnavailableError, UnauthenticatedError } from '@/shared/kernel';
import {
  InvalidMfaCodeError,
  MfaAlreadyEnrolledError,
  MfaReenrollmentRefusedError,
} from '../domain/mfa-errors';
import { ATTESTATION_REFUSALS } from '../domain/mfa-ports';
import { createSupabaseMfaAttestor, type MfaAdminApi } from './supabase-mfa-attestor';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const FACTOR_ID = '33333333-3333-4333-8333-333333333333';
const CHALLENGE_ID = '44444444-4444-4444-8444-444444444444';
const SESSION_ID = '66666666-6666-4666-8666-666666666666';

// The facade validates the payloads before they get here, so what the attestor sees is already typed;
// a test that wants "an answer it does not understand" hands the attestor an impossible value anyway.
const answer = (data: unknown): AdminRpcResult<never> =>
  ({ data, error: null, status: 200 }) as AdminRpcResult<never>;
const failure = (code: string, message: string, status = 400): AdminRpcResult<never> => ({
  data: null,
  error: { code, message },
  status,
});

type Outcome = AdminRpcResult<never> | Error;
const settle = (outcome: Outcome | undefined, fallback: AdminRpcResult<never>) =>
  outcome instanceof Error ? Promise.reject(outcome) : Promise.resolve(outcome ?? fallback);

function fakeAdmin(
  outcomes: { register?: Outcome; record?: Outcome; attest?: Outcome; burn?: Outcome } = {},
): MfaAdminApi & {
  registerBackendTotpFactor: ReturnType<typeof vi.fn>;
  recordBackendMfaChallenge: ReturnType<typeof vi.fn>;
  attestMfaSession: ReturnType<typeof vi.fn>;
  consumeTotpCode: ReturnType<typeof vi.fn>;
} {
  return {
    registerBackendTotpFactor: vi.fn(() => settle(outcomes.register, answer('registered'))),
    recordBackendMfaChallenge: vi.fn(() => settle(outcomes.record, answer(null))),
    attestMfaSession: vi.fn(() => settle(outcomes.attest, answer('attested'))),
    consumeTotpCode: vi.fn(() => settle(outcomes.burn, answer(true))),
  };
}

const registration = { userId: USER_ID, factorId: FACTOR_ID, sessionId: SESSION_ID };
const challenge = { userId: USER_ID, factorId: FACTOR_ID, challengeId: CHALLENGE_ID };
const attestation = { ...registration, challengeId: CHALLENGE_ID };

describe('SupabaseMfaAttestor.registerEnrollment', () => {
  it('F-60: asks the admin path to record the factor with the ids it was given', async () => {
    const admin = fakeAdmin();

    const result = await createSupabaseMfaAttestor(admin).registerEnrollment(registration);

    expect(result).toEqual({ ok: true, value: undefined });
    expect(admin.registerBackendTotpFactor).toHaveBeenCalledWith(registration);
  });

  it('a factor the database no longer finds (another enrollment replaced it) is a ConflictError: retrying is safe', async () => {
    const admin = fakeAdmin({ register: failure('P0001', 'NOT_FOUND') });

    const result = await createSupabaseMfaAttestor(admin).registerEnrollment(registration);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ConflictError);
  });

  it.each([
    ['the database down (503)', failure('', 'x', 503), ServiceUnavailableError],
    ['a transport failure (status 0)', failure('', 'fetch failed', 0), ServiceUnavailableError],
    ['a throw of the facade', new TypeError('fetch failed'), ServiceUnavailableError],
    ['invalid input (a bug of the caller)', failure('P0001', 'INVALID_INPUT'), Error],
    ['an error it does not know', failure('XX000', 'boom'), Error],
  ])(
    'fail closed: %s throws and nothing is recorded as done',
    async (_label, outcome, expected) => {
      const admin = fakeAdmin({ register: outcome });

      const thrown = await createSupabaseMfaAttestor(admin)
        .registerEnrollment(registration)
        .catch((error: unknown) => error);

      expect(thrown).toBeInstanceOf(expected);
      if (expected === Error) expect(thrown).not.toBeInstanceOf(ServiceUnavailableError);
    },
  );
});

describe('SupabaseMfaAttestor.recordChallenge', () => {
  it('F-63: asks the admin path to record the challenge with the ids it was given', async () => {
    const admin = fakeAdmin();

    const result = await createSupabaseMfaAttestor(admin).recordChallenge(challenge);

    expect(result).toEqual({ ok: true, value: undefined });
    expect(admin.recordBackendMfaChallenge).toHaveBeenCalledWith(challenge);
  });

  it('a factor or challenge the database does not find is refused like a wrong code (factor_not_found), naming the factor for the log', async () => {
    const admin = fakeAdmin({ record: failure('P0001', 'NOT_FOUND') });

    const result = await createSupabaseMfaAttestor(admin).recordChallenge(challenge);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(InvalidMfaCodeError);
    expect(result.error.reason).toBe('factor_not_found');
    expect(result.error.factorId).toBe(FACTOR_ID);
  });

  it.each([
    ['the database down (503)', failure('', 'x', 503), ServiceUnavailableError],
    ['a throw of the facade', new TypeError('fetch failed'), ServiceUnavailableError],
    ['an error it does not know', failure('XX000', 'boom'), Error],
  ])(
    'fail closed: %s throws, so the challenge is never answered',
    async (_label, outcome, expected) => {
      const admin = fakeAdmin({ record: outcome });

      const thrown = await createSupabaseMfaAttestor(admin)
        .recordChallenge(challenge)
        .catch((error: unknown) => error);

      expect(thrown).toBeInstanceOf(expected);
      expect(thrown).not.toBeInstanceOf(InvalidMfaCodeError);
    },
  );
});

describe('SupabaseMfaAttestor.attest', () => {
  it('F-63: asks the admin path to attest with the ids it was given and reports an attested session', async () => {
    const admin = fakeAdmin();

    const result = await createSupabaseMfaAttestor(admin).attest(attestation);

    expect(result).toEqual({ attested: true, activated: false });
    expect(admin.attestMfaSession).toHaveBeenCalledWith(attestation);
  });

  it.each(ATTESTATION_REFUSALS)(
    'F-63: the refusal %s of the database is a refusal with that reason, not an error',
    async (reason) => {
      const admin = fakeAdmin({ attest: answer(reason) });

      const result = await createSupabaseMfaAttestor(admin).attest(attestation);

      expect(result).toEqual({ attested: false, reason });
    },
  );

  it.each([
    ['a string it does not know', answer('maybe')],
    ['a number', answer(1)],
    ['no answer', answer(null)],
    ['a boolean true (not the word)', answer(true)],
    ['an object', answer({ attested: true })],
  ])('fail closed: %s is never an attestation', async (_label, outcome) => {
    const admin = fakeAdmin({ attest: outcome });

    await expect(createSupabaseMfaAttestor(admin).attest(attestation)).rejects.toThrow(
      /not understood/,
    );
  });

  it.each([
    ['the database down (503)', failure('', 'x', 503), ServiceUnavailableError],
    ['a transport failure (status 0)', failure('', 'fetch failed', 0), ServiceUnavailableError],
    ['a throw of the facade', new TypeError('fetch failed'), ServiceUnavailableError],
    ['invalid input', failure('P0001', 'INVALID_INPUT'), Error],
    ['permission denied (the key is not the service role)', failure('42501', 'denied', 403), Error],
  ])('fail closed: %s throws and nothing is attested', async (_label, outcome, expected) => {
    const admin = fakeAdmin({ attest: outcome });

    const thrown = await createSupabaseMfaAttestor(admin)
      .attest(attestation)
      .catch((error: unknown) => error);

    expect(thrown).toBeInstanceOf(expected);
    if (expected === Error) expect(thrown).not.toBeInstanceOf(ServiceUnavailableError);
  });

  it('SEC-13: what an error says never reaches the message of the thrown failure', async () => {
    const admin = fakeAdmin({ attest: failure('XX000', 'secret internal detail') });

    const thrown = await createSupabaseMfaAttestor(admin)
      .attest(attestation)
      .catch((error: unknown) => error);

    expect(String((thrown as Error).message)).not.toContain('secret internal detail');
  });
});

describe('SupabaseMfaAttestor: the admin path is resolved lazily', () => {
  it('building the attestor does not touch the admin facade (no key is read until the first call)', () => {
    // No facade injected and no environment: constructing must not throw.
    expect(() => createSupabaseMfaAttestor()).not.toThrow();
  });
});

describe('SupabaseMfaAttestor: the new answers (the review of Wave 6.1)', () => {
  it('F-72: attested_activated is an attestation that says it ACTIVATED the factor', async () => {
    const admin = fakeAdmin({ attest: answer('attested_activated') });

    expect(await createSupabaseMfaAttestor(admin).attest(attestation)).toEqual({
      attested: true,
      activated: true,
    });
  });

  it('F-64: a registration the database refuses as factor_reenrolled is MfaReenrollmentRefusedError (a 409 MFA_ALREADY_ENROLLED)', async () => {
    const admin = fakeAdmin({ register: answer('factor_reenrolled') });

    const result = await createSupabaseMfaAttestor(admin).registerEnrollment(registration);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(MfaReenrollmentRefusedError);
    expect(result.error).toBeInstanceOf(MfaAlreadyEnrolledError);
    expect(result.error.code).toBe('MFA_ALREADY_ENROLLED');
  });

  it("F-65: burnCode asks the admin path to burn the digest of the user's factor", async () => {
    const admin = fakeAdmin();
    const codeDigest = '\\x' + 'ab'.repeat(32);

    const result = await createSupabaseMfaAttestor(admin).burnCode({
      userId: USER_ID,
      factorId: FACTOR_ID,
      codeDigest,
    });

    expect(result).toEqual({ ok: true, value: undefined });
    expect(admin.consumeTotpCode).toHaveBeenCalledWith({
      userId: USER_ID,
      factorId: FACTOR_ID,
      codeDigest,
    });
  });

  it('F-21: a code the database already burned (false) is a replay: InvalidMfaCodeError (code_reused)', async () => {
    const admin = fakeAdmin({ burn: answer(false) });

    const result = await createSupabaseMfaAttestor(admin).burnCode({
      userId: USER_ID,
      factorId: FACTOR_ID,
      codeDigest: '\\x00',
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(InvalidMfaCodeError);
    expect(result.error.reason).toBe('code_reused');
    expect(result.error.factorId).toBe(FACTOR_ID);
  });

  it('F-20: a factor that is not a TOTP factor of the user (NOT_FOUND) is factor_not_found', async () => {
    const admin = fakeAdmin({ burn: failure('P0001', 'NOT_FOUND') });

    const result = await createSupabaseMfaAttestor(admin).burnCode({
      userId: USER_ID,
      factorId: FACTOR_ID,
      codeDigest: '\\x00',
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.reason).toBe('factor_not_found');
  });

  it('a user that is gone or disabled (42501) is UnauthenticatedError', async () => {
    const admin = fakeAdmin({ burn: failure('42501', 'FORBIDDEN', 403) });

    await expect(
      createSupabaseMfaAttestor(admin).burnCode({
        userId: USER_ID,
        factorId: FACTOR_ID,
        codeDigest: '\\x00',
      }),
    ).rejects.toBeInstanceOf(UnauthenticatedError);
  });

  it.each([
    ['the database down (503)', failure('', 'x', 503), ServiceUnavailableError],
    ['a throw of the facade', new TypeError('fetch failed'), ServiceUnavailableError],
    ['an error it does not know', failure('XX000', 'boom'), Error],
  ])(
    'fail closed: %s while burning throws, so the code is never tried',
    async (_label, outcome, expected) => {
      const admin = fakeAdmin({ burn: outcome });

      const thrown = await createSupabaseMfaAttestor(admin)
        .burnCode({ userId: USER_ID, factorId: FACTOR_ID, codeDigest: '\\x00' })
        .catch((error: unknown) => error);

      expect(thrown).toBeInstanceOf(expected);
      expect(thrown).not.toBeInstanceOf(InvalidMfaCodeError);
    },
  );
});
