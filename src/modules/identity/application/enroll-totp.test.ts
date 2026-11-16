import { describe, expect, it } from 'vitest';
import { ConflictError, ServiceUnavailableError, type Principal } from '@/shared/kernel';
import { MfaAlreadyEnrolledError, MfaReenrollmentRefusedError } from '../domain/mfa-errors';
import { createFakeMfa, FAKE_SESSION_ID } from './fake-mfa';
import { enrollTotp } from './enroll-totp';

const FACTOR_A = '00000000-0000-4000-8000-0000000000a1';
const FACTOR_B = '00000000-0000-4000-8000-0000000000b2';

const ceo: Principal = {
  userId: '11111111-1111-4111-8111-111111111111',
  role: 'ceo',
  clientId: null,
  displayName: 'CEO',
  aal: 'aal1',
  pendingActions: ['ENROLL_MFA'],
};

describe('enrollTotp', () => {
  it('creates a factor for a CEO who has none', async () => {
    const mfa = createFakeMfa();

    const result = await enrollTotp({ mfa, attestor: mfa.attestor }, ceo);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.replacedFactors).toBe(0);
    expect(result.value.enrollment.factorId).toBe(mfa.factors()[0]?.id);
    expect(mfa.factors()).toHaveLength(1);
    expect(mfa.factors()[0]?.verified).toBe(false);
  });

  it('E-26: removes the unverified factor of an unfinished enrollment and creates a new one', async () => {
    const mfa = createFakeMfa({ factors: [{ id: FACTOR_A, verified: false }] });

    const result = await enrollTotp({ mfa, attestor: mfa.attestor }, ceo);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.replacedFactors).toBe(1);
    expect(result.value.enrollment.factorId).not.toBe(FACTOR_A);
    expect(mfa.factors().map((factor) => factor.id)).toEqual([result.value.enrollment.factorId]);
    expect(mfa.calls).toEqual([
      'list',
      `remove:${FACTOR_A}`,
      'enroll',
      'session',
      `register:${result.value.enrollment.factorId}`,
    ]);
  });

  it('E-26: removes every unverified factor, not only the first', async () => {
    const mfa = createFakeMfa({
      factors: [
        { id: FACTOR_A, verified: false },
        { id: FACTOR_B, verified: false },
      ],
    });

    const result = await enrollTotp({ mfa, attestor: mfa.attestor }, ceo);

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.replacedFactors).toBe(2);
    expect(mfa.factors()).toHaveLength(1);
  });

  it('E-27: a verified factor is a 409 MFA_ALREADY_ENROLLED and nothing is touched', async () => {
    const mfa = createFakeMfa({ factors: [{ id: FACTOR_A, verified: true }] });

    const result = await enrollTotp(
      { mfa, attestor: mfa.attestor },
      { ...ceo, aal: 'aal2', pendingActions: [] },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(MfaAlreadyEnrolledError);
    expect(mfa.calls).toEqual(['list']);
    expect(mfa.factors()).toEqual([{ id: FACTOR_A, verified: true }]);
  });

  it('E-27: a verified factor next to an unverified one still refuses, and keeps both', async () => {
    const mfa = createFakeMfa({
      factors: [
        { id: FACTOR_A, verified: true },
        { id: FACTOR_B, verified: false },
      ],
    });

    const result = await enrollTotp({ mfa, attestor: mfa.attestor }, ceo);

    expect(result.ok).toBe(false);
    expect(mfa.factors()).toHaveLength(2);
    expect(mfa.calls).toEqual(['list']);
  });

  it('SEC-11: only a CEO enrolls; for a client the gateway is never called', async () => {
    const mfa = createFakeMfa();

    const result = await enrollTotp(
      { mfa, attestor: mfa.attestor },
      { ...ceo, role: 'client', clientId: 'c1' },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('FORBIDDEN');
    expect(mfa.calls).toEqual([]);
  });

  it('a parallel enrollment that wins the race is a ConflictError (retry), not a 500', async () => {
    const mfa = createFakeMfa();
    mfa.conflictOnNextEnroll(new ConflictError('raced'));

    const result = await enrollTotp({ mfa, attestor: mfa.attestor }, ceo);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ConflictError);
  });

  it('E-21: an outage of the auth backend propagates, so the answer is 503 and nothing is half-reported', async () => {
    const mfa = createFakeMfa();
    mfa.failWith('list');

    await expect(enrollTotp({ mfa, attestor: mfa.attestor }, ceo)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('an outage while removing the old factor stops before a new one is created', async () => {
    const mfa = createFakeMfa({ factors: [{ id: FACTOR_A, verified: false }] });
    mfa.failWith('remove');

    await expect(enrollTotp({ mfa, attestor: mfa.attestor }, ceo)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
    expect(mfa.calls).not.toContain('enroll');
  });
});

describe('enrollTotp: the backend records the factor it enrolled (ADR 0013, F-60, F-61)', () => {
  const PLANTED = '00000000-0000-4000-8000-0000000000c3';

  it("F-60: the new factor is registered as the backend's, after the session that enrolls it was read", async () => {
    const mfa = createFakeMfa();

    const result = await enrollTotp({ mfa, attestor: mfa.attestor }, ceo);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(mfa.attestor.registrations()).toEqual([result.value.enrollment.factorId]);
    expect(mfa.backendFactors()).toEqual([result.value.enrollment.factorId]);
    expect(mfa.calls.indexOf('session')).toBeLessThan(
      mfa.calls.indexOf(`register:${result.value.enrollment.factorId}`),
    );
  });

  it('F-60: the registration is made for the user of the principal and the session of the request', async () => {
    const mfa = createFakeMfa();
    const calls: unknown[] = [];
    const attestor = {
      ...mfa.attestor,
      registerEnrollment: (input: Parameters<typeof mfa.attestor.registerEnrollment>[0]) => {
        calls.push(input);
        return mfa.attestor.registerEnrollment(input);
      },
    };

    const result = await enrollTotp({ mfa, attestor }, ceo);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(calls).toEqual([
      {
        userId: ceo.userId,
        factorId: result.value.enrollment.factorId,
        sessionId: FAKE_SESSION_ID,
      },
    ]);
  });

  it('F-60: a candidate planted straight at Auth is removed by the next enrollment like any other candidate', async () => {
    const mfa = createFakeMfa();
    mfa.plant({ id: PLANTED, verified: false });

    const result = await enrollTotp({ mfa, attestor: mfa.attestor }, ceo);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.replacedFactors).toBe(1);
    expect(mfa.calls).toContain(`remove:${PLANTED}`);
    expect(mfa.factors().map((factor) => factor.id)).toEqual([result.value.enrollment.factorId]);
  });

  it('F-61: a verified factor planted straight at Auth is a 409 like any verified factor, and nothing is registered', async () => {
    const mfa = createFakeMfa();
    mfa.plant({ id: PLANTED, verified: true });

    const result = await enrollTotp({ mfa, attestor: mfa.attestor }, ceo);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(MfaAlreadyEnrolledError);
    expect(mfa.attestor.registrations()).toEqual([]);
  });

  it('a factor that vanished before it was recorded (a parallel enrollment) is a ConflictError: retrying is safe', async () => {
    const mfa = createFakeMfa();
    mfa.attestor.conflictOnNextRegistration();

    const result = await enrollTotp({ mfa, attestor: mfa.attestor }, ceo);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ConflictError);
  });

  it('fail closed: if the record cannot be written the answer is a 503 and the secret is not returned', async () => {
    const mfa = createFakeMfa();
    mfa.attestor.failWith('register');

    await expect(enrollTotp({ mfa, attestor: mfa.attestor }, ceo)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('fail closed: a session id that cannot be read stops the enrollment before anything is registered', async () => {
    const mfa = createFakeMfa();
    mfa.failWith('session');

    await expect(enrollTotp({ mfa, attestor: mfa.attestor }, ceo)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
    expect(mfa.attestor.registrations()).toEqual([]);
  });

  it('the factor of a failed record stays a plain candidate, not the one of the backend: nothing resolves it', async () => {
    const mfa = createFakeMfa();
    mfa.attestor.failWith('register');
    await expect(enrollTotp({ mfa, attestor: mfa.attestor }, ceo)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
    const stale = mfa.factors();
    expect(stale).toHaveLength(1);
    expect(mfa.backendFactors()).toEqual([]);
  });
});

describe('enrollTotp: the first factor is only enrolled once (F-64)', () => {
  it('a registration the database refuses because the account already had its first factor activated is the usual 409, and no secret is returned', async () => {
    const mfa = createFakeMfa();
    mfa.attestor.refuseNextRegistrationAsReenrollment();

    const result = await enrollTotp({ mfa, attestor: mfa.attestor }, ceo);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(MfaReenrollmentRefusedError);
    expect(result.error).toBeInstanceOf(MfaAlreadyEnrolledError);
    expect(result.error.code).toBe('MFA_ALREADY_ENROLLED');
    expect(result.error.detail).toBe(
      'An authenticator app is already registered for this account.',
    );
  });
});
