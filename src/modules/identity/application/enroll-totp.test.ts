import { describe, expect, it } from 'vitest';
import { ConflictError, ServiceUnavailableError, type Principal } from '@/shared/kernel';
import { MfaAlreadyEnrolledError } from '../domain/mfa-errors';
import { createFakeMfa } from './fake-mfa';
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

    const result = await enrollTotp({ mfa }, ceo);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.replacedFactors).toBe(0);
    expect(result.value.enrollment.factorId).toBe(mfa.factors()[0]?.id);
    expect(mfa.factors()).toHaveLength(1);
    expect(mfa.factors()[0]?.verified).toBe(false);
  });

  it('E-26: removes the unverified factor of an unfinished enrollment and creates a new one', async () => {
    const mfa = createFakeMfa({ factors: [{ id: FACTOR_A, verified: false }] });

    const result = await enrollTotp({ mfa }, ceo);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.replacedFactors).toBe(1);
    expect(result.value.enrollment.factorId).not.toBe(FACTOR_A);
    expect(mfa.factors().map((factor) => factor.id)).toEqual([result.value.enrollment.factorId]);
    expect(mfa.calls).toEqual(['list', `remove:${FACTOR_A}`, 'enroll']);
  });

  it('E-26: removes every unverified factor, not only the first', async () => {
    const mfa = createFakeMfa({
      factors: [
        { id: FACTOR_A, verified: false },
        { id: FACTOR_B, verified: false },
      ],
    });

    const result = await enrollTotp({ mfa }, ceo);

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.replacedFactors).toBe(2);
    expect(mfa.factors()).toHaveLength(1);
  });

  it('E-27: a verified factor is a 409 MFA_ALREADY_ENROLLED and nothing is touched', async () => {
    const mfa = createFakeMfa({ factors: [{ id: FACTOR_A, verified: true }] });

    const result = await enrollTotp({ mfa }, { ...ceo, aal: 'aal2', pendingActions: [] });

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

    const result = await enrollTotp({ mfa }, ceo);

    expect(result.ok).toBe(false);
    expect(mfa.factors()).toHaveLength(2);
    expect(mfa.calls).toEqual(['list']);
  });

  it('SEC-11: only a CEO enrolls; for a client the gateway is never called', async () => {
    const mfa = createFakeMfa();

    const result = await enrollTotp({ mfa }, { ...ceo, role: 'client', clientId: 'c1' });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('FORBIDDEN');
    expect(mfa.calls).toEqual([]);
  });

  it('a parallel enrollment that wins the race is a ConflictError (retry), not a 500', async () => {
    const mfa = createFakeMfa();
    mfa.conflictOnNextEnroll(new ConflictError('raced'));

    const result = await enrollTotp({ mfa }, ceo);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ConflictError);
  });

  it('E-21: an outage of the auth backend propagates, so the answer is 503 and nothing is half-reported', async () => {
    const mfa = createFakeMfa();
    mfa.failWith('list');

    await expect(enrollTotp({ mfa }, ceo)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('an outage while removing the old factor stops before a new one is created', async () => {
    const mfa = createFakeMfa({ factors: [{ id: FACTOR_A, verified: false }] });
    mfa.failWith('remove');

    await expect(enrollTotp({ mfa }, ceo)).rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(mfa.calls).not.toContain('enroll');
  });
});
