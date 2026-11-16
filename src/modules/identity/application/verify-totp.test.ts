import { describe, expect, it } from 'vitest';
import { ServiceUnavailableError, UnauthenticatedError, type Principal } from '@/shared/kernel';
import { InvalidMfaCodeError } from '../domain/mfa-errors';
import { createFakeClientDirectory } from './fakes';
import { createFakeMfa, FAKE_VALID_CODE } from './fake-mfa';
import { verifyTotp } from './verify-totp';

const FACTOR = '00000000-0000-4000-8000-0000000000a1';
const USER_ID = '11111111-1111-4111-8111-111111111111';

/** A CEO with no verified factor yet: the verification that follows ACTIVATES the first one. */
const enrolling: Principal = {
  userId: USER_ID,
  role: 'ceo',
  clientId: null,
  displayName: 'CEO',
  aal: 'aal1',
  pendingActions: ['ENROLL_MFA'],
};
/** A CEO with a verified factor on a new `aal1` session: the verification only elevates it. */
const returning: Principal = { ...enrolling, pendingActions: ['VERIFY_MFA'] };
const elevated: Principal = { ...enrolling, aal: 'aal2', pendingActions: [] };

const input = { factorId: FACTOR, code: FAKE_VALID_CODE };

function deps(options: Parameters<typeof createFakeMfa>[0] = {}) {
  const mfa = createFakeMfa({
    factors: [{ id: FACTOR, verified: false }],
    principalAfterVerify: elevated,
    ...options,
  });
  return { mfa, deps: { mfa, principals: mfa, clients: createFakeClientDirectory([]) } };
}

describe('verifyTotp', () => {
  it('AC-07: a right code elevates the session and returns the principal of the new one (aal2, nothing pending)', async () => {
    const { mfa, deps: d } = deps();

    const result = await verifyTotp(d, enrolling, input);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(mfa.elevated()).toBe(true);
    expect(result.value.session.principal.aal).toBe('aal2');
    expect(result.value.session.principal.pendingActions).toEqual([]);
    expect(result.value.session.client).toBeNull();
    expect(mfa.factors()).toEqual([{ id: FACTOR, verified: true }]);
  });

  it('E-28: a wrong code is InvalidMfaCodeError (invalid_code), the session is not elevated and nothing else runs', async () => {
    const { mfa, deps: d } = deps();

    const result = await verifyTotp(d, enrolling, { factorId: FACTOR, code: '000000' });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(InvalidMfaCodeError);
      expect((result.error as InvalidMfaCodeError).reason).toBe('invalid_code');
    }
    expect(mfa.elevated()).toBe(false);
    expect(mfa.calls).toEqual([`verify:${FACTOR}`]);
  });

  it('E-28: a factor the account does not have answers like a wrong code, with its own reason for the log', async () => {
    const { deps: d } = deps();

    const result = await verifyTotp(d, enrolling, {
      factorId: '00000000-0000-4000-8000-0000000000ff',
      code: FAKE_VALID_CODE,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(InvalidMfaCodeError);
      expect((result.error as InvalidMfaCodeError).reason).toBe('factor_not_found');
    }
  });

  it('F-21: the same code sent twice is refused the second time (code_reused), even when it was a right one', async () => {
    const { mfa, deps: d } = deps();
    const first = await verifyTotp(d, enrolling, input);
    expect(first.ok).toBe(true);
    const revocationsAfterFirst = mfa.revocations();

    const second = await verifyTotp(d, returning, input);

    expect(second.ok).toBe(false);
    if (!second.ok) {
      expect(second.error).toBeInstanceOf(InvalidMfaCodeError);
      expect((second.error as InvalidMfaCodeError).reason).toBe('code_reused');
    }
    expect(mfa.revocations()).toBe(revocationsAfterFirst);
  });

  it('SEC-11: only a CEO verifies; for a client the gateway is never called', async () => {
    const { mfa, deps: d } = deps();

    const result = await verifyTotp(d, { ...enrolling, role: 'client', clientId: 'c1' }, input);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('FORBIDDEN');
    expect(mfa.calls).toEqual([]);
  });

  it('M2: a session that ended while the code was checked is UnauthenticatedError (401), not an invariant failure', async () => {
    const { deps: d } = deps({ principalAfterVerify: null });

    const result = await verifyTotp(d, enrolling, input);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(UnauthenticatedError);
      expect(result.error.code).toBe('UNAUTHENTICATED');
    }
  });

  it('a session with no principal is not hardened any further: nothing is revoked', async () => {
    const { mfa, deps: d } = deps({ principalAfterVerify: null });

    await verifyTotp(d, enrolling, input);

    expect(mfa.revocations()).toBe(0);
  });

  it('fails closed when the elevated session belongs to another user', async () => {
    const { deps: d } = deps({
      principalAfterVerify: { ...elevated, userId: '22222222-2222-4222-8222-222222222222' },
    });

    await expect(verifyTotp(d, enrolling, input)).rejects.toThrow(/is another user/);
  });

  it('E-21: an outage while checking the code propagates as ServiceUnavailableError', async () => {
    const { mfa, deps: d } = deps();
    mfa.failWith('verify');

    await expect(verifyTotp(d, enrolling, input)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});

describe('verifyTotp: the first activation signs the other sessions out', () => {
  it('F-20: the verification that ACTIVATES the first factor signs the other sessions out', async () => {
    const { mfa, deps: d } = deps();

    const result = await verifyTotp(d, enrolling, input);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.activated).toBe(true);
    expect(result.value.otherSessionsRevoked).toBe(true);
    expect(mfa.revocations()).toBe(1);
  });

  it('F-20: a later login that only verifies the same factor does NOT sign the other sessions out', async () => {
    const { mfa, deps: d } = deps({ factors: [{ id: FACTOR, verified: true }] });

    const result = await verifyTotp(d, returning, input);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.activated).toBe(false);
    expect(result.value.otherSessionsRevoked).toBeNull();
    expect(mfa.revocations()).toBe(0);
  });

  it('F-20: revoking the other sessions comes after the new principal was read', async () => {
    const { mfa, deps: d } = deps();

    await verifyTotp(d, enrolling, input);

    expect(mfa.calls).toEqual([`verify:${FACTOR}`, 'current', 'revoke']);
  });

  it('F-20: a failed revocation does not fail the verification, and says so', async () => {
    const { mfa, deps: d } = deps();
    mfa.failWith('revoke');

    const result = await verifyTotp(d, enrolling, input);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.session.principal.aal).toBe('aal2');
    expect(result.value.otherSessionsRevoked).toBe(false);
  });
});
