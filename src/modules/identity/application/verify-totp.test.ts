import { describe, expect, it } from 'vitest';
import { ServiceUnavailableError, UnauthenticatedError, type Principal } from '@/shared/kernel';
import { InvalidMfaCodeError } from '../domain/mfa-errors';
import { createFakeClientDirectory } from './fakes';
import { createFakeMfa, FAKE_SESSION_ID, FAKE_VALID_CODE } from './fake-mfa';
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

/** The calls of a verification that gets all the way through, for a factor (see the fake's challenge ids). */
const recorded = (factorId: string, n = 1) => `record:${factorId}:challenge-${n}`;
const attested = (factorId: string, n = 1) =>
  `attest:${FAKE_SESSION_ID}:${factorId}:challenge-${n}`;

function deps(options: Parameters<typeof createFakeMfa>[0] = {}) {
  const mfa = createFakeMfa({
    factors: [{ id: FACTOR, verified: false }],
    principalAfterVerify: elevated,
    ...options,
  });
  return {
    mfa,
    deps: { mfa, attestor: mfa.attestor, principals: mfa, clients: createFakeClientDirectory([]) },
  };
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
    expect(mfa.calls).toEqual([`verify:${FACTOR}`, recorded(FACTOR)]);
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

    expect(mfa.calls).toEqual([
      `verify:${FACTOR}`,
      recorded(FACTOR),
      'current',
      'session',
      attested(FACTOR),
      'revoke',
      'current',
    ]);
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

describe('verifyTotp without a factor id (the factor of the session, E-31)', () => {
  const OTHER = '00000000-0000-4000-8000-0000000000a2';
  const code = { code: FAKE_VALID_CODE };

  const reasonOf = (result: Awaited<ReturnType<typeof verifyTotp>>) => {
    expect(result.ok).toBe(false);
    if (result.ok) return undefined;
    expect(result.error).toBeInstanceOf(InvalidMfaCodeError);
    return (result.error as InvalidMfaCodeError).reason;
  };

  it('a new device: the one VERIFIED factor of the user is used, and the session becomes aal2', async () => {
    const { mfa, deps: d } = deps({ factors: [{ id: FACTOR, verified: true }] });

    const result = await verifyTotp(d, returning, code);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.factorId).toBe(FACTOR);
    expect(result.value.activated).toBe(false);
    expect(result.value.session.principal.aal).toBe('aal2');
    expect(mfa.calls).toEqual([
      'list',
      `verify:${FACTOR}`,
      recorded(FACTOR),
      'current',
      'session',
      attested(FACTOR),
      'current',
    ]);
    expect(mfa.revocations()).toBe(0);
  });

  it('the first use: with nothing verified, the one unverified candidate of the enrollment is used and activated', async () => {
    const { mfa, deps: d } = deps();

    const result = await verifyTotp(d, enrolling, code);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.factorId).toBe(FACTOR);
    expect(result.value.activated).toBe(true);
    expect(mfa.factors()).toEqual([{ id: FACTOR, verified: true }]);
    expect(mfa.revocations()).toBe(1);
  });

  it('a verified factor wins over an unverified leftover next to it', async () => {
    const { mfa, deps: d } = deps({
      factors: [
        { id: OTHER, verified: false },
        { id: FACTOR, verified: true },
      ],
    });

    const result = await verifyTotp(d, returning, code);

    expect(result.ok && result.value.factorId).toBe(FACTOR);
    expect(mfa.calls).toContain(`verify:${FACTOR}`);
    expect(mfa.calls).not.toContain(`verify:${OTHER}`);
  });

  it('no TOTP factor at all is refused like a wrong code (factor_not_found), and no code is tried', async () => {
    const { mfa, deps: d } = deps({ factors: [] });

    const result = await verifyTotp(d, enrolling, code);

    expect(reasonOf(result)).toBe('factor_not_found');
    expect(mfa.calls).toEqual(['list']);
    expect(mfa.elevated()).toBe(false);
  });

  it.each([
    [
      'two verified factors',
      [
        { id: FACTOR, verified: true },
        { id: OTHER, verified: true },
      ],
    ],
    [
      'two unverified factors and no verified one',
      [
        { id: FACTOR, verified: false },
        { id: OTHER, verified: false },
      ],
    ],
  ])(
    '%s are ambiguous: factor_not_found would lie, so factor_ambiguous, and the code is tried on none of them',
    async (_label, factors) => {
      const { mfa, deps: d } = deps({ factors });

      const result = await verifyTotp(d, returning, code);

      expect(reasonOf(result)).toBe('factor_ambiguous');
      expect(mfa.calls).toEqual(['list']);
      expect(mfa.elevated()).toBe(false);
    },
  );

  it('a factor id in the request is used as it is: the factors of the user are not even listed', async () => {
    const { mfa, deps: d } = deps({ factors: [{ id: FACTOR, verified: true }] });

    const result = await verifyTotp(d, returning, { factorId: FACTOR, ...code });

    expect(result.ok).toBe(true);
    expect(mfa.calls).toEqual([
      `verify:${FACTOR}`,
      recorded(FACTOR),
      'current',
      'session',
      attested(FACTOR),
      'current',
    ]);
  });

  it("a factor id that is not the account's stays refused like a wrong code, and the error knows which id it was", async () => {
    const { deps: d } = deps({ factors: [{ id: FACTOR, verified: true }] });

    const result = await verifyTotp(d, returning, { factorId: OTHER, ...code });

    expect(reasonOf(result)).toBe('factor_not_found');
    if (!result.ok) expect((result.error as InvalidMfaCodeError).factorId).toBe(OTHER);
  });

  it('F-21: the replay guard is keyed by the RESOLVED factor: the same code without the id, twice, is code_reused', async () => {
    const { deps: d } = deps({ factors: [{ id: FACTOR, verified: true }] });
    expect((await verifyTotp(d, returning, code)).ok).toBe(true);

    const replay = await verifyTotp(d, returning, code);
    const replayWithId = await verifyTotp(d, returning, { factorId: FACTOR, ...code });

    expect(reasonOf(replay)).toBe('code_reused');
    // naming the factor does not give the code a second life: it is the same factor
    expect(reasonOf(replayWithId)).toBe('code_reused');
    if (!replay.ok) expect((replay.error as InvalidMfaCodeError).factorId).toBe(FACTOR);
  });

  it('SEC-11: the session decides the role before anything is listed: a client never reaches the gateway', async () => {
    const { mfa, deps: d } = deps();

    const result = await verifyTotp(d, { ...enrolling, role: 'client', clientId: 'c1' }, code);

    expect(result.ok).toBe(false);
    expect(mfa.calls).toEqual([]);
  });

  it('E-21: an outage while listing the factors is a ServiceUnavailableError, never a refused code', async () => {
    const { mfa, deps: d } = deps();
    mfa.failWith('list');

    await expect(verifyTotp(d, enrolling, code)).rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(mfa.calls).toEqual(['list']);
  });

  it('F-60, F-61: the number of TOTP factors the account has travels with the outcome and with every refusal, so the log can see a planted factor', async () => {
    const one = deps({ factors: [{ id: FACTOR, verified: true }] });
    const ok = await verifyTotp(one.deps, returning, code);
    expect(ok.ok && ok.value.candidateCount).toBe(1);

    // a wrong code on an account that has two factors: the refusal says "two"
    const two = deps({
      factors: [
        { id: FACTOR, verified: true },
        { id: OTHER, verified: false },
      ],
    });
    const wrong = await verifyTotp(two.deps, returning, { code: '000000' });
    expect(reasonOf(wrong)).toBe('invalid_code');
    if (!wrong.ok) {
      const error = wrong.error as InvalidMfaCodeError;
      expect(error.candidateCount).toBe(2);
      expect(error.factorId).toBe(FACTOR);
    }

    // the refusals of the resolution itself
    const none = await verifyTotp(deps({ factors: [] }).deps, enrolling, code);
    const ambiguous = await verifyTotp(
      deps({
        factors: [
          { id: FACTOR, verified: false },
          { id: OTHER, verified: false },
        ],
      }).deps,
      enrolling,
      code,
    );
    expect(!none.ok && (none.error as InvalidMfaCodeError).candidateCount).toBe(0);
    expect(!ambiguous.ok && (ambiguous.error as InvalidMfaCodeError).candidateCount).toBe(2);
  });

  it('a request that names the factor lists nothing, so it has no candidate count', async () => {
    const { deps: d } = deps({ factors: [{ id: FACTOR, verified: true }] });

    const ok = await verifyTotp(d, returning, { factorId: FACTOR, ...code });
    const refused = await verifyTotp(d, returning, { factorId: OTHER, ...code });

    expect(ok.ok && ok.value.candidateCount).toBeUndefined();
    expect(!refused.ok && (refused.error as InvalidMfaCodeError).candidateCount).toBeUndefined();
  });
});

describe('verifyTotp: the attestation of the session (ADR 0013, F-50 b, F-63)', () => {
  const OTHER = '00000000-0000-4000-8000-0000000000a2';
  const code = { code: FAKE_VALID_CODE };

  const refusalOf = (result: Awaited<ReturnType<typeof verifyTotp>>) => {
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('expected a refusal');
    expect(result.error).toBeInstanceOf(InvalidMfaCodeError);
    return result.error as InvalidMfaCodeError;
  };

  it('F-63: after the Auth server accepts the code, the session is attested with the ids of THIS verification', async () => {
    const { mfa, deps: d } = deps();

    const result = await verifyTotp(d, enrolling, input);

    expect(result.ok).toBe(true);
    expect(mfa.attestor.attestations()).toEqual([
      { userId: USER_ID, sessionId: FAKE_SESSION_ID, factorId: FACTOR, challengeId: 'challenge-1' },
    ]);
  });

  it("F-63: the challenge is recorded as the backend's BEFORE the Auth server answers it, a wrong code included", async () => {
    const { mfa, deps: d } = deps();

    await verifyTotp(d, enrolling, { factorId: FACTOR, code: '000000' });

    expect(mfa.attestor.recordedChallenges()).toEqual([`${FACTOR}:challenge-1`]);
    expect(mfa.calls.indexOf(recorded(FACTOR))).toBeGreaterThan(
      mfa.calls.indexOf(`verify:${FACTOR}`),
    );
    expect(mfa.attestor.attestations()).toEqual([]);
  });

  it('F-63: nothing is attested for a code the Auth server refused', async () => {
    const { mfa, deps: d } = deps();

    await verifyTotp(d, enrolling, { factorId: FACTOR, code: '000000' });

    expect(mfa.calls.some((call) => call.startsWith('attest:'))).toBe(false);
    expect(mfa.elevated()).toBe(false);
  });

  it('F-63: the outcome the answer is built from is read AFTER the attestation (it says aal2, nothing pending)', async () => {
    const { mfa, deps: d } = deps();

    const result = await verifyTotp(d, enrolling, input);

    expect(result.ok && result.value.session.principal.aal).toBe('aal2');
    expect(mfa.calls.slice(-1)).toEqual(['current']);
    expect(mfa.calls.indexOf(attested(FACTOR))).toBeLessThan(mfa.calls.lastIndexOf('current'));
  });

  it.each(['oracle', 'factor_not_backend', 'factor_not_activated_by_backend'] as const)(
    'E-33: a refused attestation (%s) is InvalidMfaCodeError (attestation_refused), the very 422 of a wrong code',
    async (reason) => {
      const { mfa, deps: d } = deps();
      mfa.attestor.refuseNextAttestationWith(reason);

      const result = await verifyTotp(d, returning, input);

      const error = refusalOf(result);
      expect(error.reason).toBe('attestation_refused');
      expect(error.attestationReason).toBe(reason);
      expect(error.factorId).toBe(FACTOR);
      expect(error.code).toBe('INVALID_MFA_CODE');
    },
  );

  it('E-33: a refused attestation signs nobody else out from here (the database deleted the sessions) and reads nothing more', async () => {
    const { mfa, deps: d } = deps();
    mfa.attestor.refuseNextAttestationWith('oracle');

    await verifyTotp(d, enrolling, input);

    expect(mfa.revocations()).toBe(0);
    expect(mfa.calls.filter((call) => call === 'current')).toHaveLength(1);
  });

  it('E-33: the refusal carries the factor count of the listing, so the log can see a planted factor', async () => {
    const { mfa, deps: d } = deps({ factors: [{ id: FACTOR, verified: true }] });
    mfa.plant({ id: OTHER, verified: false });
    mfa.attestor.refuseNextAttestationWith('oracle');

    const error = refusalOf(await verifyTotp(d, returning, code));

    expect(error.candidateCount).toBe(2);
    expect(error.foreignFactorCount).toBe(1);
    expect(error.attestationReason).toBe('oracle');
  });

  it('F-61: a verified factor planted straight at Auth is refused by the attestation when the request names it', async () => {
    const { mfa, deps: d } = deps({ factors: [] });
    mfa.plant({ id: OTHER, verified: true });

    const error = refusalOf(await verifyTotp(d, returning, { factorId: OTHER, ...code }));

    expect(error.reason).toBe('attestation_refused');
    expect(error.attestationReason).toBe('factor_not_backend');
  });

  it('F-60: a candidate planted next to the backend candidate does NOT make the verification ambiguous', async () => {
    const { mfa, deps: d } = deps({ factors: [{ id: FACTOR, verified: false }] });
    mfa.plant({ id: OTHER, verified: false });

    const result = await verifyTotp(d, enrolling, code);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.factorId).toBe(FACTOR);
    expect(result.value.candidateCount).toBe(2);
    expect(result.value.foreignFactorCount).toBe(1);
    expect(mfa.calls).not.toContain(`verify:${OTHER}`);
  });

  it('F-60: with only a planted candidate there is nothing to resolve: factor_not_found, and the code is tried on nothing', async () => {
    const { mfa, deps: d } = deps({ factors: [] });
    mfa.plant({ id: OTHER, verified: false });

    const error = refusalOf(await verifyTotp(d, enrolling, code));

    expect(error.reason).toBe('factor_not_found');
    expect(error.candidateCount).toBe(1);
    expect(error.foreignFactorCount).toBe(1);
    expect(mfa.calls).toEqual(['list']);
  });

  it("F-61: a verified factor the backend never enrolled is not the CEO's: factor_not_found, counted as foreign", async () => {
    const { mfa, deps: d } = deps({ factors: [] });
    mfa.plant({ id: OTHER, verified: true });

    const error = refusalOf(await verifyTotp(d, returning, code));

    expect(error.reason).toBe('factor_not_found');
    expect(error.foreignFactorCount).toBe(1);
    expect(mfa.calls).toEqual(['list']);
  });

  it('F-60: two backend candidates are still ambiguous (the app never makes that), and a planted one is not counted among them', async () => {
    const { mfa, deps: d } = deps({
      factors: [
        { id: FACTOR, verified: false },
        { id: OTHER, verified: false },
      ],
    });
    mfa.plant({ id: '00000000-0000-4000-8000-0000000000a3', verified: false });

    const error = refusalOf(await verifyTotp(d, enrolling, code));

    expect(error.reason).toBe('factor_ambiguous');
    expect(error.candidateCount).toBe(3);
    expect(error.foreignFactorCount).toBe(1);
  });

  it('F-63: a challenge the database refuses to record (factor or challenge not found) is a refused code, and the code is never tried', async () => {
    const { mfa, deps: d } = deps();
    mfa.attestor.refuseNextChallengeRecord();

    const error = refusalOf(await verifyTotp(d, enrolling, input));

    expect(error.reason).toBe('factor_not_found');
    expect(mfa.elevated()).toBe(false);
    expect(mfa.calls.some((call) => call.startsWith('attest:'))).toBe(false);
  });

  it('F-63: fail closed: if the challenge cannot be recorded (the database is down) the code is not tried and the answer is a 503', async () => {
    const { mfa, deps: d } = deps();
    mfa.attestor.failWith('record');

    await expect(verifyTotp(d, enrolling, input)).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(mfa.elevated()).toBe(false);
  });

  it('F-63: fail closed: if the attestation cannot be written the answer is a 503, nobody is signed out and the session is never reported as aal2', async () => {
    const { mfa, deps: d } = deps();
    mfa.attestor.failWith('attest');

    await expect(verifyTotp(d, enrolling, input)).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(mfa.revocations()).toBe(0);
    expect(mfa.calls.filter((call) => call === 'current')).toHaveLength(1);
  });

  it('F-63: fail closed: a session id that cannot be read is an error, and nothing is attested', async () => {
    const { mfa, deps: d } = deps();
    mfa.failWith('session');

    await expect(verifyTotp(d, enrolling, input)).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(mfa.attestor.attestations()).toEqual([]);
  });

  it('M2: a session that ends between the attestation and the final read is UnauthenticatedError (401)', async () => {
    const { mfa, deps: d } = deps();
    let reads = 0;
    const principals = {
      current: () => {
        reads += 1;
        return mfa.current().then((principal) => (reads === 1 ? principal : null));
      },
    };

    const result = await verifyTotp({ ...d, principals }, enrolling, input);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(UnauthenticatedError);
  });

  it('fails closed when the principal after the attestation belongs to another user', async () => {
    const { mfa, deps: d } = deps();
    let reads = 0;
    const principals = {
      current: () => {
        reads += 1;
        return mfa
          .current()
          .then((principal) =>
            reads === 1 || principal === null
              ? principal
              : { ...principal, userId: '22222222-2222-4222-8222-222222222222' },
          );
      },
    };

    await expect(verifyTotp({ ...d, principals }, enrolling, input)).rejects.toThrow(
      /is another user/,
    );
  });

  it('the attestation uses the user of the principal, never an id of the request', async () => {
    const { mfa, deps: d } = deps({ factors: [{ id: FACTOR, verified: true }] });

    await verifyTotp(d, returning, { factorId: FACTOR, ...code });

    expect(mfa.attestor.attestations().map(({ userId }) => userId)).toEqual([USER_ID]);
  });
});
