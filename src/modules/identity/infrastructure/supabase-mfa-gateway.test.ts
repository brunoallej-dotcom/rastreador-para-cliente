import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { RequestSupabase } from '@/shared/db/server-client';
import { ConflictError, ServiceUnavailableError, UnauthenticatedError } from '@/shared/kernel';
import { InvalidMfaCodeError, MfaAlreadyEnrolledError } from '../domain/mfa-errors';
import { codeDigest, createSupabaseMfaGateway } from './supabase-mfa-gateway';

const FACTOR_ID = '33333333-3333-4333-8333-333333333333';
const CHALLENGE_ID = '44444444-4444-4444-8444-444444444444';

type Outcome = { data: unknown; error: unknown } | Error;

const authError = (status: number, code: string) => ({ name: 'AuthApiError', status, code });

const ENROLLED = {
  id: FACTOR_ID,
  type: 'totp',
  totp: {
    uri: 'otpauth://totp/Rastreador:ceo?secret=JBSWY3DPEHPK3PXP&issuer=Rastreador',
    secret: 'JBSWY3DPEHPK3PXP',
    qr_code: 'data:image/svg+xml;utf-8,<svg/>',
  },
};

function fakeSupabase(
  options: {
    listFactors?: Outcome;
    unenroll?: Outcome;
    enroll?: Outcome;
    challenge?: Outcome;
    verify?: Outcome;
    signOut?: Outcome;
    /** What `consume_totp_code` answers (default: the code is accepted). */
    consume?: { data: unknown; error?: unknown; status?: number } | Error;
    principal?: { data: unknown; error?: unknown; status?: number };
  } = {},
) {
  const settle = (outcome: Outcome) =>
    outcome instanceof Error ? Promise.reject(outcome) : Promise.resolve(outcome);
  const mfa = {
    listFactors: vi.fn(() =>
      settle(options.listFactors ?? { data: { all: [], totp: [] }, error: null }),
    ),
    unenroll: vi.fn(() => settle(options.unenroll ?? { data: { id: FACTOR_ID }, error: null })),
    enroll: vi.fn(() => settle(options.enroll ?? { data: ENROLLED, error: null })),
    challenge: vi.fn(() =>
      settle(options.challenge ?? { data: { id: CHALLENGE_ID, type: 'totp' }, error: null }),
    ),
    verify: vi.fn(() => settle(options.verify ?? { data: { access_token: 'x' }, error: null })),
  };
  const signOut = vi.fn(() => settle(options.signOut ?? { data: null, error: null }));
  const rpc = vi.fn((name: string) => {
    if (name === 'consume_totp_code') {
      const consume = options.consume ?? { data: true };
      if (consume instanceof Error) return Promise.reject(consume);
      return Promise.resolve({ error: null, status: 200, ...consume });
    }
    return {
      setHeader: () => undefined,
      maybeSingle: () =>
        Promise.resolve({
          data: options.principal?.data ?? null,
          error: options.principal?.error ?? null,
          status: options.principal?.status ?? 200,
        }),
    };
  });
  const supabase = {
    auth: { mfa, signOut },
    rpc,
  } as unknown as RequestSupabase;
  return { supabase, mfa, rpc, signOut };
}

describe('SupabaseMfaGateway.listTotpFactors', () => {
  it('lists the TOTP factors with their state and ignores other factor types', async () => {
    const { supabase } = fakeSupabase({
      listFactors: {
        data: {
          all: [
            { id: FACTOR_ID, factor_type: 'totp', status: 'unverified', friendly_name: '' },
            { id: CHALLENGE_ID, factor_type: 'totp', status: 'verified' },
            {
              id: '55555555-5555-4555-8555-555555555555',
              factor_type: 'phone',
              status: 'verified',
            },
          ],
        },
        error: null,
      },
    });

    const factors = await createSupabaseMfaGateway(supabase).listTotpFactors();

    expect(factors).toEqual([
      { id: FACTOR_ID, verified: false },
      { id: CHALLENGE_ID, verified: true },
    ]);
  });

  it('never carries more than the id and the state: no secret, no friendly name', async () => {
    const { supabase } = fakeSupabase({
      listFactors: {
        data: { all: [{ id: FACTOR_ID, factor_type: 'totp', status: 'verified', secret: 'S' }] },
        error: null,
      },
    });

    const [factor] = await createSupabaseMfaGateway(supabase).listTotpFactors();

    expect(Object.keys(factor ?? {}).sort()).toEqual(['id', 'verified']);
  });

  it('a factor list it does not understand is a plain error (500), not an empty list', async () => {
    const { supabase } = fakeSupabase({
      listFactors: {
        data: { all: [{ id: 'not-a-uuid', factor_type: 'totp', status: 'x' }] },
        error: null,
      },
    });

    await expect(createSupabaseMfaGateway(supabase).listTotpFactors()).rejects.toThrow(
      /not understood/,
    );
  });

  it('E-21: an Auth outage is ServiceUnavailableError', async () => {
    const { supabase } = fakeSupabase({
      listFactors: { data: null, error: { name: 'AuthRetryableFetchError', status: 0 } },
    });

    await expect(createSupabaseMfaGateway(supabase).listTotpFactors()).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it.each([
    ['an HTTP 401', authError(401, 'unexpected')],
    ['session_not_found', authError(403, 'session_not_found')],
    ['bad_jwt', authError(403, 'bad_jwt')],
    ['user_not_found', authError(403, 'user_not_found')],
    ['a missing session in the client', { name: 'AuthSessionMissingError', status: 400 }],
  ])('B1: %s means the session is gone: UnauthenticatedError (401)', async (_label, error) => {
    const { supabase } = fakeSupabase({ listFactors: { data: null, error } });

    await expect(createSupabaseMfaGateway(supabase).listTotpFactors()).rejects.toBeInstanceOf(
      UnauthenticatedError,
    );
  });

  it('B2: an Auth 429 is the service throttling us: ServiceUnavailableError, never a refused code', async () => {
    const { supabase } = fakeSupabase({
      listFactors: { data: null, error: authError(429, 'over_request_rate_limit') },
    });

    await expect(createSupabaseMfaGateway(supabase).listTotpFactors()).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });
});

describe('SupabaseMfaGateway.removeUnverifiedTotp', () => {
  it('asks Auth to remove that factor', async () => {
    const { supabase, mfa } = fakeSupabase();

    await createSupabaseMfaGateway(supabase).removeUnverifiedTotp(FACTOR_ID);

    expect(mfa.unenroll).toHaveBeenCalledWith({ factorId: FACTOR_ID });
  });

  it('M1: a factor that is already gone is success: two tabs enrolling at once both remove it (last wins)', async () => {
    const { supabase } = fakeSupabase({
      unenroll: { data: null, error: authError(404, 'mfa_factor_not_found') },
    });

    await expect(
      createSupabaseMfaGateway(supabase).removeUnverifiedTotp(FACTOR_ID),
    ).resolves.toBeUndefined();
  });

  it('a refusal of Auth is an error, so the enrollment stops before a new factor exists', async () => {
    const { supabase } = fakeSupabase({
      unenroll: { data: null, error: authError(422, 'insufficient_aal') },
    });

    await expect(
      createSupabaseMfaGateway(supabase).removeUnverifiedTotp(FACTOR_ID),
    ).rejects.toThrow(/remove a factor failed unexpectedly/);
  });
});

describe('SupabaseMfaGateway.enrollTotp', () => {
  it('maps the answer of Auth to the enrollment of the contract (ids, URI, secret, QR code)', async () => {
    const { supabase, mfa } = fakeSupabase();

    const result = await createSupabaseMfaGateway(supabase).enrollTotp();

    expect(result).toEqual({
      ok: true,
      value: {
        factorId: FACTOR_ID,
        uri: ENROLLED.totp.uri,
        secret: ENROLLED.totp.secret,
        qrCode: ENROLLED.totp.qr_code,
      },
    });
    // no friendly name: Auth then allows one factor per user, which closes the enrollment race
    expect(mfa.enroll).toHaveBeenCalledWith({ factorType: 'totp', issuer: 'Rastreador' });
  });

  it('a name conflict (a parallel enrollment) is a ConflictError: retrying is safe', async () => {
    const { supabase } = fakeSupabase({
      enroll: { data: null, error: authError(422, 'mfa_factor_name_conflict') },
    });

    const result = await createSupabaseMfaGateway(supabase).enrollTotp();

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ConflictError);
  });

  it('E-27: Auth asking for aal2 to add a factor means a verified one exists: MfaAlreadyEnrolledError', async () => {
    const { supabase } = fakeSupabase({
      enroll: { data: null, error: authError(403, 'insufficient_aal') },
    });

    const result = await createSupabaseMfaGateway(supabase).enrollTotp();

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(MfaAlreadyEnrolledError);
  });

  it.each([
    [
      'a payload without the secret',
      { ...ENROLLED, totp: { ...ENROLLED.totp, secret: undefined } },
    ],
    ['a URI that is not otpauth', { ...ENROLLED, totp: { ...ENROLLED.totp, uri: 'https://x' } }],
    [
      'a QR code that is not an SVG data URI',
      { ...ENROLLED, totp: { ...ENROLLED.totp, qr_code: 'x' } },
    ],
    ['another factor type', { ...ENROLLED, type: 'phone' }],
    ['an id that is not a UUID', { ...ENROLLED, id: 'nope' }],
  ])('%s is a plain error (500), never a malformed response', async (_label, data) => {
    const { supabase } = fakeSupabase({ enroll: { data, error: null } });

    await expect(createSupabaseMfaGateway(supabase).enrollTotp()).rejects.toThrow(/not understood/);
  });

  it('SEC-13: the error of an unexpected failure never carries the secret', async () => {
    const { supabase } = fakeSupabase({
      enroll: { data: { ...ENROLLED, id: 'nope' }, error: null },
    });

    const failure = await createSupabaseMfaGateway(supabase)
      .enrollTotp()
      .catch((error: unknown) => error);

    expect(String((failure as Error).message)).not.toContain(ENROLLED.totp.secret);
    expect(String((failure as Error).stack)).not.toContain(ENROLLED.totp.secret);
  });

  it('E-21: an Auth outage is ServiceUnavailableError', async () => {
    const { supabase } = fakeSupabase({ enroll: new TypeError('fetch failed') });

    await expect(createSupabaseMfaGateway(supabase).enrollTotp()).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });
});

describe('SupabaseMfaGateway.verifyTotp', () => {
  const input = { factorId: FACTOR_ID, code: '123456' };

  it('burns the code, challenges the factor, answers the challenge with the code and succeeds', async () => {
    const { supabase, mfa, rpc } = fakeSupabase();

    const result = await createSupabaseMfaGateway(supabase).verifyTotp(input);

    expect(result).toEqual({ ok: true, value: undefined });
    expect(rpc).toHaveBeenCalledWith('consume_totp_code', {
      p_factor_id: FACTOR_ID,
      p_code_digest: codeDigest(FACTOR_ID, '123456'),
    });
    expect(mfa.challenge).toHaveBeenCalledWith({ factorId: FACTOR_ID });
    expect(mfa.verify).toHaveBeenCalledWith({
      factorId: FACTOR_ID,
      challengeId: CHALLENGE_ID,
      code: '123456',
    });
  });

  it('F-21: the code is burned BEFORE the Auth server sees it', async () => {
    const { supabase, mfa, rpc } = fakeSupabase();

    await createSupabaseMfaGateway(supabase).verifyTotp(input);

    const burned = rpc.mock.invocationCallOrder[0] ?? Number.POSITIVE_INFINITY;
    const challenged = mfa.challenge.mock.invocationCallOrder[0] ?? 0;
    expect(burned).toBeLessThan(challenged);
  });

  it('F-21: what the database receives is the SHA-256 of "<factorId>:<code>", never the code', () => {
    const digest = codeDigest(FACTOR_ID, '123456');

    expect(digest).toBe(`\\x${createHash('sha256').update(`${FACTOR_ID}:123456`).digest('hex')}`);
    expect(digest).toMatch(/^\\x[0-9a-f]{64}$/);
    expect(digest).not.toContain('123456');
    // another factor or another code never shares a digest
    expect(codeDigest(CHALLENGE_ID, '123456')).not.toBe(digest);
    expect(codeDigest(FACTOR_ID, '654321')).not.toBe(digest);
  });

  it('F-21: a replayed code (the database says false) is InvalidMfaCodeError (code_reused) and the Auth server is never asked', async () => {
    const { supabase, mfa } = fakeSupabase({ consume: { data: false } });

    const result = await createSupabaseMfaGateway(supabase).verifyTotp(input);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(InvalidMfaCodeError);
      expect(result.error.reason).toBe('code_reused');
    }
    expect(mfa.challenge).not.toHaveBeenCalled();
    expect(mfa.verify).not.toHaveBeenCalled();
  });

  it('F-20: a factor that is not a TOTP factor of the account (NOT_FOUND) is InvalidMfaCodeError (factor_not_found), and the code is never tried', async () => {
    const { supabase, mfa } = fakeSupabase({
      consume: { data: null, error: { code: 'P0001', message: 'NOT_FOUND' }, status: 400 },
    });

    const result = await createSupabaseMfaGateway(supabase).verifyTotp(input);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.reason).toBe('factor_not_found');
    expect(mfa.challenge).not.toHaveBeenCalled();
  });

  it('a session with no active principal (42501) is UnauthenticatedError', async () => {
    const { supabase, mfa } = fakeSupabase({
      consume: { data: null, error: { code: '42501', message: 'FORBIDDEN' }, status: 403 },
    });

    await expect(createSupabaseMfaGateway(supabase).verifyTotp(input)).rejects.toBeInstanceOf(
      UnauthenticatedError,
    );
    expect(mfa.challenge).not.toHaveBeenCalled();
  });

  it.each([
    ['the database down (503)', { data: null, error: { code: '', message: 'x' }, status: 503 }],
    ['a transport failure', new TypeError('fetch failed')],
  ])('E-21: %s while burning the code is ServiceUnavailableError', async (_label, consume) => {
    const { supabase, mfa } = fakeSupabase({ consume });

    await expect(createSupabaseMfaGateway(supabase).verifyTotp(input)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
    expect(mfa.challenge).not.toHaveBeenCalled();
  });

  it.each([
    [
      'an error it does not know',
      { data: null, error: { code: 'XX000', message: 'boom' }, status: 400 },
    ],
    ['an answer that is not a boolean', { data: 'yes' }],
    ['no answer', { data: null }],
  ])(
    '%s while burning the code is a plain error (500): nothing reaches the Auth server',
    async (_label, consume) => {
      const { supabase, mfa } = fakeSupabase({ consume });

      const failure = await createSupabaseMfaGateway(supabase)
        .verifyTotp(input)
        .catch((thrown: unknown) => thrown);

      expect(failure).toBeInstanceOf(Error);
      expect(failure).not.toBeInstanceOf(InvalidMfaCodeError);
      expect(failure).not.toBeInstanceOf(ServiceUnavailableError);
      expect(mfa.challenge).not.toHaveBeenCalled();
    },
  );

  it('E-28: a wrong code is InvalidMfaCodeError (invalid_code)', async () => {
    const { supabase } = fakeSupabase({
      verify: { data: null, error: authError(422, 'mfa_verification_failed') },
    });

    const result = await createSupabaseMfaGateway(supabase).verifyTotp(input);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(InvalidMfaCodeError);
      expect(result.error.reason).toBe('invalid_code');
    }
  });

  it("E-28: a factor that is not the account's, seen by the Auth server, answers like a wrong code, and the code is never tried", async () => {
    const { supabase, mfa } = fakeSupabase({
      challenge: { data: null, error: authError(404, 'mfa_factor_not_found') },
    });

    const result = await createSupabaseMfaGateway(supabase).verifyTotp(input);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(InvalidMfaCodeError);
      expect(result.error.reason).toBe('factor_not_found');
    }
    expect(mfa.verify).not.toHaveBeenCalled();
  });

  it.each([
    ['Auth throttling (429)', authError(429, 'over_request_rate_limit'), ServiceUnavailableError],
    ['a 500 of Auth', authError(500, 'unexpected_failure'), ServiceUnavailableError],
    ['an expired challenge', authError(422, 'mfa_challenge_expired'), Error],
    ['a session that is gone', authError(403, 'session_not_found'), UnauthenticatedError],
  ])('%s is not a verdict on the code', async (_label, error, expected) => {
    const { supabase } = fakeSupabase({ verify: { data: null, error } });

    const failure = await createSupabaseMfaGateway(supabase)
      .verifyTotp(input)
      .catch((thrown: unknown) => thrown);

    expect(failure).toBeInstanceOf(expected);
    expect(failure).not.toBeInstanceOf(InvalidMfaCodeError);
  });

  it('a challenge it does not understand is a plain error (500) and the code is never tried', async () => {
    const { supabase, mfa } = fakeSupabase({ challenge: { data: { id: 'nope' }, error: null } });

    await expect(createSupabaseMfaGateway(supabase).verifyTotp(input)).rejects.toThrow(
      /not understood/,
    );
    expect(mfa.verify).not.toHaveBeenCalled();
  });

  it('E-21: a transport failure while verifying is ServiceUnavailableError', async () => {
    const { supabase } = fakeSupabase({ verify: new TypeError('fetch failed') });

    await expect(createSupabaseMfaGateway(supabase).verifyTotp(input)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });
});

describe('SupabaseMfaGateway.revokeOtherSessions', () => {
  it('F-20: revoking signs the user out of the OTHER sessions only (scope others)', async () => {
    const { supabase, signOut } = fakeSupabase();

    await createSupabaseMfaGateway(supabase).revokeOtherSessions();

    expect(signOut).toHaveBeenCalledWith({ scope: 'others' });
  });

  it('F-20: a revocation the Auth server refuses is an error for the caller to report', async () => {
    const { supabase } = fakeSupabase({
      signOut: { data: null, error: authError(500, 'unexpected_failure') },
    });

    await expect(createSupabaseMfaGateway(supabase).revokeOtherSessions()).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });
});

describe('SupabaseMfaGateway.current', () => {
  it('reads the principal of the session the client carries now (the elevated one)', async () => {
    const { supabase, rpc } = fakeSupabase({
      principal: {
        data: {
          user_id: '11111111-1111-4111-8111-111111111111',
          role: 'ceo',
          client_id: null,
          display_name: 'CEO',
          aal: 'aal2',
          has_verified_totp: true,
          must_change_password: false,
        },
      },
    });

    const principal = await createSupabaseMfaGateway(supabase).current();

    expect(rpc).toHaveBeenCalledWith('current_principal');
    expect(principal).toMatchObject({ role: 'ceo', aal: 'aal2', pendingActions: [] });
  });
});
