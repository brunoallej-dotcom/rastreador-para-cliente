import { describe, expect, it, vi } from 'vitest';
import type { RequestSupabase } from '@/shared/db/server-client';
import { ServiceUnavailableError } from '@/shared/kernel';
import { InvalidCredentialsError, UnexpectedAuthAnswerError } from '../domain/errors';
import { createSupabaseAuthGateway } from './supabase-auth-gateway';

const CREDENTIALS = { email: 'maria@cliente.test', password: 'correct-horse-battery' };

type AuthOutcome = { data: unknown; error: unknown } | Error;

const PRINCIPAL_ROW = {
  user_id: '11111111-1111-4111-8111-111111111111',
  role: 'client',
  client_id: '22222222-2222-4222-8222-222222222222',
  display_name: 'Maria',
  aal: 'aal1',
  has_verified_totp: false,
  must_change_password: false,
};

function fakeSupabase(
  options: {
    signIn?: AuthOutcome;
    signOut?: AuthOutcome;
    /** What `current_principal()` answers: `null` is "no principal". */
    principal?: { data: unknown; error?: unknown; status?: number };
  } = {},
) {
  const settle = (outcome: AuthOutcome) =>
    outcome instanceof Error ? Promise.reject(outcome) : Promise.resolve(outcome);
  const signInWithPassword = vi.fn(() =>
    settle(options.signIn ?? { data: { session: { access_token: 'x' } }, error: null }),
  );
  const signOut = vi.fn(() => settle(options.signOut ?? { error: null, data: null }));
  const headers: Record<string, string> = {};
  const rpc = vi.fn(() => {
    const builder = {
      setHeader(name: string, value: string) {
        headers[name] = value;
        return builder;
      },
      maybeSingle: () =>
        Promise.resolve({
          data: options.principal?.data ?? null,
          error: options.principal?.error ?? null,
          status: options.principal?.status ?? 200,
        }),
    };
    return builder;
  });
  const supabase = { auth: { signInWithPassword, signOut }, rpc } as unknown as RequestSupabase;
  return { supabase, signInWithPassword, signOut, rpc, headers };
}

describe('SupabaseAuthGateway.signInWithPassword', () => {
  it('signs in with the credentials as given (already normalized by the caller)', async () => {
    const { supabase, signInWithPassword } = fakeSupabase();
    const result = await createSupabaseAuthGateway(supabase).signInWithPassword(CREDENTIALS);
    expect(result.ok).toBe(true);
    expect(signInWithPassword).toHaveBeenCalledWith(CREDENTIALS);
  });

  it('F-09: returns the id of the session it opened, read from the new access token (for the log)', async () => {
    const sessionId = '12345678-1234-4234-8234-123456789abc';
    const accessToken = `h.${Buffer.from(JSON.stringify({ session_id: sessionId })).toString('base64url')}.s`;
    const { supabase } = fakeSupabase({
      signIn: { data: { session: { access_token: accessToken } }, error: null },
    });

    const result = await createSupabaseAuthGateway(supabase).signInWithPassword(CREDENTIALS);

    expect(result).toEqual({ ok: true, value: { sessionId } });
  });

  it('F-09: the session id is null when the token carries none, never a guess', async () => {
    const { supabase } = fakeSupabase();
    const result = await createSupabaseAuthGateway(supabase).signInWithPassword(CREDENTIALS);
    expect(result).toEqual({ ok: true, value: { sessionId: null } });
  });

  it.each([
    [
      'wrong password or unknown e-mail',
      { name: 'AuthApiError', status: 400, code: 'invalid_credentials' },
      'invalid_credentials',
    ],
    [
      'an unconfirmed e-mail',
      { name: 'AuthApiError', status: 400, code: 'email_not_confirmed' },
      'account_inactive',
    ],
    [
      'a banned user',
      { name: 'AuthApiError', status: 403, code: 'user_banned' },
      'account_inactive',
    ],
  ])('SEC-12: %s is the generic InvalidCredentialsError', async (_label, error, reason) => {
    const { supabase } = fakeSupabase({ signIn: { data: { session: null }, error } });
    const result = await createSupabaseAuthGateway(supabase).signInWithPassword(CREDENTIALS);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(InvalidCredentialsError);
      expect(result.error.reason).toBe(reason);
    }
  });

  it.each([
    ['a network failure', { name: 'AuthRetryableFetchError', status: 0 }],
    ['a 5xx from the Auth server', { name: 'AuthApiError', status: 502 }],
    [
      'a 500 from the Auth server',
      { name: 'AuthApiError', status: 500, code: 'unexpected_failure' },
    ],
    [
      'the Auth server throttling (429)',
      { name: 'AuthApiError', status: 429, code: 'over_request_rate_limit' },
    ],
  ])(
    'E-21: %s is ServiceUnavailableError, never a verdict on the credentials',
    async (_label, error) => {
      const { supabase } = fakeSupabase({ signIn: { data: { session: null }, error } });
      const rejection = createSupabaseAuthGateway(supabase).signInWithPassword(CREDENTIALS);
      await expect(rejection).rejects.toBeInstanceOf(ServiceUnavailableError);
      // an outage, not an unexpected answer: the log category differs
      await expect(rejection).rejects.not.toBeInstanceOf(UnexpectedAuthAnswerError);
    },
  );

  it('E-21: a timeout thrown by fetch is ServiceUnavailableError', async () => {
    const { supabase } = fakeSupabase({ signIn: new DOMException('timed out', 'TimeoutError') });
    await expect(
      createSupabaseAuthGateway(supabase).signInWithPassword(CREDENTIALS),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it.each([
    ['an unknown error code', { name: 'AuthApiError', status: 400, code: 'some_new_error' }],
    [
      'a disabled email provider (misconfigured Auth)',
      { name: 'AuthApiError', status: 422, code: 'email_provider_disabled' },
    ],
    ['a rejected API key', { name: 'AuthApiError', status: 401, code: 'invalid_api_key' }],
    ['a validation failure', { name: 'AuthApiError', status: 422, code: 'validation_failed' }],
    ['an error without any code', { name: 'AuthApiError', status: 400 }],
    ['an error nobody classified', { name: 'AuthUnknownError', message: 'weird' }],
    // a code that is a property of Object.prototype must not be mistaken for a known refusal
    [
      'a code that looks like a prototype key',
      { name: 'AuthApiError', status: 400, code: 'constructor' },
    ],
  ])(
    'a misconfigured or changed Auth must not look like a wrong password: %s is 503',
    async (_label, error) => {
      const { supabase } = fakeSupabase({ signIn: { data: { session: null }, error } });
      const rejection = createSupabaseAuthGateway(supabase).signInWithPassword(CREDENTIALS);
      await expect(rejection).rejects.toBeInstanceOf(UnexpectedAuthAnswerError);
      await expect(rejection).rejects.toBeInstanceOf(ServiceUnavailableError);
    },
  );

  it('keeps the status and the code of an unexpected Auth answer for the log', async () => {
    const { supabase } = fakeSupabase({
      signIn: {
        data: { session: null },
        error: { name: 'AuthApiError', status: 422, code: 'email_provider_disabled' },
      },
    });
    const rejection = await createSupabaseAuthGateway(supabase)
      .signInWithPassword(CREDENTIALS)
      .catch((error: unknown) => error);
    expect(rejection).toBeInstanceOf(UnexpectedAuthAnswerError);
    expect(rejection).toMatchObject({ authStatus: 422, authCode: 'email_provider_disabled' });
    // never the Auth message, which may echo what was sent
    expect((rejection as UnexpectedAuthAnswerError).detail).toBeUndefined();
  });

  it('is 503 too when a successful answer carries no session', async () => {
    const { supabase } = fakeSupabase({ signIn: { data: { session: null }, error: null } });
    await expect(
      createSupabaseAuthGateway(supabase).signInWithPassword(CREDENTIALS),
    ).rejects.toBeInstanceOf(UnexpectedAuthAnswerError);
  });
});

describe('SupabaseAuthGateway.signOut', () => {
  it('E-09: signs out with scope "local" only', async () => {
    const { supabase, signOut } = fakeSupabase();
    await createSupabaseAuthGateway(supabase).signOut();
    expect(signOut).toHaveBeenCalledWith({ scope: 'local' });
  });

  it('E-21: a failed revocation is ServiceUnavailableError, so a logout is never reported as done', async () => {
    const { supabase } = fakeSupabase({
      signOut: { data: null, error: { name: 'AuthRetryableFetchError', status: 0 } },
    });
    await expect(createSupabaseAuthGateway(supabase).signOut()).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('does not ask the database anything when it was given no token to confirm (login cleanup)', async () => {
    const { supabase, rpc } = fakeSupabase();
    await createSupabaseAuthGateway(supabase).signOut();
    expect(rpc).not.toHaveBeenCalled();
  });

  it('AC-04: confirms the revocation with the DATABASE, using the token of the ended session', async () => {
    const { supabase, rpc, headers } = fakeSupabase({ principal: { data: null } });

    await createSupabaseAuthGateway(supabase, { confirmRevocationOf: 'old-token' }).signOut();

    expect(rpc).toHaveBeenCalledWith('current_principal');
    expect(headers).toEqual({ Authorization: 'Bearer old-token' });
  });

  it('AC-04: a token the database refuses (expired, 401) counts as revoked', async () => {
    const { supabase } = fakeSupabase({
      principal: { data: null, error: { message: 'JWT expired', code: 'PGRST301' }, status: 401 },
    });
    await expect(
      createSupabaseAuthGateway(supabase, { confirmRevocationOf: 'old-token' }).signOut(),
    ).resolves.toBeUndefined();
  });

  it('AC-04: the Auth client says "signed out" but the session is still alive: ServiceUnavailableError', async () => {
    // auth-js reports success for a 401/403/404 on the revocation call, revoking nothing
    const { supabase } = fakeSupabase({
      signOut: { data: null, error: null },
      principal: { data: PRINCIPAL_ROW },
    });

    await expect(
      createSupabaseAuthGateway(supabase, { confirmRevocationOf: 'old-token' }).signOut(),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('E-21: when the confirmation itself cannot be made, the logout is not reported as done', async () => {
    const { supabase } = fakeSupabase({
      principal: { data: null, error: { message: 'TypeError: fetch failed', code: '' }, status: 0 },
    });
    await expect(
      createSupabaseAuthGateway(supabase, { confirmRevocationOf: 'old-token' }).signOut(),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('fails (500) on an unknown sign-out error', async () => {
    const { supabase } = fakeSupabase({
      signOut: { data: null, error: { name: 'AuthUnknownError' } },
    });
    await expect(createSupabaseAuthGateway(supabase).signOut()).rejects.toThrow(
      'sign out failed unexpectedly',
    );
  });
});

describe('SupabaseAuthGateway.current', () => {
  it('reads the principal through current_principal()', async () => {
    const { supabase, rpc } = fakeSupabase();
    await expect(createSupabaseAuthGateway(supabase).current()).resolves.toBeNull();
    expect(rpc).toHaveBeenCalledWith('current_principal');
  });
});
