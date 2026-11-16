import { describe, expect, it, vi } from 'vitest';
import type { RequestSupabase } from '@/shared/db/server-client';
import { ForbiddenError, ServiceUnavailableError } from '@/shared/kernel';
import { UnexpectedAuthAnswerError } from '../domain/errors';
import {
  InvalidCurrentPasswordError,
  PasswordUnchangedError,
  WeakPasswordError,
} from '../domain/password-errors';
import type { ReauthClient } from './reauth-client';
import { createSupabasePasswordGateway } from './supabase-password-gateway';

const EMAIL = 'maria@cliente.test';
const CURRENT = 'the-current-one';
const FRESH = 'a-new-password-12';

type Outcome = { data?: unknown; error?: unknown } | Error;

const settle = (outcome: Outcome) =>
  outcome instanceof Error ? Promise.reject(outcome) : Promise.resolve(outcome);

function fakeSupabase(
  options: {
    claims?: Outcome;
    update?: Outcome;
    rpc?: { error: unknown; status?: number } | Error;
  } = {},
) {
  const getClaims = vi.fn(() =>
    settle(options.claims ?? { data: { claims: { sub: 'u', email: EMAIL } }, error: null }),
  );
  const updateUser = vi.fn(() => settle(options.update ?? { data: { user: {} }, error: null }));
  const rpc = vi.fn(() => {
    const answer = options.rpc ?? { error: null, status: 204 };
    return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
  });
  const supabase = { auth: { getClaims, updateUser }, rpc } as unknown as RequestSupabase;
  return { supabase, getClaims, updateUser, rpc };
}

function fakeReauth(options: { signIn?: Outcome; signOut?: Outcome } = {}) {
  const signInWithPassword = vi.fn(() =>
    settle(options.signIn ?? { data: { session: { access_token: 'x' } }, error: null }),
  );
  const signOut = vi.fn(() => settle(options.signOut ?? { error: null }));
  const reauth = { auth: { signInWithPassword, signOut } } as unknown as ReauthClient;
  return { reauth, signInWithPassword, signOut };
}

function build(
  parts: {
    supabase?: Parameters<typeof fakeSupabase>[0];
    reauth?: Parameters<typeof fakeReauth>[0];
    beforeReauthentication?: () => Promise<void>;
  } = {},
) {
  const s = fakeSupabase(parts.supabase);
  const r = fakeReauth(parts.reauth);
  const warn = vi.fn();
  const gateway = createSupabasePasswordGateway(s.supabase, {
    reauth: r.reauth,
    logger: { warn },
    ...(parts.beforeReauthentication === undefined
      ? {}
      : { beforeReauthentication: parts.beforeReauthentication }),
  });
  return { gateway, warn, ...s, ...r };
}

describe('SupabasePasswordGateway.verifyCurrentPassword', () => {
  it('signs in as the user of the session (e-mail from the verified claims) with the password given, then ends that session', async () => {
    const { gateway, signInWithPassword, signOut } = build();

    const result = await gateway.verifyCurrentPassword(CURRENT);

    expect(result.ok).toBe(true);
    expect(signInWithPassword).toHaveBeenCalledWith({ email: EMAIL, password: CURRENT });
    // `local`: only the session the check opened. Never `global`, which would end the user's real sessions
    expect(signOut).toHaveBeenCalledWith({ scope: 'local' });
    expect(signInWithPassword.mock.invocationCallOrder[0]).toBeLessThan(
      signOut.mock.invocationCallOrder[0] ?? 0,
    );
  });

  it('takes the e-mail from the claims, never from the request: it cannot test the password of another account', async () => {
    const { gateway, signInWithPassword } = build({
      supabase: {
        claims: { data: { claims: { sub: 'u', email: 'other@cliente.test' } }, error: null },
      },
    });
    await gateway.verifyCurrentPassword(CURRENT);
    expect(signInWithPassword).toHaveBeenCalledWith({
      email: 'other@cliente.test',
      password: CURRENT,
    });
  });

  it('awaits beforeReauthentication AFTER reading the claims and BEFORE the sign-in', async () => {
    const order: string[] = [];
    const { gateway, getClaims, signInWithPassword } = build({
      beforeReauthentication: () => {
        order.push('budget');
        return Promise.resolve();
      },
    });
    getClaims.mockImplementationOnce(() => {
      order.push('claims');
      return Promise.resolve({ data: { claims: { sub: 'u', email: EMAIL } }, error: null });
    });
    signInWithPassword.mockImplementationOnce(() => {
      order.push('sign-in');
      return Promise.resolve({ data: { session: { access_token: 'x' } }, error: null });
    });

    await gateway.verifyCurrentPassword(CURRENT);

    expect(order).toEqual(['claims', 'budget', 'sign-in']);
  });

  it('a refusal raised by beforeReauthentication (a 429) propagates as it is, and the sign-in never happens', async () => {
    const refusal = new Error('over the global budget');
    const { gateway, signInWithPassword } = build({
      beforeReauthentication: () => Promise.reject(refusal),
    });
    await expect(gateway.verifyCurrentPassword(CURRENT)).rejects.toBe(refusal);
    expect(signInWithPassword).not.toHaveBeenCalled();
  });

  it.each([
    ['a wrong password', { name: 'AuthApiError', status: 400, code: 'invalid_credentials' }],
    ['a banned user', { name: 'AuthApiError', status: 403, code: 'user_banned' }],
    ['an unconfirmed e-mail', { name: 'AuthApiError', status: 400, code: 'email_not_confirmed' }],
  ])(
    '%s is InvalidCurrentPasswordError, and no session was opened to end',
    async (_label, error) => {
      const { gateway, signOut } = build({
        reauth: { signIn: { data: { session: null }, error } },
      });

      const result = await gateway.verifyCurrentPassword(CURRENT);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error).toBeInstanceOf(InvalidCurrentPasswordError);
      expect(signOut).not.toHaveBeenCalled();
    },
  );

  it.each([
    ['a network failure', { name: 'AuthRetryableFetchError', status: 0 }],
    ['a 5xx from the Auth server', { name: 'AuthApiError', status: 502 }],
    [
      'the Auth server throttling (429)',
      { name: 'AuthApiError', status: 429, code: 'over_request_rate_limit' },
    ],
  ])(
    'E-21: %s is ServiceUnavailableError, never a verdict on the password',
    async (_label, error) => {
      const { gateway } = build({ reauth: { signIn: { data: { session: null }, error } } });
      const rejection = gateway.verifyCurrentPassword(CURRENT);
      await expect(rejection).rejects.toBeInstanceOf(ServiceUnavailableError);
      await expect(rejection).rejects.not.toBeInstanceOf(UnexpectedAuthAnswerError);
    },
  );

  it('E-21: a timeout thrown by fetch is ServiceUnavailableError', async () => {
    const { gateway } = build({
      reauth: { signIn: new DOMException('timed out', 'TimeoutError') },
    });
    await expect(gateway.verifyCurrentPassword(CURRENT)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it.each([
    ['an unknown error code', { name: 'AuthApiError', status: 400, code: 'some_new_error' }],
    ['a rejected API key', { name: 'AuthApiError', status: 401, code: 'invalid_api_key' }],
    ['an error without any code', { name: 'AuthApiError', status: 400 }],
    [
      'a code that looks like a prototype key',
      { name: 'AuthApiError', status: 400, code: 'constructor' },
    ],
  ])('%s must not look like a wrong password: it is 503, for the log', async (_label, error) => {
    const { gateway } = build({ reauth: { signIn: { data: { session: null }, error } } });
    const rejection = await gateway.verifyCurrentPassword(CURRENT).catch((e: unknown) => e);
    expect(rejection).toBeInstanceOf(UnexpectedAuthAnswerError);
    expect(rejection).toBeInstanceOf(ServiceUnavailableError);
  });

  it('a successful sign-in without a session is 503 too', async () => {
    const { gateway } = build({ reauth: { signIn: { data: { session: null }, error: null } } });
    await expect(gateway.verifyCurrentPassword(CURRENT)).rejects.toBeInstanceOf(
      UnexpectedAuthAnswerError,
    );
  });

  it.each([
    ['an error answer', { error: { name: 'AuthApiError', status: 500 } }],
    ['a thrown failure', new TypeError('fetch failed')],
  ])(
    'the check still passes when ending its session fails (%s), and says so in the log',
    async (_label, signOut) => {
      const { gateway, warn } = build({ reauth: { signOut } });

      const result = await gateway.verifyCurrentPassword(CURRENT);

      expect(result.ok).toBe(true);
      expect(warn).toHaveBeenCalledWith(
        { event: 'auth.password_change.probe_session_not_revoked' },
        'auth.password_change.probe_session_not_revoked',
      );
    },
  );

  it.each([
    ['no e-mail claim', { data: { claims: { sub: 'u' } }, error: null }],
    ['an empty e-mail claim', { data: { claims: { sub: 'u', email: '' } }, error: null }],
    ['a non-string e-mail claim', { data: { claims: { sub: 'u', email: 42 } }, error: null }],
  ])('fails closed (500) on %s, before any sign-in', async (_label, claims) => {
    const { gateway, signInWithPassword } = build({ supabase: { claims } });
    const rejection = await gateway.verifyCurrentPassword(CURRENT).catch((e: unknown) => e);
    expect(rejection).toBeInstanceOf(Error);
    expect(rejection).not.toBeInstanceOf(ServiceUnavailableError);
    expect(signInWithPassword).not.toHaveBeenCalled();
  });

  it('an outage while reading the claims is ServiceUnavailableError', async () => {
    const { gateway } = build({
      supabase: {
        claims: { data: null, error: { name: 'AuthRetryableFetchError', status: 0 } },
      },
    });
    await expect(gateway.verifyCurrentPassword(CURRENT)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });
});

describe('SupabasePasswordGateway.updatePassword', () => {
  it('updates with the user session and hands the current password along too, for a project that enforces it', async () => {
    const { gateway, updateUser } = build();

    const result = await gateway.updatePassword({ currentPassword: CURRENT, newPassword: FRESH });

    expect(result.ok).toBe(true);
    expect(updateUser).toHaveBeenCalledWith({ password: FRESH, current_password: CURRENT });
  });

  it.each([
    ['same_password', 422, PasswordUnchangedError],
    ['weak_password', 422, WeakPasswordError],
    ['current_password_mismatch', 400, InvalidCurrentPasswordError],
    ['current_password_required', 400, InvalidCurrentPasswordError],
  ])('maps the Auth code %s to its domain error', async (code, status, expected) => {
    const { gateway } = build({
      supabase: { update: { data: { user: null }, error: { name: 'AuthApiError', status, code } } },
    });

    const result = await gateway.updatePassword({ currentPassword: CURRENT, newPassword: FRESH });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(expected);
  });

  it.each([
    ['a network failure', { name: 'AuthRetryableFetchError', status: 0 }],
    ['a 500', { name: 'AuthApiError', status: 500, code: 'unexpected_failure' }],
    ['throttling', { name: 'AuthApiError', status: 429, code: 'over_request_rate_limit' }],
  ])('E-21: %s is ServiceUnavailableError', async (_label, error) => {
    const { gateway } = build({ supabase: { update: { data: { user: null }, error } } });
    await expect(
      gateway.updatePassword({ currentPassword: CURRENT, newPassword: FRESH }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it.each([
    ['a session that needs reauthentication', 'reauthentication_needed', 400],
    ['a code nobody knows', 'some_new_error', 400],
    ['a validation failure', 'validation_failed', 400],
  ])(
    '%s is 503 for the log (the service changed), not a verdict on the password',
    async (_label, code, status) => {
      const { gateway } = build({
        supabase: {
          update: { data: { user: null }, error: { name: 'AuthApiError', status, code } },
        },
      });
      const rejection = await gateway
        .updatePassword({ currentPassword: CURRENT, newPassword: FRESH })
        .catch((e: unknown) => e);
      expect(rejection).toBeInstanceOf(UnexpectedAuthAnswerError);
      expect(rejection).toMatchObject({ authStatus: status, authCode: code });
    },
  );

  it('a thrown failure is ServiceUnavailableError when it is a timeout', async () => {
    const { gateway } = build({ supabase: { update: new DOMException('t', 'TimeoutError') } });
    await expect(
      gateway.updatePassword({ currentPassword: CURRENT, newPassword: FRESH }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});

describe('SupabasePasswordGateway.markPasswordChanged', () => {
  it('AC-06: calls public.mark_password_changed() and succeeds when the database accepts the proof', async () => {
    const { gateway, rpc } = build();
    const result = await gateway.markPasswordChanged();
    expect(result.ok).toBe(true);
    expect(rpc).toHaveBeenCalledWith('mark_password_changed');
  });

  it('E-13: P0001 PASSWORD_UNCHANGED is PasswordUnchangedError', async () => {
    const { gateway } = build({
      supabase: { rpc: { error: { code: 'P0001', message: 'PASSWORD_UNCHANGED' }, status: 400 } },
    });
    const result = await gateway.markPasswordChanged();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(PasswordUnchangedError);
  });

  it('42501 is ForbiddenError, and the log says the first layer was bypassed (spec §3.7)', async () => {
    const { gateway, warn } = build({
      supabase: { rpc: { error: { code: '42501', message: 'FORBIDDEN' }, status: 403 } },
    });
    const result = await gateway.markPasswordChanged();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(warn).toHaveBeenCalledWith(
      { event: 'authz.database_denied', operation: 'mark_password_changed' },
      'authz.database_denied',
    );
  });

  it.each([
    ['a 503', { error: { code: 'PGRST000', message: 'down' }, status: 503 }],
    ['a transport failure (status 0)', { error: { code: '', message: 'fetch failed' }, status: 0 }],
  ])('E-21: %s is ServiceUnavailableError', async (_label, rpc) => {
    const { gateway } = build({ supabase: { rpc } });
    await expect(gateway.markPasswordChanged()).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('anything the database says that is not mapped is a plain Error (500), not a domain answer', async () => {
    for (const rpc of [
      { error: { code: 'P0001', message: 'SOMETHING_ELSE' }, status: 400 },
      { error: { code: '23505', message: 'duplicate' }, status: 409 },
    ]) {
      const { gateway } = build({ supabase: { rpc } });
      const rejection = await gateway.markPasswordChanged().catch((e: unknown) => e);
      expect(rejection).toBeInstanceOf(Error);
      expect(rejection).not.toBeInstanceOf(ServiceUnavailableError);
    }
  });
});
