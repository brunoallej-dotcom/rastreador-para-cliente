import { describe, expect, it } from 'vitest';
import { ServiceUnavailableError } from '@/shared/kernel';
import { readCurrentPrincipal, toPrincipal, type PrincipalRow } from './current-principal';
import type { RequestSupabase } from './server-client';

const CLIENT_ROW: PrincipalRow = {
  user_id: '11111111-1111-4111-8111-111111111111',
  role: 'client',
  client_id: '22222222-2222-4222-8222-222222222222',
  display_name: 'Maria',
  aal: 'aal1',
  has_verified_totp: false,
  must_change_password: true,
};

type RpcOutcome = { data: unknown; error: unknown; status: number };

/** The slice of the Supabase client `readCurrentPrincipal` uses, answering a scripted outcome. */
function fakeSupabase(outcome: RpcOutcome | (() => RpcOutcome)) {
  const calls: string[] = [];
  const headers: Record<string, string> = {};
  const supabase = {
    rpc(name: string) {
      calls.push(name);
      const builder = {
        setHeader(headerName: string, value: string) {
          headers[headerName] = value;
          return builder;
        },
        maybeSingle: () => Promise.resolve(typeof outcome === 'function' ? outcome() : outcome),
      };
      return builder;
    },
  } as unknown as RequestSupabase;
  return { supabase, calls, headers };
}

describe('toPrincipal', () => {
  it('maps a client row, with its pending actions computed', () => {
    expect(toPrincipal(CLIENT_ROW)).toEqual({
      userId: CLIENT_ROW.user_id,
      role: 'client',
      clientId: CLIENT_ROW.client_id,
      displayName: 'Maria',
      aal: 'aal1',
      pendingActions: ['CHANGE_PASSWORD'],
    });
  });

  it('maps a CEO row: no client, MFA pending actions from the factor and the aal', () => {
    const ceo = toPrincipal({
      ...CLIENT_ROW,
      role: 'ceo',
      client_id: null,
      must_change_password: false,
      has_verified_totp: true,
    });
    expect(ceo.clientId).toBeNull();
    expect(ceo.pendingActions).toEqual(['VERIFY_MFA']);
  });
});

describe('readCurrentPrincipal', () => {
  it('SEC-03: calls current_principal() and returns the principal the database describes', async () => {
    const { supabase, calls } = fakeSupabase({ data: CLIENT_ROW, error: null, status: 200 });
    await expect(readCurrentPrincipal(supabase)).resolves.toMatchObject({
      userId: CLIENT_ROW.user_id,
      clientId: CLIENT_ROW.client_id,
      role: 'client',
    });
    expect(calls).toEqual(['current_principal']);
  });

  it('E-08: no row (revoked session, disabled profile) means no principal', async () => {
    const { supabase } = fakeSupabase({ data: null, error: null, status: 200 });
    await expect(readCurrentPrincipal(supabase)).resolves.toBeNull();
  });

  it('asks about the token it is given, through the Authorization header, and only then', async () => {
    const withToken = fakeSupabase({ data: CLIENT_ROW, error: null, status: 200 });
    await readCurrentPrincipal(withToken.supabase, { accessToken: 'the-old-token' });
    expect(withToken.headers).toEqual({ Authorization: 'Bearer the-old-token' });

    const without = fakeSupabase({ data: CLIENT_ROW, error: null, status: 200 });
    await readCurrentPrincipal(without.supabase);
    expect(without.headers).toEqual({});
  });

  it('AC-04: a JWT PostgREST refuses (401) has no principal, instead of an error', async () => {
    const { supabase } = fakeSupabase({
      data: null,
      error: { message: 'JWT expired', code: 'PGRST301' },
      status: 401,
    });
    await expect(readCurrentPrincipal(supabase, { accessToken: 'x' })).resolves.toBeNull();
  });

  it('E-21: a transport failure is ServiceUnavailableError', async () => {
    const { supabase } = fakeSupabase({
      data: null,
      error: { message: 'TypeError: fetch failed', details: '', hint: '', code: '' },
      status: 0,
    });
    await expect(readCurrentPrincipal(supabase)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('SEC-13: any other database error is an unexpected failure that denies (plain Error)', async () => {
    const { supabase } = fakeSupabase({
      data: null,
      error: { message: 'permission denied for function current_principal', code: '42501' },
      status: 403,
    });
    const rejection = readCurrentPrincipal(supabase);
    await expect(rejection).rejects.toThrow('read the current principal failed unexpectedly');
    await expect(rejection).rejects.not.toBeInstanceOf(ServiceUnavailableError);
  });

  it.each([
    ['an unknown role', { ...CLIENT_ROW, role: 'admin' }],
    ['an unknown aal', { ...CLIENT_ROW, aal: 'aal3' }],
    ['a user id that is not a UUID', { ...CLIENT_ROW, user_id: 'not-a-uuid' }],
    ['a missing column', { ...CLIENT_ROW, must_change_password: undefined }],
    ['an empty display name', { ...CLIENT_ROW, display_name: '' }],
  ])('denies (fails closed) on a row with %s', async (_label, row) => {
    const { supabase } = fakeSupabase({ data: row, error: null, status: 200 });
    await expect(readCurrentPrincipal(supabase)).rejects.toThrow('not understood');
  });
});
