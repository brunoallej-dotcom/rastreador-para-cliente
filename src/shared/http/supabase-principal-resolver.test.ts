import { NextRequest } from 'next/server';
import { describe, expect, it, vi } from 'vitest';
import type { RequestSupabase } from '@/shared/db/server-client';
import { ServiceUnavailableError, type Principal } from '@/shared/kernel';
import { createCookieJar } from './cookies';
import type { ResolvePrincipalInput } from './principal-resolver';
import { createSupabasePrincipalResolver } from './supabase-principal-resolver';

const PRINCIPAL: Principal = {
  userId: '11111111-1111-4111-8111-111111111111',
  role: 'client',
  clientId: '22222222-2222-4222-8222-222222222222',
  displayName: 'Maria',
  aal: 'aal1',
  pendingActions: [],
};

type ClaimsOutcome = { data: unknown; error: unknown } | Error | 'never-answers';

const SESSION_COOKIES = [
  { name: '__Host-rt-session.0', value: 'chunk-0' },
  { name: '__Host-rt-session.1', value: 'chunk-1' },
];

/**
 * `dropsSession`: `getClaims()` deletes the session cookies from the jar before it answers, like the
 * client library does when a token refresh fails.
 */
function setup(
  claims: ClaimsOutcome,
  principal: Principal | null | Error = PRINCIPAL,
  dropsSession = false,
) {
  const cookies = createCookieJar(SESSION_COOKIES);
  const getClaims = vi.fn(() => {
    if (dropsSession) {
      for (const { name } of SESSION_COOKIES) cookies.delete(name);
    }
    if (claims === 'never-answers') return new Promise<never>(() => undefined);
    return claims instanceof Error ? Promise.reject(claims) : Promise.resolve(claims);
  });
  const supabase = { auth: { getClaims } } as unknown as RequestSupabase;
  const readPrincipal = vi.fn(() =>
    principal instanceof Error ? Promise.reject(principal) : Promise.resolve(principal),
  );
  const input: ResolvePrincipalInput = {
    request: new NextRequest('http://localhost:3000/api/v1/auth/session'),
    cookies,
    requestId: 'unit-test-request-1',
  };
  const resolver = createSupabasePrincipalResolver({
    clientFor: () => supabase,
    readPrincipal,
    deadlineMs: 20,
  });
  return { resolver, input, cookies, getClaims, readPrincipal, supabase };
}

const VALID_CLAIMS = { data: { claims: { sub: PRINCIPAL.userId } }, error: null };

describe('createSupabasePrincipalResolver', () => {
  it('SEC-07: verifies the token with getClaims() and then loads the principal from the database', async () => {
    const { resolver, input, getClaims, readPrincipal, supabase } = setup(VALID_CLAIMS);

    await expect(resolver.resolve(input)).resolves.toEqual(PRINCIPAL);

    expect(getClaims).toHaveBeenCalledOnce();
    expect(readPrincipal).toHaveBeenCalledOnce();
    expect(readPrincipal).toHaveBeenCalledWith(supabase);
  });

  it('is unauthenticated, without touching the database, when there is no session', async () => {
    const { resolver, input, readPrincipal } = setup({ data: null, error: null });
    await expect(resolver.resolve(input)).resolves.toBeNull();
    expect(readPrincipal).not.toHaveBeenCalled();
  });

  it.each([
    ['an invalid JWT', { name: 'AuthInvalidJwtError', status: 401 }],
    ['a revoked session', { name: 'AuthApiError', status: 403, code: 'session_not_found' }],
    ['a refresh token that was already used', { name: 'AuthApiError', status: 400 }],
    ['a missing session', { name: 'AuthSessionMissingError', status: 400 }],
  ])('is unauthenticated on %s', async (_label, error) => {
    const { resolver, input, readPrincipal } = setup({ data: null, error });
    await expect(resolver.resolve(input)).resolves.toBeNull();
    expect(readPrincipal).not.toHaveBeenCalled();
  });

  it('is unauthenticated when the claims carry no subject', async () => {
    const { resolver, input } = setup({ data: { claims: {} }, error: null });
    await expect(resolver.resolve(input)).resolves.toBeNull();
  });

  it('E-08: is unauthenticated when the database finds no principal (revoked session, disabled profile)', async () => {
    const { resolver, input } = setup(VALID_CLAIMS, null);
    await expect(resolver.resolve(input)).resolves.toBeNull();
  });

  it('E-21: the Auth server being down is ServiceUnavailableError, not a 401', async () => {
    const { resolver, input, readPrincipal } = setup({
      data: null,
      error: { name: 'AuthRetryableFetchError', status: 0 },
    });
    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(readPrincipal).not.toHaveBeenCalled();
  });

  it('E-21: Auth throttling a token refresh (429) is a 503 and keeps the session cookies', async () => {
    const { resolver, input, cookies } = setup(
      { data: null, error: { name: 'AuthApiError', status: 429, code: 'over_request_rate_limit' } },
      PRINCIPAL,
      true,
    );

    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(cookies.getAll()).toEqual(SESSION_COOKIES);
  });

  it('E-21: a getClaims() that never answers is a 503 within the deadline, cookies kept', async () => {
    const { resolver, input, cookies } = setup('never-answers', PRINCIPAL, true);

    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(cookies.getAll()).toEqual(SESSION_COOKIES);
  });

  it('a genuine "this session is dead" verdict is a 401 and does NOT restore the cookies', async () => {
    const { resolver, input, cookies } = setup(
      { data: null, error: { name: 'AuthApiError', status: 400, code: 'refresh_token_not_found' } },
      PRINCIPAL,
      true,
    );

    await expect(resolver.resolve(input)).resolves.toBeNull();

    expect(cookies.getAll()).toEqual([]);
  });

  it('E-21: a thrown timeout is ServiceUnavailableError too', async () => {
    const { resolver, input } = setup(new DOMException('timed out', 'TimeoutError'));
    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('denies (500) on an unexpected throw instead of resolving a principal', async () => {
    const { resolver, input } = setup(new Error('boom'));
    const rejection = resolver.resolve(input);
    await expect(rejection).rejects.toThrow('verify the session failed unexpectedly');
    await expect(rejection).rejects.not.toBeInstanceOf(ServiceUnavailableError);
  });

  it('passes through what the database read throws (503 or 500)', async () => {
    const { resolver, input } = setup(VALID_CLAIMS, new ServiceUnavailableError('db down'));
    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
