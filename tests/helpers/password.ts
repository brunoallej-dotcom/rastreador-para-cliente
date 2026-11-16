// Helpers of the password-change API tests (Wave 4 owns this file; fixtures.ts and http.ts are Wave 3's
// and stay as they are).
//
//   const jar = await sessionJarFor(user);                       // a signed-in browser, no login call
//   const response = await changePassword(jar, { currentPassword, newPassword });
//
// `sessionJarFor` signs in with supabase-js and writes the session into a cookie jar, exactly as the
// login route would have: tests that are not about the login do not spend the login budget (the
// global one is shared by the whole run) and can hold several sessions of one user cheaply.
import { createClient as createSupabaseClient, type Session } from '@supabase/supabase-js';
import { vi } from 'vitest';
import { POST as passwordRoute } from '@/app/api/v1/auth/password/route';
import type { Database } from '@/shared/db/database.types';
import { adminClient, publishableClient, type FixtureUser } from './fixtures';
import {
  createCookieStore,
  invoke,
  writeSessionCookie,
  type CookieStore,
  type SessionTokens,
} from './http';

/** A cookie jar holding a fresh session of `user`, opened straight at the Auth server. */
export async function sessionJarFor(
  user: Pick<FixtureUser, 'email' | 'password'>,
): Promise<CookieStore> {
  const { data, error } = await publishableClient().auth.signInWithPassword({
    email: user.email,
    password: user.password,
  });
  if (error || data.session === null) {
    throw new Error(`sign-in fixture failed: ${error?.message ?? 'no session'}`);
  }
  return jarOf(data.session);
}

/** A cookie jar holding `session` (a supabase-js session), in the format `@supabase/ssr` writes. */
export function jarOf(session: Session): CookieStore {
  const jar = createCookieStore();
  writeSessionCookie(jar, { ...session } as SessionTokens);
  return jar;
}

export type PasswordBody = {
  readonly currentPassword?: unknown;
  readonly newPassword?: unknown;
} & Record<string, unknown>;

/** `POST /auth/password` through the real route, with a fresh client IP per call. */
export function changePassword(
  cookies: CookieStore | undefined,
  body: PasswordBody,
  options: { origin?: string | null } = {},
): Promise<Response> {
  return invoke(passwordRoute, {
    method: 'POST',
    path: '/auth/password',
    body,
    ...(cookies === undefined ? {} : { cookies }),
    ...options,
  });
}

/** Does the database see a live principal behind this access token? (`current_principal()`, no pipeline.) */
export async function hasLivePrincipal(accessToken: string): Promise<boolean> {
  const client = createSupabaseClient<Database>(
    process.env.SUPABASE_URL ?? '',
    process.env.SUPABASE_PUBLISHABLE_KEY ?? '',
    {
      auth: { persistSession: false, autoRefreshToken: false },
      global: { headers: { Authorization: `Bearer ${accessToken}` } },
    },
  );
  const { data, error } = await client.rpc('current_principal');
  if (error) throw new Error(`current_principal failed: ${error.message}`);
  return data.length > 0;
}

/** Can this e-mail and password sign in at the Auth server right now? Straight to Auth: no budget spent. */
export async function canSignIn(email: string, password: string): Promise<boolean> {
  const { error } = await publishableClient().auth.signInWithPassword({ email, password });
  return error === null;
}

/** What the profile and the Auth user say about the role of an account, read with the secret key. */
export async function roleOf(
  userId: string,
): Promise<{ profile: string | undefined; appMetadata: unknown }> {
  const { data: profile, error } = await adminClient()
    .from('profiles')
    .select('role')
    .eq('id', userId)
    .maybeSingle();
  if (error) throw new Error(`profile read failed: ${error.message}`);
  const { data: auth, error: authError } = await adminClient().auth.admin.getUserById(userId);
  if (authError) throw new Error(`getUserById failed: ${authError.message}`);
  return { profile: profile?.role, appMetadata: auth.user?.app_metadata['role'] };
}

export async function mustChangePassword(userId: string): Promise<boolean | undefined> {
  const { data, error } = await adminClient()
    .from('profiles')
    .select('must_change_password')
    .eq('id', userId)
    .maybeSingle();
  if (error) throw new Error(`profile read failed: ${error.message}`);
  return data?.must_change_password;
}

// ------------------------------------------------------------------------------ Auth traffic ----

export type AuthTraffic = {
  /** Every outbound call as `METHOD path?query` (the origin is left out). */
  readonly calls: string[];
  /** The access token of every session a password sign-in opened while watching. */
  readonly signedInTokens: string[];
  restore(): void;
};

/**
 * Passes every outbound call through to the local Supabase, records it, keeps the access token of
 * each password sign-in it sees (so a test can ask the database about that very session), and lets
 * a test answer chosen calls itself with a `Response` or by failing with an `Error`.
 * Always `restore()` it (try/finally): it replaces the global `fetch`.
 */
export function watchAuthTraffic(
  intercept?: (method: string, path: string) => Response | Error | undefined,
): AuthTraffic {
  const realFetch = globalThis.fetch;
  const calls: string[] = [];
  const signedInTokens: string[] = [];
  const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    const method = (
      init?.method ?? (input instanceof Request ? input.method : 'GET')
    ).toUpperCase();
    const path = `${url.pathname}${url.search}`;
    calls.push(`${method} ${path}`);

    const answer = intercept?.(method, path);
    if (answer instanceof Error) throw answer;
    if (answer !== undefined) return answer;

    const response = await realFetch(input, init);
    if (method === 'POST' && path.startsWith('/auth/v1/token?grant_type=password')) {
      const body = (await response
        .clone()
        .json()
        .catch(() => null)) as {
        access_token?: unknown;
      } | null;
      if (typeof body?.access_token === 'string') signedInTokens.push(body.access_token);
    }
    return response;
  });
  return { calls, signedInTokens, restore: () => spy.mockRestore() };
}

/** Runs `action` while watching the traffic, always restoring `fetch`. */
export async function whileWatching<T>(
  intercept: Parameters<typeof watchAuthTraffic>[0],
  action: (traffic: AuthTraffic) => Promise<T>,
): Promise<T> {
  const traffic = watchAuthTraffic(intercept);
  try {
    return await action(traffic);
  } finally {
    traffic.restore();
  }
}
