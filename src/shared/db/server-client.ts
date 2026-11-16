import 'server-only';
import { createServerClient } from '@supabase/ssr';
import type { NextRequest } from 'next/server';
import { getEnv } from '@/shared/config/env';
import type { CookieJar } from '@/shared/http/cookies';
import type { Database } from './database.types';
import { fetchWithTimeout } from './fetch-with-timeout';
import { SESSION_COOKIE_MAX_AGE_SECONDS, SESSION_COOKIE_NAME } from './session-cookies';

/** Supabase client acting as the signed-in user: RLS applies to everything it does. */
export type RequestSupabase = ReturnType<typeof createServerClient<Database>>;

export type RequestSupabaseInput = {
  readonly request: NextRequest;
  /** The pipeline's cookie jar: session reads and refreshed tokens go through it. */
  readonly cookies: CookieJar;
  /** Sent as `x-request-id`, so database functions can record it in the audit trail. */
  readonly requestId: string;
};

/**
 * ONE client per request. The principal resolver and the handler must share it: two clients would
 * each read the same refresh token and each try to rotate it, and the second rotation looks like a
 * stolen refresh token to Supabase, which revokes the whole session family (E-10). Keyed by the
 * `NextRequest` object, so the entry dies with the request and nothing is shared across users.
 */
const clientsByRequest = new WeakMap<
  NextRequest,
  { readonly client: RequestSupabase; readonly cookies: CookieJar }
>();

/**
 * The request-scoped Supabase client (ADR 0002): publishable key, session in the
 * `__Host-rt-session` cookie, `x-request-id` on every call and a 5 s timeout (SEC-19, E-21).
 *
 * Cookie writes (a refreshed token, a new session, a sign-out) go into the pipeline's jar, which
 * applies them to the final response and forces `HttpOnly; Secure; SameSite=Lax; Path=/` with no
 * Domain, whatever this client asks for. A later call for the same request gets the same client
 * (the first caller's `requestId` stands) and must pass the same jar, or it throws.
 */
export function getRequestSupabase(input: RequestSupabaseInput): RequestSupabase {
  const existing = clientsByRequest.get(input.request);
  if (existing !== undefined) {
    // The first caller's jar is the one the client writes to. A later caller with ANOTHER jar
    // would silently have its cookie handling ignored (login relies on a buffered jar to keep a
    // refused login free of Set-Cookie), so that is a programming error, not a fallback.
    if (existing.cookies !== input.cookies) {
      throw new Error('this request already has a Supabase client bound to a different cookie jar');
    }
    return existing.client;
  }

  const env = getEnv();
  const client = createServerClient<Database>(env.SUPABASE_URL, env.SUPABASE_PUBLISHABLE_KEY, {
    cookieOptions: {
      name: SESSION_COOKIE_NAME,
      path: '/',
      sameSite: 'lax',
      secure: true,
      httpOnly: true,
      maxAge: SESSION_COOKIE_MAX_AGE_SECONDS,
    },
    cookies: {
      getAll: () => input.cookies.getAll(),
      setAll: (cookiesToSet) => {
        for (const { name, value, options } of cookiesToSet) {
          if (value === '') input.cookies.delete(name);
          else
            input.cookies.set(
              name,
              value,
              options.maxAge === undefined ? {} : { maxAge: options.maxAge },
            );
        }
      },
    },
    global: {
      headers: { 'x-request-id': input.requestId },
      fetch: fetchWithTimeout,
    },
    // `@supabase/ssr` forces these for a server client; stated here so the intent is visible:
    // the session lives in the cookie, nothing renews it in the background, and the URL is never
    // inspected for tokens. Renewal happens inside `getClaims()`, within the request.
    auth: { persistSession: true, autoRefreshToken: false, detectSessionInUrl: false },
  });

  clientsByRequest.set(input.request, { client, cookies: input.cookies });
  return client;
}
