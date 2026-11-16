import 'server-only';
import { createServerClient } from '@supabase/ssr';
import type { NextRequest } from 'next/server';
import { getEnv } from '@/shared/config/env';
import type { Database } from './database.types';
import { fetchWithTimeout, type FetchFunction } from './fetch-with-timeout';
import {
  SESSION_COOKIE_MAX_AGE_SECONDS,
  SESSION_COOKIE_NAME,
  type SessionCookieStore,
} from './session-cookies';

/** Supabase client acting as the signed-in user: RLS applies to everything it does. */
export type RequestSupabase = ReturnType<typeof createServerClient<Database>>;

export type RequestSupabaseInput = {
  readonly request: NextRequest;
  /** The pipeline's cookie jar: session reads and refreshed tokens go through it. */
  readonly cookies: SessionCookieStore;
  /** Sent as `x-request-id`, so database functions can record it in the audit trail. */
  readonly requestId: string;
};

/**
 * ONE client per request. The principal resolver and the handler must share it: two clients would
 * each read the same refresh token and each try to rotate it, and the second rotation looks like a
 * stolen refresh token to Supabase, which revokes the whole session family (E-10). Keyed by the
 * `NextRequest` object, so the entry dies with the request and nothing is shared across users.
 */
type RequestClient = {
  readonly client: RequestSupabase;
  readonly cookies: SessionCookieStore;
  /** Requests this client has made to the Auth server (`<SUPABASE_URL>/auth/v1/...`). */
  readonly authCalls: { count: number };
  /** When set, cookie writes of the client are dropped (see `fenceRequestClient`). */
  readonly fence: { closed: boolean };
};

const clientsByRequest = new WeakMap<NextRequest, RequestClient>();

/**
 * How many requests the request's client has made to the Auth server so far. It is MEASURED at the
 * fetch the client really uses, not predicted: the principal resolver compares it before and after
 * `getClaims()` to charge, after the fact, any call it had not charged beforehand (F-01).
 */
export function getRequestAuthCalls(request: NextRequest): number {
  return clientsByRequest.get(request)?.authCalls.count ?? 0;
}

/**
 * From now on the request's client can no longer write cookies. Call it when giving up on the
 * client's work (a deadline, an outage): the abandoned work may finish later and write a rotated
 * session into the jar, after the response was decided and possibly after the jar was restored.
 * Writes made before the fence stand.
 */
export function fenceRequestClient(request: NextRequest): void {
  const record = clientsByRequest.get(request);
  if (record !== undefined) record.fence.closed = true;
}

const urlOf = (input: Parameters<FetchFunction>[0]): string =>
  typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

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
  const authCalls = { count: 0 };
  const fence = { closed: false };
  const authUrlPrefix = `${env.SUPABASE_URL.replace(/\/+$/, '')}/auth/v1/`;
  const countedFetch: FetchFunction = (input, init) => {
    if (urlOf(input).startsWith(authUrlPrefix)) authCalls.count += 1;
    return fetchWithTimeout(input, init);
  };
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
        if (fence.closed) return; // abandoned work finishing late must not touch the jar
        for (const { name, value, options } of cookiesToSet) {
          if (value === '') input.cookies.delete(name);
          else {
            // `@supabase/ssr` overwrites `cookieOptions.maxAge` with its own default (400 days)
            // when it writes a session, so the lifetime cannot be set through the options alone:
            // it is capped here, at the last step before the jar (ADR 0009).
            const requested = options.maxAge ?? SESSION_COOKIE_MAX_AGE_SECONDS;
            input.cookies.set(name, value, {
              maxAge: Math.min(requested, SESSION_COOKIE_MAX_AGE_SECONDS),
            });
          }
        }
      },
    },
    global: {
      headers: { 'x-request-id': input.requestId },
      fetch: countedFetch,
    },
    // `@supabase/ssr` forces these for a server client; stated here so the intent is visible:
    // the session lives in the cookie, nothing renews it in the background, and the URL is never
    // inspected for tokens. Renewal happens inside `getClaims()`, within the request.
    auth: { persistSession: true, autoRefreshToken: false, detectSessionInUrl: false },
  });

  clientsByRequest.set(input.request, { client, cookies: input.cookies, authCalls, fence });
  return client;
}
