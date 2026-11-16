import 'server-only';
import { createClient } from '@supabase/supabase-js';
import { getEnv } from '@/shared/config/env';
import type { Database } from '@/shared/db/database.types';
import { fetchWithTimeout } from '@/shared/db/fetch-with-timeout';

/** The part of a Supabase client that proving a password needs: sign in, and end that session. */
export type ReauthClient = {
  readonly auth: Pick<
    ReturnType<typeof createClient<Database>>['auth'],
    'signInWithPassword' | 'signOut'
  >;
};

/**
 * A throwaway client for ONE re-authentication: publishable key, no session store, no cookies, no
 * refresh. The sign-in it makes opens a session that exists only in this object's memory, which
 * nobody reads and which is revoked right after.
 *
 * It must be a client of its own: the request's client (`getRequestSupabase`) holds the user's real
 * session, and a sign-in on it would replace that session and write new cookies into the response.
 * It is not a second client in the sense of E-10 either: it starts with no session, so it never
 * shares a refresh token with the request's client.
 */
export function createReauthClient(input: { readonly requestId: string }): ReauthClient {
  const env = getEnv();
  return createClient<Database>(env.SUPABASE_URL, env.SUPABASE_PUBLISHABLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    global: { headers: { 'x-request-id': input.requestId }, fetch: fetchWithTimeout },
  });
}
