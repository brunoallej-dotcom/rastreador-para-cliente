import 'server-only';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { getEnv } from '@/shared/config/env';
import type { Database } from './database.types';
import { fetchWithTimeout } from './fetch-with-timeout';

/** Supabase client with the secret key: it BYPASSES RLS (SEC-15). */
export type AdminSupabase = SupabaseClient<Database>;

let cached: AdminSupabase | undefined;

/**
 * The ONLY reader of `SUPABASE_SECRET_KEY`. `getEnv()` runs first so a missing key fails with the
 * boot-time validation message instead of an obscure client error.
 *
 * Allowed callers: `src/shared/http/rate-limit/` (the limiter RPC) and
 * `src/modules/identity/infrastructure/` (the Auth Admin API). Never for business reads or writes:
 * those go through the request-scoped client so RLS decides.
 *
 * Stateless (no session, no refresh), so one instance serves the whole process.
 */
export function getAdminClient(): AdminSupabase {
  if (cached !== undefined) return cached;

  const env = getEnv();
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (secretKey === undefined || secretKey === '') {
    throw new Error('SUPABASE_SECRET_KEY is not set');
  }
  cached = createClient<Database>(env.SUPABASE_URL, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    global: { fetch: fetchWithTimeout },
  });
  return cached;
}
