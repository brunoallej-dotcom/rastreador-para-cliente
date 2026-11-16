import 'server-only';
import { createClient } from '@supabase/supabase-js';
import { getEnv } from '@/shared/config/env';
import type { Database } from './database.types';
import { fetchWithTimeout } from './fetch-with-timeout';

/** The Auth Admin API of the secret-key client (create, delete, list users, revoke by token...). */
export type AdminAuthApi = ReturnType<typeof createClient<Database>>['auth']['admin'];

/** What `rate_limit_hit` takes: the same fields as the limiter's input. */
export type AdminRateLimitHitInput = {
  readonly bucket: string;
  readonly windowSeconds: number;
  readonly max: number;
};

/**
 * What the secret key may do for this app, and nothing else. The shared singleton is NEVER handed
 * out as a Supabase client: a caller with the whole client could `.from(...)` any table past RLS or
 * `.auth.signInWithPassword(...)` and leave a user session on a process-wide object. It gets the
 * Auth Admin API and one RPC wrapper instead.
 */
export type AdminFacade = {
  /** The Auth Admin API. It has no sign-in and holds no session. */
  readonly authAdmin: AdminAuthApi;
  /**
   * Calls `public.rate_limit_hit` (only `service_role` may execute it) and returns what it answered,
   * unvalidated. Throws when the call fails, without echoing what the database said.
   */
  rateLimitHit(input: AdminRateLimitHitInput): Promise<unknown>;
};

let cached: AdminFacade | undefined;

/**
 * The ONLY reader of `SUPABASE_SECRET_KEY` (SEC-15). `getEnv()` runs first so a missing key fails
 * with the boot-time validation message instead of an obscure client error.
 *
 * Allowed callers: `src/shared/http/rate-limit/` (the limiter RPC) and
 * `src/modules/identity/infrastructure/` (the Auth Admin API); ESLint enforces it. Never for
 * business reads or writes: those go through the request-scoped client so RLS decides.
 *
 * Stateless (no session, no refresh), so one instance serves the whole process.
 */
export function getAdminFacade(): AdminFacade {
  if (cached !== undefined) return cached;

  const env = getEnv();
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (secretKey === undefined || secretKey === '') {
    throw new Error('SUPABASE_SECRET_KEY is not set');
  }
  const client = createClient<Database>(env.SUPABASE_URL, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    global: { fetch: fetchWithTimeout },
  });

  cached = Object.freeze({
    authAdmin: client.auth.admin,
    async rateLimitHit({ bucket, windowSeconds, max }: AdminRateLimitHitInput) {
      const { data, error } = await client.rpc('rate_limit_hit', {
        p_bucket: bucket,
        p_window_seconds: windowSeconds,
        p_max: max,
      });
      if (error) throw new Error('rate_limit_hit failed', { cause: error });
      return data;
    },
  });
  return cached;
}
