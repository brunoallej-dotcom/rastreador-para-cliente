import { z } from 'zod';
import { AALS, computePendingActions, ROLES, type Principal } from '@/shared/kernel';
import type { RequestSupabase } from './server-client';
import { upstreamFailure } from './upstream-errors';

/**
 * One row of `public.current_principal()` (spec §3.7), validated: whatever the database sends is
 * checked before it becomes an identity. Extra columns are ignored, missing or mistyped ones fail.
 */
const principalRowSchema = z.object({
  user_id: z.guid(),
  role: z.enum(ROLES),
  client_id: z.guid().nullable(),
  display_name: z.string().min(1),
  aal: z.enum(AALS),
  has_verified_totp: z.boolean(),
  must_change_password: z.boolean(),
});

export type PrincipalRow = z.infer<typeof principalRowSchema>;

const UNAUTHORIZED_STATUS = 401;

export function toPrincipal(row: PrincipalRow): Principal {
  return {
    userId: row.user_id,
    role: row.role,
    clientId: row.client_id,
    displayName: row.display_name,
    aal: row.aal,
    pendingActions: computePendingActions({
      role: row.role,
      mustChangePassword: row.must_change_password,
      hasVerifiedTotp: row.has_verified_totp,
      aal: row.aal,
    }),
  };
}

/**
 * The principal of the session the client carries, or `null` when the database says there is none:
 * the session was revoked (logout, deactivation, password reset), the profile is disabled, or the
 * JWT is not a user's. The tenant and the role come from `profiles` in the database, never from the
 * JWT claims the caller could influence (SEC-03, SEC-04).
 *
 * A JWT that PostgREST itself refuses (expired, malformed: HTTP 401) has no principal either.
 *
 * `accessToken` asks about THAT token instead of the one the client carries: logout uses it to
 * confirm that a session it just revoked no longer yields a principal.
 *
 * Throws `ServiceUnavailableError` when Supabase is slow or down (E-21) and a plain `Error` (500)
 * for an error or a row it does not understand: a security step that cannot decide denies.
 */
export async function readCurrentPrincipal(
  supabase: RequestSupabase,
  options: { readonly accessToken?: string } = {},
): Promise<Principal | null> {
  const call = supabase.rpc('current_principal');
  if (options.accessToken !== undefined) {
    call.setHeader('Authorization', `Bearer ${options.accessToken}`);
  }
  const { data, error, status } = await call.maybeSingle();
  if (status === UNAUTHORIZED_STATUS) return null;
  if (error) throw upstreamFailure('read the current principal', error, status);
  if (data === null) return null;

  const row = principalRowSchema.safeParse(data);
  if (!row.success) throw new Error('current_principal() returned a row that is not understood');
  return toPrincipal(row.data);
}
