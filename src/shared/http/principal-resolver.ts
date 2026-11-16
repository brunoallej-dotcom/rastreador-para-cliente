import type { NextRequest } from 'next/server';
import type { Principal } from '@/shared/kernel';
import type { Logger } from '@/shared/observability/logger';
import type { CookieJar } from './cookies';

export type ResolvePrincipalInput = {
  readonly request: NextRequest;
  /**
   * Session cookies. The resolver may write refreshed tokens here; the pipeline applies them to
   * the final response, including error responses.
   */
  readonly cookies: CookieJar;
  /** For the `x-request-id` header the per-request Supabase client forwards to the database. */
  readonly requestId: string;
  /** Child logger that already carries the `requestId`. */
  readonly logger: Logger;
};

/**
 * Port of authentication (spec §3.3 step 5, §3.4). The real implementation (Wave 3) validates
 * the JWT with `getClaims()`, checks the session in the database and loads `current_principal()`.
 *
 * - no valid session, revoked session or deactivated account → resolve to `null` (401);
 * - dependency down or slow → throw `ServiceUnavailableError` (503);
 * - any other throw is treated as a failure of a security step: the request is denied (500) and
 *   the handler never runs.
 */
export interface PrincipalResolver {
  resolve(input: ResolvePrincipalInput): Promise<Principal | null>;
}
