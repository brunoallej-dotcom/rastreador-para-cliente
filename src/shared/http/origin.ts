import type { Env } from '@/shared/config/env';
import { AuthorizationDeniedError } from './pipeline-errors';

const SAFE_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'OPTIONS']);

export function isUnsafeMethod(method: string): boolean {
  return !SAFE_METHODS.has(method.toUpperCase());
}

/**
 * Origins allowed to send unsafe requests (SEC-08): `APP_ORIGIN` and, only on Vercel previews,
 * the deployment's own URLs (`VERCEL_URL`, `VERCEL_BRANCH_URL` are hosts without scheme).
 * Production never trusts them.
 */
export function resolveAllowedOrigins(
  env: Pick<Env, 'APP_ORIGIN' | 'VERCEL_ENV' | 'VERCEL_URL' | 'VERCEL_BRANCH_URL'>,
): readonly string[] {
  const origins = [env.APP_ORIGIN];
  if (env.VERCEL_ENV === 'preview') {
    for (const host of [env.VERCEL_URL, env.VERCEL_BRANCH_URL]) {
      if (host !== undefined) origins.push(`https://${host}`);
    }
  }
  return origins;
}

/**
 * CSRF defense for unsafe methods: the `Origin` header must be present and equal (exact string
 * match, no wildcards or suffixes) to an allowed origin. A missing or foreign origin → 403.
 */
export function assertOriginAllowed(request: Request, allowedOrigins: readonly string[]): void {
  const origin = request.headers.get('origin');
  if (origin !== null && allowedOrigins.includes(origin)) return;
  throw new AuthorizationDeniedError(
    'ORIGIN_NOT_ALLOWED',
    'origin_not_allowed',
    'The Origin header is missing or not allowed.',
  );
}
