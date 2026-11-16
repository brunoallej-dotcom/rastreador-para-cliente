import { ServiceUnavailableError } from '@/shared/kernel';
import { UPSTREAM_TIMEOUT_MS } from './fetch-with-timeout';

/**
 * Gives a whole Supabase operation at most `ms` (default 5 s, E-21). The per-request timeout of
 * `fetchWithTimeout` is not enough where a client library retries on its own: auth-js keeps
 * retrying a failed token refresh with backoff for up to 30 s, and postgrest-js retries GETs, so
 * a dead upstream could hold the request for many times 5 s.
 *
 * On expiry it throws `ServiceUnavailableError`; the abandoned work finishes (or fails) on its own
 * without anybody waiting for it, and its late result is ignored.
 */
export async function withDeadline<T>(
  operation: string,
  work: Promise<T>,
  ms: number = UPSTREAM_TIMEOUT_MS,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new ServiceUnavailableError(`${operation}: no answer within ${ms} ms`)),
      ms,
    );
  });
  try {
    return await Promise.race([work, expired]);
  } finally {
    clearTimeout(timer);
  }
}
