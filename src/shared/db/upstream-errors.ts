import { ServiceUnavailableError } from '@/shared/kernel';

const SERVER_ERROR_MIN_STATUS = 500;
/** The upstream throttling us (Auth refreshes all come from the server's IP) is about the service. */
const TOO_MANY_REQUESTS_STATUS = 429;
/** postgrest-js reports a transport failure (refused, reset, timeout) as status 0. */
const TRANSPORT_FAILURE_STATUS = 0;
const TRANSPORT_ERROR_NAMES: ReadonlySet<string> = new Set(['TimeoutError', 'AbortError']);

const isUnavailableStatus = (status: unknown): boolean =>
  typeof status === 'number' &&
  (status === TRANSPORT_FAILURE_STATUS ||
    status === TOO_MANY_REQUESTS_STATUS ||
    status >= SERVER_ERROR_MIN_STATUS);

/**
 * Is this error "Supabase is slow or down" (E-21) rather than a verdict about the request?
 * True for:
 * - auth-js `AuthRetryableFetchError` (network failure, timeout or a 5xx from the Auth server);
 * - an HTTP `status` of 0 (transport failure), 429 (the upstream throttling us) or 5xx, taken from the error object (auth-js) or from
 *   `status`, the field postgrest-js returns next to its error;
 * - a raw `TimeoutError`/`AbortError` (our 5 s abort) or the `TypeError` fetch throws on a network
 *   failure.
 * Any other 4xx (invalid credentials, bad JWT, a policy denial...) is never "unavailable".
 */
export function isUpstreamUnavailable(error: unknown, status?: number): boolean {
  if (isUnavailableStatus(status)) return true;
  if (typeof error !== 'object' || error === null) return false;
  const { name, status: ownStatus } = error as { name?: unknown; status?: unknown };
  if (name === 'AuthRetryableFetchError') return true;
  if (typeof name === 'string' && TRANSPORT_ERROR_NAMES.has(name)) return true;
  if (error instanceof TypeError && /fetch failed/i.test(error.message)) return true;
  return isUnavailableStatus(ownStatus);
}

/**
 * The error to throw when a Supabase call failed: `ServiceUnavailableError` (503) when the upstream
 * is unavailable, otherwise a plain `Error` (500). The message is for logs and never reaches the
 * client; the original error stays as `cause`.
 */
export function upstreamFailure(operation: string, error: unknown, status?: number): Error {
  if (isUpstreamUnavailable(error, status)) {
    return new ServiceUnavailableError(`${operation}: Supabase unavailable`, { cause: error });
  }
  return new Error(`${operation} failed unexpectedly`, { cause: error });
}
