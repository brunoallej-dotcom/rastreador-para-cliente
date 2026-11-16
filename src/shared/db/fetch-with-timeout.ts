/** Every outbound call goes to Supabase and may take at most this long (SEC-19, E-21). */
export const UPSTREAM_TIMEOUT_MS = 5000;

export type FetchFunction = typeof fetch;

/**
 * A `fetch` that aborts after `timeoutMs`. It keeps the caller's own `AbortSignal` working too: the
 * request is aborted by whichever fires first. The abort surfaces as a rejection (`TimeoutError`),
 * which the Supabase clients turn into an error result and `isUpstreamUnavailable` recognizes.
 */
export function createFetchWithTimeout(
  timeoutMs: number = UPSTREAM_TIMEOUT_MS,
  fetchImplementation: FetchFunction = fetch,
): FetchFunction {
  return (input, init) => {
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = init?.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
    return fetchImplementation(input, { ...init, signal });
  };
}

/** The `global.fetch` of the Supabase clients. */
export const fetchWithTimeout: FetchFunction = (input, init) =>
  createFetchWithTimeout()(input, init);
