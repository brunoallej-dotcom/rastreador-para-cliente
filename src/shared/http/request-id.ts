export const REQUEST_ID_HEADER = 'X-Request-Id';

/** Same pattern as the `X-Request-Id` header and `Problem.requestId` of the contract. */
const REQUEST_ID_PATTERN = /^[A-Za-z0-9-]{8,64}$/;

/**
 * Request correlation id (spec §3.3 step 1). An incoming `X-Request-Id` is reused only if it is
 * short and made of safe characters (it ends up in logs and response headers); otherwise a new
 * UUID v4 is generated.
 */
export function resolveRequestId(incoming: string | null): string {
  if (incoming !== null && REQUEST_ID_PATTERN.test(incoming)) return incoming;
  return crypto.randomUUID();
}
