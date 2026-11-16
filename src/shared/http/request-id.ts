export const REQUEST_ID_HEADER = 'X-Request-Id';

/** Same pattern as the `X-Request-Id` header and `Problem.requestId` of the contract. */
const CLIENT_REQUEST_ID_PATTERN = /^[A-Za-z0-9-]{8,64}$/;

/**
 * The id of THIS request (spec §3.3 step 1): always generated here, a UUID v4. It is what the
 * response header, `Problem.requestId`, the logs and the database audit trail carry, so none of
 * them can be given an id by the caller (no id collision to hide behind, no forged correlation
 * with another request or another user's trace).
 */
export function newRequestId(): string {
  return crypto.randomUUID();
}

/**
 * The `X-Request-Id` the CLIENT sent, only if it is short and made of safe characters (it ends up
 * in the logs). It never becomes the request's own id: it is logged beside it as `clientRequestId`,
 * so a caller can still correlate its trace with ours.
 */
export function clientRequestId(incoming: string | null): string | undefined {
  return incoming !== null && CLIENT_REQUEST_ID_PATTERN.test(incoming) ? incoming : undefined;
}
