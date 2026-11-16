const NO_CONTENT_STATUS = 204;

/**
 * JSON success response. Build the body from an explicit DTO mapper, never from a database row.
 * Security headers and `X-Request-Id` are added by `withRoute`.
 */
export function json(
  status: number,
  body: unknown,
  init: { readonly headers?: HeadersInit } = {},
): Response {
  const headers = new Headers(init.headers);
  headers.set('Content-Type', 'application/json');
  return new Response(JSON.stringify(body), { status, headers });
}

/** `204 No Content`. */
export function noContent(init: { readonly headers?: HeadersInit } = {}): Response {
  return new Response(null, { status: NO_CONTENT_STATUS, headers: new Headers(init.headers) });
}
