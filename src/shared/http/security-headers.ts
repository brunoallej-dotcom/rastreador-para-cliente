import { REQUEST_ID_HEADER } from './request-id';

/**
 * Headers every response carries (SEC-14). The same list feeds `next.config.ts`, so responses
 * produced outside the pipeline (Next's own 404/405) carry them too. No CORS headers: the API is
 * same-origin only. `X-Powered-By` is disabled with `poweredByHeader: false`.
 */
export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cache-Control': 'no-store',
};

/**
 * Returns a copy of `response` with the security headers and `X-Request-Id` set, overriding
 * anything a handler put there. A copy, because the headers of a `Response` produced by some
 * APIs (`Response.redirect`, fetch) are immutable; the body stream is passed through untouched.
 */
export function withSecurityHeaders(response: Response, requestId: string): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  headers.set(REQUEST_ID_HEADER, requestId);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
