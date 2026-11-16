// Public surface of the HTTP platform for module handlers (`presentation/*.handler.ts`).
// Wave wiring (limiter, resolver) is NOT exported here: it lives only in `pipeline-deps.ts`.
export { withRoute } from './with-route';
export { json, noContent } from './responses';
export {
  CURSOR_MAX_LENGTH,
  PAGE_LIMIT_DEFAULT,
  PAGE_LIMIT_MAX,
  decodeCursor,
  encodeCursor,
  pageQueryShape,
  pageQuerySchema,
  type Page,
  type PageQuery,
} from './pagination';
export { visibleText } from './validation';
export { bufferCookies, type BufferedCookieJar } from './cookie-buffer';
export { fingerprintSubject } from './rate-limit/subject-hmac';
export type { CookieJar, CookieOptions } from './cookies';
export type {
  AuthenticatedPolicy,
  HandlerContext,
  HandlerOutput,
  PublicPolicy,
  RouteHandlerFn,
  WithRoute,
} from './route-policy';
export {
  RATE_LIMIT_GROUPS,
  type RateLimitGroup,
  type RateLimitRule,
  type RateLimitScope,
} from './rate-limit/rate-limiter';
