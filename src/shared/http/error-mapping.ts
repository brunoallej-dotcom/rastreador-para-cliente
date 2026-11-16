import { DomainError, ValidationError } from '@/shared/kernel';
import type { Logger } from '@/shared/observability/logger';
import { ERROR_CATALOG } from './error-catalog';
import { RateLimitedError } from './pipeline-errors';
import { problemResponse } from './problem';

const SERVER_ERROR_MIN_STATUS = 500;
const INTERNAL_ERROR_DETAIL =
  'An unexpected error occurred. Quote the requestId when reporting it.';

/**
 * Turns anything thrown or returned during a request into the problem+json response (SEC-13).
 *
 * - `DomainError`: status and title come from the catalog; `detail` and extensions only from what
 *   the error explicitly declares client-safe. `message` and `cause` never reach the client.
 *   `problemResponse` guarantees what the contract requires of specific codes: `errors` on a 400,
 *   `Retry-After` on a 429 and a 503, `currentStageId` on a 409 STALE_STAGE.
 * - anything else: 500 `INTERNAL_ERROR` with a fixed text; the stack goes to the log only.
 */
export function errorToResponse(error: unknown, requestId: string, logger: Logger): Response {
  if (error instanceof RateLimitedError) {
    return problemResponse({
      code: error.code,
      requestId,
      detail: error.detail,
      headers: { 'Retry-After': String(error.retryAfterSeconds) },
    });
  }

  if (error instanceof DomainError) {
    if (ERROR_CATALOG[error.code].status >= SERVER_ERROR_MIN_STATUS) {
      logger.error({ err: error }, 'server error');
    }
    return problemResponse({
      code: error.code,
      requestId,
      detail: error.detail,
      errors: error instanceof ValidationError ? error.issues : undefined,
      extensions: error.extensions,
    });
  }

  logger.error({ err: error }, 'unhandled exception');
  return problemResponse({ code: 'INTERNAL_ERROR', requestId, detail: INTERNAL_ERROR_DETAIL });
}
