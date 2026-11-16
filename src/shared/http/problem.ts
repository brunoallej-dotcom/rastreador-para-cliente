import type { ErrorCode, ProblemExtensions, ValidationIssue } from '@/shared/kernel';
import { ERROR_CATALOG } from './error-catalog';

export const PROBLEM_CONTENT_TYPE = 'application/problem+json';

/** `ValidationProblem.errors` has `maxItems: 50` in the contract. */
export const MAX_PROBLEM_ERRORS = 50;
const MAX_DETAIL_LENGTH = 500;
const MAX_ERROR_FIELD_LENGTH = 200;

/** Members an extension can never set, whatever the error says. */
export const RESERVED_PROBLEM_MEMBERS: ReadonlySet<string> = new Set([
  'type',
  'title',
  'status',
  'code',
  'detail',
  'requestId',
  'errors',
]);

/**
 * Responses the contract documents with a `Retry-After` header: it is always present on them,
 * with this value when the error did not carry a more precise one.
 */
const DEFAULT_RETRY_AFTER_SECONDS: Partial<Record<ErrorCode, number>> = {
  RATE_LIMITED: 60,
  SERVICE_UNAVAILABLE: 5,
};

export type ProblemInput = {
  readonly code: ErrorCode;
  readonly requestId: string;
  /** Client-safe text. Never an upstream or internal message. */
  readonly detail?: string | undefined;
  readonly errors?: readonly ValidationIssue[] | undefined;
  readonly extensions?: ProblemExtensions | undefined;
  readonly headers?: HeadersInit | undefined;
};

const truncate = (text: string, max: number) => (text.length <= max ? text : text.slice(0, max));

/**
 * RFC 9457 problem details, with the stable `code` and `requestId` of the contract.
 * - Reserved members (`RESERVED_PROBLEM_MEMBERS`) are dropped from the extensions, so an extension
 *   can never set or shadow one of them, present or absent.
 * - A `VALIDATION_ERROR` always carries `errors` (empty when there is nothing to list), as the
 *   contract's `ValidationProblem` requires.
 * - A `STALE_STAGE` always carries `currentStageId` (`null` when the error gave none), as the
 *   contract's `StaleStageProblem` requires.
 */
export function problemBody(input: ProblemInput): Record<string, unknown> {
  const { status, title } = ERROR_CATALOG[input.code];
  const extensions = Object.fromEntries(
    Object.entries(input.extensions ?? {}).filter(([name]) => !RESERVED_PROBLEM_MEMBERS.has(name)),
  );
  const errors = input.errors ?? (input.code === 'VALIDATION_ERROR' ? [] : undefined);
  const staleStage =
    input.code === 'STALE_STAGE' && !('currentStageId' in extensions)
      ? { currentStageId: null }
      : {};

  return {
    ...extensions,
    ...staleStage,
    type: 'about:blank',
    title,
    status,
    code: input.code,
    ...(input.detail === undefined ? {} : { detail: truncate(input.detail, MAX_DETAIL_LENGTH) }),
    requestId: input.requestId,
    ...(errors === undefined
      ? {}
      : {
          errors: errors.slice(0, MAX_PROBLEM_ERRORS).map((issue) => ({
            path: truncate(issue.path, MAX_ERROR_FIELD_LENGTH),
            message: truncate(issue.message, MAX_ERROR_FIELD_LENGTH),
          })),
        }),
  };
}

/** A complete `application/problem+json` response. Security headers are added by the pipeline. */
export function problemResponse(input: ProblemInput): Response {
  const headers = new Headers(input.headers);
  headers.set('Content-Type', PROBLEM_CONTENT_TYPE);
  const retryAfter = DEFAULT_RETRY_AFTER_SECONDS[input.code];
  if (retryAfter !== undefined && !headers.has('Retry-After')) {
    headers.set('Retry-After', String(retryAfter));
  }
  return new Response(JSON.stringify(problemBody(input)), {
    status: ERROR_CATALOG[input.code].status,
    headers,
  });
}
