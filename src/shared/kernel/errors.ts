import type { ErrorCode } from './error-codes';

/** Extra top-level members of the problem+json body (e.g. `currentStageId` on STALE_STAGE). */
export type ProblemExtensions = Readonly<Record<string, string | number | boolean | null>>;

export type DomainErrorOptions = ErrorOptions & {
  /**
   * Client-safe text for the `detail` member of the problem. `message` is for logs only and is
   * never sent to the client, because it may carry upstream or internal text.
   */
  readonly detail?: string;
  /** Extra members of the problem body. Cannot override the standard members. */
  readonly extensions?: ProblemExtensions;
};

/** Base class for every error the domain and application layers can return. */
export abstract class DomainError extends Error {
  abstract readonly code: ErrorCode;
  readonly detail: string | undefined;
  readonly extensions: ProblemExtensions | undefined;

  constructor(message: string, options?: DomainErrorOptions) {
    super(message, options);
    this.name = new.target.name;
    this.detail = options?.detail;
    this.extensions = options?.extensions;
  }
}

export class NotFoundError extends DomainError {
  readonly code = 'NOT_FOUND';
}

export class ForbiddenError extends DomainError {
  readonly code = 'FORBIDDEN';
}

export class ConflictError extends DomainError {
  readonly code = 'CONFLICT';
}

export class UnauthenticatedError extends DomainError {
  readonly code = 'UNAUTHENTICATED';
}

export class ServiceUnavailableError extends DomainError {
  readonly code = 'SERVICE_UNAVAILABLE';
}

export type ValidationIssue = { readonly path: string; readonly message: string };

export class ValidationError extends DomainError {
  readonly code = 'VALIDATION_ERROR';
  readonly issues: readonly ValidationIssue[];

  constructor(
    message: string,
    issues: readonly ValidationIssue[] = [],
    options?: DomainErrorOptions,
  ) {
    super(message, options);
    this.issues = issues;
  }
}
