import type { ErrorCode } from './error-codes';

/** Base class for every error the domain and application layers can return. */
export abstract class DomainError extends Error {
  abstract readonly code: ErrorCode;

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
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

  constructor(message: string, issues: readonly ValidationIssue[] = [], options?: ErrorOptions) {
    super(message, options);
    this.issues = issues;
  }
}
