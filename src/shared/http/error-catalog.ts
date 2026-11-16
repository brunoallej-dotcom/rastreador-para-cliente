import type { ErrorCode } from '@/shared/kernel';

export type ErrorCatalogEntry = { readonly status: number; readonly title: string };

/**
 * Every `code` of the contract (`components.schemas.ErrorCode`) with its HTTP status (spec §5)
 * and a stable English title. `Record<ErrorCode, …>` makes the compiler reject a missing code, and
 * error-catalog.test.ts proves the keys equal the contract enum, so no later wave edits this file.
 */
export const ERROR_CATALOG: Readonly<Record<ErrorCode, ErrorCatalogEntry>> = {
  VALIDATION_ERROR: { status: 400, title: 'Validation error' },
  UNAUTHENTICATED: { status: 401, title: 'Authentication required' },
  INVALID_CREDENTIALS: { status: 401, title: 'Invalid credentials' },
  FORBIDDEN: { status: 403, title: 'Forbidden' },
  ORIGIN_NOT_ALLOWED: { status: 403, title: 'Origin not allowed' },
  PASSWORD_CHANGE_REQUIRED: { status: 403, title: 'Password change required' },
  MFA_ENROLLMENT_REQUIRED: { status: 403, title: 'MFA enrollment required' },
  MFA_VERIFICATION_REQUIRED: { status: 403, title: 'MFA verification required' },
  NOT_FOUND: { status: 404, title: 'Not found' },
  STALE_STAGE: { status: 409, title: 'Stage is no longer current' },
  EMAIL_ALREADY_REGISTERED: { status: 409, title: 'E-mail already registered' },
  MFA_ALREADY_ENROLLED: { status: 409, title: 'MFA already enrolled' },
  CONFLICT: { status: 409, title: 'Conflict' },
  PAYLOAD_TOO_LARGE: { status: 413, title: 'Payload too large' },
  UNSUPPORTED_MEDIA_TYPE: { status: 415, title: 'Unsupported media type' },
  PROCESS_NOT_ACTIVE: { status: 422, title: 'Process is not active' },
  CLIENT_ARCHIVED: { status: 422, title: 'Client is archived' },
  WEAK_PASSWORD: { status: 422, title: 'Weak password' },
  PASSWORD_UNCHANGED: { status: 422, title: 'New password must differ from the current one' },
  INVALID_CURRENT_PASSWORD: { status: 422, title: 'Invalid current password' },
  INVALID_MFA_CODE: { status: 422, title: 'Invalid MFA code' },
  USER_LIMIT_REACHED: { status: 422, title: 'User limit reached' },
  RATE_LIMITED: { status: 429, title: 'Too many requests' },
  INTERNAL_ERROR: { status: 500, title: 'Internal error' },
  SERVICE_UNAVAILABLE: { status: 503, title: 'Service unavailable' },
};
