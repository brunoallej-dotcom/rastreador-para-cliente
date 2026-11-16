import { z } from 'zod';
import { visibleText } from '@/shared/http';
import { CLIENT_USER_NAME_MAX_LENGTH } from '../domain/client-user';
import { normalizeEmail } from '../domain/email';

/** `Email.maxLength` of the contract. */
const EMAIL_MAX_LENGTH = 254;

/** The display name of a login: NFC, trimmed, 1 to 120 visible characters (E-30), as the contract. */
const displayName = () => visibleText({ min: 1, max: CLIENT_USER_NAME_MAX_LENGTH });

/** `ClientId` path parameter: a UUID. A malformed id is a 400, never a 404 (E-06). */
export const clientIdParamsSchema = z.object({ clientId: z.uuid() }).strict();

/** `ClientId` and `UserId` path parameters: UUIDs. */
export const clientUserParamsSchema = z.object({ clientId: z.uuid(), userId: z.uuid() }).strict();

/**
 * `ProvisionClientUserRequest` (contract). `.strict()`: any other field is a 400 (mass assignment), and
 * so is the tenant: the client comes from the PATH only, and the role is never a field. The e-mail is
 * normalized first (trim, NFC, lowercase: E-11) and then checked as an address of at most 254
 * characters, so the Auth server, the duplicate check and the list all see the same canonical value.
 */
export const provisionClientUserBodySchema = z
  .object({
    email: z
      .string()
      .max(EMAIL_MAX_LENGTH)
      .transform(normalizeEmail)
      .pipe(z.email().max(EMAIL_MAX_LENGTH)),
    displayName: displayName(),
  })
  .strict();

/**
 * `UpdateClientUserRequest` (contract): `disabled` and/or `displayName`, and at least one of them
 * (`minProperties: 1`). `.strict()`: any other field (`email`, `role`, `clientId`, `password`...) is a 400.
 */
export const updateClientUserBodySchema = z
  .object({ disabled: z.boolean().optional(), displayName: displayName().optional() })
  .strict()
  .refine((body) => body.disabled !== undefined || body.displayName !== undefined, {
    error: 'Must name at least one field to change',
  });
