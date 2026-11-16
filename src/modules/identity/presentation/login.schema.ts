import { z } from 'zod';
import { normalizeEmail } from '../domain/email';

/** `Email.maxLength` and `LoginRequest.password.maxLength` of the contract. */
const EMAIL_MAX_LENGTH = 254;
/** The contract: "no máximo 72 bytes UTF-8" (bcrypt ignores everything past byte 72). */
const PASSWORD_MAX_BYTES = 72;

const utf8ByteLength = (text: string) => new TextEncoder().encode(text).length;

/**
 * `LoginRequest` (contract). `.strict()`: any other field is a 400 (mass-assignment defense).
 *
 * - `email`: normalized first (trim, NFC, lowercase: E-11), then checked as an address of at most
 *   254 characters. The OUTPUT is the normalized e-mail, so the account rate limit, the sign-in
 *   and the failure log all use the same canonical value.
 * - `password`: only size limits (E-12: the password policy applies when a password is SET, never
 *   when it is used), 1 to 72 bytes. It is never trimmed or normalized.
 */
export const loginBodySchema = z
  .object({
    email: z
      .string()
      .max(EMAIL_MAX_LENGTH)
      .transform(normalizeEmail)
      .pipe(z.email().max(EMAIL_MAX_LENGTH)),
    password: z
      .string()
      .min(1)
      .refine((value) => utf8ByteLength(value) <= PASSWORD_MAX_BYTES, {
        error: `Must be at most ${PASSWORD_MAX_BYTES} bytes`,
      }),
  })
  .strict();

export type LoginBody = z.output<typeof loginBodySchema>;
