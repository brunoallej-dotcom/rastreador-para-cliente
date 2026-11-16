import { z } from 'zod';
import { PASSWORD_MAX_BYTES, utf8ByteLength } from '../domain/password-policy';

/**
 * `ChangePasswordRequest` (contract). `.strict()`: any other field is a 400 (mass-assignment
 * defense). Neither password is trimmed or normalized: what the user typed is what is checked.
 *
 * - `currentPassword`: 1 to 72 bytes, as in the contract. It is only checked for being a plausible
 *   password; whether it is the right one is the Auth server's answer (422 `INVALID_CURRENT_PASSWORD`).
 * - `newPassword`: ANY string. The contract says 12 characters to 72 bytes for it, but E-12 and the
 *   contract's own `Unprocessable` response say a password that breaks that policy is a 422
 *   `WEAK_PASSWORD`, not a 400. The policy lives in one place, `domain/password-policy.ts`, which
 *   the use case applies; a second copy of its limits here would answer 400 where the contract
 *   promises 422. The 16 KiB limit on the whole body (SEC-17) bounds its size.
 *
 * The messages never echo a password.
 */
export const changePasswordBodySchema = z
  .object({
    currentPassword: z
      .string()
      .min(1)
      .refine((value) => utf8ByteLength(value) <= PASSWORD_MAX_BYTES, {
        error: `Must be at most ${PASSWORD_MAX_BYTES} bytes`,
      }),
    newPassword: z.string(),
  })
  .strict();

export type ChangePasswordBody = z.output<typeof changePasswordBodySchema>;
