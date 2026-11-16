import { z } from 'zod';

/** `TotpVerifyRequest.code.pattern` of the contract: exactly six ASCII digits. */
const TOTP_CODE_PATTERN = /^[0-9]{6}$/;

/**
 * `TotpVerifyRequest` (contract). `.strict()`: any other field is a 400 (mass-assignment defense).
 * The code is not trimmed or normalized: " 123456" is not a code. The error messages Zod produces
 * never echo the value.
 */
export const verifyTotpBodySchema = z
  .object({
    factorId: z.uuid(),
    code: z.string().regex(TOTP_CODE_PATTERN, { error: 'Must be six digits' }),
  })
  .strict();

export type VerifyTotpBody = z.output<typeof verifyTotpBodySchema>;
