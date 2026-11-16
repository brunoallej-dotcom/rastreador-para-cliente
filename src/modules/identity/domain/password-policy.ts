import { err, ok, type Result } from '@/shared/kernel';
import { PasswordUnchangedError, WeakPasswordError } from './password-errors';

/** SEC-10, E-12: at least 12 characters (code points)... */
export const PASSWORD_MIN_CHARACTERS = 12;
/** ...and at most 72 bytes of UTF-8: bcrypt ignores everything past byte 72. */
export const PASSWORD_MAX_BYTES = 72;

const encoder = new TextEncoder();

/** Size of `text` in UTF-8 bytes. */
export const utf8ByteLength = (text: string): number => encoder.encode(text).length;

/**
 * The password policy (SEC-10, E-12): 12 characters at least, 72 bytes at most. Characters are
 * counted as code points, as the Auth server counts them; the maximum is in BYTES because that is
 * where bcrypt stops reading. The password is never trimmed or normalized: what the user typed is
 * what is hashed.
 */
export function checkPasswordPolicy(password: string): Result<void, WeakPasswordError> {
  if (Array.from(password).length < PASSWORD_MIN_CHARACTERS) return err(new WeakPasswordError());
  if (utf8ByteLength(password) > PASSWORD_MAX_BYTES) return err(new WeakPasswordError());
  return ok(undefined);
}

export type PasswordChange = { readonly currentPassword: string; readonly newPassword: string };

/**
 * What a password change must satisfy before anything talks to the Auth server: the new password
 * follows the policy (E-12) and differs from the current one (E-13). The comparison is a plain
 * string comparison and needs no I/O. Its answer does not depend on whether the current password is
 * right, so it cannot be used to probe it.
 */
export function checkPasswordChange({
  currentPassword,
  newPassword,
}: PasswordChange): Result<void, WeakPasswordError | PasswordUnchangedError> {
  const policy = checkPasswordPolicy(newPassword);
  if (!policy.ok) return policy;
  if (newPassword === currentPassword) return err(new PasswordUnchangedError());
  return ok(undefined);
}
