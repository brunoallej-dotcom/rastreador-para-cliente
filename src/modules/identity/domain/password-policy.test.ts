import { describe, expect, it } from 'vitest';
import { PasswordUnchangedError, WeakPasswordError } from './password-errors';
import {
  checkPasswordChange,
  checkPasswordPolicy,
  PASSWORD_MAX_BYTES,
  PASSWORD_MIN_CHARACTERS,
  utf8ByteLength,
} from './password-policy';

const GRIN = String.fromCodePoint(0x1f600); // one character, four bytes in UTF-8
const E_ACUTE = String.fromCodePoint(0x00e9); // one character, two bytes

describe('the password policy limits (SEC-10)', () => {
  it('are 12 characters and 72 bytes', () => {
    expect(PASSWORD_MIN_CHARACTERS).toBe(12);
    expect(PASSWORD_MAX_BYTES).toBe(72);
  });
});

describe('checkPasswordPolicy', () => {
  it('E-12: accepts exactly 12 characters, rejects 11', () => {
    expect(checkPasswordPolicy('a'.repeat(12)).ok).toBe(true);
    const short = checkPasswordPolicy('a'.repeat(11));
    expect(short.ok).toBe(false);
    if (!short.ok) expect(short.error).toBeInstanceOf(WeakPasswordError);
  });

  it('E-12: accepts exactly 72 bytes, rejects 73', () => {
    expect(checkPasswordPolicy('a'.repeat(72)).ok).toBe(true);
    const long = checkPasswordPolicy('a'.repeat(73));
    expect(long.ok).toBe(false);
    if (!long.ok) expect(long.error).toBeInstanceOf(WeakPasswordError);
  });

  it('E-12: the maximum counts BYTES (bcrypt reads 72), so 36 two-byte letters fit and 37 do not', () => {
    expect(utf8ByteLength(E_ACUTE.repeat(36))).toBe(72);
    expect(checkPasswordPolicy(E_ACUTE.repeat(36)).ok).toBe(true);
    expect(checkPasswordPolicy(E_ACUTE.repeat(37)).ok).toBe(false);
  });

  it('E-12: the minimum counts CHARACTERS (code points), not bytes or UTF-16 units', () => {
    // 12 characters, 48 bytes, 24 UTF-16 units: long enough
    expect(checkPasswordPolicy(GRIN.repeat(12)).ok).toBe(true);
    // 11 characters, 44 bytes: too short although it has more than 12 bytes
    expect(checkPasswordPolicy(GRIN.repeat(11)).ok).toBe(false);
    // 18 four-byte characters are exactly 72 bytes; 19 are 76
    expect(checkPasswordPolicy(GRIN.repeat(18)).ok).toBe(true);
    expect(checkPasswordPolicy(GRIN.repeat(19)).ok).toBe(false);
  });

  it('does not trim: what the user typed is what is checked', () => {
    expect(checkPasswordPolicy(' '.repeat(12)).ok).toBe(true);
    expect(checkPasswordPolicy(`${'a'.repeat(10)}  `).ok).toBe(true);
    expect(checkPasswordPolicy('').ok).toBe(false);
  });

  it('the refusal never echoes the password', () => {
    const password = 'short-secret';
    const result = checkPasswordPolicy(password.slice(0, 5));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.detail).toBeDefined();
      expect(result.error.detail).not.toContain(password.slice(0, 5));
      expect(result.error.message).not.toContain(password.slice(0, 5));
    }
  });
});

describe('checkPasswordChange', () => {
  const CURRENT = 'current-password-1';

  it('accepts a new password that follows the policy and differs from the current one', () => {
    expect(
      checkPasswordChange({ currentPassword: CURRENT, newPassword: 'another-password-2' }).ok,
    ).toBe(true);
  });

  it('E-13: the same password is PasswordUnchangedError', () => {
    const result = checkPasswordChange({ currentPassword: CURRENT, newPassword: CURRENT });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(PasswordUnchangedError);
  });

  it('E-13: a difference of one character is enough, a difference of case too', () => {
    expect(checkPasswordChange({ currentPassword: CURRENT, newPassword: `${CURRENT}x` }).ok).toBe(
      true,
    );
    expect(
      checkPasswordChange({ currentPassword: CURRENT, newPassword: CURRENT.toUpperCase() }).ok,
    ).toBe(true);
  });

  it('E-12 comes before E-13: a weak password equal to the current one is WeakPasswordError', () => {
    const result = checkPasswordChange({ currentPassword: 'short', newPassword: 'short' });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(WeakPasswordError);
  });
});
