/**
 * Temporary passwords (spec SEC-10, Q-04): 20 characters from a CSPRNG, shown ONCE to the person who
 * hands them over (`pnpm ceo:create` now, the provisioning and reset endpoints of Wave 7 later), and
 * replaced by the user at the first sign-in.
 */

/** SEC-10: a temporary password has 20 characters. */
export const TEMPORARY_PASSWORD_LENGTH = 20;

// Ambiguous characters are left out because the password is read aloud or copied from a screen:
// `0` and `O`/`o`, `1` and `l`/`I`. What remains is 24 + 24 + 8 = 56 symbols, so 20 of them carry
// about 116 bits.
const UPPERCASE = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijkmnpqrstuvwxyz';
const DIGITS = '23456789';

export const TEMPORARY_PASSWORD_ALPHABET = `${UPPERCASE}${LOWERCASE}${DIGITS}`;

const CHARACTER_CLASSES = [UPPERCASE, LOWERCASE, DIGITS] as const;

const BYTE_VALUES = 256;
/**
 * A byte is used only below this bound, the largest multiple of the alphabet size that fits in a
 * byte (224 = 4 x 56). `byte % 56` over all 256 values would favor the first 32 symbols; skipping
 * the 32 highest values makes every symbol exactly as likely as every other.
 */
const ACCEPT_BELOW = BYTE_VALUES - (BYTE_VALUES % TEMPORARY_PASSWORD_ALPHABET.length);

/**
 * Safety bounds against a broken random source (one that returns too few bytes, or always the
 * same ones): after them the generator throws instead of looping or returning a predictable
 * password (fail closed). A healthy CSPRNG never gets near either.
 */
const MAX_DRAW_ROUNDS = 64;
const MAX_ATTEMPTS = 64;

/** `length` random bytes. The default is the platform CSPRNG; tests inject their own. */
export type RandomBytes = (length: number) => Uint8Array;

export const platformRandomBytes: RandomBytes = (length) =>
  globalThis.crypto.getRandomValues(new Uint8Array(length));

function drawCharacters(randomBytes: RandomBytes): string {
  let characters = '';
  for (let round = 0; round < MAX_DRAW_ROUNDS; round += 1) {
    // twice as many bytes as characters: a byte is skipped about one time in eight
    const bytes = randomBytes(TEMPORARY_PASSWORD_LENGTH * 2);
    for (const byte of bytes) {
      if (byte >= ACCEPT_BELOW) continue;
      characters += TEMPORARY_PASSWORD_ALPHABET.charAt(byte % TEMPORARY_PASSWORD_ALPHABET.length);
      if (characters.length === TEMPORARY_PASSWORD_LENGTH) return characters;
    }
  }
  throw new Error('the random source did not produce enough usable bytes');
}

const hasEveryClass = (password: string): boolean =>
  CHARACTER_CLASSES.every((characterClass) =>
    Array.from(password).some((character) => characterClass.includes(character)),
  );

/**
 * A new temporary password: `TEMPORARY_PASSWORD_LENGTH` characters of `TEMPORARY_PASSWORD_ALPHABET`,
 * each drawn uniformly and independently, with at least one uppercase letter, one lowercase letter
 * and one digit (so it also satisfies the strictest character requirement a project may set in
 * Auth). That last rule is enforced by drawing again, not by planting characters, so the result
 * stays uniform among the passwords that satisfy it. It always satisfies the password policy
 * (12 to 72 bytes). It is a secret: never log it.
 */
export function generateTemporaryPassword(randomBytes: RandomBytes = platformRandomBytes): string {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    const password = drawCharacters(randomBytes);
    if (hasEveryClass(password)) return password;
  }
  throw new Error('the random source never produced a password with every character class');
}
