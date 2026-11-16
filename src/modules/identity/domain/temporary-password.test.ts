import { describe, expect, it } from 'vitest';
import { checkPasswordPolicy } from './password-policy';
import {
  generateTemporaryPassword,
  TEMPORARY_PASSWORD_ALPHABET,
  TEMPORARY_PASSWORD_LENGTH,
  type RandomBytes,
} from './temporary-password';

// the alphabet, by position: A-Z without I and O (0-23), a-z without l and o (24-47), 2-9 (48-55)
const FIRST_UPPERCASE = 0;
const FIRST_LOWERCASE = 24;
const FIRST_DIGIT = 48;
const LAST_SYMBOL = 55;
const BYTE_LIMIT = 224;
const AMBIGUOUS = ['0', 'O', 'o', '1', 'l', 'I'];

/** A source that hands out `bytes` in a loop, `length` at a time, recording each request. */
function cyclingSource(bytes: readonly number[]): RandomBytes & { readonly requests: number[] } {
  const requests: number[] = [];
  let cursor = 0;
  const source = ((length: number) => {
    requests.push(length);
    const out = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) {
      out[index] = bytes[cursor % bytes.length] ?? 0;
      cursor += 1;
    }
    return out;
  }) as RandomBytes & { requests: number[] };
  source.requests = requests;
  return source;
}

describe('the alphabet', () => {
  it('has 56 distinct symbols and none of the ambiguous ones (0 O o 1 l I)', () => {
    expect(TEMPORARY_PASSWORD_ALPHABET).toHaveLength(56);
    expect(new Set(TEMPORARY_PASSWORD_ALPHABET).size).toBe(56);
    for (const symbol of AMBIGUOUS) expect(TEMPORARY_PASSWORD_ALPHABET).not.toContain(symbol);
  });

  it('is letters and digits only, so it survives being read aloud or pasted anywhere', () => {
    expect(TEMPORARY_PASSWORD_ALPHABET).toMatch(/^[A-Za-z0-9]+$/);
  });

  it('is laid out as the byte mapping below assumes', () => {
    expect(TEMPORARY_PASSWORD_ALPHABET.charAt(FIRST_UPPERCASE)).toBe('A');
    expect(TEMPORARY_PASSWORD_ALPHABET.charAt(FIRST_LOWERCASE)).toBe('a');
    expect(TEMPORARY_PASSWORD_ALPHABET.charAt(FIRST_DIGIT)).toBe('2');
    expect(TEMPORARY_PASSWORD_ALPHABET.charAt(LAST_SYMBOL)).toBe('9');
  });
});

describe('generateTemporaryPassword', () => {
  it('SEC-10: is 20 characters, all of them from the alphabet', () => {
    expect(TEMPORARY_PASSWORD_LENGTH).toBe(20);
    for (let n = 0; n < 200; n += 1) {
      const password = generateTemporaryPassword();
      expect(password).toHaveLength(20);
      for (const character of password) expect(TEMPORARY_PASSWORD_ALPHABET).toContain(character);
    }
  });

  it('always has an uppercase letter, a lowercase letter and a digit', () => {
    for (let n = 0; n < 500; n += 1) {
      const password = generateTemporaryPassword();
      expect(password).toMatch(/[A-Z]/);
      expect(password).toMatch(/[a-z]/);
      expect(password).toMatch(/[0-9]/);
    }
  });

  it('always satisfies the password policy (it is a valid password to set)', () => {
    for (let n = 0; n < 100; n += 1) {
      expect(checkPasswordPolicy(generateTemporaryPassword()).ok).toBe(true);
    }
  });

  it('never repeats: 5,000 passwords are 5,000 different ones', () => {
    const seen = new Set<string>();
    for (let n = 0; n < 5000; n += 1) seen.add(generateTemporaryPassword());
    expect(seen.size).toBe(5000);
  });

  it('distribution: every symbol appears about equally often (no modulo bias)', () => {
    const passwords = 10_000;
    const counts = new Map<string, number>();
    for (let n = 0; n < passwords; n += 1) {
      for (const character of generateTemporaryPassword()) {
        counts.set(character, (counts.get(character) ?? 0) + 1);
      }
    }
    const total = passwords * TEMPORARY_PASSWORD_LENGTH;
    const symbols = TEMPORARY_PASSWORD_ALPHABET.length;
    const expected = total / symbols;
    // about 3,571 per symbol, standard deviation about 59: six sigma is a bound a healthy
    // generator never touches, and a bias of even one extra use in the first 32 symbols would show
    const tolerance = 6 * Math.sqrt(expected * (1 - 1 / symbols));
    expect(counts.size).toBe(symbols);
    for (const [symbol, count] of counts) {
      expect(Math.abs(count - expected), `symbol ${symbol}: ${count} of ~${expected}`).toBeLessThan(
        tolerance,
      );
    }
  });

  it('distribution: the first symbol of the password is as varied as the others', () => {
    const firsts = new Set<string>();
    for (let n = 0; n < 2000; n += 1) firsts.add(generateTemporaryPassword().charAt(0));
    expect(firsts.size).toBeGreaterThan(50);
  });

  it('maps a byte to its symbol by position, and draws twice as many bytes as characters', () => {
    // 0 -> A, 24 -> a, 48 -> 2 : every class is present, so the first draw is accepted
    const source = cyclingSource([FIRST_UPPERCASE, FIRST_LOWERCASE, FIRST_DIGIT]);
    const password = generateTemporaryPassword(source);
    expect(password).toBe('Aa2Aa2Aa2Aa2Aa2Aa2Aa');
    expect(source.requests).toEqual([40]);
  });

  it('uses the high bytes modulo the alphabet size and skips the ones that would bias it', () => {
    // 223 is the last byte kept (223 % 56 = 55 -> "9"); 224..255 are skipped
    const source = cyclingSource([223, 224, 255, FIRST_UPPERCASE, FIRST_LOWERCASE, FIRST_DIGIT]);
    const password = generateTemporaryPassword(source);
    // the bytes 224 and 255 never became a symbol: only 9, A, a, 2 appear
    expect(password).toMatch(/^[9Aa2]{20}$/);
    expect(password).toMatch(/^9Aa2/);
    expect(BYTE_LIMIT).toBe(224);
  });

  it('draws again when a draw lacks a character class, instead of planting a character', () => {
    let draws = 0;
    const source: RandomBytes = (length) => {
      draws += 1;
      // first draw: only uppercase (all zeros); second: every class
      if (draws === 1) return new Uint8Array(length);
      const out = new Uint8Array(length);
      for (let index = 0; index < length; index += 1) {
        out[index] = [FIRST_UPPERCASE, FIRST_LOWERCASE, FIRST_DIGIT][index % 3] ?? 0;
      }
      return out;
    };
    expect(generateTemporaryPassword(source)).toMatch(/[a-z]/);
    expect(draws).toBe(2);
  });

  it('fails closed on a random source that never gives a usable password', () => {
    // all zeros: always "AAAA...", never a lowercase letter or a digit
    expect(() => generateTemporaryPassword(() => new Uint8Array(40))).toThrow(/character class/);
    // all too high: no byte is ever usable
    expect(() => generateTemporaryPassword((length) => new Uint8Array(length).fill(255))).toThrow(
      /usable bytes/,
    );
    // an empty source
    expect(() => generateTemporaryPassword(() => new Uint8Array(0))).toThrow(/usable bytes/);
  });

  it('uses the platform CSPRNG by default (crypto.getRandomValues)', () => {
    const calls: number[] = [];
    const original = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
    const spy = (array: ArrayBufferView) => {
      calls.push(array.byteLength);
      return original(array as Uint8Array);
    };
    Object.defineProperty(globalThis.crypto, 'getRandomValues', { value: spy, configurable: true });
    try {
      generateTemporaryPassword();
    } finally {
      Object.defineProperty(globalThis.crypto, 'getRandomValues', {
        value: original,
        configurable: true,
      });
    }
    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every((size) => size === 40)).toBe(true);
  });
});
