// Unit tests of the pure parts of tests/helpers/mfa.ts: the TOTP codes the API tests send. They run
// with a frozen clock, so they need no database and no sleep. No literal TOTP seed appears here:
// the RFC vector is derived from its ASCII text and the others are random.
import * as OTPAuth from 'otpauth';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { nextTotpCode, totpCode, wrongTotpCode } from './mfa';

const PERIOD_MS = 30_000;
const SOME_DAY_MS = 1_700_000_000_000;

/** The seed of RFC 6238 appendix B is the ASCII text "12345678901234567890". */
const rfcSeed = () => OTPAuth.Secret.fromUTF8('12345678901234567890').base32;
const randomSeed = () => new OTPAuth.Secret({ size: 20 }).base32;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('totpCode', () => {
  it('matches the RFC 6238 test vector (T = 59 s is 94287082 with eight digits, 287082 with six)', () => {
    vi.setSystemTime(59_000);
    expect(totpCode(rfcSeed())).toBe('287082');
  });

  it('shifts by whole periods: the code of the next period is the code of 30 s later', () => {
    const seed = rfcSeed();
    vi.setSystemTime(59_000);
    const next = totpCode(seed, 1);
    vi.setSystemTime(59_000 + PERIOD_MS);
    expect(next).toBe(totpCode(seed));
  });
});

describe('wrongTotpCode', () => {
  it('index picks different wrong codes, all of them wrong', () => {
    const seed = randomSeed();
    vi.setSystemTime(SOME_DAY_MS);

    const codes = [0, 1, 2, 3].map((index) => wrongTotpCode(seed, index));

    expect(new Set(codes).size).toBe(4);
    for (const code of codes) {
      for (let offset = -2; offset <= 2; offset += 1) {
        expect(code).not.toBe(totpCode(seed, offset));
      }
    }
  });

  it('is six digits and none of the codes of the previous, current and next period (nor two beyond)', () => {
    const seed = randomSeed();
    for (const start of [0, 29_999, 30_000, SOME_DAY_MS]) {
      vi.setSystemTime(start);
      const wrong = wrongTotpCode(seed);
      expect(wrong).toMatch(/^[0-9]{6}$/);
      for (let offset = -2; offset <= 2; offset += 1) {
        expect(wrong).not.toBe(totpCode(seed, offset));
      }
    }
  });
});

describe('nextTotpCode', () => {
  it('M3: hands out the current period and then the next one, never the previous (it fails near a rollover)', () => {
    const seed = randomSeed();
    vi.setSystemTime(SOME_DAY_MS);

    const codes = [nextTotpCode(seed), nextTotpCode(seed)];

    expect(codes).toEqual([totpCode(seed, 0), totpCode(seed, 1)]);
    expect(codes).not.toContain(totpCode(seed, -1));
  });

  it('fails with an explanation after the second code of one window, instead of sending a replay', () => {
    const seed = randomSeed();
    vi.setSystemTime(SOME_DAY_MS);
    nextTotpCode(seed);
    nextTotpCode(seed);

    expect(() => nextTotpCode(seed)).toThrow(/use a fresh CEO/);
  });

  it('hands out a new code again once the window moved on', () => {
    const seed = randomSeed();
    vi.setSystemTime(SOME_DAY_MS);
    nextTotpCode(seed);
    nextTotpCode(seed);

    vi.setSystemTime(SOME_DAY_MS + 2 * PERIOD_MS);

    expect(() => nextTotpCode(seed)).not.toThrow();
  });

  it('keeps seeds apart', () => {
    const used = randomSeed();
    vi.setSystemTime(SOME_DAY_MS);
    nextTotpCode(used);
    nextTotpCode(used);

    expect(() => nextTotpCode(randomSeed())).not.toThrow();
  });
});
