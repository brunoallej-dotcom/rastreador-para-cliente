import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fingerprintSubject, hmacSubject } from './subject-hmac';

// Obviously fake, lowercase-only values (the secret-detection hook rightly ignores them).
const KEY = 'unit-test-only-hmac-key-not-a-real-value-at-all';
const HEX_64 = /^[0-9a-f]{64}$/;

describe('hmacSubject', () => {
  it('is HMAC-SHA256 as 64 lowercase hex characters, stable for the same input', () => {
    // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
    expect(hmacSubject('Jefe', 'what do ya want for nothing?')).toBe(
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    );
    expect(hmacSubject(KEY, 'a')).toMatch(HEX_64);
    expect(hmacSubject(KEY, 'a')).toBe(hmacSubject(KEY, 'a'));
  });

  it('differs by subject and by key', () => {
    expect(hmacSubject(KEY, 'a')).not.toBe(hmacSubject(KEY, 'b'));
    expect(hmacSubject(KEY, 'a')).not.toBe(hmacSubject(`${KEY}-other`, 'a'));
  });
});

describe('fingerprintSubject', () => {
  beforeEach(() => {
    vi.stubEnv('APP_ORIGIN', 'http://localhost:3000');
    vi.stubEnv('SUPABASE_URL', 'http://127.0.0.1:54321');
    vi.stubEnv('SUPABASE_PUBLISHABLE_KEY', 'fake-publishable-key-for-unit-tests');
    vi.stubEnv('SUPABASE_SECRET_KEY', 'fake-secret-key-for-unit-tests');
    vi.stubEnv('RATE_LIMIT_KEY_SECRET', KEY);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('SEC-16: is stable and 64 hex characters, and never contains the subject', () => {
    const fingerprint = fingerprintSubject('maria@cliente.test');
    expect(fingerprint).toMatch(HEX_64);
    expect(fingerprint).toBe(fingerprintSubject('maria@cliente.test'));
    expect(fingerprint).not.toContain('maria');
  });

  it('is NOT the value the rate limiter stores: a log line cannot be matched to a database row', () => {
    expect(fingerprintSubject('maria@cliente.test')).not.toBe(
      hmacSubject(KEY, 'maria@cliente.test'),
    );
  });
});
