import { createHmac } from 'node:crypto';
import { getEnv } from '@/shared/config/env';

/** Purpose of the key derived for log fingerprints; changing it changes every fingerprint. */
const LOG_FINGERPRINT_PURPOSE = 'log-fingerprint-v1';

/**
 * HMAC-SHA256 of a rate-limit subject (an IP, a normalized e-mail, a user id), as lowercase hex
 * (64 characters). The database only ever sees this value, never the subject (spec §3.9), and
 * without the key it cannot be reversed or guessed by brute-forcing the small space of IPs.
 */
export function hmacSubject(secret: string, subject: string): string {
  return createHmac('sha256', secret).update(subject).digest('hex');
}

/**
 * A stable, non-reversible fingerprint of a subject for LOG lines (`auth.login.failed`), without
 * logging the subject. It uses a key DERIVED from `RATE_LIMIT_KEY_SECRET` for this one purpose, so
 * it never equals the value stored in `private.rate_limit_counters`: someone who reads the logs
 * cannot match a log line to a database row (and the other way round).
 */
export function fingerprintSubject(subject: string): string {
  const logKey = hmacSubject(getEnv().RATE_LIMIT_KEY_SECRET, LOG_FINGERPRINT_PURPOSE);
  return hmacSubject(logKey, subject);
}
