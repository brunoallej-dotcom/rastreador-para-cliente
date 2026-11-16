import { clientIp } from './client-ip';
import { fingerprintSubject } from './rate-limit/subject-hmac';

/**
 * Keyed, non-reversible fingerprint of the client IP (IPv6 aggregated to its /64), for log lines
 * (`ipHash`): it lets an operator group the events of one source without the log holding the IP.
 * `undefined` when the platform gave no IP.
 */
export function clientIpFingerprint(request: Request): string | undefined {
  const ip = clientIp(request);
  return ip === undefined ? undefined : fingerprintSubject(ip);
}
