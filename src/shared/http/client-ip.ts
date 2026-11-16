import { isIP } from 'node:net';
import { ipAddress } from '@vercel/functions';

/** Subject used outside production when the platform gives no IP: all such requests share it. */
export const UNKNOWN_IP = 'unknown';

const IPV6_GROUPS = 8;
const IPV6_PREFIX_GROUPS = 4; // /64
const IPV4_MAPPED_MARKER = 0xffff;
const MAX_HEX_GROUP = 0xffff;
const BYTE = 0xff;
const BITS_PER_BYTE = 8;

/** `a.b.c.d` in the last 32 bits of an IPv6 text becomes two hex groups. */
function expandIpv4Tail(text: string): string | undefined {
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (!tail.includes('.')) return text;
  const octets = tail.split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > BYTE)) {
    return undefined;
  }
  const [a = 0, b = 0, c = 0, d = 0] = octets;
  const high = ((a << BITS_PER_BYTE) | b).toString(16);
  const low = ((c << BITS_PER_BYTE) | d).toString(16);
  return `${text.slice(0, lastColon + 1)}${high}:${low}`;
}

/** The eight 16-bit groups of a valid IPv6 address (`::` expanded, embedded IPv4 converted). */
function ipv6Groups(address: string): number[] | undefined {
  const text = expandIpv4Tail(address);
  if (text === undefined) return undefined;
  const halves = text.split('::');
  if (halves.length > 2) return undefined;

  const split = (part: string | undefined) =>
    part === undefined || part === '' ? [] : part.split(':');
  const head = split(halves[0]);
  const tail = split(halves[1]);
  const missing = IPV6_GROUPS - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return undefined;

  const groups = [
    ...head,
    ...Array<string>(halves.length === 2 ? missing : 0).fill('0'),
    ...tail,
  ].map((group) => (/^[0-9a-f]{1,4}$/i.test(group) ? parseInt(group, 16) : Number.NaN));
  if (groups.length !== IPV6_GROUPS || groups.some((g) => !(g >= 0 && g <= MAX_HEX_GROUP))) {
    return undefined;
  }
  return groups;
}

/**
 * Rate-limit subject for an IP address, or `undefined` when the text is not an IP:
 * - IPv4 is kept as is;
 * - an IPv4-mapped IPv6 address (`::ffff:1.2.3.4`, in any spelling) is the IPv4 address;
 * - any other IPv6 address is aggregated to its /64 prefix (`2001:db8:1:2::/64`), because one
 *   subscriber normally controls a whole /64 and could otherwise rotate addresses to dodge a limit.
 * A zone id (`%eth0`) is dropped.
 */
export function ipSubject(raw: string): string | undefined {
  const text = raw.trim().split('%')[0] ?? '';
  const version = isIP(text);
  if (version === 4) return text;
  if (version !== 6) return undefined;

  const groups = ipv6Groups(text);
  if (groups === undefined) return undefined;

  const mapped = groups.slice(0, 5).every((g) => g === 0) && groups[5] === IPV4_MAPPED_MARKER;
  if (mapped) {
    const [g6 = 0, g7 = 0] = groups.slice(6);
    return [g6 >> BITS_PER_BYTE, g6 & BYTE, g7 >> BITS_PER_BYTE, g7 & BYTE].join('.');
  }
  return `${groups
    .slice(0, IPV6_PREFIX_GROUPS)
    .map((g) => g.toString(16))
    .join(':')}::/64`;
}

/**
 * Client IP for `ip` rate-limit rules (SEC-09), normalized by `ipSubject`. It comes only from the
 * platform helper `ipAddress()` of `@vercel/functions` (the `x-real-ip` that Vercel's proxy sets),
 * never from `X-Forwarded-For` or another header the client can forge. `undefined` when the
 * platform gives none (local dev, tests) or gives something that is not an IP.
 */
export function clientIp(request: Request): string | undefined {
  const raw = ipAddress(request);
  return raw === undefined ? undefined : ipSubject(raw);
}
