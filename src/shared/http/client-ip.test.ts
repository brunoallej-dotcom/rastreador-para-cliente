import { describe, expect, it } from 'vitest';
import { ipSubject } from './client-ip';

describe('ipSubject', () => {
  describe('IPv4 is kept as is', () => {
    it.each(['203.0.113.7', '10.0.0.1', '255.255.255.255', '0.0.0.0'])('%s', (ip) => {
      expect(ipSubject(ip)).toBe(ip);
    });
  });

  describe('IPv6 is aggregated to its /64 prefix', () => {
    it.each([
      ['2001:db8:1:2::1', '2001:db8:1:2::/64'],
      ['2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64'],
      ['2001:0DB8:0001:0002:FFFF:FFFF:FFFF:FFFF', '2001:db8:1:2::/64'],
      ['2001:db8:1:2::', '2001:db8:1:2::/64'],
      ['2001:db8::1', '2001:db8:0:0::/64'],
      ['2001:db8:0:0:0:0:0:1', '2001:db8:0:0::/64'],
      ['2001:db8:abcd:ef01:1234:5678:9abc:def0', '2001:db8:abcd:ef01::/64'],
      ['::1', '0:0:0:0::/64'],
      ['::', '0:0:0:0::/64'],
      ['fe80::1', 'fe80:0:0:0::/64'],
      ['1::', '1:0:0:0::/64'],
      ['ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'ffff:ffff:ffff:ffff::/64'],
    ])('%s → %s', (ip, expected) => {
      expect(ipSubject(ip)).toBe(expected);
    });

    it('gives every spelling of addresses in one /64 the same subject', () => {
      const subjects = new Set(
        [
          '2001:db8:1:2::1',
          '2001:DB8:1:2::2',
          '2001:db8:1:2:0:0:0:3',
          '2001:0db8:0001:0002:aaaa:bbbb:cccc:dddd',
        ].map(ipSubject),
      );
      expect(subjects).toEqual(new Set(['2001:db8:1:2::/64']));
    });

    it('keeps different /64 prefixes apart, even when they differ in the last prefix bit group', () => {
      expect(ipSubject('2001:db8:1:2::1')).not.toBe(ipSubject('2001:db8:1:3::1'));
      expect(ipSubject('2001:db8:1:2::1')).not.toBe(ipSubject('2001:db8:2:2::1'));
    });

    it('drops a zone id', () => {
      expect(ipSubject('fe80::1%eth0')).toBe('fe80:0:0:0::/64');
    });
  });

  describe('IPv4-mapped IPv6 is the IPv4 address, in any spelling', () => {
    it.each([
      ['::ffff:203.0.113.7', '203.0.113.7'],
      ['::FFFF:203.0.113.7', '203.0.113.7'],
      ['::ffff:cb00:7107', '203.0.113.7'],
      ['0:0:0:0:0:ffff:203.0.113.7', '203.0.113.7'],
      ['0000:0000:0000:0000:0000:ffff:cb00:7107', '203.0.113.7'],
      ['::ffff:0.0.0.0', '0.0.0.0'],
      ['::ffff:255.255.255.255', '255.255.255.255'],
      ['::ffff:10.0.0.1', '10.0.0.1'],
    ])('%s → %s', (ip, expected) => {
      expect(ipSubject(ip)).toBe(expected);
    });

    it('the mapped and the plain spelling of one client share a subject', () => {
      expect(ipSubject('::ffff:203.0.113.7')).toBe(ipSubject('203.0.113.7'));
    });

    it('is not fooled by near misses: only 0:0:0:0:0:ffff:x:x is IPv4-mapped', () => {
      expect(ipSubject('::fffe:203.0.113.7')).toBe('0:0:0:0::/64');
      expect(ipSubject('1::ffff:203.0.113.7')).toBe('1:0:0:0::/64');
      expect(ipSubject('64:ff9b::203.0.113.7')).toBe('64:ff9b:0:0::/64');
    });
  });

  describe('anything that is not an IP has no subject', () => {
    it.each([
      '',
      ' ',
      'unknown',
      'not-an-ip',
      '203.0.113',
      '203.0.113.256',
      '203.0.113.7.1',
      '1.2.3.4/24',
      '2001:db8::/32',
      '2001:db8:1:2:3:4:5:6:7',
      '2001:db8::1::2',
      '[::1]',
      'gggg::1',
      '203.0.113.7, 198.51.100.1',
      'a'.repeat(100),
    ])('%j', (value) => {
      expect(ipSubject(value)).toBeUndefined();
    });
  });

  it('trims surrounding spaces', () => {
    expect(ipSubject('  203.0.113.7 ')).toBe('203.0.113.7');
  });
});
