import { describe, expect, it } from 'vitest';
import { bufferCookies } from './cookie-buffer';
import { createCookieJar } from './cookies';

const incoming = [
  { name: 'a', value: '1' },
  { name: 'b', value: '2' },
];

function setCookieHeaders(jar: ReturnType<typeof createCookieJar>): string[] {
  const headers = new Headers();
  jar.applyTo(headers);
  return headers.getSetCookie();
}

describe('bufferCookies', () => {
  it('reads the parent and sees its own writes and deletes before commit', () => {
    const parent = createCookieJar(incoming);
    const buffer = bufferCookies(parent);

    buffer.set('a', 'new');
    buffer.delete('b');
    buffer.set('c', '3');

    expect(buffer.get('a')).toBe('new');
    expect(buffer.get('b')).toBeUndefined();
    expect(buffer.get('c')).toBe('3');
    expect(buffer.getAll()).toEqual([
      { name: 'a', value: 'new' },
      { name: 'c', value: '3' },
    ]);
  });

  it('writes nothing to the parent until commit, so a discarded login sets no cookie', () => {
    const parent = createCookieJar(incoming);
    const buffer = bufferCookies(parent);
    buffer.set('a', 'new');
    buffer.delete('b');

    expect(parent.get('a')).toBe('1');
    expect(parent.get('b')).toBe('2');
    expect(setCookieHeaders(parent)).toEqual([]);

    buffer.discard();
    buffer.commit(); // nothing left to replay
    expect(setCookieHeaders(parent)).toEqual([]);
    expect(buffer.get('a')).toBe('1');
  });

  it('commit replays sets (with their options) and deletes onto the parent', () => {
    const parent = createCookieJar(incoming);
    const buffer = bufferCookies(parent);
    buffer.set('a', 'new', { maxAge: 60 });
    buffer.delete('b');

    buffer.commit();

    expect(parent.get('a')).toBe('new');
    expect(parent.get('b')).toBeUndefined();
    const headers = setCookieHeaders(parent);
    expect(headers.find((cookie) => cookie.startsWith('a=new'))).toMatch(/Max-Age=60/i);
    expect(headers.find((cookie) => cookie.startsWith('b='))).toMatch(/Max-Age=0/i);
  });

  it('keeps the last write of a name', () => {
    const parent = createCookieJar([]);
    const buffer = bufferCookies(parent);
    buffer.set('x', '1');
    buffer.delete('x');
    buffer.set('x', '3');
    buffer.commit();
    expect(parent.get('x')).toBe('3');
  });
});
