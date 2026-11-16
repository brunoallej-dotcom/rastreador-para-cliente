import type { CookieJar, CookieOptions } from './cookies';

type BufferedWrite =
  | { readonly kind: 'set'; readonly value: string; readonly options: CookieOptions }
  | { readonly kind: 'delete' };

/**
 * A cookie jar whose writes wait in a buffer until `commit()`. Reads see the parent's cookies
 * overlaid with the buffered writes, so a client using it behaves as if it wrote for real.
 * `discard()` (or simply never committing) drops the writes: the response then carries no cookie
 * change at all.
 *
 * Login needs it: when the credentials are right but the account is disabled, the session that
 * Supabase just created is revoked and the response must look exactly like a wrong password,
 * `Set-Cookie` header included.
 */
export type BufferedCookieJar = CookieJar & {
  /** Replays the buffered writes onto the parent jar and empties the buffer. */
  commit(): void;
  /** Forgets the buffered writes. */
  discard(): void;
};

export function bufferCookies(parent: CookieJar): BufferedCookieJar {
  const writes = new Map<string, BufferedWrite>();

  const read = (name: string): string | undefined => {
    const write = writes.get(name);
    if (write === undefined) return parent.get(name);
    return write.kind === 'set' ? write.value : undefined;
  };

  return {
    get: read,
    getAll() {
      const visible = new Map(parent.getAll().map(({ name, value }) => [name, value] as const));
      for (const [name, write] of writes) {
        if (write.kind === 'set') visible.set(name, write.value);
        else visible.delete(name);
      }
      return [...visible].map(([name, value]) => ({ name, value }));
    },
    set(name, value, options = {}) {
      writes.set(name, { kind: 'set', value, options });
    },
    delete(name) {
      writes.set(name, { kind: 'delete' });
    },
    commit() {
      for (const [name, write] of writes) {
        if (write.kind === 'set') parent.set(name, write.value, write.options);
        else parent.delete(name);
      }
      writes.clear();
    },
    discard() {
      writes.clear();
    },
  };
}
