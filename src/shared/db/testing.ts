// Test kit of shared/db: an in-memory cookie store that records every write. Imported only by
// tests; nothing in production code depends on it.
import type { SessionCookieStore } from './session-cookies';

export type CookieWrite =
  | {
      readonly kind: 'set';
      readonly name: string;
      readonly value: string;
      readonly maxAge?: number;
    }
  | { readonly kind: 'delete'; readonly name: string };

export type FakeCookieStore = SessionCookieStore & {
  /** Every write, in order, with the options that were passed. */
  readonly writes: CookieWrite[];
  get(name: string): string | undefined;
};

export function createFakeCookieStore(
  initial: readonly { name: string; value: string }[] = [],
): FakeCookieStore {
  const current = new Map(initial.map(({ name, value }) => [name, value] as const));
  const writes: CookieWrite[] = [];

  return {
    writes,
    get: (name) => current.get(name),
    getAll: () => [...current].map(([name, value]) => ({ name, value })),
    set(name, value, options) {
      current.set(name, value);
      writes.push(
        options?.maxAge === undefined
          ? { kind: 'set', name, value }
          : { kind: 'set', name, value, maxAge: options.maxAge },
      );
    },
    delete(name) {
      current.delete(name);
      writes.push({ kind: 'delete', name });
    },
  };
}
