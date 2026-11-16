import { NextResponse } from 'next/server';

export type CookieOptions = {
  readonly maxAge?: number;
  readonly expires?: Date;
};

type PendingCookie = { readonly value: string; readonly options: CookieOptions };

/**
 * The cookies of one request, with `getAll`/`setAll`-style access for `@supabase/ssr`.
 *
 * Reads come from the incoming request; writes are collected and applied to the FINAL response
 * (success or error) by the pipeline, so a token refreshed while authenticating is not lost when
 * the request is then denied. Reads see the pending writes, like Next's mutable `cookies()`.
 *
 * Every cookie written here is forced to `HttpOnly; Secure; SameSite=Lax; Path=/` with no
 * `Domain` (SEC-07, and required by the `__Host-` prefix), whatever the caller asked for.
 */
export type CookieJar = {
  get(name: string): string | undefined;
  getAll(): { name: string; value: string }[];
  set(name: string, value: string, options?: CookieOptions): void;
  delete(name: string): void;
};

export type ManagedCookieJar = CookieJar & {
  /** Appends one `Set-Cookie` header per pending write. */
  applyTo(headers: Headers): void;
};

export function createCookieJar(
  incoming: readonly { name: string; value: string }[],
): ManagedCookieJar {
  const current = new Map(incoming.map(({ name, value }) => [name, value] as const));
  const pending = new Map<string, PendingCookie>();

  return {
    get: (name) => current.get(name),
    getAll: () => [...current].map(([name, value]) => ({ name, value })),
    set(name, value, options = {}) {
      current.set(name, value);
      pending.set(name, { value, options });
    },
    delete(name) {
      current.delete(name);
      pending.set(name, { value: '', options: { maxAge: 0, expires: new Date(0) } });
    },
    applyTo(headers) {
      if (pending.size === 0) return;
      // NextResponse only serves as a correct Set-Cookie serializer.
      const serializer = new NextResponse(null);
      for (const [name, { value, options }] of pending) {
        // An allow-list, not a spread: whatever else a caller (or a future `CookieOptions` field,
        // or a JS caller past the types) put in `options`, e.g. a `domain`, never reaches the header.
        serializer.cookies.set(name, value, {
          ...(options.maxAge === undefined ? {} : { maxAge: options.maxAge }),
          ...(options.expires === undefined ? {} : { expires: options.expires }),
          httpOnly: true,
          secure: true,
          sameSite: 'lax',
          path: '/',
        });
      }
      for (const cookie of serializer.headers.getSetCookie()) headers.append('Set-Cookie', cookie);
    },
  };
}
