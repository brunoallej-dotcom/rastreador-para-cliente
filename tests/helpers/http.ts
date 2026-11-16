// HTTP helpers for the API tests (Wave 3 owns this file; later waves add their own helper files).
//
//   const jar = createCookieStore();
//   const login = await invoke(loginRoute, { method: 'POST', path: '/auth/login', body: {...}, cookies: jar });
//   const session = await invoke(sessionRoute, { path: '/auth/session', cookies: jar });
//
// `invoke` builds a real `NextRequest` and calls the route handler directly, like Next would. On
// unsafe methods it sets the allowed `Origin` and a JSON content type; every call gets a client IP
// of its own, so the Postgres rate-limit counters of one test never touch another's.
import { randomBytes } from 'node:crypto';
import { NextRequest } from 'next/server';
import type { NextRouteHandler } from '@/shared/http/route-policy';

const API_BASE_PATH = '/api/v1';
const SESSION_COOKIE = '__Host-rt-session';
const BASE64_PREFIX = 'base64-';
const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const MAX_IPV6_GROUP = 0x10000;

/** Origin of the app in the test env (set from the local stack by tests/setup). */
export function appOrigin(): string {
  return process.env.APP_ORIGIN ?? 'http://localhost:3000';
}

/**
 * A client IP nobody else uses: IPv6 documentation range (2001:db8::/32, RFC 3849), with two random
 * 16-bit groups. The pipeline aggregates IPv6 to its /64, which is exactly these four groups, so
 * every call is its own rate-limit subject. The counters live in the database and survive between
 * runs, so the address must not repeat between runs: hence random, not a counter.
 */
export function newClientIp(): string {
  const group = () => randomBytes(2).readUInt16BE(0) % MAX_IPV6_GROUP;
  return `2001:db8:${group().toString(16)}:${group().toString(16)}::1`;
}

// ------------------------------------------------------------------------------ cookies ----

/** What a browser keeps for the app: `name=value` pairs, updated from `Set-Cookie`. */
export type CookieStore = {
  /** Applies the `Set-Cookie` headers of a response (a deleted cookie disappears). */
  absorb(response: Response): void;
  get(name: string): string | undefined;
  names(): string[];
  set(name: string, value: string): void;
  delete(name: string): void;
  /** The `Cookie` request header, or `undefined` when empty. */
  header(): string | undefined;
  /** An independent copy: "the cookie I had before logging out". */
  clone(): CookieStore;
};

export function createCookieStore(initial: Readonly<Record<string, string>> = {}): CookieStore {
  const values = new Map(Object.entries(initial));

  const store: CookieStore = {
    absorb(response) {
      for (const line of response.headers.getSetCookie()) {
        const [pair = '', ...attributes] = line.split(';');
        const separator = pair.indexOf('=');
        if (separator <= 0) continue;
        const name = pair.slice(0, separator).trim();
        const value = pair.slice(separator + 1).trim();
        const expired = attributes.some((attribute) => {
          const [key = '', raw = ''] = attribute.trim().split('=');
          if (key.toLowerCase() === 'max-age') return Number(raw) <= 0;
          if (key.toLowerCase() === 'expires') return Date.parse(raw) <= Date.now();
          return false;
        });
        if (expired || value === '') values.delete(name);
        else values.set(name, value);
      }
    },
    get: (name) => values.get(name),
    names: () => [...values.keys()],
    set: (name, value) => void values.set(name, value),
    delete: (name) => void values.delete(name),
    header() {
      if (values.size === 0) return undefined;
      return [...values].map(([name, value]) => `${name}=${value}`).join('; ');
    },
    clone: () => createCookieStore(Object.fromEntries(values)),
  };
  return store;
}

export type SessionTokens = {
  readonly access_token: string;
  readonly refresh_token: string;
  readonly expires_at: number;
  readonly [field: string]: unknown;
};

/** The names of the session cookie and its chunks (`.0`, `.1`...), in chunk order. */
function sessionCookieNames(store: CookieStore): string[] {
  const chunks = store
    .names()
    .filter((name) => name.startsWith(`${SESSION_COOKIE}.`))
    .sort((a, b) => Number(a.split('.').pop()) - Number(b.split('.').pop()));
  return store.get(SESSION_COOKIE) === undefined ? chunks : [SESSION_COOKIE];
}

/**
 * Decodes the session `@supabase/ssr` keeps in the cookie (`base64-` + base64url JSON, possibly
 * split in chunks). Test-only: it is how a test shows what a stolen cookie would carry.
 */
export function readSessionCookie(store: CookieStore): SessionTokens {
  const joined = sessionCookieNames(store)
    .map((name) => decodeURIComponent(store.get(name) ?? ''))
    .join('');
  if (!joined.startsWith(BASE64_PREFIX)) throw new Error('no session cookie in the store');
  return JSON.parse(
    Buffer.from(joined.slice(BASE64_PREFIX.length), 'base64url').toString('utf8'),
  ) as SessionTokens;
}

/** Replaces the session cookie (and its chunks) by one holding `session`. */
export function writeSessionCookie(store: CookieStore, session: SessionTokens): void {
  for (const name of sessionCookieNames(store)) store.delete(name);
  const encoded = Buffer.from(JSON.stringify(session), 'utf8').toString('base64url');
  store.set(SESSION_COOKIE, encodeURIComponent(`${BASE64_PREFIX}${encoded}`));
}

// ------------------------------------------------------------------------------ requests ----

export type InvokeInit = {
  /** Default `GET`. */
  readonly method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Path under `/api/v1`, e.g. `/auth/login`. */
  readonly path: string;
  /** Dynamic path segments, as Next passes them to the handler. */
  readonly params?: Readonly<Record<string, string>>;
  readonly query?: Readonly<Record<string, string | readonly string[]>>;
  /** JSON body; sets `Content-Type: application/json` (unless `headers` already sets one). */
  readonly body?: unknown;
  /** A raw body, sent as is (for malformed-body tests). */
  readonly rawBody?: string;
  /** A store is read AND updated from the response, like a browser. A record is sent as given. */
  readonly cookies?: CookieStore | Readonly<Record<string, string>>;
  readonly headers?: Readonly<Record<string, string>>;
  /** `Origin` of unsafe requests. Default: the allowed origin. `null` omits the header. */
  readonly origin?: string | null;
  /** `x-real-ip`. Default: a fresh address (see `newClientIp`). `null` omits the header. */
  readonly ip?: string | null;
};

const isStore = (value: unknown): value is CookieStore =>
  typeof value === 'object' && value !== null && 'absorb' in value;

export async function invoke(handler: NextRouteHandler, init: InvokeInit): Promise<Response> {
  const method = init.method ?? 'GET';
  const headers = new Headers(init.headers);

  const ip = init.ip === undefined ? newClientIp() : init.ip;
  if (ip !== null && !headers.has('x-real-ip')) headers.set('x-real-ip', ip);

  const origin = init.origin === undefined ? appOrigin() : init.origin;
  if (UNSAFE_METHODS.has(method) && origin !== null && !headers.has('origin')) {
    headers.set('origin', origin);
  }

  const cookieSource = init.cookies;
  const store = isStore(cookieSource) ? cookieSource : undefined;
  const cookieHeader = isStore(cookieSource)
    ? cookieSource.header()
    : cookieSource === undefined
      ? undefined
      : createCookieStore(cookieSource).header();
  if (cookieHeader !== undefined) headers.set('cookie', cookieHeader);

  let body: string | undefined = init.rawBody;
  if (init.body !== undefined) {
    body = JSON.stringify(init.body);
    if (!headers.has('content-type')) headers.set('content-type', 'application/json');
  }

  const url = new URL(`${appOrigin()}${API_BASE_PATH}${init.path}`);
  for (const [key, value] of Object.entries(init.query ?? {})) {
    for (const item of Array.isArray(value) ? value : [value]) {
      url.searchParams.append(key, String(item));
    }
  }

  const request = new NextRequest(url, {
    method,
    headers,
    ...(body === undefined ? {} : { body }),
  });
  const response = await handler(request, { params: Promise.resolve({ ...init.params }) });
  store?.absorb(response);
  return response;
}

// ------------------------------------------------------------------------------ responses ----

/** The parsed JSON body, leaving the response readable again. */
export async function bodyOf(response: Response): Promise<unknown> {
  return response.clone().json();
}

/** The response text, leaving the response readable again. */
export async function textOf(response: Response): Promise<string> {
  return response.clone().text();
}

/**
 * A problem+json body without its `requestId`, which differs per request and is the ONLY member
 * that may differ between two answers that must be indistinguishable (SEC-12).
 */
export function withoutRequestId(body: unknown): Record<string, unknown> {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new Error('expected a JSON object');
  }
  const { requestId: _requestId, ...rest } = body as Record<string, unknown>;
  return rest;
}

/** The response headers a client can observe, without the one that is unique per request. */
export function observableHeaders(response: Response): Record<string, string> {
  const headers: Record<string, string> = {};
  response.headers.forEach((value, name) => {
    if (name.toLowerCase() !== 'x-request-id') headers[name.toLowerCase()] = value;
  });
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 0) headers['set-cookie'] = cookies.join('\n');
  return headers;
}
