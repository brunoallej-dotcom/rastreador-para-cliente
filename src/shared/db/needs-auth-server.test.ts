import { describe, expect, it } from 'vitest';
import {
  classifySession,
  KID_FRESH_MS,
  needsAuthServer,
  type KnownKid,
  type KnownKids,
  type SessionClass,
} from './needs-auth-server';

const NOW_MS = Date.parse('2026-11-16T12:00:00Z');
const NOW_S = NOW_MS / 1000;
const HOUR_S = 3600;
const NAME = '__Host-rt-session';

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
const SIGNATURE = 'A'.repeat(43); // base64url, as long as an ES256 signature

/** A JWT with a well-formed shape. The signature is NOT valid: classification never checks it. */
const jwt = (
  header: Record<string, unknown>,
  payload: Record<string, unknown> = { sub: 'x', exp: NOW_S + HOUR_S },
) => `${b64url(header)}.${b64url(payload)}.${SIGNATURE}`;

const ES256 = jwt({ alg: 'ES256', kid: 'key-1', typ: 'JWT' });

const session = (accessToken: unknown, expiresAt: unknown = NOW_S + HOUR_S) => ({
  access_token: accessToken,
  refresh_token: 'refresh',
  expires_at: expiresAt,
});

/** The cookie as @supabase/ssr writes it: one value, `base64-` + base64url of the JSON. */
const whole = (value: unknown) => [{ name: NAME, value: `base64-${b64url(value)}` }];
/** The same JSON as a plain value, without the prefix (ssr accepts it as it is). */
const raw = (jsonText: string) => [{ name: NAME, value: jsonText }];

const known: KnownKids = new Map<string, KnownKid>([
  ['key-1', { alg: 'ES256', learnedAtMs: NOW_MS - 60_000 }],
]);

const classify = (cookies: { name: string; value: string }[], kids: KnownKids = known) =>
  classifySession(cookies, NOW_MS, kids);
const kindOf = async (cookies: { name: string; value: string }[], kids?: KnownKids) =>
  (await classify(cookies, kids)).kind;

describe('needsAuthServer: false only when it can be shown that no call to Auth happens', () => {
  it('false: no session cookie at all', async () => {
    expect(await needsAuthServer([], NOW_MS, known)).toBe(false);
    expect(await needsAuthServer([{ name: 'unrelated', value: 'x' }], NOW_MS, known)).toBe(false);
    // `.abc` is not a chunk: combineChunks never reads it, so the library sees no session
    expect(await needsAuthServer([{ name: `${NAME}.abc`, value: 'x' }], NOW_MS, known)).toBe(false);
  });

  it('false: a token that positively verifies with a signing key the process already holds', async () => {
    expect(await needsAuthServer(whole(session(ES256)), NOW_MS, known)).toBe(false);
    expect(await kindOf(whole(session(ES256)))).toBe('local');
  });

  it.each([
    ['a session cookie with an empty value', [{ name: NAME, value: '' }]],
    [
      'an empty cookie and an empty chunk',
      [
        { name: NAME, value: '' },
        { name: `${NAME}.0`, value: '' },
      ],
    ],
  ])('false: %s is no session (ssr treats an empty value as absent)', async (_label, cookies) => {
    expect(await needsAuthServer(cookies, NOW_MS, known)).toBe(false);
  });

  it.each([
    ['garbage that is not base64 JSON', [{ name: NAME, value: 'base64-@@@' }]],
    ['plain text', [{ name: NAME, value: 'garbage' }]],
    [
      'valid base64url of something that is not JSON',
      [{ name: NAME, value: `base64-${Buffer.from('not json').toString('base64url')}` }],
    ],
    ['JSON that is not an object', raw('"x"')],
    ['JSON null', raw('null')],
    ['an object without the three fields', whole({ access_token: 'x' })],
    ['an object with only two of them', whole({ access_token: 'x', refresh_token: 'y' })],
  ])(
    'true: %s is present but unreadable, so it is charged (it costs only a forger)',
    async (_label, cookies) => {
      expect(await needsAuthServer(cookies, NOW_MS, known)).toBe(true);
    },
  );
});

describe("needsAuthServer: the `expires_at` of the cookie, with the library's own truthiness and coercion", () => {
  const HS256 = jwt({ alg: 'HS256', typ: 'JWT' });

  it.each([
    ['the string "1" (coerced: expired)', '1'],
    ['a number in the past', 1],
    ['-1 (truthy, expired)', -1],
    ['a number within the 90 s refresh margin', NOW_S + 30],
    ['a numeric string within the margin', String(NOW_S + 30)],
  ])('true: %s makes the library refresh, a call to Auth', async (_label, expiresAt) => {
    // whatever the token looks like, even a strong one: the refresh comes first
    expect(await needsAuthServer(whole(session(ES256, expiresAt)), NOW_MS, known)).toBe(true);
    expect(await needsAuthServer(whole(session('x', expiresAt)), NOW_MS, known)).toBe(true);
    expect((await classify(whole(session('x', expiresAt)))).kind).toBe('upstream');
  });

  it.each([
    ['null', null],
    ['0', 0],
    ['false', false],
    ['an empty string', ''],
    ['Infinity (1e999 in the JSON)', 'infinity'],
    ['an unparseable string (NaN)', 'abc'],
  ])(
    'true: expires_at %s is "not expired" to the library, and an HS256 token is then a getUser call',
    async (label, expiresAt) => {
      const cookie =
        expiresAt === 'infinity'
          ? raw(`{"access_token":"${HS256}","refresh_token":"r","expires_at":1e999}`)
          : whole(session(HS256, expiresAt));
      expect(await needsAuthServer(cookie, NOW_MS, known), label).toBe(true);
    },
  );

  it('true: a kid-less token is a getUser call whatever expires_at is', async () => {
    const noKid = jwt({ alg: 'ES256' });
    for (const expiresAt of [null, 0, NOW_S + HOUR_S]) {
      expect(await needsAuthServer(whole(session(noKid, expiresAt)), NOW_MS, known)).toBe(true);
    }
  });

  it('false: a locally verifiable token stays local when expires_at is falsy (no refresh happens)', async () => {
    for (const expiresAt of [null, 0]) {
      expect(await needsAuthServer(whole(session(ES256, expiresAt)), NOW_MS, known)).toBe(false);
    }
  });
});

describe('needsAuthServer: the cookie is read exactly as @supabase/ssr reads it', () => {
  const localJson = JSON.stringify(session(ES256));
  const encoded = `base64-${Buffer.from(localJson).toString('base64url')}`;

  it('reads a raw JSON value and a base64- value alike', async () => {
    expect(await kindOf(raw(localJson))).toBe('local');
    expect(await kindOf([{ name: NAME, value: encoded }])).toBe('local');
    const expired = JSON.stringify(session(ES256, 1));
    expect(await kindOf(raw(expired))).toBe('upstream');
    expect(
      await kindOf([{ name: NAME, value: `base64-${Buffer.from(expired).toString('base64url')}` }]),
    ).toBe('upstream');
  });

  it('an EMPTY whole cookie falls through to the chunks, like combineChunks (it is falsy)', async () => {
    const half = Math.ceil(encoded.length / 2);
    const cookies = [
      { name: NAME, value: '' },
      { name: `${NAME}.0`, value: encoded.slice(0, half) },
      { name: `${NAME}.1`, value: encoded.slice(half) },
    ];
    expect(await kindOf(cookies)).toBe('local');
    // and the same chunks WITHOUT the empty whole cookie
    expect(await kindOf(cookies.slice(1))).toBe('local');
  });

  it('a non-empty whole cookie wins over the chunks, which are then never read', async () => {
    const cookies = [
      { name: NAME, value: encoded },
      {
        name: `${NAME}.0`,
        value: `base64-${Buffer.from(JSON.stringify(session('x', 1))).toString('base64url')}`,
      },
    ];
    expect(await kindOf(cookies)).toBe('local');
  });

  it('chunks stop at the first missing one: a hole cuts the value there, and the cut value is unreadable', async () => {
    const third = Math.ceil(encoded.length / 3);
    const withHole = [
      { name: `${NAME}.0`, value: encoded.slice(0, third) },
      { name: `${NAME}.2`, value: encoded.slice(third * 2) }, // .1 is missing: never read
    ];
    // only `.0` is read, which is a truncated base64 JSON: present but unreadable, so charged
    expect(await kindOf(withHole)).toBe('upstream');
    expect(await needsAuthServer(withHole, NOW_MS, known)).toBe(true);
  });

  it('a chunk past a complete value, or one named `.abc`, changes nothing', async () => {
    const cookies = [
      { name: `${NAME}.0`, value: encoded },
      { name: `${NAME}.2`, value: 'junk' },
      { name: `${NAME}.abc`, value: 'junk' },
      { name: `${NAME}.01`, value: 'junk' },
    ];
    expect(await kindOf(cookies)).toBe('local');
  });

  it('an empty chunk ends the chunks too', async () => {
    const third = Math.ceil(encoded.length / 3);
    const cookies = [
      { name: `${NAME}.0`, value: encoded.slice(0, third) },
      { name: `${NAME}.1`, value: '' },
      { name: `${NAME}.2`, value: encoded.slice(third) },
    ];
    expect(await kindOf(cookies)).toBe('upstream');
  });
});

describe('classifySession: what the library does with the token of an unexpired session', () => {
  const kinds = async (token: unknown, kids: KnownKids = known): Promise<SessionClass['kind']> =>
    kindOf(whole(session(token)), kids);

  it('HS256 (a symmetric key) is a getUser call', async () => {
    expect(await kinds(jwt({ alg: 'HS256' }))).toBe('upstream');
    expect(await kinds(jwt({ alg: 'HS512', kid: 'key-1' }))).toBe('upstream');
  });

  it('an asymmetric token with no kid is a getUser call', async () => {
    expect(await kinds(jwt({ alg: 'ES256' }))).toBe('upstream');
    expect(await kinds(jwt({ alg: 'ES256', kid: '' }))).toBe('upstream');
    expect(await kinds(jwt({ alg: 'RS256', kid: 5 }))).toBe('upstream');
  });

  it('an unknown kid is a JWKS fetch (and a getUser): charged, and the kid is kept for later', async () => {
    expect(await classify(whole(session(jwt({ alg: 'ES256', kid: 'never-seen' }))))).toEqual({
      kind: 'upstream',
      kid: 'never-seen',
    });
  });

  it('a known kid that has not been seen verifying for KID_FRESH_MS may have left the key cache: charged', async () => {
    const stale = new Map<string, KnownKid>([
      ['key-1', { alg: 'ES256', learnedAtMs: NOW_MS - KID_FRESH_MS }],
    ]);
    const almostStale = new Map<string, KnownKid>([
      ['key-1', { alg: 'ES256', learnedAtMs: NOW_MS - KID_FRESH_MS + 1 }],
    ]);
    expect(await kinds(ES256, stale)).toBe('upstream');
    expect(await kinds(ES256, almostStale)).toBe('local');
  });

  it.each([
    ['ES384', { alg: 'ES384', kid: 'key-1' }],
    ['ES512', { alg: 'ES512', kid: 'key-1' }],
    ['PS256', { alg: 'PS256', kid: 'key-1' }],
    ['none', { alg: 'none' }],
    ['no alg at all', { kid: 'key-1' }],
    ['an empty alg', { alg: '', kid: 'key-1' }],
    ['a numeric alg (a TypeError in the library)', { alg: 5, kid: 'key-1' }],
    ['an object alg', { alg: {}, kid: 'key-1' }],
    [
      'lowercase hs256 (not an HS* of the library, and not supported)',
      { alg: 'hs256', kid: 'key-1' },
    ],
  ])(
    'refuse: %s would make the library throw a plain error (a 500), so it is refused here',
    async (_label, header) => {
      expect(await kinds(jwt(header))).toBe('refuse');
      // and it is still "true" for the boolean question: it is not provably local
      expect(await needsAuthServer(whole(session(jwt(header))), NOW_MS, known)).toBe(true);
    },
  );

  it('refuse: a known kid asked to verify another algorithm than the one it verifies (importKey throws)', async () => {
    expect(await kinds(jwt({ alg: 'RS256', kid: 'key-1' }))).toBe('refuse');
  });

  it.each([
    ['not a string', 5],
    ['null', null],
    ['an object', {}],
    ['two parts', 'a.b'],
    ['four parts', 'a.b.c.d'],
    ['parts that are not base64url', '@@@@.@@@@.@@@@'],
    [
      'a header that is not JSON',
      `${Buffer.from('nope').toString('base64url')}.${b64url({ exp: NOW_S + HOUR_S })}.${SIGNATURE}`,
    ],
    [
      'a payload that is not JSON',
      `${b64url({ alg: 'ES256', kid: 'key-1' })}.${Buffer.from('nope').toString('base64url')}.${SIGNATURE}`,
    ],
    [
      'a header that is JSON null',
      `${b64url(null)}.${b64url({ exp: NOW_S + HOUR_S })}.${SIGNATURE}`,
    ],
    [
      'a payload that is JSON null',
      `${b64url({ alg: 'ES256', kid: 'key-1' })}.${b64url(null)}.${SIGNATURE}`,
    ],
    [
      'a header that is a JSON string',
      `${b64url('x')}.${b64url({ exp: NOW_S + HOUR_S })}.${SIGNATURE}`,
    ],
  ])(
    'refuse: an access token that is %s fails inside the library without a call to Auth',
    async (_label, token) => {
      expect(await kinds(token)).toBe('refuse');
    },
  );

  it.each([
    ['missing', {}],
    ['0', { exp: 0 }],
    ['in the past', { exp: NOW_S - 1 }],
    ['exactly now', { exp: NOW_S }],
  ])(
    'refuse: an `exp` that is %s is an AuthInvalidJwtError before any call',
    async (_label, payload) => {
      expect(await kinds(jwt({ alg: 'ES256', kid: 'key-1' }, payload))).toBe('refuse');
    },
  );

  it('an `exp` of another type is not mirrored: the token is judged by its algorithm and key as usual', async () => {
    expect(await kinds(jwt({ alg: 'ES256', kid: 'key-1' }, { exp: String(NOW_S + HOUR_S) }))).toBe(
      'local',
    );
    expect(await kinds(jwt({ alg: 'HS256' }, { exp: 'soon' }))).toBe('upstream');
  });

  it('the kid of an upstream or local verdict is reported, for the resolver to forget it on a failure', async () => {
    expect(await classify(whole(session(ES256)))).toEqual({
      kind: 'local',
      kid: 'key-1',
      alg: 'ES256',
    });
  });
});
