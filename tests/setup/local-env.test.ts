import { describe, expect, it } from 'vitest';
import { parseEnv } from '@/shared/config/env';
import { buildLocalEnv, LocalEnvError, loadLocalEnv, parseStatusEnv } from './local-env';

const SECRET_KEY_VALUE = 'sentinel-local-secret-key-do-not-print';
const PUBLISHABLE_KEY_VALUE = 'sentinel-local-publishable-key-do-not-print';
const LEGACY_SECRET_VALUE = 'sentinel-legacy-service-role-do-not-print';
const LEGACY_PUBLIC_VALUE = 'sentinel-legacy-anon-do-not-print';
const ALL_SENTINELS = [
  SECRET_KEY_VALUE,
  PUBLISHABLE_KEY_VALUE,
  LEGACY_SECRET_VALUE,
  LEGACY_PUBLIC_VALUE,
];

const STATUS_OUTPUT = [
  'API_URL="http://127.0.0.1:54321"',
  'DB_URL="postgresql://postgres:postgres@127.0.0.1:54322/postgres"',
  `PUBLISHABLE_KEY="${PUBLISHABLE_KEY_VALUE}"`,
  `SECRET_KEY="${SECRET_KEY_VALUE}"`,
  'STUDIO_URL="http://127.0.0.1:54323"',
].join('\n');

function messageOf(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    if (error instanceof LocalEnvError) return error.message;
    throw error;
  }
  throw new Error('expected the action to throw');
}

describe('parseStatusEnv', () => {
  it('parses quoted KEY="value" lines', () => {
    expect(parseStatusEnv(STATUS_OUTPUT)).toMatchObject({
      API_URL: 'http://127.0.0.1:54321',
      PUBLISHABLE_KEY: PUBLISHABLE_KEY_VALUE,
      SECRET_KEY: SECRET_KEY_VALUE,
    });
  });

  it('accepts unquoted values, CRLF and values containing "="', () => {
    expect(parseStatusEnv('A=plain\r\nB="x=y=="\r\n')).toEqual({ A: 'plain', B: 'x=y==' });
  });

  it('ignores blank lines, prose and lowercase names', () => {
    const parsed = parseStatusEnv(
      '\nStopped services: [a b]\nnot_a_var="x"\nAPI_URL="http://localhost:1"',
    );
    expect(parsed).toEqual({ API_URL: 'http://localhost:1' });
  });
});

describe('buildLocalEnv', () => {
  it('maps API_URL / PUBLISHABLE_KEY / SECRET_KEY and adds the fixed test values', () => {
    const env = buildLocalEnv(parseStatusEnv(STATUS_OUTPUT));
    expect(env).toMatchObject({
      APP_ORIGIN: 'http://localhost:3000',
      SUPABASE_URL: 'http://127.0.0.1:54321',
      SUPABASE_PUBLISHABLE_KEY: PUBLISHABLE_KEY_VALUE,
      SUPABASE_SECRET_KEY: SECRET_KEY_VALUE,
    });
    expect(env.RATE_LIMIT_KEY_SECRET.length).toBeGreaterThanOrEqual(32);
  });

  it('gives every run its own rate-limit key, so counters never carry over between runs', () => {
    const status = parseStatusEnv(STATUS_OUTPUT);
    const first = buildLocalEnv(status).RATE_LIMIT_KEY_SECRET;
    const second = buildLocalEnv(status).RATE_LIMIT_KEY_SECRET;
    expect(first).toMatch(/^[0-9a-f]{48}$/);
    expect(second).not.toBe(first);
  });

  it('produces a set the app env schema accepts', () => {
    expect(() => parseEnv(buildLocalEnv(parseStatusEnv(STATUS_OUTPUT)))).not.toThrow();
  });

  it('falls back to ANON_KEY and SERVICE_ROLE_KEY (older CLI output)', () => {
    const env = buildLocalEnv({
      API_URL: 'http://localhost:54321',
      ANON_KEY: LEGACY_PUBLIC_VALUE,
      SERVICE_ROLE_KEY: LEGACY_SECRET_VALUE,
    });
    expect(env.SUPABASE_PUBLISHABLE_KEY).toBe(LEGACY_PUBLIC_VALUE);
    expect(env.SUPABASE_SECRET_KEY).toBe(LEGACY_SECRET_VALUE);
    expect(env.SUPABASE_URL).toBe('http://localhost:54321');
  });

  it('prefers the new key names when both generations are present', () => {
    const env = buildLocalEnv({
      API_URL: 'http://127.0.0.1:54321',
      PUBLISHABLE_KEY: PUBLISHABLE_KEY_VALUE,
      ANON_KEY: LEGACY_PUBLIC_VALUE,
      SECRET_KEY: SECRET_KEY_VALUE,
      SERVICE_ROLE_KEY: LEGACY_SECRET_VALUE,
    });
    expect(env.SUPABASE_PUBLISHABLE_KEY).toBe(PUBLISHABLE_KEY_VALUE);
    expect(env.SUPABASE_SECRET_KEY).toBe(SECRET_KEY_VALUE);
  });

  it.each([
    ['a hosted project', 'https://abcdefghijklmnop.supabase.co'],
    ['a LAN address', 'http://192.168.0.10:54321'],
    ['a lookalike host', 'http://127.0.0.1.evil.example'],
    ['userinfo that hides the real host', 'http://127.0.0.1@evil.example:54321'],
    ['localhost as a subdomain', 'http://localhost.evil.example'],
    ['an IPv6 address', 'http://[::1]:54321'],
  ])('rejects %s without printing any key value', (_label, url) => {
    const message = messageOf(() =>
      buildLocalEnv({
        API_URL: url,
        PUBLISHABLE_KEY: PUBLISHABLE_KEY_VALUE,
        SECRET_KEY: SECRET_KEY_VALUE,
        ANON_KEY: LEGACY_PUBLIC_VALUE,
        SERVICE_ROLE_KEY: LEGACY_SECRET_VALUE,
      }),
    );
    expect(message).toContain('Refusing');
    for (const sentinel of ALL_SENTINELS) expect(message).not.toContain(sentinel);
  });

  it('rejects an unparseable URL without printing key values', () => {
    const message = messageOf(() =>
      buildLocalEnv({
        API_URL: 'not a url',
        PUBLISHABLE_KEY: PUBLISHABLE_KEY_VALUE,
        SECRET_KEY: SECRET_KEY_VALUE,
      }),
    );
    expect(message).toContain('API_URL');
    for (const sentinel of ALL_SENTINELS) expect(message).not.toContain(sentinel);
  });

  it('names the missing variables and nothing else', () => {
    const message = messageOf(() =>
      buildLocalEnv({ API_URL: 'http://127.0.0.1:54321', PUBLISHABLE_KEY: PUBLISHABLE_KEY_VALUE }),
    );
    expect(message).toContain('SECRET_KEY');
    expect(message).not.toContain('PUBLISHABLE_KEY (or ANON_KEY)');
    for (const sentinel of ALL_SENTINELS) expect(message).not.toContain(sentinel);
  });
});

describe('loadLocalEnv', () => {
  it('parses the CLI output and builds the env', async () => {
    const env = await loadLocalEnv(() => Promise.resolve(STATUS_OUTPUT));
    expect(env.SUPABASE_URL).toBe('http://127.0.0.1:54321');
  });

  it('turns a CLI failure into a hint, never echoing its output', async () => {
    const failing = () => Promise.reject(new Error(`boom ${SECRET_KEY_VALUE}`));
    await expect(loadLocalEnv(failing)).rejects.toThrow(LocalEnvError);
    await expect(loadLocalEnv(failing)).rejects.not.toThrow(SECRET_KEY_VALUE);
  });
});
