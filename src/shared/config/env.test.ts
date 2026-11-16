import { afterEach, describe, expect, it, vi } from 'vitest';
import { EnvValidationError, parseEnv } from './env';

const SECRET_KEY_VALUE = 'sentinel-supabase-secret-key-do-not-leak';
const PUBLISHABLE_KEY_VALUE = 'sentinel-publishable-key-do-not-leak';
const HMAC_VALUE = 'sentinel-hmac-key-value-with-more-than-32-chars';

const validSource = {
  APP_ORIGIN: 'http://localhost:3000',
  SUPABASE_URL: 'http://127.0.0.1:54321',
  SUPABASE_PUBLISHABLE_KEY: PUBLISHABLE_KEY_VALUE,
  SUPABASE_SECRET_KEY: SECRET_KEY_VALUE,
  RATE_LIMIT_KEY_SECRET: HMAC_VALUE,
};

function failureOf(source: Record<string, string | undefined>): EnvValidationError {
  try {
    parseEnv(source);
  } catch (error) {
    if (error instanceof EnvValidationError) return error;
    throw error;
  }
  throw new Error('expected parseEnv to throw');
}

describe('parseEnv', () => {
  it('returns the validated variables', () => {
    expect(parseEnv(validSource)).toEqual({
      APP_ORIGIN: 'http://localhost:3000',
      SUPABASE_URL: 'http://127.0.0.1:54321',
      SUPABASE_PUBLISHABLE_KEY: PUBLISHABLE_KEY_VALUE,
      RATE_LIMIT_KEY_SECRET: HMAC_VALUE,
      LOG_LEVEL: 'info',
    });
  });

  it('does not include the Supabase secret key in the returned object', () => {
    const env = parseEnv(validSource);
    expect(Object.keys(env)).not.toContain('SUPABASE_SECRET_KEY');
    expect(JSON.stringify(env)).not.toContain(SECRET_KEY_VALUE);
  });

  it('throws when SUPABASE_URL is missing, naming the variable and no secret value', () => {
    const { SUPABASE_URL: _omitted, ...source } = validSource;
    const error = failureOf(source);
    expect(error.message).toContain('SUPABASE_URL');
    for (const value of [SECRET_KEY_VALUE, PUBLISHABLE_KEY_VALUE, HMAC_VALUE]) {
      expect(error.message).not.toContain(value);
    }
  });

  it('requires the Supabase secret key to be present', () => {
    const { SUPABASE_SECRET_KEY: _omitted, ...source } = validSource;
    const error = failureOf(source);
    expect(error.message).toContain('SUPABASE_SECRET_KEY');
  });

  it('never echoes the value of an invalid variable', () => {
    const error = failureOf({ ...validSource, RATE_LIMIT_KEY_SECRET: 'too-short-secret' });
    expect(error.message).toContain('RATE_LIMIT_KEY_SECRET');
    expect(error.message).not.toContain('too-short-secret');
    expect(error.message).not.toContain(SECRET_KEY_VALUE);
  });

  it('lists every problem at once', () => {
    const error = failureOf({});
    expect(error.problems.length).toBeGreaterThanOrEqual(5);
    expect(error.message).toContain('APP_ORIGIN');
    expect(error.message).toContain('SUPABASE_PUBLISHABLE_KEY');
  });

  it.each([
    ['a path', 'https://app.example.com/dashboard'],
    ['a trailing slash', 'https://app.example.com/'],
    ['a non-http scheme', 'ftp://app.example.com'],
    ['a bare host', 'app.example.com'],
    ['an empty string', ''],
  ])('rejects APP_ORIGIN with %s', (_label, origin) => {
    const error = failureOf({ ...validSource, APP_ORIGIN: origin });
    expect(error.message).toContain('APP_ORIGIN');
  });

  it('accepts an https origin with port', () => {
    const env = parseEnv({ ...validSource, APP_ORIGIN: 'https://app.example.com:8443' });
    expect(env.APP_ORIGIN).toBe('https://app.example.com:8443');
  });

  it('defaults LOG_LEVEL to info and accepts the allowed levels', () => {
    expect(parseEnv(validSource).LOG_LEVEL).toBe('info');
    expect(parseEnv({ ...validSource, LOG_LEVEL: 'debug' }).LOG_LEVEL).toBe('debug');
  });

  it('rejects an unknown LOG_LEVEL', () => {
    const error = failureOf({ ...validSource, LOG_LEVEL: 'verbose' });
    expect(error.message).toContain('LOG_LEVEL');
    expect(error.message).not.toContain('verbose');
  });

  it('rejects a RATE_LIMIT_KEY_SECRET shorter than 32 characters', () => {
    const error = failureOf({ ...validSource, RATE_LIMIT_KEY_SECRET: 'x'.repeat(31) });
    expect(error.message).toContain('RATE_LIMIT_KEY_SECRET');
  });

  it('leaves the Vercel variables unset when they are absent or empty', () => {
    const env = parseEnv({ ...validSource, VERCEL_ENV: '', VERCEL_URL: '', VERCEL_BRANCH_URL: '' });
    expect(env.VERCEL_ENV).toBeUndefined();
    expect(env.VERCEL_URL).toBeUndefined();
    expect(env.VERCEL_BRANCH_URL).toBeUndefined();
    expect(parseEnv(validSource).VERCEL_URL).toBeUndefined();
  });

  it('accepts the Vercel preview variables', () => {
    const env = parseEnv({
      ...validSource,
      VERCEL_ENV: 'preview',
      VERCEL_URL: 'app-abc123-team.vercel.app',
      VERCEL_BRANCH_URL: 'app-git-feature-team.vercel.app',
    });
    expect(env.VERCEL_ENV).toBe('preview');
    expect(env.VERCEL_URL).toBe('app-abc123-team.vercel.app');
    expect(env.VERCEL_BRANCH_URL).toBe('app-git-feature-team.vercel.app');
  });

  it.each([
    ['VERCEL_ENV', 'staging'],
    ['VERCEL_URL', 'https://app.vercel.app'],
    ['VERCEL_URL', 'app.vercel.app/path'],
    ['VERCEL_BRANCH_URL', 'evil.test, other.test'],
  ])('rejects %s=%s without echoing the value', (name, value) => {
    const error = failureOf({ ...validSource, [name]: value });
    expect(error.message).toContain(name);
    expect(error.message).not.toContain(value);
  });
});

describe('getEnv', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it('reads process.env once and memoizes the result', async () => {
    for (const [key, value] of Object.entries(validSource)) vi.stubEnv(key, value);
    const { getEnv } = await import('./env');
    const first = getEnv();
    vi.stubEnv('LOG_LEVEL', 'error');
    expect(getEnv()).toBe(first);
    expect(first.LOG_LEVEL).toBe('info');
  });

  it('throws when process.env is incomplete', async () => {
    for (const key of Object.keys(validSource)) vi.stubEnv(key, undefined);
    const { getEnv, EnvValidationError: Fresh } = await import('./env');
    expect(() => getEnv()).toThrow(Fresh);
  });
});
