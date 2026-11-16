import { describe, expect, it } from 'vitest';
import { assertOriginAllowed, isUnsafeMethod, resolveAllowedOrigins } from './origin';

const APP_ORIGIN = 'https://app.example.com';

describe('resolveAllowedOrigins', () => {
  it('is only APP_ORIGIN outside previews', () => {
    expect(resolveAllowedOrigins({ APP_ORIGIN })).toEqual([APP_ORIGIN]);
    expect(
      resolveAllowedOrigins({
        APP_ORIGIN,
        VERCEL_ENV: 'production',
        VERCEL_URL: 'app-abc123.vercel.app',
        VERCEL_BRANCH_URL: 'app-git-x.vercel.app',
      }),
    ).toEqual([APP_ORIGIN]);
    expect(
      resolveAllowedOrigins({ APP_ORIGIN, VERCEL_ENV: 'development', VERCEL_URL: 'x.vercel.app' }),
    ).toEqual([APP_ORIGIN]);
  });

  it('adds the deployment URLs (https) in preview', () => {
    expect(
      resolveAllowedOrigins({
        APP_ORIGIN,
        VERCEL_ENV: 'preview',
        VERCEL_URL: 'app-abc123.vercel.app',
        VERCEL_BRANCH_URL: 'app-git-feature-team.vercel.app',
      }),
    ).toEqual([
      APP_ORIGIN,
      'https://app-abc123.vercel.app',
      'https://app-git-feature-team.vercel.app',
    ]);
  });

  it('adds only the URLs that are set', () => {
    expect(
      resolveAllowedOrigins({
        APP_ORIGIN,
        VERCEL_ENV: 'preview',
        VERCEL_URL: 'app-abc123.vercel.app',
      }),
    ).toEqual([APP_ORIGIN, 'https://app-abc123.vercel.app']);
    expect(resolveAllowedOrigins({ APP_ORIGIN, VERCEL_ENV: 'preview' })).toEqual([APP_ORIGIN]);
  });
});

describe('isUnsafeMethod', () => {
  it.each(['GET', 'HEAD', 'OPTIONS', 'get'])('%s is safe', (method) => {
    expect(isUnsafeMethod(method)).toBe(false);
  });
  it.each(['POST', 'PUT', 'PATCH', 'DELETE', 'post', 'TRACE', 'CONNECT'])(
    '%s is unsafe',
    (method) => {
      expect(isUnsafeMethod(method)).toBe(true);
    },
  );
});

describe('assertOriginAllowed', () => {
  const request = (origin?: string) =>
    new Request('https://app.example.com/api/v1/x', {
      method: 'POST',
      headers: origin === undefined ? {} : { Origin: origin },
    });

  it('passes for an exact match', () => {
    expect(() => assertOriginAllowed(request(APP_ORIGIN), [APP_ORIGIN])).not.toThrow();
  });

  it.each([
    undefined,
    'null',
    '',
    'https://app.example.com.evil.test',
    'https://evil.test',
    'http://app.example.com',
    'https://app.example.com:8443',
    'https://app.example.com/',
    'https://APP.example.com',
    `${APP_ORIGIN}, https://evil.test`,
  ])('refuses Origin %j', (origin) => {
    expect(() => assertOriginAllowed(request(origin), [APP_ORIGIN])).toThrow(
      expect.objectContaining({ code: 'ORIGIN_NOT_ALLOWED' }) as Error,
    );
  });

  it('refuses everything when no origin is allowed', () => {
    expect(() => assertOriginAllowed(request(APP_ORIGIN), [])).toThrow();
  });
});
