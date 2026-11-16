import { describe, expect, it } from 'vitest';
import { ServiceUnavailableError } from '@/shared/kernel';
import { isUpstreamUnavailable, upstreamFailure } from './upstream-errors';

describe('isUpstreamUnavailable', () => {
  it.each([
    ['an auth-js retryable fetch error', { name: 'AuthRetryableFetchError', status: 0 }],
    ['a 5xx from the Auth server', { name: 'AuthApiError', status: 502 }],
    ['the Auth server throttling us (429)', { name: 'AuthApiError', status: 429 }],
    [
      'a postgrest-js transport failure (status 0)',
      { message: 'TypeError: fetch failed', status: 0 },
    ],
    ['a postgrest-js 5xx', { code: 'PGRST000', status: 503 }],
    ['our 5 s abort', new DOMException('The operation timed out', 'TimeoutError')],
    ['an aborted request', new DOMException('aborted', 'AbortError')],
    ['the TypeError fetch throws on a network failure', new TypeError('fetch failed')],
  ])('is true for %s', (_label, error) => {
    expect(isUpstreamUnavailable(error)).toBe(true);
  });

  it.each([
    [
      'invalid credentials (400)',
      { name: 'AuthApiError', status: 400, code: 'invalid_credentials' },
    ],
    ['a 401', { name: 'AuthApiError', status: 401 }],
    ['a policy denial (403)', { code: '42501', status: 403 }],
    ['a plain Error', new Error('boom')],
    ['a TypeError that is not a network failure', new TypeError('x is not a function')],
    ['null', null],
    ['a string', 'fetch failed'],
  ])('is false for %s', (_label, error) => {
    expect(isUpstreamUnavailable(error)).toBe(false);
  });
});

describe('isUpstreamUnavailable with the status next to a postgrest-js error', () => {
  const postgrestError = { message: 'TypeError: fetch failed', code: '' };

  it('treats status 0 and 5xx as unavailable, and a 4xx as a verdict', () => {
    expect(isUpstreamUnavailable(postgrestError, 0)).toBe(true);
    expect(isUpstreamUnavailable({ code: 'PGRST000' }, 503)).toBe(true);
    expect(isUpstreamUnavailable({ code: 'over_request_rate_limit' }, 429)).toBe(true);
    expect(isUpstreamUnavailable({ code: '42501' }, 403)).toBe(false);
    expect(isUpstreamUnavailable({ code: 'PGRST301' }, 401)).toBe(false);
  });
});

describe('upstreamFailure', () => {
  it('E-21: wraps an unavailable upstream in ServiceUnavailableError, keeping the cause', () => {
    const cause = { name: 'AuthRetryableFetchError', status: 0 };
    const failure = upstreamFailure('sign in', cause);
    expect(failure).toBeInstanceOf(ServiceUnavailableError);
    expect(failure.cause).toBe(cause);
    // the message is for logs only; the client-safe `detail` stays unset
    expect((failure as ServiceUnavailableError).detail).toBeUndefined();
  });

  it('turns anything else into a plain Error (500, never a client-visible detail)', () => {
    const failure = upstreamFailure('read principal', { status: 400, message: 'secret detail' });
    expect(failure).not.toBeInstanceOf(ServiceUnavailableError);
    expect(failure.message).toBe('read principal failed unexpectedly');
  });
});
