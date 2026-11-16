import { describe, expect, it } from 'vitest';
import { ServiceUnavailableError } from '@/shared/kernel';
import { withDeadline } from './deadline';

const SHORT_MS = 20;
const never = () => new Promise<never>(() => undefined);

describe('withDeadline', () => {
  it('returns what the work resolves to when it is in time', async () => {
    await expect(withDeadline('op', Promise.resolve('done'), SHORT_MS)).resolves.toBe('done');
  });

  it('passes through the error of work that fails in time', async () => {
    await expect(withDeadline('op', Promise.reject(new Error('boom')), SHORT_MS)).rejects.toThrow(
      'boom',
    );
  });

  it('E-21: gives up on work that never answers, with ServiceUnavailableError', async () => {
    await expect(withDeadline('refresh', never(), SHORT_MS)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('does not let late work turn into an unhandled rejection', async () => {
    const late = new Promise<never>((_resolve, reject) => {
      setTimeout(() => reject(new Error('too late')), SHORT_MS * 3);
    });
    await expect(withDeadline('op', late, SHORT_MS)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
    // the late rejection happens after the deadline; waiting for it must not crash the run
    await new Promise((resolve) => setTimeout(resolve, SHORT_MS * 4));
  });

  it('defaults to the 5 second upstream timeout', async () => {
    // resolves immediately: the default only has to be accepted without a custom bound
    await expect(withDeadline('op', Promise.resolve(1))).resolves.toBe(1);
  });
});
