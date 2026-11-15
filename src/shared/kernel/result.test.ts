import { describe, expect, it } from 'vitest';
import { err, ok, type Result } from './result';

function parsePositive(n: number): Result<number, string> {
  return n > 0 ? ok(n) : err('not positive');
}

describe('Result', () => {
  it('ok() builds the success branch', () => {
    expect(ok(42)).toEqual({ ok: true, value: 42 });
  });

  it('err() builds the failure branch', () => {
    expect(err('boom')).toEqual({ ok: false, error: 'boom' });
  });

  it('narrows on the ok discriminant', () => {
    const success = parsePositive(1);
    const failure = parsePositive(-1);
    expect(success.ok && success.value).toBe(1);
    expect(!failure.ok && failure.error).toBe('not positive');
  });
});
