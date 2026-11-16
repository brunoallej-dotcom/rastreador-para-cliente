import { describe, expect, it } from 'vitest';
import {
  createFetchWithTimeout,
  UPSTREAM_TIMEOUT_MS,
  type FetchFunction,
} from './fetch-with-timeout';

/** A fetch that never answers; it only rejects when its signal aborts, like a hung connection. */
const hangingFetch: FetchFunction = (_input, init) =>
  new Promise<Response>((_resolve, reject) => {
    const signal = init?.signal;
    if (!signal) return;
    // `reason` is a DOMException (TimeoutError) or whatever the caller aborted with: what fetch does.
    // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
    const abort = () => reject(signal.reason);
    if (signal.aborted) abort();
    else signal.addEventListener('abort', abort, { once: true });
  });

const FAST_TIMEOUT_MS = 20;

describe('createFetchWithTimeout', () => {
  it('SEC-19: the upstream timeout is 5 seconds', () => {
    expect(UPSTREAM_TIMEOUT_MS).toBe(5000);
  });

  it('E-21: aborts a request that does not answer within the timeout', async () => {
    const guarded = createFetchWithTimeout(FAST_TIMEOUT_MS, hangingFetch);
    await expect(guarded('http://localhost/never')).rejects.toMatchObject({ name: 'TimeoutError' });
  });

  it('passes the response of a request that answers in time', async () => {
    const guarded = createFetchWithTimeout(FAST_TIMEOUT_MS, () =>
      Promise.resolve(new Response('ok')),
    );
    const response = await guarded('http://localhost/fast');
    expect(await response.text()).toBe('ok');
  });

  it('keeps the signal of the caller working', async () => {
    const guarded = createFetchWithTimeout(UPSTREAM_TIMEOUT_MS, hangingFetch);
    const controller = new AbortController();
    const pending = guarded('http://localhost/never', { signal: controller.signal });
    controller.abort(new Error('caller gave up'));
    await expect(pending).rejects.toThrow('caller gave up');
  });

  it('forwards the other request options untouched', async () => {
    let seen: RequestInit | undefined;
    const guarded = createFetchWithTimeout(UPSTREAM_TIMEOUT_MS, (_input, init) => {
      seen = init;
      return Promise.resolve(new Response(null));
    });
    await guarded('http://localhost/x', { method: 'POST', headers: { a: 'b' } });
    expect(seen?.method).toBe('POST');
    expect(seen?.headers).toEqual({ a: 'b' });
    expect(seen?.signal).toBeInstanceOf(AbortSignal);
  });
});
