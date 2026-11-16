// What login and logout write to the logs (spec §3.10, SEC-16): the events exist, they carry the
// request id and an internal id or an HMAC, and never the e-mail, the password, a token or the
// cookie. The process logger is replaced by one that captures its lines; everything else is real.
import { describe, expect, it, vi } from 'vitest';
import type * as LoggerModule from '@/shared/observability/logger';
import { POST as loginRoute } from '@/app/api/v1/auth/login/route';
import { POST as logoutRoute } from '@/app/api/v1/auth/logout/route';
import { hmacSubject } from '@/shared/http/rate-limit/subject-hmac';
import {
  ceoAal2Client,
  createClient,
  createClientUser,
  disableAccount,
  uniqueEmail,
} from '../helpers/fixtures';
import { createCookieStore, invoke } from '../helpers/http';

const logged = vi.hoisted(() => ({ lines: [] as string[] }));

vi.mock('@/shared/observability/logger', async (importOriginal) => {
  const original = await importOriginal<typeof LoggerModule>();
  const logger = original.createLogger({
    level: 'trace',
    destination: {
      write(chunk: string) {
        logged.lines.push(chunk);
      },
    },
  });
  return { ...original, getLogger: () => logger };
});

const records = () => logged.lines.map((line) => JSON.parse(line) as Record<string, unknown>);
const events = (name: string) => records().filter((record) => record['event'] === name);

const login = (email: string, password: string, cookies = createCookieStore()) =>
  invoke(loginRoute, { method: 'POST', path: '/auth/login', body: { email, password }, cookies });

describe('auth events in the logs', () => {
  it('SEC-16: auth.login.failed carries an HMAC of the normalized e-mail and a generic reason, never the e-mail or the password', async () => {
    const email = uniqueEmail('Failing');
    const password = 'Wrong-Password-For-Logs-1';
    logged.lines.length = 0;

    const response = await login(`  ${email.toUpperCase()} `, password);

    expect(response.status).toBe(401);
    const [failed] = events('auth.login.failed');
    expect(failed).toBeDefined();
    expect(failed).toMatchObject({
      level: 'warn',
      reason: 'invalid_credentials',
      requestId: response.headers.get('x-request-id'),
    });
    const secret = process.env.RATE_LIMIT_KEY_SECRET ?? '';
    // the HMAC is over the NORMALIZED e-mail: every spelling of it is the same account...
    const logKey = hmacSubject(secret, 'log-fingerprint-v1');
    expect(failed?.['accountHash']).toBe(hmacSubject(logKey, email.toLowerCase()));
    // ...and it is NOT the value the rate limiter stores in the database for that account
    expect(failed?.['accountHash']).not.toBe(hmacSubject(secret, email.toLowerCase()));

    const everything = logged.lines.join('\n');
    expect(everything).not.toContain(password);
    expect(everything.toLowerCase()).not.toContain(email.toLowerCase());
    expect(everything.toLowerCase()).not.toContain(email.split('@')[0]?.toLowerCase());
  });

  it('SEC-12: a wrong password, an unknown e-mail and a disabled account log the same generic reason', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });
    const disabled = await createClientUser({ clientId: client.id });
    await disableAccount(await ceoAal2Client(), disabled.id);
    logged.lines.length = 0;

    await login(user.email, `${user.password}-wrong`);
    await login(uniqueEmail('nobody'), user.password);
    await login(disabled.email, disabled.password);

    const reasons = events('auth.login.failed').map((record) => record['reason']);
    expect(reasons).toEqual(['invalid_credentials', 'invalid_credentials', 'invalid_credentials']);
  });

  it('SEC-16: auth.login.succeeded carries the user id only; auth.logout the same; no secrets anywhere', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });
    const jar = createCookieStore();
    logged.lines.length = 0;

    const loginResponse = await login(user.email, user.password, jar);
    const cookieHeader = jar.header() ?? '';
    const logoutResponse = await invoke(logoutRoute, {
      method: 'POST',
      path: '/auth/logout',
      cookies: jar,
    });

    expect(loginResponse.status).toBe(200);
    expect(logoutResponse.status).toBe(204);

    const [succeeded] = events('auth.login.succeeded');
    expect(succeeded).toMatchObject({
      level: 'info',
      userId: user.id,
      requestId: loginResponse.headers.get('x-request-id'),
    });
    expect(Object.keys(succeeded ?? {}).sort()).toEqual(
      ['event', 'level', 'msg', 'requestId', 'time', 'userId'].sort(),
    );
    const [loggedOut] = events('auth.logout');
    expect(loggedOut).toMatchObject({
      userId: user.id,
      requestId: logoutResponse.headers.get('x-request-id'),
    });

    const everything = logged.lines.join('\n');
    expect(everything).not.toContain(user.password);
    expect(everything.toLowerCase()).not.toContain(user.email.toLowerCase());
    expect(everything).not.toContain('__Host-rt-session');
    expect(everything).not.toMatch(/eyJ[\w-]+\.[\w-]+\./);
    // nothing of the session cookie value either
    const cookieValue = cookieHeader.split(';')[0]?.split('=')[1] ?? '';
    expect(cookieValue.length).toBeGreaterThan(20);
    expect(everything).not.toContain(cookieValue.slice(0, 40));
  });
});
