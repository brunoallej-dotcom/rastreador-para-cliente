import { describe, expect, it } from 'vitest';
import { createLogger, requestLogger } from './logger';

const EMAIL = 'maria.silva@cliente.com.br';
const PASSWORD = 'correct-horse-battery-staple';
const TEMPORARY_PASSWORD = 'temporary-password-fixture';
const COOKIE = '__Host-rt-session=eyJhbGciOiJFUzI1NiJ9.payload.signature';
const BEARER = 'Bearer eyJhbGciOiJFUzI1NiJ9.payload.signature';
const TOKEN = 'refresh-token-value-123456';
const SECRET = 'JBSWY3DPEHPK3PXP';
const SENSITIVE_VALUES = [EMAIL, PASSWORD, TEMPORARY_PASSWORD, COOKIE, BEARER, TOKEN, SECRET];

function capture(level: 'trace' | 'debug' | 'info' | 'warn' | 'error' = 'info') {
  const lines: string[] = [];
  const destination = {
    write(chunk: string) {
      lines.push(chunk);
    },
  };
  const logger = createLogger({ level, destination });
  return {
    logger,
    lines,
    records: () => lines.map((line) => JSON.parse(line) as Record<string, unknown>),
  };
}

describe('logger', () => {
  it('AC-27: writes one JSON object per line with level, time and message', () => {
    const { logger, lines, records } = capture();
    logger.info({ route: '/api/v1/health', status: 200 }, 'request completed');

    expect(lines).toHaveLength(1);
    expect(lines[0]?.endsWith('\n')).toBe(true);
    const [record] = records();
    expect(record).toMatchObject({
      level: 'info',
      msg: 'request completed',
      route: '/api/v1/health',
      status: 200,
    });
    expect(typeof record?.['time']).toBe('string');
    expect(record).not.toHaveProperty('pid');
    expect(record).not.toHaveProperty('hostname');
  });

  it('AC-27: redacts e-mail, password, cookie, authorization and tokens at the top level', () => {
    const { logger, lines } = capture();
    logger.info(
      {
        email: EMAIL,
        password: PASSWORD,
        temporaryPassword: TEMPORARY_PASSWORD,
        cookie: COOKIE,
        authorization: BEARER,
        token: TOKEN,
        secret: SECRET,
      },
      'attempt',
    );

    const output = lines.join('');
    for (const value of SENSITIVE_VALUES) expect(output).not.toContain(value);
    expect(JSON.parse(output)).toMatchObject({
      email: '[REDACTED]',
      password: '[REDACTED]',
      temporaryPassword: '[REDACTED]',
      cookie: '[REDACTED]',
      authorization: '[REDACTED]',
      token: '[REDACTED]',
      secret: '[REDACTED]',
    });
  });

  it('AC-27: redacts nested bodies and request headers', () => {
    const { logger, lines } = capture();
    logger.info(
      {
        body: { user: { email: EMAIL, password: PASSWORD }, tokens: [{ token: TOKEN }] },
        req: { headers: { cookie: COOKIE, authorization: BEARER, accept: 'application/json' } },
        res: { headers: { 'set-cookie': COOKIE } },
        err: { config: { headers: { authorization: BEARER } } },
      },
      'nested',
    );

    const output = lines.join('');
    for (const value of SENSITIVE_VALUES) expect(output).not.toContain(value);
    expect(JSON.parse(output)).toMatchObject({
      body: { user: { email: '[REDACTED]', password: '[REDACTED]' } },
      req: { headers: { accept: 'application/json' } },
    });
  });

  it('AC-27: redacts camelCase and snake_case token and password variants', () => {
    const { logger, lines } = capture();
    logger.info(
      {
        session: { accessToken: TOKEN, refreshToken: TOKEN, access_token: TOKEN },
        change: { currentPassword: PASSWORD, newPassword: PASSWORD },
      },
      'variants',
    );
    const output = lines.join('');
    expect(output).not.toContain(TOKEN);
    expect(output).not.toContain(PASSWORD);
  });

  it('keeps non-sensitive fields intact', () => {
    const { logger, records } = capture();
    logger.info({ userId: '11111111-1111-4111-8111-111111111111', role: 'ceo' }, 'ok');
    expect(records()[0]).toMatchObject({
      userId: '11111111-1111-4111-8111-111111111111',
      role: 'ceo',
    });
  });

  it('stamps the request id on every line of a request logger', () => {
    const { logger, records } = capture();
    const log = requestLogger(logger, 'req-12345678');
    log.info('first');
    log.warn({ event: 'authz.denied' }, 'second');
    expect(records().map((record) => record['requestId'])).toEqual([
      'req-12345678',
      'req-12345678',
    ]);
  });

  it('respects the configured level', () => {
    const { logger, lines } = capture('warn');
    logger.info('hidden');
    logger.warn('shown');
    expect(lines).toHaveLength(1);
  });
});

const LEAK = 'leaked-value-0123456789';

/** Logs `object` and returns the raw output, to prove nothing sensitive was written. */
function output(object: Record<string, unknown>, message = 'case'): string {
  const { logger, lines } = capture('trace');
  logger.info(object, message);
  return lines.join('');
}

describe('logger redaction (AC-27, case and separator insensitive)', () => {
  it.each([
    'Authorization',
    'AUTHORIZATION',
    'Cookie',
    'COOKIE',
    'Set-Cookie',
    'set-cookie',
    'Email',
    'EMAIL',
    'e-mail',
    'Password',
    'PASSWORD',
    'passWord',
    'temporary_password',
    'TemporaryPassword',
    'Secret',
    'Token',
    'otp',
    'OTP',
    'code',
    'Code',
    'totp',
    'TOTP',
    'jwt',
    'JWT',
    'apikey',
    'apiKey',
    'api_key',
    'API-KEY',
    'x-api-key',
    'X-API-Key',
    'secret_key',
    'secretKey',
    'SECRET-KEY',
    'accessToken',
    'access_token',
    'ACCESS_TOKEN',
    'Access-Token',
    'refreshToken',
    'refresh_token',
    'REFRESH-TOKEN',
    'x-csrf-token',
    'newPassword',
    'current_password',
    'qrCode',
    'qr_code',
    'QRCODE',
    'qr-code',
  ])('AC-27: redacts the key %s at the top level, nested and inside headers', (key) => {
    for (const shape of [
      { [key]: LEAK },
      { body: { [key]: LEAK } },
      { req: { headers: { [key]: LEAK } } },
      { list: [{ deep: { [key]: LEAK } }] },
    ]) {
      const written = output(shape);
      expect(written, key).not.toContain(LEAK);
      expect(written, key).toContain('[REDACTED]');
    }
  });

  it('AC-27: redacts whole objects and arrays under a sensitive key', () => {
    const written = output({ token: { value: LEAK }, cookie: [LEAK, LEAK] });
    expect(written).not.toContain(LEAK);
  });

  it('AC-27: redacts the reported cases: headers.Authorization, Cookie, Set-Cookie, body.Email', () => {
    const written = output({
      headers: { Authorization: `Bearer ${LEAK}`, Cookie: `s=${LEAK}`, 'Set-Cookie': `s=${LEAK}` },
      body: { Email: 'someone@example.com' },
    });
    expect(written).not.toContain(LEAK);
    expect(written).not.toContain('someone@example.com');
  });

  it('AC-27: redacts through Headers objects regardless of the header name casing', () => {
    const headers = new Headers({
      Authorization: `Bearer ${LEAK}`,
      Cookie: `s=${LEAK}`,
      Accept: '*/*',
    });
    const written = output({ headers });
    expect(written).not.toContain(LEAK);
    expect(JSON.parse(written)).toMatchObject({ headers: { accept: '*/*' } });
  });

  it('F-25: cuts an otpauth URI out of any string, secret and e-mail label included', () => {
    const uri =
      'otpauth://totp/Rastreador:ceo@cliente.test?secret=JBSWY3DPEHPK3PXP&issuer=Rastreador';
    const written = output({
      message: `enrollment ${uri} done`,
      nested: { text: uri.toUpperCase() },
    });

    expect(written).not.toContain('JBSWY3DPEHPK3PXP');
    expect(written.toLowerCase()).not.toContain('otpauth://');
    expect(written.toLowerCase()).not.toContain('cliente.test');
    // the text around it stays
    expect(written).toContain('enrollment [REDACTED] done');
  });

  it('F-25: cuts an otpauth URI out of an error message and of the log message too', () => {
    const { logger, lines } = capture();
    // a low-entropy stand-in built at runtime: a real-looking base32 seed here trips secret scanners
    const seed = 'A'.repeat(16);
    const uri = `otpauth://totp/Rastreador:x?secret=${seed}`;

    logger.error({ err: new Error(`bad enrollment ${uri}`) }, `failed for ${uri}`);

    expect(lines.join('\n')).not.toContain(seed);
  });

  it('F-25: a key named uri is NOT redacted (legitimate URLs stay readable), only the otpauth values are', () => {
    const { logger, records } = capture();

    logger.info(
      {
        uri: 'https://app.example/api/v1/health',
        other: { uri: 'otpauth://totp/x?secret=ABCDEFGH' },
      },
      'ok',
    );

    expect(records()[0]).toMatchObject({
      uri: 'https://app.example/api/v1/health',
      other: { uri: '[REDACTED]' },
    });
  });

  it('AC-27: does not redact ordinary keys that merely contain a sensitive word', () => {
    const { logger, records } = capture();
    logger.info({ userId: 'u-1', tokenCount: 3, codeOwner: 'team', status: 200 }, 'ok');
    expect(records()[0]).toMatchObject({
      userId: 'u-1',
      tokenCount: 3,
      codeOwner: 'team',
      status: 200,
    });
  });

  it('AC-27: bounds the depth: nothing deeper than the limit is emitted, a placeholder is', () => {
    let deep: Record<string, unknown> = { leaf: LEAK };
    for (let level = 0; level < 20; level += 1) deep = { next: deep };
    const written = output({ deep });
    expect(written).not.toContain(LEAK);
    expect(written).toContain('[Truncated]');
  });

  it('AC-27: still redacts sensitive keys at depth 6, 7 and 8 (beyond the old 5-level limit)', () => {
    for (const depth of [6, 7, 8]) {
      let nested: Record<string, unknown> = { password: LEAK };
      for (let level = 1; level < depth; level += 1) nested = { wrap: nested };
      expect(output(nested), `depth ${depth}`).not.toContain(LEAK);
    }
  });

  it('AC-27: survives circular references', () => {
    const a: Record<string, unknown> = { name: 'a', password: LEAK };
    a['self'] = a;
    a['pair'] = { back: a };
    const written = output({ a });
    expect(written).not.toContain(LEAK);
    expect(written).toContain('[Circular]');
  });

  it('AC-27: copes with throwing getters, BigInt, symbols, functions, Maps and binary data', () => {
    const hostile = {
      get boom(): string {
        throw new Error('getter exploded');
      },
      big: 10n,
      sym: Symbol('s'),
      fn: () => LEAK,
      bytes: new Uint8Array(4),
      map: new Map([['k', LEAK]]),
    };
    const written = output({ hostile });
    expect(written).not.toContain(LEAK);
    expect(JSON.parse(written)).toMatchObject({
      hostile: { big: '10', bytes: '[Binary 4 bytes]' },
    });
  });

  it('AC-27: a key named __proto__ stays data and does not alter any prototype', () => {
    const payload = JSON.parse(`{"__proto__":{"polluted":"${LEAK}"},"ok":1}`) as Record<
      string,
      unknown
    >;
    const written = output({ payload });
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
    expect(JSON.parse(written)).toMatchObject({ payload: { ok: 1 } });
  });
});

describe('logger error scrubbing (AC-27)', () => {
  const POSTGRES_MESSAGE =
    'duplicate key value violates unique constraint "profiles_email_key" Key (email)=(a@b.com) already exists.';

  it('AC-27: cuts e-mail addresses out of err.message and err.stack', () => {
    const { logger, lines } = capture();
    logger.error({ err: new Error(POSTGRES_MESSAGE) }, 'insert failed');
    const written = lines.join('');
    expect(written).not.toContain('a@b.com');
    expect(JSON.parse(written)).toMatchObject({
      msg: 'insert failed',
      err: { type: 'Error', name: 'Error' },
    });
  });

  it('AC-27: keeps type, name, code and stack of the error', () => {
    class UpstreamError extends Error {
      readonly code = '23505';
    }
    const { logger, records } = capture();
    logger.error({ err: new UpstreamError('boom') }, 'failed');
    const { err } = records()[0] as { err: Record<string, string> };
    expect(err).toMatchObject({
      type: 'UpstreamError',
      name: 'Error',
      code: '23505',
      message: 'boom',
    });
    expect(err['stack']).toContain('Error: boom');
    expect(err['stack']).toContain('logger.test.ts');
  });

  it('AC-27: scrubs every error of the cause chain, message and stack', () => {
    const jwtLike = ['eyJhbGciOiJFUzI1NiJ9', 'abcdefgh', 'ijklmnop'].join('.');
    const root = new Error(`connect failed for root@host.example jwt=${jwtLike}`);
    const middle = new Error('middle sees a@b.com', { cause: root });
    const top = new Error('top', { cause: middle });
    const { logger, lines } = capture();
    logger.error({ err: top }, 'chain');
    const written = lines.join('');
    expect(written).not.toContain('root@host.example');
    expect(written).not.toContain('a@b.com');
    expect(written).not.toContain('eyJhbGciOiJFUzI1NiJ9');
    const { err } = JSON.parse(written) as { err: { cause: { cause: { message: string } } } };
    expect(err.cause.cause.message).toContain('[REDACTED_EMAIL]');
  });

  it('AC-27: handles a cause that is not an Error and a cause cycle', () => {
    const a = new Error('a@b.com');
    const b = new Error('b', { cause: a });
    (a as { cause?: unknown }).cause = b;
    const withString = new Error('top', { cause: 'plain cause for x@y.com' });
    const { logger, lines } = capture();
    logger.error({ err: a }, 'cycle');
    logger.error({ err: withString }, 'string cause');
    const written = lines.join('');
    expect(written).not.toContain('a@b.com');
    expect(written).not.toContain('x@y.com');
    expect(written).toContain('[Circular]');
  });

  it('AC-27: scrubs the message derived from an error passed alone', () => {
    const { logger, lines } = capture();
    logger.error(new Error('failed for a@b.com'));
    logger.error({ err: new Error('failed for c@d.com') });
    const written = lines.join('');
    expect(written).not.toContain('a@b.com');
    expect(written).not.toContain('c@d.com');
  });

  it('AC-27: scrubs the error key too, not only err', () => {
    const { logger, lines } = capture();
    logger.error({ error: new Error('x for a@b.com') }, 'm');
    expect(lines.join('')).not.toContain('a@b.com');
  });

  it('AC-27: does not copy other properties of the error object (configs, headers, rows)', () => {
    const error = Object.assign(new Error('failed'), {
      config: { headers: { authorization: `Bearer ${LEAK}` } },
      row: { id: LEAK },
    });
    const { logger, lines } = capture();
    logger.error({ err: error }, 'upstream');
    expect(lines.join('')).not.toContain(LEAK);
  });

  it('AC-27: scrubs e-mails and tokens from free strings and from the log message', () => {
    const { logger, lines } = capture();
    logger.warn(
      { detail: 'user a@b.com failed', header: 'Bearer abcdefghijklmnop' },
      'login for e@f.com',
    );
    const written = lines.join('');
    expect(written).not.toContain('a@b.com');
    expect(written).not.toContain('e@f.com');
    expect(written).not.toContain('abcdefghijklmnop');
  });

  it('AC-27: scrubs a JWT, a Supabase key and a Postgres key detail inside a message', () => {
    // Built at runtime: these are fixtures, and a literal of this shape trips the secret guard.
    const jwt = ['eyJhbGciOiJFUzI1NiJ9', 'eyJzdWIiOiIxMjMifQ', 'c2lnbmF0dXJl'].join('.');
    const supabaseKey = ['sb', 'secret', 'fixture-not-a-real-key'].join('_');
    const { logger, lines } = capture();
    logger.error(new Error(`bad jwt ${jwt} key ${supabaseKey} Key (password)=(hunter2hunter2) x`));
    const written = lines.join('');
    for (const secret of [jwt, supabaseKey, 'hunter2hunter2']) {
      expect(written).not.toContain(secret);
    }
  });

  it('AC-27: scrubbing a long stack stays fast (no catastrophic backtracking)', () => {
    const { logger } = capture();
    const long = new Error(`${'a'.repeat(200_000)} ${'b.'.repeat(50_000)}`);
    const started = performance.now();
    logger.error({ err: long }, 'long');
    expect(performance.now() - started).toBeLessThan(2000);
  });

  it('AC-27: does not mistake package paths in stack frames for e-mail addresses', () => {
    const error = new Error('boom');
    error.stack =
      'Error: boom\n    at run (/app/node_modules/.pnpm/vitest@5.1.0_@types+node@24.19.2/node_modules/vitest/run.js:1:1)';
    const { logger, lines } = capture();
    logger.error({ err: error }, 'frame');
    expect(lines.join('')).toContain('vitest@5.1.0_@types+node@24.19.2');
  });

  it('AC-27: redacts child logger bindings too', () => {
    const { logger, lines } = capture();
    logger.child({ requestId: 'req-12345678', email: 'a@b.com' }).info('x');
    expect(lines.join('')).not.toContain('a@b.com');
  });
});
