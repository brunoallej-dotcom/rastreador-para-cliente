// Unit tests of `scripts/create-ceo.ts`: the arguments, the call to the Auth Admin API (a fake) and
// what the script prints. The real thing against the local Supabase is `tests/int/create-ceo.int.test.ts`.
import { describe, expect, it, vi } from 'vitest';
import {
  createCeoAccount,
  EXIT,
  main,
  parseCeoArguments,
  type CeoAuthAdmin,
  type ScriptIo,
} from '../../scripts/create-ceo';

// Obviously fake, lowercase-only values (the secret-detection hook rightly ignores them).
const SECRET_KEY = 'fake-secret-key-for-unit-tests';
const FAKE_ENV = {
  APP_ORIGIN: 'http://localhost:3000',
  SUPABASE_URL: 'http://127.0.0.1:54321',
  SUPABASE_PUBLISHABLE_KEY: 'fake-publishable-key-for-unit-tests',
  SUPABASE_SECRET_KEY: SECRET_KEY,
  RATE_LIMIT_KEY_SECRET: 'unit-test-only-rate-limit-key-not-a-real-value',
};

const EMAIL = 'Chief.Executive@Empresa.test';
const NAME = 'Maria Souza';
const GENERATED = 'Gen3ratedTempPassw0rd';
const USER_ID = '33333333-3333-4333-8333-333333333333';
const ARGV = ['--email', EMAIL, '--name', NAME];

type CreateUserAnswer = Awaited<ReturnType<CeoAuthAdmin['createUser']>>;

function fakeAdmin(
  answer: CreateUserAnswer | Error = { data: { user: { id: USER_ID } }, error: null },
) {
  const createUser = vi.fn(() =>
    answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer),
  );
  return { authAdmin: { createUser } satisfies CeoAuthAdmin, createUser };
}

/** Runs `main` with captured output; returns what each stream got. */
async function run(
  argv: readonly string[],
  options: {
    answer?: CreateUserAnswer | Error;
    env?: Record<string, string | undefined>;
  } = {},
) {
  const { authAdmin, createUser } = fakeAdmin(options.answer);
  const createAuthAdmin = vi.fn(() => authAdmin);
  let stdout = '';
  let stderr = '';
  const io: ScriptIo = {
    stdout: { write: (text) => void (stdout += text) },
    stderr: { write: (text) => void (stderr += text) },
    env: options.env ?? FAKE_ENV,
    createAuthAdmin,
    generatePassword: () => GENERATED,
  };
  const code = await main(argv, io);
  return { code, stdout, stderr, createUser, createAuthAdmin };
}

const occurrences = (text: string, needle: string) => text.split(needle).length - 1;

describe('parseCeoArguments', () => {
  it('reads --email and --name, normalizing the e-mail (trim, NFC, lowercase) and the name (NFC, trim)', () => {
    const result = parseCeoArguments(['--email', '  Maria@Empresa.TEST ', '--name', '  Maria  ']);
    expect(result).toEqual({ ok: true, value: { email: 'maria@empresa.test', name: 'Maria' } });
  });

  it('accepts the --name=value form too', () => {
    expect(parseCeoArguments(['--email=a@b.test', '--name=CEO Teste'])).toEqual({
      ok: true,
      value: { email: 'a@b.test', name: 'CEO Teste' },
    });
  });

  it.each([
    ['no arguments', [], '--email is required'],
    ['no name', ['--email', 'a@b.test'], '--name is required'],
    ['no e-mail', ['--name', 'CEO'], '--email is required'],
    ['an invalid e-mail', ['--email', 'not-an-email', '--name', 'CEO'], '--email is not a valid'],
    [
      'an e-mail that is too long',
      ['--email', `${'a'.repeat(250)}@b.test`, '--name', 'CEO'],
      '--email is not a valid',
    ],
    ['an empty name', ['--email', 'a@b.test', '--name', '   '], '--name must be'],
    [
      'a name with a control character',
      ['--email', 'a@b.test', '--name', 'Ma\nria'],
      '--name must be',
    ],
    [
      'a name with an invisible character',
      ['--email', 'a@b.test', '--name', 'Ma​ria'],
      '--name must be',
    ],
    [
      'a name of 121 characters',
      ['--email', 'a@b.test', '--name', 'x'.repeat(121)],
      '--name must be',
    ],
    ['an unknown option', [...ARGV, '--role', 'ceo'], 'unknown or malformed'],
    ['a positional argument', [...ARGV, 'extra'], 'unknown or malformed'],
    ['an option without a value', ['--email'], 'unknown or malformed'],
  ])('refuses %s', (_label, argv, problem) => {
    const result = parseCeoArguments(argv);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.problem).toContain(problem);
  });

  it('accepts a name of exactly 120 characters', () => {
    expect(parseCeoArguments(['--email', 'a@b.test', '--name', 'x'.repeat(120)]).ok).toBe(true);
  });

  it('there is no way to ask for another role: --role is an unknown option, not a parameter', () => {
    expect(parseCeoArguments([...ARGV, '--role', 'client']).ok).toBe(false);
  });

  it('the messages never echo the values', () => {
    for (const argv of [
      ['--email', 'secret.value@x', '--name', 'CEO'],
      ['--email', 'a@b.test', '--name', `${'x'.repeat(130)}-sentinel`],
    ]) {
      const result = parseCeoArguments(argv);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.problem).not.toMatch(/sentinel|secret\.value/);
    }
  });
});

describe('createCeoAccount', () => {
  it('AC-31: creates the user with the password already set, the CEO role and the display name in app_metadata', async () => {
    const { authAdmin, createUser } = fakeAdmin();

    const result = await createCeoAccount(
      { authAdmin, generatePassword: () => GENERATED },
      { email: 'ceo@empresa.test', name: NAME },
    );

    expect(result).toEqual({ ok: true, value: { userId: USER_ID, temporaryPassword: GENERATED } });
    expect(createUser).toHaveBeenCalledTimes(1);
    // ONE call, with everything: the password is the baseline of mark_password_changed (ADR 0007)
    expect(createUser).toHaveBeenCalledWith({
      email: 'ceo@empresa.test',
      password: GENERATED,
      email_confirm: true,
      app_metadata: { role: 'ceo', display_name: NAME },
    });
  });

  it('puts nothing in user_metadata (the user could edit it) and uses no other Admin API call', async () => {
    const { authAdmin, createUser } = fakeAdmin();
    await createCeoAccount({ authAdmin }, { email: 'ceo@empresa.test', name: NAME });
    const [attributes] = createUser.mock.calls[0] as unknown as [Record<string, unknown>];
    expect(attributes).not.toHaveProperty('user_metadata');
    expect(Object.keys(authAdmin)).toEqual(['createUser']);
  });

  it('SEC-10: the password is a fresh temporary one (20 characters) when none is injected', async () => {
    const { authAdmin } = fakeAdmin();
    const result = await createCeoAccount({ authAdmin }, { email: 'ceo@empresa.test', name: NAME });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.temporaryPassword).toMatch(/^[A-Za-z0-9]{20}$/);
  });

  it('an e-mail that already has an account is email_taken, whatever the account is', async () => {
    const { authAdmin } = fakeAdmin({
      data: { user: null },
      error: { status: 422, code: 'email_exists' },
    });
    const result = await createCeoAccount({ authAdmin }, { email: 'ceo@empresa.test', name: NAME });
    expect(result).toEqual({ ok: false, error: { kind: 'email_taken' } });
  });

  it('any other refusal is an auth_error with ONLY its status and code', async () => {
    const { authAdmin } = fakeAdmin({
      data: { user: null },
      error: { status: 500, code: 'unexpected_failure' },
    });
    const result = await createCeoAccount({ authAdmin }, { email: 'ceo@empresa.test', name: NAME });
    expect(result).toEqual({
      ok: false,
      error: { kind: 'auth_error', status: 500, code: 'unexpected_failure' },
    });
  });

  it('an answer with neither an error nor a user is a failure, never a created CEO', async () => {
    const { authAdmin } = fakeAdmin({ data: { user: null }, error: null });
    const result = await createCeoAccount({ authAdmin }, { email: 'ceo@empresa.test', name: NAME });
    expect(result.ok).toBe(false);
  });
});

describe('main', () => {
  it('AC-31: creates the CEO and exits 0', async () => {
    const { code, createUser } = await run(ARGV);
    expect(code).toBe(EXIT.created);
    expect(createUser).toHaveBeenCalledWith({
      email: 'chief.executive@empresa.test',
      password: GENERATED,
      email_confirm: true,
      app_metadata: { role: 'ceo', display_name: NAME },
    });
  });

  it('prints the temporary password exactly once, on stdout, and nothing else there', async () => {
    const { stdout, stderr } = await run(ARGV);
    expect(occurrences(stdout, GENERATED)).toBe(1);
    expect(stdout).toBe(`temporary password: ${GENERATED}\n`);
    expect(stderr).not.toContain(GENERATED);
  });

  it('prints nothing else sensitive: no secret key, no e-mail, on either stream', async () => {
    const { stdout, stderr } = await run(ARGV);
    for (const text of [stdout, stderr]) {
      expect(text).not.toContain(SECRET_KEY);
      expect(text).not.toContain(FAKE_ENV.SUPABASE_PUBLISHABLE_KEY);
      expect(text).not.toContain(FAKE_ENV.RATE_LIMIT_KEY_SECRET);
      expect(text.toLowerCase()).not.toContain('empresa.test');
    }
    // the operator sees which environment is being changed, and the id of the new user
    expect(stderr).toContain('target: 127.0.0.1:54321');
    expect(stderr).toContain(USER_ID);
  });

  it('hands the Admin API factory the URL and the secret key of the environment, and only them', async () => {
    const { createAuthAdmin } = await run(ARGV);
    expect(createAuthAdmin).toHaveBeenCalledWith({
      url: FAKE_ENV.SUPABASE_URL,
      secretKey: SECRET_KEY,
    });
  });

  it('a usage problem is exit 2, prints the usage on stderr and calls nothing', async () => {
    const { code, stdout, stderr, createUser, createAuthAdmin } = await run([
      '--email',
      'a@b.test',
    ]);
    expect(code).toBe(EXIT.usage);
    expect(stdout).toBe('');
    expect(stderr).toContain('--name is required');
    expect(stderr).toContain('Usage: pnpm ceo:create');
    expect(createAuthAdmin).not.toHaveBeenCalled();
    expect(createUser).not.toHaveBeenCalled();
  });

  it('an invalid environment is exit 1, names the variables (never their values) and calls nothing', async () => {
    const { code, stdout, stderr, createAuthAdmin } = await run(ARGV, {
      env: { ...FAKE_ENV, SUPABASE_SECRET_KEY: undefined, SUPABASE_URL: 'not-a-url' },
    });
    expect(code).toBe(EXIT.failed);
    expect(stdout).toBe('');
    expect(stderr).toContain('SUPABASE_SECRET_KEY');
    expect(stderr).toContain('SUPABASE_URL');
    expect(stderr).not.toContain('not-a-url');
    expect(createAuthAdmin).not.toHaveBeenCalled();
  });

  it('an e-mail that already has an account is exit 3: nothing on stdout, no password, nothing about the account', async () => {
    const { code, stdout, stderr } = await run(ARGV, {
      answer: {
        data: { user: null },
        error: {
          status: 422,
          code: 'email_exists',
          message: 'A user with this email address has already been registered',
        } as never,
      },
    });
    expect(code).toBe(EXIT.emailTaken);
    expect(stdout).toBe('');
    expect(stderr).toContain('already exists; nothing was changed');
    // the password was generated before the call and is discarded: it is never shown
    expect(stderr).not.toContain(GENERATED);
    expect(stderr.toLowerCase()).not.toContain('empresa.test');
    expect(stderr).not.toContain('registered');
  });

  it('a refusal of the Auth server is exit 1 with its status and code, never its message', async () => {
    const { code, stdout, stderr } = await run(ARGV, {
      answer: {
        data: { user: null },
        error: {
          status: 500,
          code: 'unexpected_failure',
          message: 'Database error echoing chief.executive@empresa.test',
        } as never,
      },
    });
    expect(code).toBe(EXIT.failed);
    expect(stdout).toBe('');
    expect(stderr).toContain('status 500, code unexpected_failure');
    expect(stderr).not.toContain('Database error');
    expect(stderr.toLowerCase()).not.toContain('empresa.test');
    expect(stderr).not.toContain(GENERATED);
  });

  it('a failure that throws (transport, timeout) is exit 1 with a generic message: what it threw is never printed', async () => {
    const { code, stdout, stderr } = await run(ARGV, {
      answer: new TypeError(`fetch failed for ${EMAIL} with ${GENERATED} and ${SECRET_KEY}`),
    });
    expect(code).toBe(EXIT.failed);
    expect(stdout).toBe('');
    expect(stderr).toContain('nothing was confirmed');
    expect(stderr).not.toContain('fetch failed');
    for (const sensitive of [EMAIL, GENERATED, SECRET_KEY]) {
      expect(stderr).not.toContain(sensitive);
    }
  });

  it('the exit codes are distinct, and only 0 is success', () => {
    expect(new Set(Object.values(EXIT)).size).toBe(Object.values(EXIT).length);
    expect(EXIT.created).toBe(0);
  });
});
