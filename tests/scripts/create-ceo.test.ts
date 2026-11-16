// Unit tests of `scripts/create-ceo.ts`: the arguments, the guards of the command, the call to the Auth
// Admin API (a fake) and what the script prints. The real thing against the local Supabase is
// `tests/int/create-ceo.int.test.ts`.
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
const URL_VALUE = 'http://127.0.0.1:54321';
const HOST = '127.0.0.1:54321';
/** What the script needs, and nothing more: it is not the app's environment. */
const FAKE_ENV = { SUPABASE_URL: URL_VALUE, SUPABASE_SECRET_KEY: SECRET_KEY };

const EMAIL = 'Chief.Executive@Empresa.test';
const NAME = 'Maria Souza';
const GENERATED = 'Gen3ratedTempPassw0rd';
const USER_ID = '33333333-3333-4333-8333-333333333333';
const ARGV = ['--target', HOST, '--email', EMAIL, '--name', NAME];
const ZERO_WIDTH_SPACE = String.fromCodePoint(0x200b);

type CreateUserAnswer = Awaited<ReturnType<CeoAuthAdmin['createUser']>>;

function fakeAdmin(
  answer: CreateUserAnswer | Error = { data: { user: { id: USER_ID } }, error: null },
) {
  const createUser = vi.fn(() =>
    answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer),
  );
  return { authAdmin: { createUser } satisfies CeoAuthAdmin, createUser };
}

type RunOptions = {
  answer?: CreateUserAnswer | Error;
  env?: Record<string, string | undefined>;
  stdoutIsTTY?: boolean;
  /** What each env file path holds; a path not listed does not exist. */
  files?: Record<string, string>;
  readEnvFile?: ScriptIo['readEnvFile'];
};

/** Runs `main` with captured output; returns what each stream got. */
async function run(argv: readonly string[], options: RunOptions = {}) {
  const { authAdmin, createUser } = fakeAdmin(options.answer);
  const createAuthAdmin = vi.fn((_env: { url: string; secretKey: string }) => authAdmin);
  const readEnvFile = vi.fn(
    options.readEnvFile ?? ((path: string) => options.files?.[path] ?? undefined),
  );
  let stdout = '';
  let stderr = '';
  const io: ScriptIo = {
    stdout: { write: (text) => void (stdout += text) },
    stderr: { write: (text) => void (stderr += text) },
    env: options.env ?? FAKE_ENV,
    stdoutIsTTY: options.stdoutIsTTY ?? true,
    readEnvFile,
    createAuthAdmin,
    generatePassword: () => GENERATED,
  };
  const code = await main(argv, io);
  return { code, stdout, stderr, createUser, createAuthAdmin, readEnvFile };
}

const occurrences = (text: string, needle: string) => text.split(needle).length - 1;

describe('parseCeoArguments', () => {
  it('reads the arguments, normalizing the e-mail (trim, NFC, lowercase) and the name (NFC, trim)', () => {
    const result = parseCeoArguments([
      '--target',
      'Abcd.Supabase.Co',
      '--email',
      '  Maria@Empresa.TEST ',
      '--name',
      '  Maria  ',
    ]);
    expect(result).toEqual({
      ok: true,
      value: {
        email: 'maria@empresa.test',
        name: 'Maria',
        target: 'abcd.supabase.co',
        envFile: { path: '.env.local', explicit: false },
        allowNonTty: false,
      },
    });
  });

  it('accepts the --name=value form, an explicit env file and --allow-non-tty', () => {
    expect(
      parseCeoArguments([
        '--target=h.test',
        '--email=a@b.test',
        '--name=CEO Teste',
        '--env-file=staging.env',
        '--allow-non-tty',
      ]),
    ).toEqual({
      ok: true,
      value: {
        email: 'a@b.test',
        name: 'CEO Teste',
        target: 'h.test',
        envFile: { path: 'staging.env', explicit: true },
        allowNonTty: true,
      },
    });
  });

  it.each([
    ['no arguments', [], '--email is required'],
    ['no name', ['--target', 'h.test', '--email', 'a@b.test'], '--name is required'],
    ['no e-mail', ['--target', 'h.test', '--name', 'CEO'], '--email is required'],
    ['no target', ['--email', 'a@b.test', '--name', 'CEO'], '--target is required'],
    [
      'an empty target',
      ['--target', '  ', '--email', 'a@b.test', '--name', 'CEO'],
      '--target must be',
    ],
    [
      'an invalid e-mail',
      ['--target', 'h.test', '--email', 'not-an-email', '--name', 'CEO'],
      '--email is not a valid',
    ],
    [
      'an e-mail that is too long',
      ['--target', 'h.test', '--email', `${'a'.repeat(250)}@b.test`, '--name', 'CEO'],
      '--email is not a valid',
    ],
    [
      'an empty name',
      ['--target', 'h.test', '--email', 'a@b.test', '--name', '   '],
      '--name must be',
    ],
    [
      'a name with a control character',
      ['--target', 'h.test', '--email', 'a@b.test', '--name', 'Ma\nria'],
      '--name must be',
    ],
    [
      'a name with an invisible character',
      ['--target', 'h.test', '--email', 'a@b.test', '--name', `Ma${ZERO_WIDTH_SPACE}ria`],
      '--name must be',
    ],
    [
      'a name of 121 characters',
      ['--target', 'h.test', '--email', 'a@b.test', '--name', 'x'.repeat(121)],
      '--name must be',
    ],
    [
      'an empty env file path',
      ['--target', 'h.test', '--email', 'a@b.test', '--name', 'CEO', '--env-file', ''],
      '--env-file must not be empty',
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
    expect(
      parseCeoArguments(['--target', 'h.test', '--email', 'a@b.test', '--name', 'x'.repeat(120)])
        .ok,
    ).toBe(true);
  });

  it('there is no way to ask for another role: --role is an unknown option, not a parameter', () => {
    expect(parseCeoArguments([...ARGV, '--role', 'client']).ok).toBe(false);
  });

  it('the messages never echo the values', () => {
    for (const argv of [
      ['--target', 'h.test', '--email', 'secret.value@x', '--name', 'CEO'],
      ['--target', 'h.test', '--email', 'a@b.test', '--name', `${'x'.repeat(130)}-sentinel`],
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

describe('main: the output', () => {
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

  it('F-43: stdout is the temporary password and NOTHING else: one line, no label', async () => {
    const { stdout, stderr } = await run(ARGV);
    expect(stdout).toBe(`${GENERATED}\n`);
    expect(occurrences(stdout, GENERATED)).toBe(1);
    // the labels go to stderr, which never carries the password
    expect(stderr).toContain('temporary password');
    expect(stderr).not.toContain(GENERATED);
  });

  it('prints nothing else sensitive: no secret key, no e-mail, on either stream', async () => {
    const { stdout, stderr } = await run(ARGV);
    for (const text of [stdout, stderr]) {
      expect(text).not.toContain(SECRET_KEY);
      expect(text.toLowerCase()).not.toContain('empresa.test');
    }
    // the operator sees which environment is being changed, and the id of the new user
    expect(stderr).toContain(`target: ${HOST}`);
    expect(stderr).toContain(USER_ID);
  });

  it('F-41: needs only SUPABASE_URL and SUPABASE_SECRET_KEY: none of the app variables', async () => {
    const { code } = await run(ARGV, { env: FAKE_ENV });
    expect(code).toBe(EXIT.created);
  });

  it('hands the Admin API factory the URL and the secret key of the environment, and only them', async () => {
    const { createAuthAdmin } = await run(ARGV);
    expect(createAuthAdmin).toHaveBeenCalledWith({ url: URL_VALUE, secretKey: SECRET_KEY });
  });

  it('a usage problem is exit 2, prints the usage on stderr and calls nothing', async () => {
    const { code, stdout, stderr, createUser, createAuthAdmin, readEnvFile } = await run([
      '--email',
      'a@b.test',
    ]);
    expect(code).toBe(EXIT.usage);
    expect(stdout).toBe('');
    expect(stderr).toContain('--name is required');
    expect(stderr).toContain('Usage: pnpm -s ceo:create');
    expect(readEnvFile).not.toHaveBeenCalled();
    expect(createAuthAdmin).not.toHaveBeenCalled();
    expect(createUser).not.toHaveBeenCalled();
  });

  it('the exit codes are distinct, and only 0 is success', () => {
    expect(new Set(Object.values(EXIT)).size).toBe(Object.values(EXIT).length);
    expect(EXIT.created).toBe(0);
  });
});

describe('main: who may run it and where the password may go (F-43)', () => {
  it('refuses to run when CI is set: exit 2, no file read, no call', async () => {
    const { code, stdout, stderr, createAuthAdmin, readEnvFile } = await run(ARGV, {
      env: { ...FAKE_ENV, CI: 'true' },
    });
    expect(code).toBe(EXIT.usage);
    expect(stdout).toBe('');
    expect(stderr).toContain('CI is set');
    expect(readEnvFile).not.toHaveBeenCalled();
    expect(createAuthAdmin).not.toHaveBeenCalled();
  });

  it('an empty CI is not CI', async () => {
    const { code } = await run(ARGV, { env: { ...FAKE_ENV, CI: '' } });
    expect(code).toBe(EXIT.created);
  });

  it('refuses a stdout that is not a terminal, unless --allow-non-tty is given: exit 2, no call', async () => {
    const refused = await run(ARGV, { stdoutIsTTY: false });
    expect(refused.code).toBe(EXIT.usage);
    expect(refused.stdout).toBe('');
    expect(refused.stderr).toContain('not a terminal');
    expect(refused.stderr).toContain('--allow-non-tty');
    expect(refused.createAuthAdmin).not.toHaveBeenCalled();
    expect(refused.readEnvFile).not.toHaveBeenCalled();

    const allowed = await run([...ARGV, '--allow-non-tty'], { stdoutIsTTY: false });
    expect(allowed.code).toBe(EXIT.created);
    expect(allowed.stdout).toBe(`${GENERATED}\n`);
  });
});

describe('main: the target (F-41)', () => {
  it('the host of SUPABASE_URL must be the --target, or it is exit 2 and nothing is called', async () => {
    const { code, stdout, stderr, createAuthAdmin, createUser } = await run([
      '--target',
      'other.supabase.co',
      '--email',
      EMAIL,
      '--name',
      NAME,
    ]);
    expect(code).toBe(EXIT.usage);
    expect(stdout).toBe('');
    // the operator is told which host the environment really names (a host is not a secret)
    expect(stderr).toContain('--target does not match');
    expect(stderr).toContain(HOST);
    expect(stderr).not.toContain(SECRET_KEY);
    expect(createAuthAdmin).not.toHaveBeenCalled();
    expect(createUser).not.toHaveBeenCalled();
  });

  it('compares the host WITH its port, and without regard to case', async () => {
    const withoutPort = await run(['--target', '127.0.0.1', '--email', EMAIL, '--name', NAME]);
    expect(withoutPort.code).toBe(EXIT.usage);

    const env = { SUPABASE_URL: 'https://Abcd.Supabase.CO', SUPABASE_SECRET_KEY: SECRET_KEY };
    const matching = await run(['--target', 'ABCD.supabase.co', '--email', EMAIL, '--name', NAME], {
      env,
    });
    expect(matching.code).toBe(EXIT.created);
    expect(matching.stderr).toContain('target: abcd.supabase.co');
  });

  it('refuses http: for a host that is not loopback, even when it is the target', async () => {
    const { code, stderr, createAuthAdmin } = await run(
      ['--target', 'db.empresa.test', '--email', EMAIL, '--name', NAME],
      { env: { SUPABASE_URL: 'http://db.empresa.test', SUPABASE_SECRET_KEY: SECRET_KEY } },
    );
    expect(code).toBe(EXIT.usage);
    expect(stderr).toContain('not loopback');
    expect(createAuthAdmin).not.toHaveBeenCalled();
  });

  it.each(['http://localhost:54321', 'http://127.0.0.1:54321', 'http://[::1]:54321'])(
    'accepts http: for the loopback host %s',
    async (supabaseUrl) => {
      const target = new URL(supabaseUrl).host;
      const { code } = await run(['--target', target, '--email', EMAIL, '--name', NAME], {
        env: { SUPABASE_URL: supabaseUrl, SUPABASE_SECRET_KEY: SECRET_KEY },
      });
      expect(code).toBe(EXIT.created);
    },
  );

  it('accepts https: for any host named as the target', async () => {
    const { code } = await run(['--target', 'abcd.supabase.co', '--email', EMAIL, '--name', NAME], {
      env: { SUPABASE_URL: 'https://abcd.supabase.co', SUPABASE_SECRET_KEY: SECRET_KEY },
    });
    expect(code).toBe(EXIT.created);
  });
});

describe('main: the environment and its env file (F-41, M5)', () => {
  const FILE = `# the target environment\nSUPABASE_URL="${URL_VALUE}"\nSUPABASE_SECRET_KEY=${SECRET_KEY}\n`;

  it('says that no env file was found, and works from the shell alone', async () => {
    const { code, stderr, readEnvFile } = await run(ARGV);
    expect(code).toBe(EXIT.created);
    expect(readEnvFile).toHaveBeenCalledWith('.env.local');
    expect(stderr).toContain('env file: none (.env.local not found)');
  });

  it('reads .env.local by default, and says it did', async () => {
    const { code, stderr, createAuthAdmin } = await run(ARGV, {
      env: {},
      files: { '.env.local': FILE },
    });
    expect(code).toBe(EXIT.created);
    expect(stderr).toContain('env file: .env.local');
    expect(createAuthAdmin).toHaveBeenCalledWith({ url: URL_VALUE, secretKey: SECRET_KEY });
  });

  it('--env-file reads that file instead, and says so', async () => {
    const { code, stderr, readEnvFile } = await run([...ARGV, '--env-file', 'staging.env'], {
      env: {},
      files: { 'staging.env': FILE },
    });
    expect(code).toBe(EXIT.created);
    expect(readEnvFile).toHaveBeenCalledTimes(1);
    expect(readEnvFile).toHaveBeenCalledWith('staging.env');
    expect(stderr).toContain('env file: staging.env');
  });

  it('an env file that was asked for and does not exist is exit 2', async () => {
    const { code, stderr, createAuthAdmin } = await run([...ARGV, '--env-file', 'missing.env'], {
      env: {},
    });
    expect(code).toBe(EXIT.usage);
    expect(stderr).toContain('missing.env does not exist');
    expect(createAuthAdmin).not.toHaveBeenCalled();
  });

  it('an env file that cannot be read is exit 1', async () => {
    const { code, stderr, createAuthAdmin } = await run(ARGV, {
      env: {},
      readEnvFile: () => {
        throw new Error('EACCES: the path of a secret file');
      },
    });
    expect(code).toBe(EXIT.failed);
    expect(stderr).toContain('could not be read');
    expect(stderr).not.toContain('EACCES');
    expect(createAuthAdmin).not.toHaveBeenCalled();
  });

  it('a variable already set in the shell wins over the file, and the pair still comes from ONE place', async () => {
    const other = 'http://127.0.0.1:55555';
    const { code, createAuthAdmin } = await run(ARGV, {
      env: { SUPABASE_URL: URL_VALUE, SUPABASE_SECRET_KEY: 'fake-shell-key-for-unit-tests' },
      files: { '.env.local': FILE.replace(URL_VALUE, other) },
    });
    expect(code).toBe(EXIT.created);
    expect(createAuthAdmin).toHaveBeenCalledWith({
      url: URL_VALUE,
      secretKey: 'fake-shell-key-for-unit-tests',
    });
  });

  it.each([
    ['URL from the shell, key from the file', { SUPABASE_URL: URL_VALUE }, 'SUPABASE_SECRET_KEY'],
    ['key from the shell, URL from the file', { SUPABASE_SECRET_KEY: SECRET_KEY }, 'SUPABASE_URL'],
  ])(
    'F-41: %s is refused (exit 2): a key must not meet the URL of another place',
    async (_label, shell, _fromFile) => {
      const { code, stdout, stderr, createAuthAdmin, createUser } = await run(ARGV, {
        env: shell,
        files: { '.env.local': FILE },
      });
      expect(code).toBe(EXIT.usage);
      expect(stdout).toBe('');
      expect(stderr).toContain('refusing to pair a key with a URL from another place');
      expect(stderr).toMatch(/comes from the (shell|env file)/);
      // sources, never values
      expect(stderr).not.toContain(SECRET_KEY);
      expect(stderr).not.toContain(URL_VALUE);
      expect(createAuthAdmin).not.toHaveBeenCalled();
      expect(createUser).not.toHaveBeenCalled();
    },
  );

  it('an invalid environment is exit 1, names the variables (never their values) and calls nothing', async () => {
    const { code, stdout, stderr, createAuthAdmin } = await run(ARGV, {
      env: { SUPABASE_URL: 'not-a-url' },
    });
    expect(code).toBe(EXIT.failed);
    expect(stdout).toBe('');
    expect(stderr).toContain('SUPABASE_SECRET_KEY');
    expect(stderr).toContain('SUPABASE_URL');
    expect(stderr).not.toContain('not-a-url');
    expect(createAuthAdmin).not.toHaveBeenCalled();
  });

  it('a URL that is neither http: nor https: is an invalid environment', async () => {
    const { code, stderr } = await run(ARGV, {
      env: { SUPABASE_URL: 'ftp://127.0.0.1:54321', SUPABASE_SECRET_KEY: SECRET_KEY },
    });
    expect(code).toBe(EXIT.failed);
    expect(stderr).toContain('SUPABASE_URL');
  });
});

describe('main: what goes wrong at the Auth server', () => {
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
});
