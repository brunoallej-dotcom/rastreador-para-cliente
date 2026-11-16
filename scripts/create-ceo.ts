// `pnpm -s ceo:create --target <host> --email <e-mail> --name <name>`: creates the account of a CEO
// (spec §3.4, RF-14).
//
// A MANUAL operation, run by a person at a terminal against ONE environment. The secret key of that
// environment lets the script reach the Auth Admin API; no endpoint of the API creates or promotes a
// CEO, and this is the only way in.
//
//   pnpm -s ceo:create --target abcd.supabase.co --email ceo@empresa.com --name "Maria Souza"
//
// `-s` (silent) matters: without it pnpm prints its own banner on stdout, and stdout is reserved for
// the temporary password.
//
// What it does, in this order:
//   1. reads the arguments and refuses anything invalid before a single call. It refuses to run at all
//      when `CI` is set, and when stdout is not a terminal unless `--allow-non-tty` says the operator
//      knows where the password is going (a pipe to a clipboard tool, say): a password written to a log
//      by accident is a leaked password;
//   2. builds the environment it needs, and ONLY it: `SUPABASE_URL` and `SUPABASE_SECRET_KEY`, from the
//      shell and from an env file (`--env-file`, default `.env.local`). A variable already set in the
//      shell wins over the file, and the two must come from the same place: a URL from the shell and a
//      key from the file (or the other way around) is how a key of one project meets the URL of
//      another, so it is refused;
//   3. requires `--target` to be the host of `SUPABASE_URL`, so the operator names the environment they
//      mean in the command itself, and refuses `http:` unless the host is loopback;
//   4. generates a temporary password (20 characters from the CSPRNG, `generateTemporaryPassword`);
//   5. creates the user through `auth.admin.createUser` WITH that password in the same call (ADR 0007:
//      it is the baseline `mark_password_changed()` compares against), with `app_metadata` role `ceo`
//      and the display name. The database trigger builds the profile from `app_metadata` in the same
//      transaction, with `must_change_password = true`, so the CEO is born with CHANGE_PASSWORD and
//      ENROLL_MFA pending (AC-31), and records `account.provisioned` in the audit trail (RF-14, F-42);
//   6. prints the temporary password ONCE.
//
// Output: stdout carries the temporary password and NOTHING else: one line, the password. Every label,
// the target host, the id of the new user, what to do next and every error go to stderr. Neither stream
// ever carries the secret key, the e-mail, or what the Auth server said. The exit code is 0 only when
// the CEO was created: 1 failed, 2 refused before any call (usage, CI, terminal, environment mix,
// target), 3 the e-mail already has an account.
//
// Audit: the database records the account itself (`account.provisioned`, no actor, channel
// `auth_admin`), and the Auth server keeps its own log of admin actions. The script writes to no table.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { parseArgs, parseEnv as parseDotenv } from 'node:util';
import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';
import { generateTemporaryPassword, normalizeEmail } from '@/modules/identity';
import type { Database } from '@/shared/db/database.types';
import { fetchWithTimeout } from '@/shared/db/fetch-with-timeout';
import { visibleText } from '@/shared/http/validation';
import { err, ok, type Result } from '@/shared/kernel';

/** Exit codes. 0 is the only success; the others tell the operator what to fix. */
export const EXIT = {
  created: 0,
  failed: 1,
  /** Refused before any call: usage, CI, not a terminal, mixed environment, wrong target. */
  usage: 2,
  emailTaken: 3,
} as const;

const EMAIL_MAX_LENGTH = 254;
/** `profiles.display_name`: 1 to 120 characters (the trigger refuses anything else). */
const NAME_MAX_LENGTH = 120;
const DEFAULT_ENV_FILE = '.env.local';
/** Hosts for which a plain `http:` Supabase URL is acceptable (the local stack). */
const LOOPBACK_HOSTNAMES: ReadonlySet<string> = new Set(['localhost', '127.0.0.1', '[::1]']);

const USAGE =
  'Usage: pnpm -s ceo:create --target <host of SUPABASE_URL> --email <e-mail> --name <display name>\n' +
  '       [--env-file <path>] [--allow-non-tty]';

export type CeoInput = { readonly email: string; readonly name: string };

export type CeoCommand = CeoInput & {
  /** The host (with the port, if any) the operator says they are creating the CEO on. */
  readonly target: string;
  readonly envFile: { readonly path: string; readonly explicit: boolean };
  readonly allowNonTty: boolean;
};

export type UsageProblem = { readonly problem: string };

const emailSchema = z
  .string()
  .max(EMAIL_MAX_LENGTH)
  .transform(normalizeEmail)
  .pipe(z.email().max(EMAIL_MAX_LENGTH));
const nameSchema = visibleText({ min: 1, max: NAME_MAX_LENGTH });
/** Whatever `new URL(...).host` can be: a name or an address, with an optional port. */
const MAX_TARGET_LENGTH = 270;

/**
 * The command line, validated like the API validates the same values: the e-mail is normalized
 * (trim, NFC, lowercase) and the name is visible text of 1 to 120 characters (E-30). The messages
 * name the argument, never its value.
 */
export function parseCeoArguments(argv: readonly string[]): Result<CeoCommand, UsageProblem> {
  let values: {
    email?: string | undefined;
    name?: string | undefined;
    target?: string | undefined;
    'env-file'?: string | undefined;
    'allow-non-tty'?: boolean | undefined;
  };
  try {
    ({ values } = parseArgs({
      args: [...argv],
      options: {
        email: { type: 'string' },
        name: { type: 'string' },
        target: { type: 'string' },
        'env-file': { type: 'string' },
        'allow-non-tty': { type: 'boolean' },
      },
      strict: true,
      allowPositionals: false,
    }));
  } catch {
    return err({ problem: 'unknown or malformed arguments' });
  }

  if (values.email === undefined) return err({ problem: '--email is required' });
  if (values.name === undefined) return err({ problem: '--name is required' });
  if (values.target === undefined) return err({ problem: '--target is required' });

  const email = emailSchema.safeParse(values.email);
  if (!email.success) return err({ problem: '--email is not a valid e-mail address' });
  const name = nameSchema.safeParse(values.name);
  if (!name.success) {
    return err({
      problem: `--name must be 1 to ${NAME_MAX_LENGTH} visible characters (no control or invisible characters)`,
    });
  }
  const target = values.target.trim().toLowerCase();
  if (target === '' || target.length > MAX_TARGET_LENGTH) {
    return err({ problem: '--target must be the host of SUPABASE_URL' });
  }
  const envFilePath = values['env-file'];
  if (envFilePath === '') return err({ problem: '--env-file must not be empty' });

  return ok({
    email: email.data,
    name: name.data,
    target,
    envFile: { path: envFilePath ?? DEFAULT_ENV_FILE, explicit: envFilePath !== undefined },
    allowNonTty: values['allow-non-tty'] === true,
  });
}

/** The part of the Auth Admin API the script uses. */
export type CeoAuthAdmin = {
  createUser(attributes: {
    email: string;
    password: string;
    email_confirm: boolean;
    app_metadata: Record<string, unknown>;
  }): Promise<{
    data: { user: { id: string } | null };
    error: { status?: number | undefined; code?: string | undefined } | null;
  }>;
};

export type CreateCeoDeps = {
  readonly authAdmin: CeoAuthAdmin;
  /** Default: `generateTemporaryPassword` (the platform CSPRNG). Tests inject a fixed one. */
  readonly generatePassword?: () => string;
};

export type CreatedCeo = { readonly userId: string; readonly temporaryPassword: string };

export type CreateCeoFailure =
  | { readonly kind: 'email_taken' }
  /** The Auth server refused or failed. Only its status and error code, never its message. */
  | {
      readonly kind: 'auth_error';
      readonly status: number | undefined;
      readonly code: string | undefined;
    };

/**
 * Creates the CEO. The user is created with the temporary password already set and
 * `app_metadata = { role: 'ceo', display_name }`; `email_confirm: true` because there is no mailbox
 * round trip in this flow. Nothing is written anywhere else.
 *
 * An e-mail that already has an account (of ANY role: the Auth server compares case-insensitively)
 * is `email_taken` and nothing changes: the script never touches an existing account, so it can
 * neither promote a client login nor reset a password.
 *
 * This is the part that talks to the Auth server. The checks of the command line (CI, terminal,
 * environment, target) live in `main`, so that a test, or another script, can call this directly.
 */
export async function createCeoAccount(
  deps: CreateCeoDeps,
  input: CeoInput,
): Promise<Result<CreatedCeo, CreateCeoFailure>> {
  const temporaryPassword = (deps.generatePassword ?? generateTemporaryPassword)();

  const { data, error } = await deps.authAdmin.createUser({
    email: input.email,
    password: temporaryPassword,
    email_confirm: true,
    app_metadata: { role: 'ceo', display_name: input.name },
  });

  if (error) {
    if (error.code === 'email_exists') return err({ kind: 'email_taken' });
    return err({ kind: 'auth_error', status: error.status, code: error.code });
  }
  // A successful answer always carries the user; without one nothing can be reported as created.
  if (data.user === null) return err({ kind: 'auth_error', status: undefined, code: undefined });
  return ok({ userId: data.user.id, temporaryPassword });
}

export type ScriptIo = {
  readonly stdout: { write(text: string): unknown };
  readonly stderr: { write(text: string): unknown };
  /** The environment of the SHELL (a snapshot; the script never writes to `process.env`). */
  readonly env: Readonly<Record<string, string | undefined>>;
  /** Is stdout a terminal? `process.stdout.isTTY === true` in the real command. */
  readonly stdoutIsTTY: boolean;
  /** Default: reads the file as UTF-8. `undefined` when the file does not exist. */
  readonly readEnvFile?: (path: string) => string | undefined;
  /** Default: the Auth Admin API of the project in `env`. Tests inject a fake or the local one. */
  readonly createAuthAdmin?: (env: { url: string; secretKey: string }) => CeoAuthAdmin;
  /** Default: `generateTemporaryPassword`. */
  readonly generatePassword?: () => string;
};

/** The Auth Admin API of the project, with the secret key and the 5 s timeout of every upstream call. */
function adminApiOf({ url, secretKey }: { url: string; secretKey: string }): CeoAuthAdmin {
  const client = createClient<Database>(url, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    global: { fetch: fetchWithTimeout },
  });
  return client.auth.admin;
}

function readTextFileIfPresent(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8');
  } catch (error) {
    if ((error as { code?: unknown }).code === 'ENOENT') return undefined;
    throw error;
  }
}

/** What the script needs from the environment, and nothing else (it is not the app's env). */
const targetEnvSchema = z.object({
  SUPABASE_URL: z.url({ protocol: /^https?$/ }),
  SUPABASE_SECRET_KEY: z.string().min(1),
});

type EnvSource = 'shell' | 'env file';

const line = (text: string) => `${text}\n`;
const isSet = (value: string | undefined) => value !== undefined && value !== '';

/**
 * The whole command: arguments, guards, environment, creation, output. Returns the exit code; it
 * never throws and never calls `process.exit` (so it is testable and stdout is flushed).
 */
export async function main(argv: readonly string[], io: ScriptIo): Promise<number> {
  const { stdout, stderr } = io;
  const refuse = (message: string, code: number = EXIT.usage) => {
    stderr.write(line(`error: ${message}`));
    return code;
  };

  const parsed = parseCeoArguments(argv);
  if (!parsed.ok) {
    stderr.write(line(`error: ${parsed.error.problem}`));
    stderr.write(line(USAGE));
    return EXIT.usage;
  }
  const command = parsed.value;

  // 1. Who may run it, and where the password may go: before the environment is even read.
  if (isSet(io.env.CI)) {
    return refuse('CI is set: a CEO is created by a person at a terminal, never by a pipeline');
  }
  if (!io.stdoutIsTTY && !command.allowNonTty) {
    return refuse(
      'stdout is not a terminal, so the temporary password would be written to a pipe or a file; ' +
        'pass --allow-non-tty only if that is exactly what you mean',
    );
  }

  // 2. The environment: the shell wins over the env file, and the two variables must share a source.
  let fileText: string | undefined;
  try {
    fileText = (io.readEnvFile ?? readTextFileIfPresent)(command.envFile.path);
  } catch {
    return refuse(`the env file ${command.envFile.path} could not be read`, EXIT.failed);
  }
  if (fileText === undefined && command.envFile.explicit) {
    return refuse(`the env file ${command.envFile.path} does not exist`);
  }
  stderr.write(
    line(
      fileText === undefined
        ? `env file: none (${command.envFile.path} not found); the shell environment only`
        : `env file: ${command.envFile.path} (variables already set in the shell win)`,
    ),
  );
  const fileVariables = fileText === undefined ? {} : parseDotenv(fileText);

  const resolve = (name: 'SUPABASE_URL' | 'SUPABASE_SECRET_KEY') => {
    const fromShell = io.env[name];
    if (fromShell !== undefined) return { value: fromShell, source: 'shell' as EnvSource };
    const fromFile = fileVariables[name];
    return { value: fromFile, source: 'env file' as EnvSource };
  };
  const urlVariable = resolve('SUPABASE_URL');
  const keyVariable = resolve('SUPABASE_SECRET_KEY');

  const environment = targetEnvSchema.safeParse({
    SUPABASE_URL: urlVariable.value,
    SUPABASE_SECRET_KEY: keyVariable.value,
  });
  if (!environment.success) {
    // names and issue kinds only: the values may be secrets
    const problems = environment.error.issues.map(
      (issue) => `${issue.path.map(String).join('.') || '(root)'} (${issue.code})`,
    );
    return refuse(`invalid environment configuration: ${problems.join('; ')}`, EXIT.failed);
  }
  if (urlVariable.source !== keyVariable.source) {
    return refuse(
      `SUPABASE_URL comes from the ${urlVariable.source} and SUPABASE_SECRET_KEY from the ` +
        `${keyVariable.source}: refusing to pair a key with a URL from another place`,
    );
  }

  // 3. The environment the operator means is the one the URL names.
  const url = new URL(environment.data.SUPABASE_URL);
  if (url.protocol === 'http:' && !LOOPBACK_HOSTNAMES.has(url.hostname)) {
    return refuse('SUPABASE_URL is http: for a host that is not loopback; use https');
  }
  if (command.target !== url.host) {
    return refuse(
      `--target does not match the host of SUPABASE_URL (${url.host}): nothing was changed`,
    );
  }
  stderr.write(line(`target: ${url.host}`));

  // 4. The creation.
  let result: Awaited<ReturnType<typeof createCeoAccount>>;
  try {
    const authAdmin = (io.createAuthAdmin ?? adminApiOf)({
      url: environment.data.SUPABASE_URL,
      secretKey: environment.data.SUPABASE_SECRET_KEY,
    });
    result = await createCeoAccount(
      {
        authAdmin,
        ...(io.generatePassword === undefined ? {} : { generatePassword: io.generatePassword }),
      },
      command,
    );
  } catch {
    // transport failure, timeout, a bug: say that it failed, never what it threw (it may echo input)
    return refuse(
      'the Auth server could not be reached or failed; nothing was confirmed. ' +
        'Check whether the account exists before trying again',
      EXIT.failed,
    );
  }

  if (!result.ok) {
    if (result.error.kind === 'email_taken') {
      return refuse(
        'an account with this e-mail already exists; nothing was changed',
        EXIT.emailTaken,
      );
    }
    const { status, code } = result.error;
    return refuse(
      `the Auth server refused the request (status ${status ?? 'none'}, code ${code ?? 'none'})`,
      EXIT.failed,
    );
  }

  stderr.write(line(`CEO created (user id ${result.value.userId}).`));
  stderr.write(
    line('The ONLY line on stdout is the temporary password. It is shown once and not stored.'),
  );
  stdout.write(line(result.value.temporaryPassword));
  stderr.write(
    line('Hand it over through a secure channel. At the first sign-in the CEO must change'),
  );
  stderr.write(line('the password and enroll the TOTP second factor.'));
  return EXIT.created;
}

// Runs only when this file is the command (`tsx scripts/create-ceo.ts`), not when it is imported.
const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  void main(process.argv.slice(2), {
    stdout: process.stdout,
    stderr: process.stderr,
    env: { ...process.env },
    stdoutIsTTY: process.stdout.isTTY === true,
  }).then((code) => {
    process.exitCode = code;
  });
}
