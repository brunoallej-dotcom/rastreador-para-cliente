// `pnpm ceo:create --email <e-mail> --name <name>`: creates the account of a CEO (spec §3.4, RF-14).
//
// A MANUAL operation, run by a person against ONE environment: the secret key of that environment
// (`SUPABASE_SECRET_KEY`, validated with the app's own env schema) lets the script reach the Auth
// Admin API. No endpoint of the API creates or promotes a CEO; this is the only way in.
//
// What it does, in this order:
//   1. reads the arguments and the environment, and refuses anything invalid before a single call;
//   2. generates a temporary password (20 characters from the CSPRNG, `generateTemporaryPassword`);
//   3. creates the user through `auth.admin.createUser` WITH that password in the same call (ADR 0007:
//      it is the baseline `mark_password_changed()` compares against), with `app_metadata` role `ceo`
//      and the display name. The database trigger builds the profile from `app_metadata` in the same
//      transaction, with `must_change_password = true`, so the CEO is born with CHANGE_PASSWORD and
//      ENROLL_MFA pending (AC-31);
//   4. prints the temporary password ONCE, on stdout, and nothing else secret anywhere.
//
// Output: the password alone goes to stdout; everything else (the target host, the id of the new
// user, what to do next, every error) goes to stderr. Neither stream ever carries the secret key,
// the e-mail, or what the Auth server said. The exit code is 0 only when the CEO was created.
//
// Audit: the account is recorded by the Auth server itself (its own audit log of admin actions) and
// by the database trigger. No function of the database records a CEO provisioning in `audit_events`
// (`record_account_provisioned` is for client logins and needs a CEO session), and this script writes
// nothing there: the audit trail stays on the existing database path.
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';
import { createClient } from '@supabase/supabase-js';
import { generateTemporaryPassword, normalizeEmail } from '@/modules/identity';
import { EnvValidationError, parseEnv } from '@/shared/config/env';
import type { Database } from '@/shared/db/database.types';
import { fetchWithTimeout } from '@/shared/db/fetch-with-timeout';
import { visibleText } from '@/shared/http/validation';
import { err, ok, type Result } from '@/shared/kernel';
import { z } from 'zod';

/** Exit codes. 0 is the only success; the others tell the operator what to fix. */
export const EXIT = {
  created: 0,
  failed: 1,
  usage: 2,
  emailTaken: 3,
} as const;

const EMAIL_MAX_LENGTH = 254;
/** `profiles.display_name`: 1 to 120 characters (the trigger refuses anything else). */
const NAME_MAX_LENGTH = 120;

const USAGE = 'Usage: pnpm ceo:create --email <e-mail> --name <display name>';

export type CeoInput = { readonly email: string; readonly name: string };

export type UsageProblem = { readonly problem: string };

const emailSchema = z
  .string()
  .max(EMAIL_MAX_LENGTH)
  .transform(normalizeEmail)
  .pipe(z.email().max(EMAIL_MAX_LENGTH));
const nameSchema = visibleText({ min: 1, max: NAME_MAX_LENGTH });

/**
 * The command line, validated like the API validates the same values: the e-mail is normalized
 * (trim, NFC, lowercase) and the name is visible text of 1 to 120 characters (E-30). The messages
 * name the argument, never its value.
 */
export function parseCeoArguments(argv: readonly string[]): Result<CeoInput, UsageProblem> {
  let values: { email?: string | undefined; name?: string | undefined };
  try {
    ({ values } = parseArgs({
      args: [...argv],
      options: { email: { type: 'string' }, name: { type: 'string' } },
      strict: true,
      allowPositionals: false,
    }));
  } catch {
    return err({ problem: 'unknown or malformed arguments' });
  }

  if (values.email === undefined) return err({ problem: '--email is required' });
  if (values.name === undefined) return err({ problem: '--name is required' });

  const email = emailSchema.safeParse(values.email);
  if (!email.success) return err({ problem: '--email is not a valid e-mail address' });
  const name = nameSchema.safeParse(values.name);
  if (!name.success) {
    return err({
      problem: `--name must be 1 to ${NAME_MAX_LENGTH} visible characters (no control or invisible characters)`,
    });
  }
  return ok({ email: email.data, name: name.data });
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
  readonly env: Readonly<Record<string, string | undefined>>;
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

const line = (text: string) => `${text}\n`;

/**
 * The whole command: arguments, environment, creation, output. Returns the exit code; it never
 * throws and never calls `process.exit` (so it is testable and stdout is flushed).
 */
export async function main(argv: readonly string[], io: ScriptIo): Promise<number> {
  const { stdout, stderr } = io;

  const parsed = parseCeoArguments(argv);
  if (!parsed.ok) {
    stderr.write(line(`error: ${parsed.error.problem}`));
    stderr.write(line(USAGE));
    return EXIT.usage;
  }

  let env: ReturnType<typeof parseEnv>;
  try {
    env = parseEnv(io.env);
  } catch (error) {
    // `EnvValidationError` lists variable names and issue kinds, never values
    stderr.write(
      line(
        error instanceof EnvValidationError
          ? `error: ${error.message}`
          : 'error: the environment could not be read',
      ),
    );
    return EXIT.failed;
  }
  // `parseEnv` proved the secret key is present; the app's `Env` deliberately does not carry it
  const secretKey = io.env.SUPABASE_SECRET_KEY;
  if (secretKey === undefined || secretKey === '') {
    stderr.write(line('error: SUPABASE_SECRET_KEY is not set'));
    return EXIT.failed;
  }

  // The operator must see WHICH environment is about to get a CEO before it happens.
  stderr.write(line(`target: ${new URL(env.SUPABASE_URL).host}`));

  let result: Awaited<ReturnType<typeof createCeoAccount>>;
  try {
    const authAdmin = (io.createAuthAdmin ?? adminApiOf)({ url: env.SUPABASE_URL, secretKey });
    result = await createCeoAccount(
      {
        authAdmin,
        ...(io.generatePassword === undefined ? {} : { generatePassword: io.generatePassword }),
      },
      parsed.value,
    );
  } catch {
    // transport failure, timeout, a bug: say that it failed, never what it threw (it may echo input)
    stderr.write(
      line('error: the Auth server could not be reached or failed; nothing was confirmed'),
    );
    stderr.write(line('check whether the account exists before trying again'));
    return EXIT.failed;
  }

  if (!result.ok) {
    if (result.error.kind === 'email_taken') {
      stderr.write(line('error: an account with this e-mail already exists; nothing was changed'));
      return EXIT.emailTaken;
    }
    const { status, code } = result.error;
    stderr.write(
      line(
        `error: the Auth server refused the request (status ${status ?? 'none'}, code ${code ?? 'none'})`,
      ),
    );
    return EXIT.failed;
  }

  stderr.write(line(`CEO created (user id ${result.value.userId}).`));
  stderr.write(
    line('The temporary password follows, on stdout. It is shown ONCE and is not stored.'),
  );
  stdout.write(line(`temporary password: ${result.value.temporaryPassword}`));
  stderr.write(
    line('Hand it over through a secure channel. At the first sign-in the CEO must change'),
  );
  stderr.write(line('the password and enroll the TOTP second factor.'));
  return EXIT.created;
}

/**
 * Like Next.js, the script reads `.env.local` when it exists, WITHOUT overriding variables the shell
 * already set: `SUPABASE_URL=... SUPABASE_SECRET_KEY=... pnpm ceo:create ...` targets exactly that
 * environment. Called only by the command line entry point, never by tests.
 */
function loadLocalEnvFile(): void {
  try {
    process.loadEnvFile('.env.local');
  } catch {
    // no file: the variables must come from the shell, and `parseEnv` will say which are missing
  }
}

// Runs only when this file is the command (`tsx scripts/create-ceo.ts`), not when it is imported.
const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  loadLocalEnvFile();
  void main(process.argv.slice(2), {
    stdout: process.stdout,
    stderr: process.stderr,
    env: process.env,
  }).then((code) => {
    process.exitCode = code;
  });
}
