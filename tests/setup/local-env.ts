// Vitest globalSetup for the `int` and `api` projects.
//
// Reads the URL and keys of the LOCAL Supabase from `supabase status -o env` (worktrees have no
// .env.local, and agents must never read .env*), accepts only a loopback URL, adds fixed test
// values for the rest and hands everything to the workers through provide()/inject().
// tests/setup/apply-local-env.ts (setupFiles) copies it into process.env inside each worker.
import { execFile } from 'node:child_process';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import type { TestProject } from 'vitest/node';

const execFileAsync = promisify(execFile);

const SUPABASE_BIN = resolve(process.cwd(), 'node_modules/.bin/supabase');
const STATUS_TIMEOUT_MS = 30_000;
const STATUS_MAX_BUFFER_BYTES = 1024 * 1024;
const LOCAL_HOSTNAMES: ReadonlySet<string> = new Set(['127.0.0.1', 'localhost']);

// Fixed, obviously fake values: tests never need real ones.
const TEST_APP_ORIGIN = 'http://localhost:3000';
const TEST_RATE_LIMIT_KEY_SECRET = 'local-test-only-rate-limit-hmac-key-not-a-real-one';

export type LocalEnv = {
  APP_ORIGIN: string;
  SUPABASE_URL: string;
  SUPABASE_PUBLISHABLE_KEY: string;
  SUPABASE_SECRET_KEY: string;
  RATE_LIMIT_KEY_SECRET: string;
};

declare module 'vitest' {
  export interface ProvidedContext {
    localEnv: LocalEnv;
  }
}

/** Never carries key values: only variable names and the (non-secret) hostname. */
export class LocalEnvError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LocalEnvError';
  }
}

/** Parses `KEY="value"` (or `KEY=value`) lines. Anything else is ignored. */
export function parseStatusEnv(output: string): Record<string, string> {
  const parsed: Record<string, string> = {};
  for (const line of output.split(/\r?\n/)) {
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim());
    if (!match) continue;
    const [, key, rawValue] = match;
    if (key === undefined || rawValue === undefined) continue;
    const quoted = /^"(.*)"$/.exec(rawValue);
    parsed[key] = quoted?.[1] ?? rawValue;
  }
  return parsed;
}

function firstPresent(
  status: Record<string, string>,
  names: readonly string[],
): string | undefined {
  for (const name of names) {
    const value = status[name];
    if (value !== undefined && value !== '') return value;
  }
  return undefined;
}

function assertLocalUrl(rawUrl: string): void {
  let hostname: string;
  try {
    hostname = new URL(rawUrl).hostname;
  } catch {
    throw new LocalEnvError('API_URL from "supabase status" is not a valid URL.');
  }
  if (!LOCAL_HOSTNAMES.has(hostname)) {
    throw new LocalEnvError(
      `Refusing to run tests against "${hostname}": only a local Supabase ` +
        `(${[...LOCAL_HOSTNAMES].join(' or ')}) is accepted.`,
    );
  }
}

/** Pure mapping from `supabase status -o env` variables to the app's env. */
export function buildLocalEnv(status: Record<string, string>): LocalEnv {
  const url = firstPresent(status, ['API_URL']);
  const publishableKey = firstPresent(status, ['PUBLISHABLE_KEY', 'ANON_KEY']);
  const secretKey = firstPresent(status, ['SECRET_KEY', 'SERVICE_ROLE_KEY']);

  const missing = [
    url === undefined ? 'API_URL' : null,
    publishableKey === undefined ? 'PUBLISHABLE_KEY (or ANON_KEY)' : null,
    secretKey === undefined ? 'SECRET_KEY (or SERVICE_ROLE_KEY)' : null,
  ].filter((name) => name !== null);
  if (url === undefined || publishableKey === undefined || secretKey === undefined) {
    throw new LocalEnvError(
      `"supabase status -o env" did not report: ${missing.join(', ')}. ` +
        'Is the local Supabase running? Try "pnpm db:start".',
    );
  }

  assertLocalUrl(url);

  return {
    APP_ORIGIN: TEST_APP_ORIGIN,
    SUPABASE_URL: url,
    SUPABASE_PUBLISHABLE_KEY: publishableKey,
    SUPABASE_SECRET_KEY: secretKey,
    RATE_LIMIT_KEY_SECRET: TEST_RATE_LIMIT_KEY_SECRET,
  };
}

/** Runs the project's own Supabase CLI (no shell). */
async function runSupabaseStatus(): Promise<string> {
  const { stdout } = await execFileAsync(SUPABASE_BIN, ['status', '-o', 'env'], {
    timeout: STATUS_TIMEOUT_MS,
    maxBuffer: STATUS_MAX_BUFFER_BYTES,
  });
  return stdout;
}

export async function loadLocalEnv(
  readStatus: () => Promise<string> = runSupabaseStatus,
): Promise<LocalEnv> {
  let output: string;
  try {
    output = await readStatus();
  } catch {
    // The failure (and any CLI output) is deliberately not echoed: it could carry key values.
    throw new LocalEnvError(
      '"supabase status -o env" failed. Is the local Supabase running? ' +
        'Try "pnpm db:start" (run "pnpm db:status" to see the CLI output).',
    );
  }
  return buildLocalEnv(parseStatusEnv(output));
}

export default async function setup(project: TestProject): Promise<void> {
  project.provide('localEnv', await loadLocalEnv());
}
