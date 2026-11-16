import { z } from 'zod';

const MIN_RATE_LIMIT_KEY_SECRET_LENGTH = 32;
const LOG_LEVELS = ['trace', 'debug', 'info', 'warn', 'error'] as const;

const VERCEL_ENVIRONMENTS = ['production', 'preview', 'development'] as const;
/** Host with optional port, no scheme and no path: what Vercel puts in `VERCEL_URL`. */
const HOST_PATTERN = /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\d{1,5})?$/;

const httpUrl = z.url({ protocol: /^https?$/ });

/** Vercel sets these on deployments; an empty value (local .env) counts as unset. */
const optionalVercel = <T extends z.ZodType>(schema: T) =>
  z.preprocess((value) => (value === '' ? undefined : value), schema.optional());

/** Variables the app exposes to the rest of the code. No `NEXT_PUBLIC_*` anywhere. */
const envSchema = z.object({
  APP_ORIGIN: httpUrl.refine((value) => URL.canParse(value) && new URL(value).origin === value, {
    error: 'must be an origin (scheme://host[:port]) without path or trailing slash',
  }),
  SUPABASE_URL: httpUrl,
  SUPABASE_PUBLISHABLE_KEY: z.string().min(1),
  RATE_LIMIT_KEY_SECRET: z.string().min(MIN_RATE_LIMIT_KEY_SECRET_LENGTH),
  LOG_LEVEL: z.enum(LOG_LEVELS).default('info'),
  // Only used by the preview-origin rule of the Origin check (spec SEC-08).
  VERCEL_ENV: optionalVercel(z.enum(VERCEL_ENVIRONMENTS)),
  VERCEL_URL: optionalVercel(z.string().regex(HOST_PATTERN)),
  VERCEL_BRANCH_URL: optionalVercel(z.string().regex(HOST_PATTERN)),
});

/**
 * The Supabase secret key (bypasses RLS) is validated for presence only. It is NOT part of the
 * returned object: `src/shared/db/admin-client.ts` is the single place that reads it, straight
 * from `process.env`, after `getEnv()` has proven it exists at boot.
 */
const validationSchema = envSchema.extend({
  SUPABASE_SECRET_KEY: z.string().min(1),
});

export type Env = z.infer<typeof envSchema>;

export class EnvValidationError extends Error {
  constructor(readonly problems: readonly string[]) {
    super(`Invalid environment configuration: ${problems.join('; ')}`);
    this.name = 'EnvValidationError';
  }
}

/**
 * Pure validation. Errors list variable names and issue kinds, never values:
 * the input may contain secrets.
 */
export function parseEnv(source: Readonly<Record<string, string | undefined>>): Env {
  const result = validationSchema.safeParse(source);
  if (!result.success) {
    const problems = result.error.issues.map((issue) => {
      const name = issue.path.map(String).join('.') || '(root)';
      // Only our own static refine messages are safe to print; Zod's may quote the input.
      const kind = issue.code === 'custom' ? issue.message : issue.code;
      return `${name} (${kind})`;
    });
    throw new EnvValidationError(problems);
  }
  // Re-parsing with the public schema strips SUPABASE_SECRET_KEY from the result.
  return envSchema.parse(result.data);
}

let cached: Env | undefined;

/** Memoized. Never call at module top level: `next build` runs without env. */
export function getEnv(): Env {
  cached ??= parseEnv(process.env);
  return cached;
}
