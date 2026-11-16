import 'server-only';
import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';
import { getEnv } from '@/shared/config/env';
import type { Database } from './database.types';
import { fetchWithTimeout } from './fetch-with-timeout';

/**
 * What may be kept of a failed Auth Admin call: the kind of the error, its HTTP status and its code.
 * Never the message (it can echo the e-mail of the account), so nothing a caller logs or throws from
 * it carries PII.
 */
export type AdminAuthFailure = {
  readonly name: string;
  readonly status: number | undefined;
  readonly code: string | undefined;
};

/**
 * What an Auth Admin call answered: its payload (`null` when it failed or has none) or the failure
 * reduced to `AdminAuthFailure`. A call that cannot even reach the server THROWS instead (the caller
 * maps it to an outage).
 */
export type AdminAuthResult<T> = {
  readonly data: T | null;
  readonly error: AdminAuthFailure | null;
};

/** Arguments of `createClientUser`: the login of a client. The ROLE is not an argument (see below). */
export type AdminCreateClientUserInput = {
  /** Already normalized (`normalizeEmail`) and validated. */
  readonly email: string;
  /** The temporary password, set in the same call (ADR 0007). A secret: never logged. */
  readonly password: string;
  readonly displayName: string;
  readonly clientId: string;
};

/**
 * What a creation that Auth accepted answers. `id` is `null` when the answer carries no usable user id:
 * the account may exist all the same, so the caller must not treat it as "nothing was created".
 */
export type AdminCreatedUser = { readonly id: string | null };

/** The ban of a disabled login: a century (Go durations go up to hours). `none` lifts it. */
const BAN_DURATION = '876000h';
const UNBAN_DURATION = 'none';
const USER_ID = z.guid();
const CREATED_USER_ID = z.object({ user: z.object({ id: USER_ID }) });

/** What `rate_limit_hit` takes: the same fields as the limiter's input. */
export type AdminRateLimitHitInput = {
  readonly bucket: string;
  readonly windowSeconds: number;
  readonly max: number;
};

/**
 * What a `service_role` RPC answered: the payload, checked against the schema of that function (it is
 * `null` when the call failed), the PostgREST error reduced to its SQLSTATE and message (what the
 * caller maps to a business outcome), and the HTTP status (0 for a transport failure). It never
 * carries `details` or `hint`.
 */
export type AdminRpcResult<T> = {
  readonly data: T | null;
  readonly error: { readonly code: string; readonly message: string } | null;
  readonly status: number;
};

/** What `register_backend_totp_factor` returns (F-64): the factor was recorded, or it was refused. */
export type AdminRegisterFactorAnswer = 'registered' | 'factor_reenrolled';

/** The payload schemas: a function that answers anything else is not the function the app knows. */
const REGISTER_ANSWER = z.enum(['registered', 'factor_reenrolled']);
const NO_ANSWER = z.null();
/** The attestation answer is a word the caller maps (the identity module knows the vocabulary). */
const ATTEST_ANSWER = z.string();
const CONSUME_ANSWER = z.boolean();

/** Arguments of `public.consume_totp_code`: burn a TOTP code of this user's factor (F-21, F-65). */
export type AdminConsumeCodeInput = {
  readonly userId: string;
  readonly factorId: string;
  /** PostgREST `bytea` literal of the SHA-256 digest, never the code. */
  readonly codeDigest: string;
};

/** Arguments of `public.register_backend_totp_factor`: the enroll just created this factor. */
export type AdminRegisterFactorInput = {
  readonly userId: string;
  readonly factorId: string;
  readonly sessionId: string;
};

/** Arguments of `public.record_backend_mfa_challenge`: the backend created this challenge. */
export type AdminRecordChallengeInput = {
  readonly userId: string;
  readonly factorId: string;
  readonly challengeId: string;
};

/** Arguments of `public.attest_mfa_session`: the backend's verify of this session passed. */
export type AdminAttestSessionInput = {
  readonly userId: string;
  readonly sessionId: string;
  readonly factorId: string;
  readonly challengeId: string;
};

/**
 * What the secret key may do for this app, and nothing else. The shared singleton is NEVER handed
 * out as a Supabase client: a caller with the whole client could `.from(...)` any table past RLS or
 * `.auth.signInWithPassword(...)` and leave a user session on a process-wide object. It gets four typed
 * Auth Admin operations for client logins and a handful of named RPC wrappers instead, one per
 * `service_role` function. The Auth Admin API itself is NOT exposed (F-91): with it, a request path
 * could create a CEO (`app_metadata.role`), read or change any account. The operator's script
 * (`pnpm ceo:create`) builds its own client in `scripts/`, and nothing under `src/` may use `auth.admin`
 * outside this file (ESLint, and the Semgrep rule `no-auth-admin-outside-facade`).
 */
export type AdminFacade = {
  /**
   * Creates the login of a client WITH its password, in one Auth call (ADR 0007), confirmed (there is
   * no mailbox round trip). The role is FIXED to `client` in here and the caller cannot pass
   * `app_metadata`: this wrapper cannot create a CEO or any other role (AC-31). The database trigger
   * builds the profile from the `app_metadata` set here, in the same transaction, and refuses an
   * archived client or one at the limit (that refusal comes back as a 500 the Auth server cannot name).
   */
  createClientUser(input: AdminCreateClientUserInput): Promise<AdminAuthResult<AdminCreatedUser>>;
  /** Deletes an account (hard delete: the profile goes with it). `user_not_found` is the caller's to read. */
  deleteUser(userId: string): Promise<AdminAuthResult<null>>;
  /** Stores a new password. Auth also drops every session of the user (observed on the local stack). */
  setPassword(userId: string, password: string): Promise<AdminAuthResult<null>>;
  /** Bans (a century) or unbans (`false`) the account in the Auth server. */
  setBan(userId: string, banned: boolean): Promise<AdminAuthResult<null>>;
  /**
   * Calls `public.rate_limit_hit` (only `service_role` may execute it) and returns what it answered,
   * unvalidated. Throws when the call fails, without echoing what the database said.
   */
  rateLimitHit(input: AdminRateLimitHitInput): Promise<unknown>;
  /**
   * The three `service_role` functions of the CEO attestation (Wave 6.1, ADR 0013): the database
   * revalidates every id they take, and the caller is `identity/infrastructure` only. They return
   * the PostgREST answer as it is (see `AdminRpcResult`), because the caller maps the SQLSTATE and
   * message to its own outcomes; none of them reads or writes business data.
   */
  registerBackendTotpFactor(
    input: AdminRegisterFactorInput,
  ): Promise<AdminRpcResult<AdminRegisterFactorAnswer>>;
  recordBackendMfaChallenge(input: AdminRecordChallengeInput): Promise<AdminRpcResult<null>>;
  attestMfaSession(input: AdminAttestSessionInput): Promise<AdminRpcResult<string>>;
  /**
   * `public.consume_totp_code`: the replay guard of the TOTP codes. It is `service_role` only (F-65):
   * with a user's own session it was a code oracle at PostgREST. `data` is `true` the first time a
   * code is seen, `false` for a replay inside 120 s.
   */
  consumeTotpCode(input: AdminConsumeCodeInput): Promise<AdminRpcResult<boolean>>;
};

let cached: AdminFacade | undefined;

/**
 * The ONLY reader of `SUPABASE_SECRET_KEY` (SEC-15). `getEnv()` runs first so a missing key fails
 * with the boot-time validation message instead of an obscure client error.
 *
 * Allowed callers: `src/shared/http/rate-limit/` (the limiter RPC) and
 * `src/modules/identity/infrastructure/` (the four client-login operations of the Auth Admin API and
 * the CEO attestation RPCs); ESLint enforces it. Never for business reads or writes: those go through the request-scoped client so
 * RLS decides.
 *
 * Stateless (no session, no refresh), so one instance serves the whole process.
 */
export function getAdminFacade(): AdminFacade {
  if (cached !== undefined) return cached;

  const env = getEnv();
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (secretKey === undefined || secretKey === '') {
    throw new Error('SUPABASE_SECRET_KEY is not set');
  }
  const client = createClient<Database>(env.SUPABASE_URL, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    global: { fetch: fetchWithTimeout },
  });

  /**
   * Keeps only what the caller maps (SQLSTATE and message; `details` and `hint` stay behind) and
   * checks the payload of a call that worked against the schema of that function: an answer it does
   * not understand throws (a plain error, fail closed) instead of reaching the caller as `unknown`.
   */
  const settle = <T>(
    name: string,
    schema: z.ZodType<T>,
    {
      data,
      error,
      status,
    }: { data: unknown; error: { code: string; message: string } | null; status: number },
  ): AdminRpcResult<T> => {
    if (error !== null) {
      return { data: null, error: { code: error.code, message: error.message }, status };
    }
    const parsed = schema.safeParse(data);
    if (!parsed.success) throw new Error(`${name}: an answer that is not understood`);
    return { data: parsed.data, error: null, status };
  };

  /** Reduces an Auth error to what may be kept of it (see `AdminAuthFailure`). */
  const failureOf = (error: { name?: unknown; status?: unknown; code?: unknown }) => ({
    name: typeof error.name === 'string' ? error.name : 'AuthError',
    status: typeof error.status === 'number' ? error.status : undefined,
    code: typeof error.code === 'string' ? error.code : undefined,
  });

  /** A user id goes into the URL of the Auth Admin API: anything but a UUID never gets there. */
  const requireUserId = (userId: string): string => {
    if (!USER_ID.safeParse(userId).success) throw new Error('the user id is not a UUID');
    return userId;
  };

  const settleAuth = (result: {
    error: { name?: unknown; status?: unknown; code?: unknown } | null;
  }) =>
    result.error === null
      ? { data: null, error: null }
      : { data: null, error: failureOf(result.error) };

  cached = Object.freeze({
    async createClientUser({ email, password, displayName, clientId }: AdminCreateClientUserInput) {
      if (!USER_ID.safeParse(clientId).success) throw new Error('the client id is not a UUID');
      const result = await client.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        // The role is a literal in this file and an argument nowhere: the Semgrep rule
        // `no-app-metadata-role-but-client` holds every use of `app_metadata` in src/ to it.
        app_metadata: { role: 'client', client_id: clientId, display_name: displayName },
      });
      if (result.error) return { data: null, error: failureOf(result.error) };
      // Tolerant on purpose: whatever else the answer says, an id that is a UUID is the one thing the
      // caller can use to take the account back; without one it must not claim nothing was created.
      const answer = CREATED_USER_ID.safeParse(result.data);
      return { data: { id: answer.success ? answer.data.user.id : null }, error: null };
    },
    async deleteUser(userId: string) {
      return settleAuth(await client.auth.admin.deleteUser(requireUserId(userId)));
    },
    async setPassword(userId: string, password: string) {
      return settleAuth(
        await client.auth.admin.updateUserById(requireUserId(userId), { password }),
      );
    },
    async setBan(userId: string, banned: boolean) {
      return settleAuth(
        await client.auth.admin.updateUserById(requireUserId(userId), {
          ban_duration: banned ? BAN_DURATION : UNBAN_DURATION,
        }),
      );
    },
    async rateLimitHit({ bucket, windowSeconds, max }: AdminRateLimitHitInput) {
      const { data, error } = await client.rpc('rate_limit_hit', {
        p_bucket: bucket,
        p_window_seconds: windowSeconds,
        p_max: max,
      });
      if (error) throw new Error('rate_limit_hit failed', { cause: error });
      return data;
    },
    async registerBackendTotpFactor({ userId, factorId, sessionId }: AdminRegisterFactorInput) {
      return settle(
        'register_backend_totp_factor',
        REGISTER_ANSWER,
        await client.rpc('register_backend_totp_factor', {
          p_user_id: userId,
          p_factor_id: factorId,
          p_session_id: sessionId,
        }),
      );
    },
    async recordBackendMfaChallenge({ userId, factorId, challengeId }: AdminRecordChallengeInput) {
      return settle(
        'record_backend_mfa_challenge',
        NO_ANSWER,
        await client.rpc('record_backend_mfa_challenge', {
          p_user_id: userId,
          p_factor_id: factorId,
          p_challenge_id: challengeId,
        }),
      );
    },
    async attestMfaSession({ userId, sessionId, factorId, challengeId }: AdminAttestSessionInput) {
      return settle(
        'attest_mfa_session',
        ATTEST_ANSWER,
        await client.rpc('attest_mfa_session', {
          p_user_id: userId,
          p_session_id: sessionId,
          p_factor_id: factorId,
          p_challenge_id: challengeId,
        }),
      );
    },
    async consumeTotpCode({ userId, factorId, codeDigest }: AdminConsumeCodeInput) {
      return settle(
        'consume_totp_code',
        CONSUME_ANSWER,
        await client.rpc('consume_totp_code', {
          p_user_id: userId,
          p_factor_id: factorId,
          p_code_digest: codeDigest,
        }),
      );
    },
  });
  return cached;
}
