// Fixtures for the API and integration tests (Wave 3 owns this file; later waves add their own).
//
// They talk to the LOCAL Supabase with the secret key, which `tests/setup` copies from
// `supabase status -o env` into process.env (and refuses anything that is not a loopback URL).
// Every fixture is unique per call (UUID-suffixed), so tests never depend on each other or on a
// reset database. Users are created WITH their password in the same `createUser` call (spec §3.4):
// that is what makes `must_change_password` provable later.
import { randomUUID } from 'node:crypto';
import { createClient as createSupabaseClient, type SupabaseClient } from '@supabase/supabase-js';
import * as OTPAuth from 'otpauth';
import type { Database } from '@/shared/db/database.types';

type Env = 'SUPABASE_URL' | 'SUPABASE_PUBLISHABLE_KEY' | 'SUPABASE_SECRET_KEY';

function requireEnv(name: Env): string {
  const value = process.env[name];
  if (value === undefined || value === '') {
    throw new Error(`${name} is not set: the api/int test projects fill it from the local stack`);
  }
  return value;
}

const NO_SESSION = { persistSession: false, autoRefreshToken: false } as const;

let admin: SupabaseClient<Database> | undefined;

/** Secret-key client for fixtures only. It bypasses RLS: never use it to check behavior. */
export function adminClient(): SupabaseClient<Database> {
  admin ??= createSupabaseClient<Database>(
    requireEnv('SUPABASE_URL'),
    requireEnv('SUPABASE_SECRET_KEY'),
    { auth: NO_SESSION },
  );
  return admin;
}

/** A client signed in as nobody, with the publishable key: what a browser could build itself. */
export function publishableClient(): SupabaseClient<Database> {
  return createSupabaseClient<Database>(
    requireEnv('SUPABASE_URL'),
    requireEnv('SUPABASE_PUBLISHABLE_KEY'),
    { auth: NO_SESSION },
  );
}

/** 8 hex characters: short enough to read in a failing test, unique enough for a local database. */
const shortId = () => randomUUID().slice(0, 8);

/** A fresh e-mail. Lowercase: it is already in normalized form. */
export function uniqueEmail(label = 'user'): string {
  return `${label}.${shortId()}@cliente.test`;
}

/** A fresh password of 40 characters: past the 12-character minimum, within 72 bytes. */
function uniquePassword(): string {
  return `Pw-${randomUUID()}`;
}

const LIST_USERS_PAGE_SIZE = 1000;

/** Does an auth user with this e-mail exist? Pages through the whole list. */
export async function authUserExists(email: string): Promise<boolean> {
  for (let page = 1; ; page += 1) {
    const { data, error } = await adminClient().auth.admin.listUsers({
      page,
      perPage: LIST_USERS_PAGE_SIZE,
    });
    if (error) throw new Error(`listUsers failed: ${error.message}`);
    if (data.users.some((user) => user.email === email)) return true;
    if (data.users.length < LIST_USERS_PAGE_SIZE) return false;
  }
}

export type FixtureClient = { readonly id: string; readonly name: string };

/** A tenant. The secret key keeps DML on `public.clients` for fixtures (spec §4.2). */
export async function createClient(name = `Cliente ${shortId()}`): Promise<FixtureClient> {
  const { data, error } = await adminClient()
    .from('clients')
    .insert({ name })
    .select('id, name')
    .single();
  if (error) throw new Error(`createClient failed: ${error.message}`);
  return { id: data.id, name: data.name };
}

export type FixtureUser = {
  readonly id: string;
  readonly email: string;
  readonly password: string;
  readonly displayName: string;
  readonly role: 'client' | 'ceo';
  /** `null` for a CEO. */
  readonly clientId: string | null;
};

type UserInit = {
  readonly email?: string;
  readonly password?: string;
  readonly displayName?: string;
};

async function createUser(
  role: 'client' | 'ceo',
  clientId: string | null,
  init: UserInit,
): Promise<FixtureUser> {
  const email = init.email ?? uniqueEmail(role);
  const password = init.password ?? uniquePassword();
  const displayName = init.displayName ?? (role === 'ceo' ? 'CEO Teste' : 'Cliente Teste');

  // The profile is created by the database trigger from `app_metadata` (only the secret key can
  // write it), and `must_change_password` starts true: the user is born with a temporary password.
  const { data, error } = await adminClient().auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    app_metadata: {
      role,
      display_name: displayName,
      ...(clientId === null ? {} : { client_id: clientId }),
    },
  });
  if (error) throw new Error(`createUser (${role}) failed: ${error.message}`);
  return { id: data.user.id, email, password, displayName, role, clientId };
}

/** A login of a client (tenant user), born with CHANGE_PASSWORD pending. */
export function createClientUser(
  init: UserInit & { readonly clientId: string },
): Promise<FixtureUser> {
  return createUser('client', init.clientId, init);
}

/** A CEO, born with CHANGE_PASSWORD and ENROLL_MFA pending. */
export function createCeo(init: UserInit = {}): Promise<FixtureUser> {
  return createUser('ceo', null, init);
}

function currentTotpCode(secret: string): string {
  return new OTPAuth.TOTP({
    secret: OTPAuth.Secret.fromBase32(secret),
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
  }).generate();
}

export type CeoAal2 = {
  readonly ceo: FixtureUser;
  /**
   * A client holding an `aal2` session of that CEO that the backend ATTESTED (Wave 6.1): it can call
   * the CEO functions of the database.
   */
  readonly supabase: SupabaseClient<Database>;
};

/** The `session_id` claim of an access token (test code: the payload is read without verifying it). */
export function sessionIdOf(accessToken: string): string {
  const payload = accessToken.split('.')[1] ?? '';
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
    session_id?: string;
  };
  if (claims.session_id === undefined) throw new Error('the access token has no session_id');
  return claims.session_id;
}

/**
 * A CEO session at `aal2` straight at Supabase Auth, exactly what anyone holding the password and the
 * publishable key can build: NO attestation, no backend involved. The session is not a CEO's (E-32);
 * tests use it as the attacker's. `code` is the code that verified it, so a test can send the very
 * same code to the backend (E-33).
 */
export type DirectAal2 = {
  readonly supabase: SupabaseClient<Database>;
  readonly sessionId: string;
  readonly factorId: string;
  readonly secret: string;
  readonly code: string;
};

/**
 * Signs in with supabase-js, then challenges and verifies straight at Auth. With `factor` the session
 * verifies an EXISTING factor (the CEO's, whose secret the test has); without it a factor is enrolled
 * and verified here. `code` picks the code (default: the current one).
 */
export async function directAal2Session(
  ceo: Pick<FixtureUser, 'email' | 'password'>,
  factor?: { readonly factorId: string; readonly secret: string },
  code?: string,
): Promise<DirectAal2> {
  const supabase = publishableClient();
  const signIn = await supabase.auth.signInWithPassword({
    email: ceo.email,
    password: ceo.password,
  });
  if (signIn.error || signIn.data.session === null) {
    throw new Error(`CEO sign-in failed: ${signIn.error?.message ?? 'no session'}`);
  }

  let factorId: string;
  let secret: string;
  if (factor === undefined) {
    const enrolled = await supabase.auth.mfa.enroll({ factorType: 'totp' });
    if (enrolled.error) throw new Error(`TOTP enroll failed: ${enrolled.error.message}`);
    factorId = enrolled.data.id;
    secret = enrolled.data.totp.secret;
  } else {
    ({ factorId, secret } = factor);
  }

  const challenge = await supabase.auth.mfa.challenge({ factorId });
  if (challenge.error) throw new Error(`TOTP challenge failed: ${challenge.error.message}`);

  const used = code ?? currentTotpCode(secret);
  const verified = await supabase.auth.mfa.verify({
    factorId,
    challengeId: challenge.data.id,
    code: used,
  });
  if (verified.error) throw new Error(`TOTP verify failed: ${verified.error.message}`);

  return {
    supabase,
    sessionId: sessionIdOf(verified.data.access_token),
    factorId,
    secret,
    code: used,
  };
}

/**
 * Signs a fresh CEO in with supabase-js, enrolls TOTP, computes the code from the secret Supabase
 * returns, then challenges and verifies to reach `aal2`, and ATTESTS the session the way the backend
 * does (Wave 6.1, ADR 0013): the factor and the challenge are recorded, and `attest_mfa_session` runs,
 * all with the secret key, like `identity/infrastructure` does. Tests need it only to call CEO
 * functions (`set_account_disabled`...) as a fixture: not even the secret key can update `profiles`
 * (by design), so a disabled account has to be made the way production makes it.
 *
 * The CEO keeps the temporary password (`CHANGE_PASSWORD` pending), which the backend routes do not
 * allow past the verification: that is why this fixture does not call them. The API-level helper that
 * goes through the routes is `loginAsCeoWithMfa` in `mfa.ts`.
 */
export async function ceoAal2Client(init: UserInit = {}): Promise<CeoAal2> {
  const ceo = await createCeo(init);
  const supabase = publishableClient();

  const signIn = await supabase.auth.signInWithPassword({
    email: ceo.email,
    password: ceo.password,
  });
  if (signIn.error || signIn.data.session === null) {
    throw new Error(`CEO sign-in failed: ${signIn.error?.message ?? 'no session'}`);
  }
  const sessionId = sessionIdOf(signIn.data.session.access_token);

  const enrolled = await supabase.auth.mfa.enroll({ factorType: 'totp' });
  if (enrolled.error) throw new Error(`TOTP enroll failed: ${enrolled.error.message}`);
  const factorId = enrolled.data.id;

  const registered = await adminClient().rpc('register_backend_totp_factor', {
    p_user_id: ceo.id,
    p_factor_id: factorId,
    p_session_id: sessionId,
  });
  if (registered.error || registered.data !== 'registered') {
    throw new Error(
      `register factor failed: ${registered.error?.message ?? String(registered.data)}`,
    );
  }

  const challenge = await supabase.auth.mfa.challenge({ factorId });
  if (challenge.error) throw new Error(`TOTP challenge failed: ${challenge.error.message}`);
  const challengeId = challenge.data.id;

  const recorded = await adminClient().rpc('record_backend_mfa_challenge', {
    p_user_id: ceo.id,
    p_factor_id: factorId,
    p_challenge_id: challengeId,
  });
  if (recorded.error) throw new Error(`record challenge failed: ${recorded.error.message}`);

  const verified = await supabase.auth.mfa.verify({
    factorId,
    challengeId,
    code: currentTotpCode(enrolled.data.totp.secret),
  });
  if (verified.error) throw new Error(`TOTP verify failed: ${verified.error.message}`);

  const attested = await adminClient().rpc('attest_mfa_session', {
    p_user_id: ceo.id,
    p_session_id: sessionId,
    p_factor_id: factorId,
    p_challenge_id: challengeId,
  });
  if (attested.error || (attested.data !== 'attested' && attested.data !== 'attested_activated')) {
    throw new Error(`attest session failed: ${attested.error?.message ?? String(attested.data)}`);
  }

  return { ceo, supabase };
}

/** Disables a client login the way a CEO does: through the database function. */
export async function disableAccount(ceo: CeoAal2, userId: string): Promise<void> {
  const { error } = await ceo.supabase.rpc('set_account_disabled', {
    p_user_id: userId,
    p_disabled: true,
  });
  if (error) throw new Error(`set_account_disabled failed: ${error.message}`);
}
