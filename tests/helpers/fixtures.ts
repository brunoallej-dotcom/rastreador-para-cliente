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
  /** A client holding an `aal2` session of that CEO: it can call the CEO functions of the database. */
  readonly supabase: SupabaseClient<Database>;
};

/**
 * Signs a fresh CEO in with supabase-js, enrolls TOTP, computes the code from the secret Supabase
 * returns, then challenges and verifies to reach `aal2`. Tests need it only to call CEO functions
 * (`set_account_disabled`...) as a fixture: not even the secret key can update `profiles` (by
 * design), so a disabled account has to be made the way production makes it. The API-level MFA
 * helper comes with Wave 5, in its own file.
 */
export async function ceoAal2Client(init: UserInit = {}): Promise<CeoAal2> {
  const ceo = await createCeo(init);
  const supabase = publishableClient();

  const signIn = await supabase.auth.signInWithPassword({
    email: ceo.email,
    password: ceo.password,
  });
  if (signIn.error) throw new Error(`CEO sign-in failed: ${signIn.error.message}`);

  const enrolled = await supabase.auth.mfa.enroll({ factorType: 'totp' });
  if (enrolled.error) throw new Error(`TOTP enroll failed: ${enrolled.error.message}`);

  const challenge = await supabase.auth.mfa.challenge({ factorId: enrolled.data.id });
  if (challenge.error) throw new Error(`TOTP challenge failed: ${challenge.error.message}`);

  const verified = await supabase.auth.mfa.verify({
    factorId: enrolled.data.id,
    challengeId: challenge.data.id,
    code: currentTotpCode(enrolled.data.totp.secret),
  });
  if (verified.error) throw new Error(`TOTP verify failed: ${verified.error.message}`);

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
