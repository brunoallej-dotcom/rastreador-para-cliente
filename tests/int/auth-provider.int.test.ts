// What the local Auth server (supabase/config.toml) must allow and refuse for the identity module:
// password sign-in is ON (the email provider), public sign-up is OFF (SEC-20, RF-01), and the Admin
// API creates users (with the profile made from app_metadata, in the same transaction).
import { describe, expect, it } from 'vitest';
import {
  adminClient,
  authUserExists,
  createCeo,
  createClient,
  createClientUser,
  publishableClient,
  uniqueEmail,
} from '../helpers/fixtures';

describe('local Auth server configuration', () => {
  it('SEC-20: public sign-up is refused', async () => {
    const email = uniqueEmail('signup');
    const { data, error } = await publishableClient().auth.signUp({
      email,
      password: `Pw-${crypto.randomUUID()}`,
    });

    expect(error).not.toBeNull();
    expect(error?.status).toBeGreaterThanOrEqual(400);
    expect(data.session).toBeNull();
    // and no user was created
    expect(await authUserExists(email)).toBe(false);
  });

  it('SEC-20: the passwordless endpoints do not create users either (OTP and magic link)', async () => {
    const viaOtp = uniqueEmail('otp');
    const viaMagicLink = uniqueEmail('magic');

    const otp = await publishableClient().auth.signInWithOtp({
      email: viaOtp,
      options: { shouldCreateUser: true },
    });
    // supabase-js has no call for the magic-link endpoint: ask the Auth server directly
    const magicLink = await fetch(`${process.env.SUPABASE_URL}/auth/v1/magiclink`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        apikey: process.env.SUPABASE_PUBLISHABLE_KEY ?? '',
      },
      body: JSON.stringify({ email: viaMagicLink }),
    });

    expect(otp.error).not.toBeNull();
    expect(magicLink.status).toBeGreaterThanOrEqual(400);
    expect(await authUserExists(viaOtp)).toBe(false);
    expect(await authUserExists(viaMagicLink)).toBe(false);
  });

  it('AC-01: the email provider is on: a user created by the Admin API signs in with the password', async () => {
    const client = await createClient();
    const user = await createClientUser({ clientId: client.id });

    const { data, error } = await publishableClient().auth.signInWithPassword({
      email: user.email,
      password: user.password,
    });

    expect(error).toBeNull();
    expect(data.session?.access_token).toBeTruthy();
    expect(data.user?.id).toBe(user.id);
  });

  it('AC-31: the Admin API creates the profile from app_metadata, and only from it', async () => {
    const client = await createClient();
    const clientUser = await createClientUser({
      clientId: client.id,
      displayName: 'Maria Cliente',
    });
    const ceo = await createCeo({ displayName: 'Carlos CEO' });

    const { data: profiles, error } = await adminClient()
      .from('profiles')
      .select('id, role, client_id, display_name, must_change_password')
      .in('id', [clientUser.id, ceo.id]);

    expect(error).toBeNull();
    expect(profiles).toHaveLength(2);
    expect(profiles?.find((profile) => profile.id === clientUser.id)).toEqual({
      id: clientUser.id,
      role: 'client',
      client_id: client.id,
      display_name: 'Maria Cliente',
      must_change_password: true,
    });
    expect(profiles?.find((profile) => profile.id === ceo.id)).toEqual({
      id: ceo.id,
      role: 'ceo',
      client_id: null,
      display_name: 'Carlos CEO',
      must_change_password: true,
    });
  });

  it('E-18: twelve concurrent Admin API creations for one client leave exactly ten logins', async () => {
    const client = await createClient();

    const results = await Promise.allSettled(
      Array.from({ length: 12 }, () => createClientUser({ clientId: client.id })),
    );

    const created = results.filter((result) => result.status === 'fulfilled');
    expect(created).toHaveLength(10);
    const { count, error } = await adminClient()
      .from('profiles')
      .select('id', { count: 'exact', head: true })
      .eq('client_id', client.id);
    expect(error).toBeNull();
    // the limit is enforced at COMMIT under the lock of the client row: no race lets an 11th through,
    // and no refused creation left a profile behind
    expect(count).toBe(10);
  });

  it('AC-31: a user whose app_metadata has no role is not created at all (fail closed)', async () => {
    const email = uniqueEmail('norole');
    const { error } = await adminClient().auth.admin.createUser({
      email,
      password: `Pw-${crypto.randomUUID()}`,
      email_confirm: true,
      app_metadata: { display_name: 'Sem Papel' },
      // user_metadata is never read: a role there must not help
      user_metadata: { role: 'ceo' },
    });

    expect(error).not.toBeNull();
    expect(await authUserExists(email)).toBe(false);
  });
});
