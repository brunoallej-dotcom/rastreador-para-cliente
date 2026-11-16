// `scripts/create-ceo.ts` against the LOCAL Supabase (Auth Admin API + the profile trigger). The
// command itself (`pnpm ceo:create`) is a manual operation and is not run here: these tests call its
// exported functions with the secret-key client of the test setup.
import { describe, expect, it } from 'vitest';
import { computePendingActions } from '@/shared/kernel';
import { createCeoAccount, EXIT, main } from '../../scripts/create-ceo';
import {
  adminClient,
  authUserExists,
  createClient,
  createClientUser,
  publishableClient,
  uniqueEmail,
} from '../helpers/fixtures';

const authAdmin = () => adminClient().auth.admin;

async function profileOf(userId: string) {
  const { data, error } = await adminClient()
    .from('profiles')
    .select('role, client_id, display_name, must_change_password')
    .eq('id', userId)
    .maybeSingle();
  if (error) throw new Error(`profile read failed: ${error.message}`);
  return data;
}

describe('createCeoAccount against the local stack', () => {
  it('AC-31: creates a CEO born with CHANGE_PASSWORD and ENROLL_MFA pending', async () => {
    const email = uniqueEmail('ceo-script');

    const result = await createCeoAccount(
      { authAdmin: authAdmin() },
      { email, name: 'CEO do Script' },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const { userId, temporaryPassword } = result.value;

    // the profile came from app_metadata, in the same transaction as the user
    expect(await profileOf(userId)).toEqual({
      role: 'ceo',
      client_id: null,
      display_name: 'CEO do Script',
      must_change_password: true,
    });

    // and what the app sees at the first sign-in: both pendings
    const supabase = publishableClient();
    const signIn = await supabase.auth.signInWithPassword({ email, password: temporaryPassword });
    expect(signIn.error).toBeNull();
    const { data: principal, error } = await supabase.rpc('current_principal').single();
    expect(error).toBeNull();
    expect(principal).toMatchObject({ role: 'ceo', must_change_password: true });
    expect(
      computePendingActions({
        role: principal?.role ?? 'client',
        mustChangePassword: principal?.must_change_password ?? false,
        hasVerifiedTotp: principal?.has_verified_totp ?? true,
        aal: principal?.aal === 'aal2' ? 'aal2' : 'aal1',
      }),
    ).toEqual(['CHANGE_PASSWORD', 'ENROLL_MFA']);
  });

  it('F-42, RF-14: creating a CEO leaves exactly one audit row: account.provisioned, without actor, in auth_admin channel', async () => {
    const result = await createCeoAccount(
      { authAdmin: authAdmin() },
      { email: uniqueEmail('ceo-audit'), name: 'CEO Auditado' },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const { data, error } = await adminClient()
      .from('audit_events')
      .select(
        'action, resource_type, actor_id, actor_role, client_id, process_id, request_id, metadata',
      )
      .eq('resource_id', result.value.userId);

    expect(error).toBeNull();
    expect(data).toEqual([
      {
        action: 'account.provisioned',
        resource_type: 'account',
        actor_id: null,
        actor_role: null,
        client_id: null,
        process_id: null,
        request_id: null,
        // db_user: the connection role that created the account; through the Auth Admin API it is
        // GoTrue's own role, which tells it apart from a CEO inserted by direct SQL (T-13)
        metadata: { role: 'ceo', channel: 'auth_admin', db_user: 'supabase_auth_admin' },
      },
    ]);
  });

  it('F-42: an e-mail that is refused leaves no audit row for it, and the account it names keeps its own single row', async () => {
    const email = uniqueEmail('ceo-audit-dup');
    const first = await createCeoAccount({ authAdmin: authAdmin() }, { email, name: 'CEO Um' });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const before = await adminClient()
      .from('audit_events')
      .select('id')
      .eq('action', 'account.provisioned');

    const again = await createCeoAccount({ authAdmin: authAdmin() }, { email, name: 'CEO Dois' });

    expect(again).toEqual({ ok: false, error: { kind: 'email_taken' } });
    const after = await adminClient()
      .from('audit_events')
      .select('id')
      .eq('action', 'account.provisioned');
    expect(after.data?.length).toBe(before.data?.length);
    const own = await adminClient()
      .from('audit_events')
      .select('id', { count: 'exact', head: true })
      .eq('resource_id', first.value.userId);
    expect(own.count).toBe(1);
  });

  it('F-42: a client login created through the same Auth Admin API is NOT audited by the trigger (record_account_provisioned does it, on a CEO call)', async () => {
    const tenant = await createClient();
    const login = await createClientUser({ clientId: tenant.id });

    const { count, error } = await adminClient()
      .from('audit_events')
      .select('id', { count: 'exact', head: true })
      .eq('resource_id', login.id);

    expect(error).toBeNull();
    expect(count).toBe(0);
  });

  it('AC-31: the CEO is created WITH the temporary password, so it is the baseline: clearing the pendency needs a real change (ADR 0007)', async () => {
    const email = uniqueEmail('ceo-baseline');
    const result = await createCeoAccount({ authAdmin: authAdmin() }, { email, name: 'CEO Base' });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const supabase = publishableClient();
    await supabase.auth.signInWithPassword({ email, password: result.value.temporaryPassword });
    const { error } = await supabase.rpc('mark_password_changed');

    expect(error).toMatchObject({ code: 'P0001', message: 'PASSWORD_UNCHANGED' });
    expect((await profileOf(result.value.userId))?.must_change_password).toBe(true);
  });

  it('AC-31: the role lives in app_metadata only, never in user_metadata', async () => {
    const result = await createCeoAccount(
      { authAdmin: authAdmin() },
      { email: uniqueEmail('ceo-meta'), name: 'CEO Meta' },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const { data, error } = await authAdmin().getUserById(result.value.userId);
    expect(error).toBeNull();
    expect(data.user?.app_metadata).toMatchObject({ role: 'ceo', display_name: 'CEO Meta' });
    // nothing of ours in user_metadata, which the user can edit and which is never read
    // (the Auth server adds `email_verified` by itself)
    expect(data.user?.user_metadata).not.toHaveProperty('role');
    expect(data.user?.user_metadata).not.toHaveProperty('display_name');
  });

  it('each CEO gets a password of its own', async () => {
    const first = await createCeoAccount(
      { authAdmin: authAdmin() },
      { email: uniqueEmail('ceo-a'), name: 'CEO A' },
    );
    const second = await createCeoAccount(
      { authAdmin: authAdmin() },
      { email: uniqueEmail('ceo-b'), name: 'CEO B' },
    );
    expect(first.ok && second.ok).toBe(true);
    if (first.ok && second.ok) {
      expect(first.value.temporaryPassword).not.toBe(second.value.temporaryPassword);
    }
  });

  it('an e-mail that already has a CEO account is refused, in any spelling, and the account is untouched', async () => {
    const email = uniqueEmail('ceo-dup');
    const first = await createCeoAccount({ authAdmin: authAdmin() }, { email, name: 'CEO Um' });
    expect(first.ok).toBe(true);
    if (!first.ok) return;

    const again = await createCeoAccount({ authAdmin: authAdmin() }, { email, name: 'CEO Dois' });
    const upper = await createCeoAccount(
      { authAdmin: authAdmin() },
      { email: email.toUpperCase(), name: 'CEO Tres' },
    );

    expect(again).toEqual({ ok: false, error: { kind: 'email_taken' } });
    expect(upper).toEqual({ ok: false, error: { kind: 'email_taken' } });
    // the first account: same name, and the first password still works (nothing was reset)
    expect((await profileOf(first.value.userId))?.display_name).toBe('CEO Um');
    const signIn = await publishableClient().auth.signInWithPassword({
      email,
      password: first.value.temporaryPassword,
    });
    expect(signIn.error).toBeNull();
  });

  it('AC-31: the script cannot promote an existing client login to CEO: its e-mail is refused and the role stays', async () => {
    const tenant = await createClient();
    const login = await createClientUser({ clientId: tenant.id });

    const result = await createCeoAccount(
      { authAdmin: authAdmin() },
      { email: login.email, name: 'Promotion Attempt' },
    );

    expect(result).toEqual({ ok: false, error: { kind: 'email_taken' } });
    expect(await profileOf(login.id)).toMatchObject({ role: 'client', client_id: tenant.id });
    // and the client login still opens with its own password
    const signIn = await publishableClient().auth.signInWithPassword({
      email: login.email,
      password: login.password,
    });
    expect(signIn.error).toBeNull();
  });
});

describe('main against the local stack', () => {
  async function runMain(email: string, name: string) {
    let stdout = '';
    let stderr = '';
    // the target is the host of the local stack; the env is the shell's (CI cleared: this test may run
    // in a pipeline) and no env file is read
    const target = new URL(process.env.SUPABASE_URL ?? '').host;
    const code = await main(['--target', target, '--email', email, '--name', name], {
      stdout: { write: (text) => void (stdout += text) },
      stderr: { write: (text) => void (stderr += text) },
      env: { ...process.env, CI: undefined },
      stdoutIsTTY: true,
      readEnvFile: () => undefined,
    });
    return { code, stdout, stderr };
  }

  it('AC-31: the whole command creates the CEO, prints the password once and nothing sensitive, exits 0', async () => {
    const email = uniqueEmail('ceo-main');

    const { code, stdout, stderr } = await runMain(email, 'CEO do Comando');

    expect(code).toBe(EXIT.created);
    const password = /^([A-Za-z0-9]{20})\n$/.exec(stdout)?.[1];
    expect(password, 'stdout carries exactly one line with the password').toBeDefined();
    expect(stderr).not.toContain(password ?? '');
    for (const text of [stdout, stderr]) {
      expect(text).not.toContain(process.env.SUPABASE_SECRET_KEY ?? 'unset');
      expect(text).not.toContain(email);
    }
    // the printed password is the real one
    const signIn = await publishableClient().auth.signInWithPassword({
      email,
      password: password ?? '',
    });
    expect(signIn.error).toBeNull();
  });

  it('AC-31: running it again for the same e-mail exits 3, prints no password and creates nothing', async () => {
    const email = uniqueEmail('ceo-main-dup');
    expect((await runMain(email, 'CEO Primeiro')).code).toBe(EXIT.created);

    const { code, stdout, stderr } = await runMain(email, 'CEO Segundo');

    expect(code).toBe(EXIT.emailTaken);
    expect(stdout).toBe('');
    expect(stderr).not.toContain(email);
    expect(await authUserExists(email)).toBe(true);
  });
});
