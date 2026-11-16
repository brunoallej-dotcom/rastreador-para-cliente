// Fixtures for .semgrep/rules.yml. They violate the rules on purpose and are never compiled or linted.
// `ruleid:` marks the next line as a finding; `ok:` marks it as clean.

declare const supabase: any;
declare const auth: any;
declare const userInput: string;

async function getSession() {
  // ruleid: no-auth-getsession
  await supabase.auth.getSession();
  // ruleid: no-auth-getsession
  await supabase.auth?.getSession();
  // ruleid: no-auth-getsession
  await supabase['auth']['getSession']();
  // ruleid: no-auth-getsession
  await auth.getSession();
  // ruleid: no-auth-getsession
  const { getSession } = supabase.auth;
  // ruleid: no-auth-getsession
  const { getSession: read } = supabase.auth;
  // ruleid: no-auth-getsession
  const {
    auth: { getSession: nested },
  } = supabase;

  // ruleid: no-auth-getsession
  const { getSession: fromBare } = auth;

  // ok: no-auth-getsession
  await supabase.auth.getClaims();
  // ok: no-auth-getsession
  await supabase.auth.getUser();
}

function postgrestFilters() {
  // ruleid: no-interpolated-postgrest-filter
  supabase.from('t').select('id').or(`name.eq.${userInput}`);
  // ruleid: no-interpolated-postgrest-filter
  supabase
    .from('t')
    .select('id')
    .or('name.eq.' + userInput);
  // ruleid: no-interpolated-postgrest-filter
  supabase.from('t').select('id').filter('name', 'eq', `${userInput}`);
  // ruleid: no-interpolated-postgrest-filter
  supabase
    .from('t')
    .select('id')
    .filter('name', 'eq', 'a' + userInput);
  // ruleid: no-interpolated-postgrest-filter
  supabase.from('t').select('id').textSearch('name', `${userInput}`);
  // ruleid: no-interpolated-postgrest-filter
  supabase
    .from('t')
    .select('id')
    .textSearch('name', 'a' + userInput);

  // ok: no-interpolated-postgrest-filter
  supabase.from('t').select('id').or('name.eq.fixed,name.eq.other');
  // ok: no-interpolated-postgrest-filter
  supabase.from('t').select('id').filter('name', 'eq', userInput);
  // ok: no-interpolated-postgrest-filter
  supabase.from('t').select('id').eq('name', `${userInput}`);
  // ok: no-interpolated-postgrest-filter
  [userInput].filter((value) => value === `${userInput}`);
}

function authAdmin() {
  // ruleid: no-auth-admin-outside-facade
  supabase.auth.admin.createUser({});
  // ruleid: no-auth-admin-outside-facade
  supabase.auth?.admin.listUsers();
  // ruleid: no-auth-admin-outside-facade
  supabase.auth['admin'].deleteUser('id');
  // ruleid: no-auth-admin-outside-facade
  supabase['auth']['admin'].getUserById('id');
  // ruleid: no-auth-admin-outside-facade
  auth.admin.updateUserById('id', {});
  // ruleid: no-auth-admin-outside-facade
  const { admin } = supabase.auth;
  // ruleid: no-auth-admin-outside-facade
  const { admin: named } = supabase.auth;
  // ruleid: no-auth-admin-outside-facade
  const {
    auth: { admin: nested },
  } = supabase;
  // ruleid: no-auth-admin-outside-facade
  const { admin: fromBare } = auth;

  // ok: no-auth-admin-outside-facade
  supabase.auth.getClaims();
  // ok: no-auth-admin-outside-facade
  supabase.auth.mfa.enroll({ factorType: 'totp' });
  // ok: no-auth-admin-outside-facade
  const administrator = { admin: true };
}

function appMetadata() {
  // ruleid: no-app-metadata-role-but-client
  const ceo = { email: 'a@b.test', app_metadata: { role: 'ceo', display_name: 'x' } };
  // ruleid: no-app-metadata-role-but-client
  const variable = { app_metadata: { role: userInput } };
  // ruleid: no-app-metadata-role-but-client
  const spread = { app_metadata: { ...userInput, role: 'client' } };
  // ruleid: no-app-metadata-role-but-client
  const whole = { app_metadata: userInput };
  // ruleid: no-app-metadata-role-but-client
  const noRole = { app_metadata: { display_name: 'x' } };
  // ruleid: no-app-metadata-role-but-client
  supabase.auth.updateUser({ app_metadata: { role: 'ceo' } });

  // ok: no-app-metadata-role-but-client
  const client = { email: 'a@b.test', app_metadata: { role: 'client', client_id: userInput } };
  // ok: no-app-metadata-role-but-client
  const read = supabase.user.app_metadata.role;
  // ok: no-app-metadata-role-but-client
  const other = { metadata: { role: 'ceo' } };
}
