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
