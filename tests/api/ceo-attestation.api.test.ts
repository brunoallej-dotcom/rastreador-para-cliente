// API tests of the backend-attested CEO elevation (F-50 b, F-60, F-61, F-63) and of the 72 h validity of
// a temporary password (F-41), Wave 6.1 (ADR 0013): the real route modules, the real pipeline and
// wiring (Postgres rate limiter, Supabase resolver, the admin path of the attestor), and the local
// Supabase (Auth + PostgREST + the database functions).
//
// The attacker of these tests holds the password of a CEO and the publishable key: he talks to Supabase
// Auth directly with supabase-js, exactly as anyone could. What the backend does about it is what is
// being checked: a session he elevates there is not a CEO's, and a code he finds there is no use at the
// backend.
import { createClient as createSupabaseClient } from '@supabase/supabase-js';
import { afterEach, beforeEach, describe, expect, it, onTestFailed, vi } from 'vitest';
import { POST as loginRoute } from '@/app/api/v1/auth/login/route';
import { GET as sessionRoute } from '@/app/api/v1/auth/session/route';
import type * as LoggerModule from '@/shared/observability/logger';
import type { Database } from '@/shared/db/database.types';
import { timing } from '@/shared/http/response-floor';
import {
  activationProofOf,
  agePasswordBaseline,
  backendChallengeIdsOf,
  firstActivationFactorOf,
  markPasswordPendingFixture,
  resetFirstActivation,
} from '../helpers/db';
import { listClientsViaApi } from '../helpers/clients';
import { expectToMatchContract } from '../helpers/contract';
import {
  adminClient,
  ceoAal2Client,
  createClient,
  createClientUser,
  directAal2Session,
  publishableClient,
  sessionIdOf,
  uniqueEmail,
} from '../helpers/fixtures';
import {
  bodyOf,
  createCookieStore,
  invoke,
  readSessionCookie,
  spyOnSupabaseFetch,
  withoutRequestId,
  writeSessionCookie,
  type CookieStore,
  type SessionTokens,
} from '../helpers/http';
import {
  enrollTotp,
  enrollTotpViaApi,
  factorsOf,
  loginAsCeoReadyToEnroll,
  loginAsCeoWithMfa,
  loginViaApi,
  nextTotpCode,
  signInCeoWithMfa,
  verifyTotpViaApi,
  wrongTotpCode,
} from '../helpers/mfa';

// ------------------------------------------------------------------------------ logger ----
// The process logger is replaced by one that captures its lines; everything else is real.

const logged = vi.hoisted(() => ({ lines: [] as string[] }));

vi.mock('@/shared/observability/logger', async (importOriginal) => {
  const original = await importOriginal<typeof LoggerModule>();
  const logger = original.createLogger({
    level: 'trace',
    destination: {
      write(chunk: string) {
        logged.lines.push(chunk);
      },
    },
  });
  return { ...original, getLogger: () => logger };
});

const records = () => logged.lines.map((line) => JSON.parse(line) as Record<string, unknown>);
const events = (name: string) => records().filter((record) => record['event'] === name);

/** Every primitive value of a log record, at any depth. */
function valuesOf(value: unknown): unknown[] {
  if (Array.isArray(value)) return value.flatMap(valuesOf);
  if (typeof value === 'object' && value !== null) return Object.values(value).flatMap(valuesOf);
  return [value];
}

beforeEach(() => {
  logged.lines.length = 0;
  // a refused login waits for its floor (F-05); these tests do not wait for real
  vi.spyOn(timing, 'sleep').mockResolvedValue(undefined);
  onTestFailed(() => {
    const errors = logged.lines.filter((line) => line.includes('"level":"error"'));
    if (errors.length > 0)
      process.stderr.write(`server errors of the failed test:\n${errors.join('')}`);
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

// --------------------------------------------------------------------------------- helpers ----

const getSession = (cookies: CookieStore) =>
  invoke(sessionRoute, { path: '/auth/session', cookies });

const login = (email: string, password: string, cookies = createCookieStore()) =>
  invoke(loginRoute, { method: 'POST', path: '/auth/login', body: { email, password }, cookies });

/** A browser holding the session a supabase-js client holds: what the attacker sends the backend. */
async function cookiesOf(client: ReturnType<typeof publishableClient>): Promise<CookieStore> {
  const { data } = await client.auth.getSession();
  if (data.session === null) throw new Error('the client holds no session');
  const cookies = createCookieStore();
  writeSessionCookie(cookies, data.session as unknown as SessionTokens);
  return cookies;
}

/** The status of a CEO-only operation: 200 for a CEO, 403 for a session that is not one yet. */
const listClientsStatus = async (cookies: CookieStore) => (await listClientsViaApi(cookies)).status;

/** The body of a wrong code, from a CEO of its own: what a refused attestation must look like. */
async function wrongCodeBody(): Promise<unknown> {
  const { cookies } = await loginAsCeoReadyToEnroll();
  const enrollment = await enrollTotp(cookies);
  const response = await verifyTotpViaApi(cookies, { code: wrongTotpCode(enrollment.secret) });
  expect(response.status).toBe(422);
  return withoutRequestId(await bodyOf(response));
}

/** The audit events a user has with that action, read with the secret key (a fixture). */
async function auditOf(userId: string, action: string) {
  const { data, error } = await adminClient()
    .from('audit_events')
    .select('action, actor_id, actor_role, resource_type, resource_id, metadata')
    .eq('resource_id', userId)
    .eq('action', action);
  if (error) throw new Error(`reading audit_events failed: ${error.message}`);
  return data;
}

// --------------------------------------------------------------------------------- E-32 ----

describe('E-32: an aal2 session obtained straight at Supabase Auth is not a CEO', () => {
  it('E-32: PostgREST denies the CEO functions and hides the data, and the backend shows the session as pending VERIFY_MFA', async () => {
    const legit = await loginAsCeoWithMfa();
    // the attacker: password + publishable key. A code he found: here, the CEO's next one.
    const attacker = await directAal2Session(
      legit.ceo,
      { factorId: legit.factorId, secret: legit.secret },
      nextTotpCode(legit.secret),
    );

    const { data: session } = await attacker.supabase.auth.getSession();
    const claims = JSON.parse(
      Buffer.from((session.session?.access_token ?? '').split('.')[1] ?? '', 'base64url').toString(
        'utf8',
      ),
    ) as Record<string, unknown>;
    expect(claims['aal']).toBe('aal2'); // Auth did elevate it: the claim alone is worth nothing

    // PostgREST: not a CEO. The write function refuses and RLS shows nothing.
    const created = await attacker.supabase.rpc('create_client', { p_name: 'Cliente do atacante' });
    expect(created.error?.code).toBe('42501');
    expect(created.error?.message).toBe('FORBIDDEN');
    const clients = await attacker.supabase.from('clients').select('id');
    expect(clients.error).toBeNull();
    expect(clients.data).toEqual([]);
    const principal = await attacker.supabase.rpc('current_principal');
    expect(principal.error).toBeNull();
    expect(principal.data).toEqual([
      expect.objectContaining({ user_id: legit.ceo.id, aal: 'aal1', has_verified_totp: true }),
    ]);

    // the backend: the same token is an aal1 session with VERIFY_MFA pending, so /admin/* refuses it
    const cookies = await cookiesOf(attacker.supabase);
    expect(await getSession(cookies).then(bodyOf)).toMatchObject({
      user: { id: legit.ceo.id },
      aal: 'aal1',
      pendingActions: ['VERIFY_MFA'],
    });
    const refused = await listClientsViaApi(cookies);
    expect(refused.status).toBe(403);
    expect(await bodyOf(refused)).toMatchObject({ code: 'MFA_VERIFICATION_REQUIRED' });

    // the CEO, on the session the backend attested, is untouched
    expect(await listClientsStatus(legit.cookies)).toBe(200);
    expect(await getSession(legit.cookies).then(bodyOf)).toMatchObject({ aal: 'aal2' });
  });

  it('E-32: a factor the CEO enrolled and verified at Auth by themselves is no better: the session is not a CEO', async () => {
    const { ceo } = await loginAsCeoReadyToEnroll();
    // no backend enrollment at all: the whole MFA ceremony is done straight at Auth
    const direct = await directAal2Session(ceo);

    const created = await direct.supabase.rpc('create_client', { p_name: 'Cliente direto' });
    expect(created.error?.code).toBe('42501');
    const cookies = await cookiesOf(direct.supabase);
    expect(await getSession(cookies).then(bodyOf)).toMatchObject({
      aal: 'aal1',
      pendingActions: ['VERIFY_MFA'],
    });
    expect(await listClientsStatus(cookies)).toBe(403);
  });

  it('E-36: the attestation survives a token refresh: the session id and aal2 do', async () => {
    const legit = await loginAsCeoWithMfa();
    const before = readSessionCookie(legit.cookies);
    // an expired access token makes the pipeline renew it with the refresh token
    writeSessionCookie(legit.cookies, { ...before, expires_at: 1 });

    const response = await listClientsViaApi(legit.cookies);

    expect(response.status).toBe(200);
    const after = readSessionCookie(legit.cookies);
    expect(after.access_token).not.toBe(before.access_token);
    expect(sessionIdOf(after.access_token)).toBe(sessionIdOf(before.access_token));
    expect(await getSession(legit.cookies).then(bodyOf)).toMatchObject({
      aal: 'aal2',
      pendingActions: [],
    });
  });
});

// --------------------------------------------------------------------------------- E-33 ----

describe('E-33: a code found straight at Auth is no use at the backend', () => {
  it('E-33: the same code replayed through the backend inside the window is 422, no attestation, an alert, and every session of the CEO is gone', async () => {
    const legit = await loginAsCeoWithMfa();
    const reference = await wrongCodeBody();
    // the attacker finds a valid code at Auth (no replay protection there) and verifies it
    const code = nextTotpCode(legit.secret);
    const attacker = await directAal2Session(
      legit.ceo,
      { factorId: legit.factorId, secret: legit.secret },
      code,
    );
    const attackerCookies = await cookiesOf(attacker.supabase);
    logged.lines.length = 0;

    // ... and presents it to the backend with his own session, which has not burned it (it never
    // saw it): the whole point of the attestation is that this does not make him a CEO
    const response = await verifyTotpViaApi(attackerCookies, { code });

    expect(response.status).toBe(422);
    expectToMatchContract('verifyTotp', 422, await bodyOf(response), response);
    expect(withoutRequestId(await bodyOf(response))).toEqual(reference); // uniform answer

    // the alert: error level, a stable name, the reason, ids only
    const [alert, ...more] = events('auth.mfa.attestation_refused');
    expect(more).toEqual([]);
    expect(alert).toMatchObject({
      level: 'error',
      userId: legit.ceo.id,
      factorId: legit.factorId,
      attestationReason: 'oracle',
    });
    expect(events('auth.mfa.failed')).toEqual([
      expect.objectContaining({ reason: 'attestation_refused', userId: legit.ceo.id }),
    ]);
    const everything = JSON.stringify(valuesOf(records()));
    for (const secret of [code, legit.secret, legit.ceo.password, legit.ceo.email]) {
      expect(everything).not.toContain(secret);
    }

    // every session of the CEO is gone: the attested one and the attacker's
    for (const cookies of [legit.cookies, attackerCookies]) {
      expect((await getSession(cookies)).status).toBe(401);
    }
    expect((await listClientsViaApi(legit.cookies)).status).toBe(401);

    // the audit trail: who, what and why (no PII, no actor: the backend acted for nobody)
    expect(await auditOf(legit.ceo.id, 'auth.mfa_attestation_refused')).toEqual([
      {
        action: 'auth.mfa_attestation_refused',
        actor_id: null,
        actor_role: null,
        resource_type: 'account',
        resource_id: legit.ceo.id,
        metadata: {
          reason: 'oracle',
          factor_id: legit.factorId,
          severity: 'alert',
          revoked: true,
        },
      },
    ]);
  });

  it('E-33: after the refusal the CEO can sign in again (VERIFY_MFA pending) and the factor is intact', async () => {
    const legit = await loginAsCeoWithMfa();
    const code = nextTotpCode(legit.secret);
    const attacker = await directAal2Session(
      legit.ceo,
      { factorId: legit.factorId, secret: legit.secret },
      code,
    );
    expect((await verifyTotpViaApi(await cookiesOf(attacker.supabase), { code })).status).toBe(422);

    // the refusal deleted the sessions, not the factor: the way back is a new login, then a code once
    // the 120 s window of the code the attacker verified has passed
    expect(await factorsOf(legit.ceo.id)).toEqual([
      { id: legit.factorId, type: 'totp', status: 'verified' },
    ]);
    const fresh = await loginViaApi(legit.ceo);
    expect(await getSession(fresh).then(bodyOf)).toMatchObject({
      aal: 'aal1',
      pendingActions: ['VERIFY_MFA'],
    });
  });

  it('E-33: the oracle only counts what was verified OUTSIDE the backend: a second legitimate device inside the window is attested', async () => {
    const legit = await loginAsCeoWithMfa();

    // a second device verifies right after the first, both through the backend, inside the same window
    const second = await signInCeoWithMfa(legit);

    expect(await listClientsStatus(second)).toBe(200);
    expect(await getSession(second).then(bodyOf)).toMatchObject({
      aal: 'aal2',
      pendingActions: [],
    });
    expect(await listClientsStatus(legit.cookies)).toBe(200);
    expect(events('auth.mfa.attestation_refused')).toEqual([]);
  });

  it('E-33: a wrong code at Auth leaves no verified challenge: the attacker guessing cannot make the CEO unable to sign in', async () => {
    const legit = await loginAsCeoWithMfa();
    const attacker = publishableClient();
    await attacker.auth.signInWithPassword({
      email: legit.ceo.email,
      password: legit.ceo.password,
    });
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const challenge = await attacker.auth.mfa.challenge({ factorId: legit.factorId });
      const refused = await attacker.auth.mfa.verify({
        factorId: legit.factorId,
        challengeId: challenge.data?.id ?? '',
        code: wrongTotpCode(legit.secret, attempt),
      });
      expect(refused.error).not.toBeNull();
    }

    const second = await signInCeoWithMfa(legit);

    expect(await listClientsStatus(second)).toBe(200);
    expect(events('auth.mfa.attestation_refused')).toEqual([]);
  });
});

// ------------------------------------------------------------------------- F-60 and F-61 ----

describe('F-60, F-61: factors the backend did not enroll', () => {
  /** A named second factor, made and verified (or not) straight at Auth with the CEO's password. */
  async function plantFactor(
    ceo: { email: string; password: string },
    options: { verify: boolean },
  ) {
    const direct = publishableClient();
    const signedIn = await direct.auth.signInWithPassword(ceo);
    expect(signedIn.error).toBeNull();
    const planted = await direct.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'planted' });
    if (planted.error) throw new Error(`planting failed: ${planted.error.message}`);
    if (options.verify) {
      const challenge = await direct.auth.mfa.challenge({ factorId: planted.data.id });
      if (challenge.error) throw new Error(`challenge failed: ${challenge.error.message}`);
      const activated = await direct.auth.mfa.verify({
        factorId: planted.data.id,
        challengeId: challenge.data.id,
        code: nextTotpCode(planted.data.totp.secret),
      });
      expect(activated.error).toBeNull();
    }
    return { direct, id: planted.data.id, secret: planted.data.totp.secret };
  }

  it('F-60: a candidate planted straight at Auth does not block the first activation without a factorId', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const own = await enrollTotp(cookies);
    const planted = await plantFactor(ceo, { verify: false });
    expect(await factorsOf(ceo.id)).toHaveLength(2);
    logged.lines.length = 0;

    // the CEO sends only the code: with two candidates the old resolution said `factor_ambiguous`
    const response = await verifyTotpViaApi(cookies, { code: nextTotpCode(own.secret) });

    expect(response.status).toBe(200);
    expectToMatchContract('verifyTotp', 200, await bodyOf(response), response);
    expect(await bodyOf(response)).toMatchObject({ aal: 'aal2', pendingActions: [] });
    expect(await listClientsStatus(cookies)).toBe(200);
    expect(events('auth.mfa.factor_ambiguous')).toEqual([]);
    // the app never makes a factor of its own kind outside the enrollment: the planted one is an alert
    expect(events('auth.mfa.foreign_factor')).toEqual([
      expect.objectContaining({
        level: 'error',
        userId: ceo.id,
        factorId: own.factorId,
        foreignFactorCount: 1,
      }),
    ]);
    expect(events('auth.mfa.verified')).toEqual([
      expect.objectContaining({ factorId: own.factorId, candidateCount: 2, foreignFactorCount: 1 }),
    ]);
    expect((await factorsOf(ceo.id)).find((factor) => factor.id === own.factorId)?.status).toBe(
      'verified',
    );
    expect(planted.id).not.toBe(own.factorId);
  });

  it('F-61: a factor activated straight at Auth is refused attestation, with the alert, and every session of the CEO is gone', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    await enrollTotp(cookies);
    // the attacker plants a factor and verifies it at Auth (with no verified factor yet, Auth asks for
    // no aal2); Auth then deletes the CEO's candidate
    const planted = await plantFactor(ceo, { verify: true });
    const plantedCookies = await cookiesOf(planted.direct);
    expect(await factorsOf(ceo.id)).toEqual([{ id: planted.id, type: 'totp', status: 'verified' }]);
    // he comes in through the backend, with the password and a fresh code of HIS factor
    const attacker = await loginViaApi(ceo);
    const reference = await wrongCodeBody();
    logged.lines.length = 0;

    const response = await verifyTotpViaApi(attacker, {
      factorId: planted.id,
      code: nextTotpCode(planted.secret),
    });

    expect(response.status).toBe(422);
    expectToMatchContract('verifyTotp', 422, await bodyOf(response), response);
    expect(withoutRequestId(await bodyOf(response))).toEqual(reference);
    expect(events('auth.mfa.attestation_refused')).toEqual([
      expect.objectContaining({
        level: 'error',
        userId: ceo.id,
        factorId: planted.id,
        attestationReason: 'factor_not_backend',
      }),
    ]);
    for (const jar of [attacker, plantedCookies, cookies]) {
      expect((await getSession(jar)).status).toBe(401);
    }
    expect(await auditOf(ceo.id, 'auth.mfa_attestation_refused')).toEqual([
      expect.objectContaining({
        metadata: {
          reason: 'factor_not_backend',
          factor_id: planted.id,
          severity: 'alert',
          revoked: true,
        },
      }),
    ]);
  });

  it('F-61: the CEO code of THEIR factor, sent without a factorId, is refused as factor_not_found (the planted factor is not theirs), and the log raises the alert', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const own = await enrollTotp(cookies);
    const planted = await plantFactor(ceo, { verify: true });
    // the CEO signs in again: a verified factor exists, so VERIFY_MFA is pending
    const fresh = await loginViaApi(ceo);
    expect(await getSession(fresh).then(bodyOf)).toMatchObject({ pendingActions: ['VERIFY_MFA'] });
    logged.lines.length = 0;

    const response = await verifyTotpViaApi(fresh, { code: nextTotpCode(own.secret) });

    expect(response.status).toBe(422);
    expectToMatchContract('verifyTotp', 422, await bodyOf(response), response);
    // Verifying the planted factor at Auth DELETED the CEO's candidate: the account has one factor,
    // the attacker's. It is not among the ones the backend enrolled, so there is nothing to resolve
    // and the CEO's code is not tried on it.
    expect(await factorsOf(ceo.id)).toEqual([{ id: planted.id, type: 'totp', status: 'verified' }]);
    expect(events('auth.mfa.failed')).toEqual([
      expect.objectContaining({
        reason: 'factor_not_found',
        factorSource: 'session',
        candidateCount: 1,
        foreignFactorCount: 1,
      }),
    ]);
    expect(events('auth.mfa.failed')[0]).not.toHaveProperty('factorId');
    expect(events('auth.mfa.foreign_factor')).toEqual([
      expect.objectContaining({ level: 'error', userId: ceo.id, foreignFactorCount: 1 }),
    ]);
    // and nothing was elevated
    expect(await getSession(fresh).then(bodyOf)).toMatchObject({ aal: 'aal1' });
  });
});

// --------------------------------------------------------------------------------- E-37 ----

describe('E-37: fail closed', () => {
  it('E-37: when the attestation cannot be written the answer is 503 and the session stays at VERIFY_MFA; the next code attests it', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);

    // the database function of the attestation is unavailable (the admin path answers 503)
    const spy = spyOnSupabaseFetch((url) =>
      url.includes('/rest/v1/rpc/attest_mfa_session')
        ? Response.json({ message: 'down' }, { status: 503 })
        : undefined,
    );
    let failed: Response;
    try {
      failed = await verifyTotpViaApi(cookies, { code: nextTotpCode(enrollment.secret) });
    } finally {
      spy.restore();
    }

    expect(failed.status).toBe(503);
    expectToMatchContract('verifyTotp', 503, await bodyOf(failed), failed);
    // the 503 tells the CEO what to do: this code is burned, wait for the next one
    expect(await bodyOf(failed)).toMatchObject({
      code: 'SERVICE_UNAVAILABLE',
      detail: expect.stringContaining('next code') as string,
    });
    // the Auth server did take the code (the session is aal2 there) but nothing is attested
    expect(await factorsOf(ceo.id)).toEqual([
      { id: enrollment.factorId, type: 'totp', status: 'verified' },
    ]);
    expect(await getSession(cookies).then(bodyOf)).toMatchObject({
      aal: 'aal1',
      pendingActions: ['VERIFY_MFA'],
    });
    expect(await listClientsStatus(cookies)).toBe(403);

    // the CEO verifies again with the next code: the activation by the backend is recovered from the
    // proof the database wrote when Auth activated the factor (F-73), and the session is attested. The
    // principal of the retry is a returning one (VERIFY_MFA, no ENROLL_MFA), but the database says it
    // ACTIVATED the factor now (F-72), and it deletes the other sessions of the CEO in the same
    // transaction (F-74): the app asks the Auth server for no revocation at all
    const retrySpy = spyOnSupabaseFetch();
    let retry: Response;
    try {
      retry = await verifyTotpViaApi(cookies, { code: nextTotpCode(enrollment.secret) });
    } finally {
      retrySpy.restore();
    }
    expect(retry.status).toBe(200);
    expect(await bodyOf(retry)).toMatchObject({ aal: 'aal2', pendingActions: [] });
    expect(await listClientsStatus(cookies)).toBe(200);
    const logouts = (calls: string[]) => calls.filter((call) => call.includes('/auth/v1/logout'));
    expect(logouts(spy.calls)).toEqual([]);
    expect(logouts(retrySpy.calls)).toEqual([]);
    expect(events('auth.mfa.verified').at(-1)).toMatchObject({ activated: true });
  });

  it('F-72: a verification of a factor the database had ALREADY activated reports no activation', async () => {
    const legit = await loginAsCeoWithMfa();
    const secondLogin = await loginViaApi(legit.ceo);
    const spy = spyOnSupabaseFetch();
    try {
      const verified = await verifyTotpViaApi(secondLogin, { code: nextTotpCode(legit.secret) });
      expect(verified.status).toBe(200);
    } finally {
      spy.restore();
    }

    expect(spy.calls.filter((call) => call.includes('/auth/v1/logout'))).toEqual([]);
    expect(events('auth.mfa.verified').at(-1)).toMatchObject({ activated: false });
    expect(await listClientsStatus(legit.cookies)).toBe(200); // the first session is untouched
  });

  it('E-37: when the challenge cannot be recorded the code is never tried at Auth', async () => {
    const legit = await loginAsCeoWithMfa();
    const second = await loginViaApi(legit.ceo);

    const spy = spyOnSupabaseFetch((url) =>
      url.includes('/rest/v1/rpc/record_backend_mfa_challenge')
        ? Response.json({ message: 'down' }, { status: 503 })
        : undefined,
    );
    let response: Response;
    try {
      response = await verifyTotpViaApi(second, { code: nextTotpCode(legit.secret) });
    } finally {
      spy.restore();
    }

    expect(response.status).toBe(503);
    expect(
      spy.calls.some((call) => call.includes('/auth/v1/factors/') && call.includes('/verify')),
    ).toBe(false);
    expect(await getSession(second).then(bodyOf)).toMatchObject({
      aal: 'aal1',
      pendingActions: ['VERIFY_MFA'],
    });
  });
});

// --------------------------------------------------------------------------------- F-64 ----

describe('E-38 (F-64): deleting the CEO factor at Auth does not let anyone enroll a new one', () => {
  it('E-38: the attacker deletes the verified factor with an aal2 he got at Auth, then enrolls through the backend: refused with a 409, an alert, every session gone; only the operator reset reopens the enrollment', async () => {
    const legit = await loginAsCeoWithMfa();
    // the attacker: password, the publishable key and a code he found at Auth. With the aal2 session
    // that gives him, Auth lets him delete the factor (it asks for aal2, which he has)
    const attacker = await directAal2Session(
      legit.ceo,
      { factorId: legit.factorId, secret: legit.secret },
      nextTotpCode(legit.secret),
    );
    const attackerCookies = await cookiesOf(attacker.supabase);
    const removed = await attacker.supabase.auth.mfa.unenroll({ factorId: legit.factorId });
    expect(removed.error).toBeNull();
    expect(await factorsOf(legit.ceo.id)).toEqual([]);

    // the CEO's attested session lost its power with the factor (F-24); the account is back to ENROLL_MFA
    expect(await listClientsStatus(legit.cookies)).not.toBe(200);

    // the attacker comes through the backend with the password and tries to enroll HIS factor
    const viaBackend = await loginViaApi(legit.ceo);
    expect(await getSession(viaBackend).then(bodyOf)).toMatchObject({
      pendingActions: ['ENROLL_MFA'],
    });
    logged.lines.length = 0;

    const response = await enrollTotpViaApi(viaBackend);

    // the usual 409 (nothing new for the client), the alert and the sessions
    expect(response.status).toBe(409);
    expectToMatchContract('enrollTotp', 409, await bodyOf(response), response);
    expect(await bodyOf(response)).toMatchObject({ code: 'MFA_ALREADY_ENROLLED' });
    expect(events('auth.mfa.reenrollment_refused')).toEqual([
      expect.objectContaining({ level: 'error', userId: legit.ceo.id }),
    ]);
    for (const jar of [viaBackend, attackerCookies, legit.cookies]) {
      expect((await getSession(jar)).status).toBe(401);
    }
    expect(await auditOf(legit.ceo.id, 'auth.mfa_attestation_refused')).toEqual([
      expect.objectContaining({
        metadata: expect.objectContaining({
          reason: 'factor_reenrolled',
          severity: 'alert',
          revoked: true,
        }) as unknown,
      }),
    ]);

    // signing in again does not help: the mark of the first activation outlived the factor
    const again = await loginViaApi(legit.ceo);
    expect((await enrollTotpViaApi(again)).status).toBe(409);
    expect((await getSession(again)).status).toBe(401);

    // only the operator's reset (E-25) deletes the mark, and then the CEO enrolls and activates anew
    expect(await resetFirstActivation(legit.ceo.id)).toBe(true);
    const fresh = await loginViaApi(legit.ceo);
    const enrollment = await enrollTotp(fresh);
    const verified = await verifyTotpViaApi(fresh, { code: nextTotpCode(enrollment.secret) });
    expect(verified.status).toBe(200);
    expect(await listClientsStatus(fresh)).toBe(200);
  });

  it('E-38: a CEO that never activated a factor is not affected: the enrollment can be repeated (E-26) and activated', async () => {
    const { cookies } = await loginAsCeoReadyToEnroll();
    await enrollTotp(cookies);
    const second = await enrollTotp(cookies); // replaces the first candidate (E-26)

    const verified = await verifyTotpViaApi(cookies, { code: nextTotpCode(second.secret) });

    expect(verified.status).toBe(200);
    expect(await listClientsStatus(cookies)).toBe(200);
  });
});

// --------------------------------------------------------------------------------- F-65 ----

describe('E-39 (F-65): the replay guard is not a code oracle at PostgREST', () => {
  it('E-39: a session that is not even a CEO (an aal2 straight at Auth) cannot call consume_totp_code, in either signature', async () => {
    const legit = await loginAsCeoWithMfa();
    const attacker = await directAal2Session(
      legit.ceo,
      { factorId: legit.factorId, secret: legit.secret },
      nextTotpCode(legit.secret),
    );
    const digest = `\\x${'ab'.repeat(32)}`;

    const threeArguments = await attacker.supabase.rpc('consume_totp_code', {
      p_user_id: legit.ceo.id,
      p_factor_id: legit.factorId,
      p_code_digest: digest,
    });
    const twoArguments = await attacker.supabase.rpc('consume_totp_code', {
      p_factor_id: legit.factorId,
      p_code_digest: digest,
    } as never);

    expect(threeArguments.error?.code).toBe('42501');
    expect(threeArguments.data).toBeNull();
    expect(twoArguments.error).not.toBeNull();
    expect(twoArguments.data).toBeNull();
  });

  it('E-39: nor can the attested CEO session itself: the burn belongs to the admin path, behind the limits of the route', async () => {
    const legit = await loginAsCeoWithMfa();
    const holder = createSupabaseClient<Database>(
      process.env.SUPABASE_URL ?? '',
      process.env.SUPABASE_PUBLISHABLE_KEY ?? '',
      {
        auth: { persistSession: false, autoRefreshToken: false },
        global: {
          headers: { Authorization: `Bearer ${readSessionCookie(legit.cookies).access_token}` },
        },
      },
    );

    const result = await holder.rpc('consume_totp_code', {
      p_user_id: legit.ceo.id,
      p_factor_id: legit.factorId,
      p_code_digest: `\\x${'cd'.repeat(32)}`,
    });

    expect(result.error?.code).toBe('42501');
    expect(result.data).toBeNull();
  });
});

// --------------------------------------------------------------------------------- F-73 ----

describe('F-73: the mark and the proof of the activation are written when Auth activates the factor', () => {
  it('F-73: with the attestation unavailable (503) the mark and the proof already exist, so deleting the factor at Auth does not reopen the enrollment', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);
    expect(await firstActivationFactorOf(ceo.id)).toBeUndefined();

    const spy = spyOnSupabaseFetch((url) =>
      url.includes('/rest/v1/rpc/attest_mfa_session')
        ? Response.json({ message: 'down' }, { status: 503 })
        : undefined,
    );
    let failed: Response;
    try {
      failed = await verifyTotpViaApi(cookies, { code: nextTotpCode(enrollment.secret) });
    } finally {
      spy.restore();
    }
    expect(failed.status).toBe(503);

    // nothing was attested, and yet the activation trigger ran in the transaction of the Auth server
    expect(await firstActivationFactorOf(ceo.id)).toBe(enrollment.factorId);
    expect(await activationProofOf(enrollment.factorId)).toEqual({
      byBackend: true,
      hasChallenge: true,
      hasInstant: true,
    });

    // the session the verification elevated at Auth is aal2 there: with it the factor can be deleted
    const tokens = readSessionCookie(cookies);
    const holder = createSupabaseClient<Database>(
      process.env.SUPABASE_URL ?? '',
      process.env.SUPABASE_PUBLISHABLE_KEY ?? '',
      { auth: { persistSession: false, autoRefreshToken: false } },
    );
    const adopted = await holder.auth.setSession({
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
    });
    expect(adopted.error).toBeNull();
    const removed = await holder.auth.mfa.unenroll({ factorId: enrollment.factorId });
    expect(removed.error).toBeNull();
    expect(await factorsOf(ceo.id)).toEqual([]);
    logged.lines.length = 0;

    // enrolling through the backend (a new login: the password is all it takes) is refused
    const again = await loginViaApi(ceo);
    const response = await enrollTotpViaApi(again);

    expect(response.status).toBe(409);
    expect(await bodyOf(response)).toMatchObject({ code: 'MFA_ALREADY_ENROLLED' });
    expect(events('auth.mfa.reenrollment_refused')).toEqual([
      expect.objectContaining({ level: 'error', userId: ceo.id }),
    ]);
  });
});

// ------------------------------------------------------------------ the challenge id stays here ----

describe('the id of a challenge the backend creates never leaves the server (F-63)', () => {
  /** True when `text` carries none of the ids. */
  const carriesNone = (text: string, ids: readonly string[]) =>
    ids.every((id) => !text.includes(id));
  const headersOf = (response: Response) =>
    [...response.headers].map(([name, value]) => `${name}: ${value}`).join('\n');

  it('a verification that works: not in the response, its headers, the cookies or any log line', async () => {
    const { ceo, cookies } = await loginAsCeoReadyToEnroll();
    const enrollment = await enrollTotp(cookies);

    const response = await verifyTotpViaApi(cookies, { code: nextTotpCode(enrollment.secret) });

    expect(response.status).toBe(200);
    const ids = await backendChallengeIdsOf(ceo.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(carriesNone(await response.clone().text(), ids)).toBe(true);
    expect(carriesNone(headersOf(response), ids)).toBe(true);
    expect(carriesNone(decodeURIComponent(cookies.header() ?? ''), ids)).toBe(true);
    expect(carriesNone(logged.lines.join(''), ids)).toBe(true);
  });

  it('a verification the attestation refuses (the oracle): not in the 422, its headers, any log line or the audit trail', async () => {
    const legit = await loginAsCeoWithMfa();
    const code = nextTotpCode(legit.secret);
    const attacker = await directAal2Session(
      legit.ceo,
      { factorId: legit.factorId, secret: legit.secret },
      code,
    );
    logged.lines.length = 0;

    const response = await verifyTotpViaApi(await cookiesOf(attacker.supabase), { code });

    expect(response.status).toBe(422);
    const ids = await backendChallengeIdsOf(legit.ceo.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(carriesNone(await response.clone().text(), ids)).toBe(true);
    expect(carriesNone(headersOf(response), ids)).toBe(true);
    expect(carriesNone(logged.lines.join(''), ids)).toBe(true);
    const audit = JSON.stringify(await auditOf(legit.ceo.id, 'auth.mfa_attestation_refused'));
    expect(carriesNone(audit, ids)).toBe(true);
  });
});

// --------------------------------------------------------------------------- E-34 and E-35 ----

describe('F-41: a temporary password is valid for 72 h', () => {
  it('E-34: a login with an expired temporary password is the generic refusal, byte for byte the answer of an unknown e-mail, and sets no cookie', async () => {
    const { id: clientId } = await createClient();
    const user = await createClientUser({ clientId });
    const unknown = await login(uniqueEmail('nobody'), 'Not-The-Password-1');
    await agePasswordBaseline(user.id, 73);
    logged.lines.length = 0;

    const response = await login(user.email, user.password);

    expect(response.status).toBe(401);
    expectToMatchContract('login', 401, await bodyOf(response), response);
    expect(withoutRequestId(await bodyOf(response))).toEqual(
      withoutRequestId(await bodyOf(unknown)),
    );
    expect(response.headers.getSetCookie()).toEqual([]);
    // the log (and only the log) knows why: the same path as a disabled account
    expect(events('auth.login.failed')).toEqual([
      expect.objectContaining({ reason: 'account_inactive' }),
    ]);
  });

  it('E-34: the same login is accepted inside the 72 h', async () => {
    const { id: clientId } = await createClient();
    const user = await createClientUser({ clientId });
    await agePasswordBaseline(user.id, 71);

    const response = await login(user.email, user.password);

    expect(response.status).toBe(200);
    expect(await bodyOf(response)).toMatchObject({ pendingActions: ['CHANGE_PASSWORD'] });
  });

  it('E-34: a CEO with an expired temporary password is refused the same way', async () => {
    // a CEO that has the temporary password (again: `ceoAal2Client` completes the first access, as production
    // does, and an operator's reset gives the temporary password back, F-41)
    const { ceo } = await ceoAal2Client();
    await markPasswordPendingFixture(ceo.id);
    await agePasswordBaseline(ceo.id, 80);

    const response = await login(ceo.email, ceo.password);

    expect(response.status).toBe(401);
    expect(await bodyOf(response)).toMatchObject({ code: 'INVALID_CREDENTIALS' });
  });

  it('E-34: an expired session of that login is 401 on the next request too, even with a token that is still valid', async () => {
    const { id: clientId } = await createClient();
    const user = await createClientUser({ clientId });
    const jar = createCookieStore();
    expect((await login(user.email, user.password, jar)).status).toBe(200);
    expect((await getSession(jar)).status).toBe(200);
    await agePasswordBaseline(user.id, 73);

    expect((await getSession(jar)).status).toBe(401);
  });

  it('E-35: a reset by a CEO renews the validity: the new temporary password logs in, and the 72 h start over', async () => {
    const { id: clientId } = await createClient();
    const user = await createClientUser({ clientId });
    await agePasswordBaseline(user.id, 73);
    expect((await login(user.email, user.password)).status).toBe(401);

    // what Wave 7's reset does: the new password goes into Auth, then the database function of
    // Wave 2 records the new temporary password and ends the old sessions
    const fresh = 'Reset-Temp-Pw-2026-A1b2c3';
    const updated = await adminClient().auth.admin.updateUserById(user.id, { password: fresh });
    expect(updated.error).toBeNull();
    const { supabase } = await ceoAal2Client();
    const reset = await supabase.rpc('require_password_change', { p_user_id: user.id });
    expect(reset.error).toBeNull();

    const response = await login(user.email, fresh);
    expect(response.status).toBe(200);
    expect(await bodyOf(response)).toMatchObject({ pendingActions: ['CHANGE_PASSWORD'] });

    // and it is a fresh period: 71 h later still valid, 73 h later expired again
    await agePasswordBaseline(user.id, 71);
    expect((await login(user.email, fresh)).status).toBe(200);
    await agePasswordBaseline(user.id, 73);
    expect((await login(user.email, fresh)).status).toBe(401);
  });
});
