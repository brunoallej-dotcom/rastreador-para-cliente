// MFA helpers for the API tests (Wave 5 owns this file). They bring a CEO to `aal2` THROUGH THE HTTP
// API, the way a browser does, so the tests of the `/admin/*` routes of Waves 6 to 9 start from real
// cookies:
//
//   const session = await loginAsCeoWithMfa();
//   const response = await invoke(someAdminRoute, { path: '/admin/...', cookies: session.cookies });
//
// Everything goes through the real route modules (login, enroll, verify), the real pipeline and the
// local Supabase. The TOTP codes are computed from the secret the enroll endpoint returned, with
// `otpauth`, exactly as an authenticator app would.
//
// Test code only: it uses the secret key (to set a password) and nothing here may be imported by
// `src/`.
import { randomUUID } from 'node:crypto';
import * as OTPAuth from 'otpauth';
import { POST as loginRoute } from '@/app/api/v1/auth/login/route';
import { POST as enrollRoute } from '@/app/api/v1/auth/mfa/totp/enroll/route';
import { POST as verifyRoute } from '@/app/api/v1/auth/mfa/totp/verify/route';
import { adminClient, createCeo, publishableClient, type FixtureUser } from './fixtures';
import { bodyOf, createCookieStore, invoke, type CookieStore } from './http';

const TOTP_PERIOD_SECONDS = 30;
const MILLISECONDS = 1000;
/** Auth accepts the code of the previous and of the next period too (clock skew of one period). */
const ACCEPTED_PERIOD_SKEW = 1;
/** A wrong code must stay wrong even if the clock moved: it avoids this many periods around now. */
const WRONG_CODE_MARGIN_PERIODS = ACCEPTED_PERIOD_SKEW + 1;

function totp(secret: string): OTPAuth.TOTP {
  return new OTPAuth.TOTP({
    secret: OTPAuth.Secret.fromBase32(secret),
    algorithm: 'SHA1',
    digits: 6,
    period: TOTP_PERIOD_SECONDS,
  });
}

/**
 * The code an authenticator app shows now for `secret`. `periodOffset` shifts it by whole 30 s
 * periods: -1 and +1 are still accepted by Auth, which is how a test can use a second, different
 * code in the same period if it ever has to.
 */
export function totpCode(secret: string, periodOffset = 0): string {
  const timestamp = Date.now() + periodOffset * TOTP_PERIOD_SECONDS * MILLISECONDS;
  return totp(secret).generate({ timestamp });
}

/** `secret:periodIndex` of every code `nextTotpCode` handed out in this test process. */
const usedPeriods = new Set<string>();

/**
 * A RIGHT code that this process has not used yet for `secret`. The app refuses a code that was
 * already accepted for the same factor in the last 120 s (replay protection, F-21), so a test must
 * never send the same right code twice by accident: every right code a helper sends is a different
 * one, taken from the first unused period among now and the next, so no test needs to sleep.
 *
 * The previous period is NOT used on purpose: the Auth server accepts it only until the clock
 * crosses into the following period, so a code generated near a rollover could be refused by the
 * time it arrives. The next period is safe (it only gets closer). After two verifications of the
 * same secret inside one 30 s window it fails with a message, which means the test should use a
 * fresh CEO.
 */
export function nextTotpCode(secret: string, now: number = Date.now()): string {
  const currentPeriod = Math.floor(now / (TOTP_PERIOD_SECONDS * MILLISECONDS));
  for (const offset of [0, 1]) {
    const key = `${secret}:${currentPeriod + offset}`;
    if (usedPeriods.has(key)) continue;
    usedPeriods.add(key);
    return totp(secret).generate({
      timestamp: now + offset * TOTP_PERIOD_SECONDS * MILLISECONDS,
    });
  }
  throw new Error('all the codes Auth accepts for this secret were already used: use a fresh CEO');
}

/**
 * Six digits that are NOT the code of the current, the previous or the next period (nor of the two
 * beyond): a wrong code that cannot become right because the 30 s period turned meanwhile.
 * `index` picks the n-th such code (0, 1, 2...), for tests that send several DIFFERENT wrong codes:
 * the app burns every code it sees, so the same wrong code twice is a replay, not a second try.
 */
export function wrongTotpCode(secret: string, index = 0): string {
  const forbidden = new Set<string>();
  for (let offset = -WRONG_CODE_MARGIN_PERIODS; offset <= WRONG_CODE_MARGIN_PERIODS; offset += 1) {
    forbidden.add(totpCode(secret, offset));
  }
  let skipped = 0;
  for (let candidate = 0; candidate < 1_000_000; candidate += 1) {
    const code = String(candidate).padStart(6, '0');
    if (forbidden.has(code)) continue;
    if (skipped === index) return code;
    skipped += 1;
  }
  throw new Error('unreachable: at most five of a million codes are forbidden');
}

/** A fresh password of 40 characters: past the 12-character minimum, within 72 bytes. */
const newPassword = () => `Pw2-${randomUUID()}`;

/**
 * Clears the `CHANGE_PASSWORD` pending of a CEO the way production's database function requires:
 * the password is changed in Auth (here through the Auth Admin API, with the secret key), the user
 * signs in with the new one, and `mark_password_changed()` runs AS THAT USER. It proves the change
 * against the baseline hash (spec §3.7, ADR 0007), and an `aal1` session is enough as long as the
 * CEO has no verified factor.
 *
 * It exists because `POST /auth/password` is Wave 4's endpoint. Returns the user with the new
 * password, which is the one to log in with from now on.
 */
export async function completeFirstAccess(ceo: FixtureUser): Promise<FixtureUser> {
  const password = newPassword();
  const updated = await adminClient().auth.admin.updateUserById(ceo.id, { password });
  if (updated.error) throw new Error(`updateUserById failed: ${updated.error.message}`);

  const asUser = publishableClient();
  const signedIn = await asUser.auth.signInWithPassword({ email: ceo.email, password });
  if (signedIn.error)
    throw new Error(`sign-in with the new password failed: ${signedIn.error.message}`);

  const marked = await asUser.rpc('mark_password_changed');
  if (marked.error) throw new Error(`mark_password_changed failed: ${marked.error.message}`);

  await asUser.auth.signOut({ scope: 'local' });
  return { ...ceo, password };
}

/** `POST /auth/login` through the real route. Fails the helper (not the assertion) unless 200. */
export async function loginViaApi(
  user: Pick<FixtureUser, 'email' | 'password'>,
  cookies: CookieStore = createCookieStore(),
): Promise<CookieStore> {
  const response = await invoke(loginRoute, {
    method: 'POST',
    path: '/auth/login',
    body: { email: user.email, password: user.password },
    cookies,
  });
  if (response.status !== 200) {
    throw new Error(`login fixture failed with ${response.status}: ${await response.text()}`);
  }
  return cookies;
}

/** `POST /auth/mfa/totp/enroll` through the real route. The response is returned as it is. */
export function enrollTotpViaApi(cookies: CookieStore, options: { ip?: string | null } = {}) {
  return invoke(enrollRoute, {
    method: 'POST',
    path: '/auth/mfa/totp/enroll',
    cookies,
    ...options,
  });
}

/** `POST /auth/mfa/totp/verify` through the real route. The response is returned as it is. */
export function verifyTotpViaApi(
  cookies: CookieStore,
  body: { factorId: string; code: string },
  options: { ip?: string | null } = {},
) {
  return invoke(verifyRoute, {
    method: 'POST',
    path: '/auth/mfa/totp/verify',
    body,
    cookies,
    ...options,
  });
}

export type StartedEnrollment = {
  readonly factorId: string;
  /** The base32 secret the endpoint returned (what an authenticator app would store). */
  readonly secret: string;
};

/** Enrolls and returns the factor id and the secret; fails the helper unless the answer is 200. */
export async function enrollTotp(cookies: CookieStore): Promise<StartedEnrollment> {
  const response = await enrollTotpViaApi(cookies);
  if (response.status !== 200) {
    throw new Error(`enroll fixture failed with ${response.status}: ${await response.text()}`);
  }
  const body = (await bodyOf(response)) as { factorId: string; secret: string };
  return { factorId: body.factorId, secret: body.secret };
}

/** Verifies with a right code (see `nextTotpCode`); fails the helper unless the answer is 200. */
export async function verifyTotp(cookies: CookieStore, enrollment: StartedEnrollment) {
  const response = await verifyTotpViaApi(cookies, {
    factorId: enrollment.factorId,
    code: nextTotpCode(enrollment.secret),
  });
  if (response.status !== 200) {
    throw new Error(`verify fixture failed with ${response.status}: ${await response.text()}`);
  }
  return response;
}

export type CeoAtAal1 = {
  /** The CEO, with the password to log in with (the one set by `completeFirstAccess`). */
  readonly ceo: FixtureUser;
  /** The browser's cookies: an `aal1` session. No factor exists yet: `ENROLL_MFA` is pending. */
  readonly cookies: CookieStore;
};

/**
 * A fresh CEO that already changed the temporary password and is logged in through the API with an
 * `aal1` session. Its only pending action is `ENROLL_MFA`: the state in which the MFA routes are
 * reachable.
 */
export async function loginAsCeoReadyToEnroll(): Promise<CeoAtAal1> {
  const ceo = await completeFirstAccess(await createCeo());
  return { ceo, cookies: await loginViaApi(ceo) };
}

/** A CEO whose `cookies` are an `aal2` session, plus the factor it verified. */
export type CeoWithMfa = CeoAtAal1 & StartedEnrollment;

/**
 * A fresh CEO with an `aal2` session, ready for the `/admin/*` tests: it changed the temporary
 * password, logged in through `POST /auth/login`, enrolled TOTP through `POST /auth/mfa/totp/enroll`
 * and verified the code through `POST /auth/mfa/totp/verify`, whose response rewrote `cookies`.
 *
 * `secret` and `factorId` let a test log the same CEO in again (see `signInCeoWithMfa`).
 */
export async function loginAsCeoWithMfa(): Promise<CeoWithMfa> {
  const { ceo, cookies } = await loginAsCeoReadyToEnroll();
  const enrollment = await enrollTotp(cookies);
  await verifyTotp(cookies, enrollment);
  return { ceo, cookies, ...enrollment };
}

/**
 * A NEW session of a CEO that already has a verified factor (another browser, another day): login
 * (`aal1`, `VERIFY_MFA` pending), then, unless `verify: false`, the verification that makes it
 * `aal2`. The CEO's first session is untouched.
 */
export async function signInCeoWithMfa(
  session: Pick<CeoWithMfa, 'ceo' | 'factorId' | 'secret'>,
  options: { verify?: boolean } = {},
): Promise<CookieStore> {
  const cookies = await loginViaApi(session.ceo);
  if (options.verify !== false) await verifyTotp(cookies, session);
  return cookies;
}

/** The factors of a user as Auth holds them, read with the secret key (a fixture, not a behavior). */
export async function factorsOf(userId: string) {
  const { data, error } = await adminClient().auth.admin.mfa.listFactors({ userId });
  if (error) throw new Error(`listFactors failed: ${error.message}`);
  return data.factors.map((factor) => ({
    id: factor.id,
    type: factor.factor_type,
    status: factor.status,
  }));
}
