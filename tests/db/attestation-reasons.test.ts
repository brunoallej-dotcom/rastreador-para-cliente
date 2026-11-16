// The refusal reasons of the attestation live in two places that must agree: the SQL (`attest_mfa_session`
// and `private.refuse_mfa_attestation`, which decides what revokes) and the identity module (the
// vocabulary the attestor accepts and the signs of an attack the handler logs as an alert). A reason the
// SQL can return and the module does not know would be a 500 on a real attack; a sign of an attack the
// SQL does not revoke for would be a false alert. This test reads the migration and pins both.
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  ATTESTATION_ATTACK_SIGNALS,
  ATTESTATION_REFUSALS,
} from '@/modules/identity/domain/mfa-ports';

const MIGRATIONS = fileURLToPath(new URL('../../supabase/migrations/', import.meta.url));

const migration = readFileSync(
  `${MIGRATIONS}${readdirSync(MIGRATIONS).find((name) => name.endsWith('_ceo_attestation_and_temp_password_expiry.sql')) ?? ''}`,
  'utf8',
);

const quoted = (text: string): string[] =>
  [...text.matchAll(/'([a-z0-9_]+)'/g)].map((match) => match[1] ?? '');

/** The reasons `refuse_mfa_attestation` revokes the sessions for. */
function revokingReasons(): string[] {
  const body = /v_attack boolean := p_reason IN \(([^)]*)\)/.exec(migration)?.[1];
  if (body === undefined) throw new Error('the list of attack signals is not in the migration');
  return quoted(body);
}

/** Every reason a function of the migration hands to `refuse_mfa_attestation`. */
function returnedReasons(): string[] {
  return [
    ...migration.matchAll(/refuse_mfa_attestation\(p_user_id, p_factor_id, '([a-z0-9_]+)'\)/g),
  ].map((match) => match[1] ?? '');
}

describe('the refusal reasons of the attestation: SQL and identity module agree', () => {
  it('F-66: the reasons the SQL revokes for are exactly the signs of an attack of the module', () => {
    expect(new Set(revokingReasons())).toEqual(new Set(ATTESTATION_ATTACK_SIGNALS));
    expect(revokingReasons().length).toBe(new Set(revokingReasons()).size);
  });

  it('every reason the SQL can return is one the attestor knows (so a real refusal is never a 500)', () => {
    const known = new Set<string>(ATTESTATION_REFUSALS);
    for (const reason of returnedReasons()) expect(known.has(reason), reason).toBe(true);
  });

  it('every reason the attestor knows is returned somewhere (no dead vocabulary)', () => {
    const returned = new Set(returnedReasons());
    for (const reason of ATTESTATION_REFUSALS) expect(returned.has(reason), reason).toBe(true);
  });

  it('every sign of an attack is a reason of the module', () => {
    for (const reason of ATTESTATION_ATTACK_SIGNALS) {
      expect(ATTESTATION_REFUSALS).toContain(reason);
    }
  });

  it('F-66: the races named by the review (not_ceo, session_not_found, session_not_aal2, challenge_stale) do NOT revoke', () => {
    for (const reason of ['not_ceo', 'session_not_found', 'session_not_aal2', 'challenge_stale']) {
      expect(ATTESTATION_ATTACK_SIGNALS.has(reason as never)).toBe(false);
    }
  });
});
