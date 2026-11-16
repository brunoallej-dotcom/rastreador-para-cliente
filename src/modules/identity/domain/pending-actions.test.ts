import { describe, expect, it } from 'vitest';
import { computePendingActions } from './pending-actions';

describe('computePendingActions (spec §3.5, as identity sees it)', () => {
  it('AC-05: a fresh client login has CHANGE_PASSWORD pending', () => {
    expect(
      computePendingActions({
        role: 'client',
        mustChangePassword: true,
        hasVerifiedTotp: false,
        aal: 'aal1',
      }),
    ).toEqual(['CHANGE_PASSWORD']);
  });

  it('AC-31: a fresh CEO has CHANGE_PASSWORD and ENROLL_MFA pending', () => {
    expect(
      computePendingActions({
        role: 'ceo',
        mustChangePassword: true,
        hasVerifiedTotp: false,
        aal: 'aal1',
      }),
    ).toEqual(['CHANGE_PASSWORD', 'ENROLL_MFA']);
  });

  it('AC-07: a CEO with a verified factor must verify it on an aal1 session, and is free on aal2', () => {
    const ceo = { role: 'ceo', mustChangePassword: false, hasVerifiedTotp: true } as const;
    expect(computePendingActions({ ...ceo, aal: 'aal1' })).toEqual(['VERIFY_MFA']);
    expect(computePendingActions({ ...ceo, aal: 'aal2' })).toEqual([]);
  });
});
