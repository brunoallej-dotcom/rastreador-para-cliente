import { describe, expect, it } from 'vitest';
import { computePendingActions, type PendingActionsInput } from './pending-actions';

const base: PendingActionsInput = {
  role: 'client',
  mustChangePassword: false,
  hasVerifiedTotp: false,
  aal: 'aal1',
};

describe('computePendingActions', () => {
  it('has nothing pending for a client with a permanent password, whatever MFA says', () => {
    expect(computePendingActions(base)).toEqual([]);
    expect(computePendingActions({ ...base, hasVerifiedTotp: true })).toEqual([]);
    expect(computePendingActions({ ...base, aal: 'aal2' })).toEqual([]);
  });

  it('asks a client with a temporary password to change it, and nothing else', () => {
    expect(computePendingActions({ ...base, mustChangePassword: true })).toEqual([
      'CHANGE_PASSWORD',
    ]);
  });

  it('asks a fresh CEO to change the password and to enroll MFA, in priority order', () => {
    expect(computePendingActions({ ...base, role: 'ceo', mustChangePassword: true })).toEqual([
      'CHANGE_PASSWORD',
      'ENROLL_MFA',
    ]);
  });

  it('asks a CEO without a verified factor to enroll, even on an aal2 session', () => {
    expect(computePendingActions({ ...base, role: 'ceo', aal: 'aal2' })).toEqual(['ENROLL_MFA']);
  });

  it('asks a CEO with a verified factor and an aal1 session to verify', () => {
    expect(computePendingActions({ ...base, role: 'ceo', hasVerifiedTotp: true })).toEqual([
      'VERIFY_MFA',
    ]);
    expect(
      computePendingActions({
        ...base,
        role: 'ceo',
        hasVerifiedTotp: true,
        mustChangePassword: true,
      }),
    ).toEqual(['CHANGE_PASSWORD', 'VERIFY_MFA']);
  });

  it('has nothing pending for a CEO with a verified factor on an aal2 session', () => {
    expect(
      computePendingActions({ ...base, role: 'ceo', hasVerifiedTotp: true, aal: 'aal2' }),
    ).toEqual([]);
  });
});
