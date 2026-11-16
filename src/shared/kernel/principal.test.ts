import { describe, expect, it } from 'vitest';
import { PENDING_ACTION_PRIORITY, PENDING_ACTIONS } from './principal';

describe('PENDING_ACTION_PRIORITY', () => {
  it('lists every pending action once, CHANGE_PASSWORD > ENROLL_MFA > VERIFY_MFA', () => {
    expect([...PENDING_ACTION_PRIORITY]).toEqual(['CHANGE_PASSWORD', 'ENROLL_MFA', 'VERIFY_MFA']);
    expect([...PENDING_ACTION_PRIORITY].sort()).toEqual([...PENDING_ACTIONS].sort());
  });
});
