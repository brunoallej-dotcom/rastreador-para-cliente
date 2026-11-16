import { describe, expect, it } from 'vitest';
import { ForbiddenError, ServiceUnavailableError } from '@/shared/kernel';
import {
  InvalidCurrentPasswordError,
  PasswordChangeIncompleteError,
  PasswordUnchangedError,
  WeakPasswordError,
} from '../domain/password-errors';
import type { PasswordGateway } from '../domain/password-ports';
import { changePassword } from './change-password';
import { createFakePasswordGateway } from './password-fakes';

// Obviously fake values (the secret-detection hook rightly ignores names without "password").
const TEMPORARY = 'Temporary-Pass-1234';
const FRESH = 'A-brand-new-password-9';

describe('changePassword', () => {
  it('AC-06: with the right current password and a valid new one, the password is new and the pendency is cleared', async () => {
    const passwords = createFakePasswordGateway(TEMPORARY);

    const result = await changePassword(
      { passwords },
      { currentPassword: TEMPORARY, newPassword: FRESH },
    );

    expect(result.ok).toBe(true);
    expect(passwords.password()).toBe(FRESH);
    expect(passwords.pending()).toBe(false);
    // verify, then update, then mark: the proof comes before the change, the mark after it
    expect(passwords.calls).toEqual(['verify', 'update', 'mark']);
  });

  it('AC-06: a wrong current password is InvalidCurrentPasswordError and nothing changes', async () => {
    const passwords = createFakePasswordGateway(TEMPORARY);

    const result = await changePassword(
      { passwords },
      { currentPassword: 'not-the-current-one', newPassword: FRESH },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(InvalidCurrentPasswordError);
    expect(passwords.password()).toBe(TEMPORARY);
    expect(passwords.pending()).toBe(true);
    expect(passwords.calls).toEqual(['verify']);
  });

  it('E-12: a weak new password is refused before the backend is asked anything', async () => {
    const passwords = createFakePasswordGateway(TEMPORARY);

    const result = await changePassword(
      { passwords },
      { currentPassword: TEMPORARY, newPassword: 'too-short' },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(WeakPasswordError);
    expect(passwords.calls).toEqual([]);
  });

  it('E-13: the same password is refused before the backend is asked anything, right or wrong', async () => {
    for (const currentPassword of [TEMPORARY, 'a-wrong-current-password']) {
      const passwords = createFakePasswordGateway(TEMPORARY);

      const result = await changePassword(
        { passwords },
        { currentPassword, newPassword: currentPassword },
      );

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error).toBeInstanceOf(PasswordUnchangedError);
      // the answer does not depend on whether the current password is right: no oracle
      expect(passwords.calls).toEqual([]);
    }
  });

  it('a password the backend judges weak (a stricter project policy) is WeakPasswordError, and the pendency stays', async () => {
    const passwords = createFakePasswordGateway(TEMPORARY);
    passwords.rejectNewPasswordAsWeak();

    const result = await changePassword(
      { passwords },
      { currentPassword: TEMPORARY, newPassword: FRESH },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(WeakPasswordError);
    expect(passwords.pending()).toBe(true);
    expect(passwords.calls).toEqual(['verify', 'update']);
  });

  it('a database that is briefly unavailable is tried once more', async () => {
    const passwords = createFakePasswordGateway(TEMPORARY);
    passwords.failMarkTimes(1);

    const result = await changePassword(
      { passwords },
      { currentPassword: TEMPORARY, newPassword: FRESH },
    );

    expect(result.ok).toBe(true);
    expect(passwords.pending()).toBe(false);
    expect(passwords.calls).toEqual(['verify', 'update', 'mark', 'mark']);
  });

  it('a database that stays unavailable is PasswordChangeIncompleteError (503), never a silent success', async () => {
    const passwords = createFakePasswordGateway(TEMPORARY);
    passwords.failMarkTimes(5);

    const rejection = changePassword(
      { passwords },
      { currentPassword: TEMPORARY, newPassword: FRESH },
    );

    await expect(rejection).rejects.toBeInstanceOf(PasswordChangeIncompleteError);
    await expect(rejection).rejects.toBeInstanceOf(ServiceUnavailableError);
    // the password IS new; the pendency is still set, and the way out is in the client-safe detail
    expect(passwords.password()).toBe(FRESH);
    expect(passwords.pending()).toBe(true);
    expect(passwords.calls).toEqual(['verify', 'update', 'mark', 'mark']);
    const failure = await rejection.catch((error: unknown) => error);
    expect((failure as PasswordChangeIncompleteError).detail).toContain(
      'new password as the current password',
    );
  });

  it('only an outage is retried: any other failure of the last step propagates at once', async () => {
    const calls: string[] = [];
    const passwords: PasswordGateway = {
      verifyCurrentPassword: () => Promise.resolve({ ok: true, value: undefined }),
      updatePassword: () => Promise.resolve({ ok: true, value: undefined }),
      markPasswordChanged() {
        calls.push('mark');
        return Promise.reject(new Error('a bug'));
      },
    };

    await expect(
      changePassword({ passwords }, { currentPassword: TEMPORARY, newPassword: FRESH }),
    ).rejects.toThrow('a bug');
    expect(calls).toEqual(['mark']);
  });

  it('a refusal of the last step is returned as the error it is, without a retry', async () => {
    const calls: string[] = [];
    const passwords: PasswordGateway = {
      verifyCurrentPassword: () => Promise.resolve({ ok: true, value: undefined }),
      updatePassword: () => Promise.resolve({ ok: true, value: undefined }),
      markPasswordChanged() {
        calls.push('mark');
        return Promise.resolve({ ok: false, error: new ForbiddenError('denied') });
      },
    };

    const result = await changePassword(
      { passwords },
      { currentPassword: TEMPORARY, newPassword: FRESH },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(calls).toEqual(['mark']);
  });

  it('an outage while proving the current password propagates (503) and nothing is changed', async () => {
    const passwords: PasswordGateway = {
      verifyCurrentPassword: () => Promise.reject(new ServiceUnavailableError('auth down')),
      updatePassword: () => Promise.reject(new Error('must not be called')),
      markPasswordChanged: () => Promise.reject(new Error('must not be called')),
    };

    await expect(
      changePassword({ passwords }, { currentPassword: TEMPORARY, newPassword: FRESH }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
