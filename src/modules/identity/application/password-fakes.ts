// In-memory fake of the password change port, for the unit tests of the use case. Imported by tests only.
import { err, ok, ServiceUnavailableError, type Result } from '@/shared/kernel';
import {
  InvalidCurrentPasswordError,
  PasswordUnchangedError,
  WeakPasswordError,
} from '../domain/password-errors';
import type { PasswordGateway } from '../domain/password-ports';

export type FakePasswordGateway = PasswordGateway & {
  readonly calls: string[];
  /** The password the account has right now. */
  password(): string;
  /** Is the pending `CHANGE_PASSWORD` still set? */
  readonly pending: () => boolean;
  /** Makes `markPasswordChanged` throw `ServiceUnavailableError` this many times. */
  failMarkTimes(times: number): void;
  /** The backend judges every new password too weak (a stricter policy than ours). */
  rejectNewPasswordAsWeak(): void;
};

/** An account with a temporary password and CHANGE_PASSWORD pending, behind the port. */
export function createFakePasswordGateway(initialPassword: string): FakePasswordGateway {
  const calls: string[] = [];
  let password = initialPassword;
  let pending = true;
  let markFailures = 0;
  let weak = false;
  /** What the database remembers as the password the pendency was set with (ADR 0007). */
  let baseline = initialPassword;

  return {
    calls,
    password: () => password,
    pending: () => pending,
    failMarkTimes: (times) => void (markFailures = times),
    rejectNewPasswordAsWeak: () => void (weak = true),

    verifyCurrentPassword(currentPassword) {
      calls.push('verify');
      return Promise.resolve<Result<void, InvalidCurrentPasswordError>>(
        currentPassword === password ? ok(undefined) : err(new InvalidCurrentPasswordError()),
      );
    },

    updatePassword({ newPassword }) {
      calls.push('update');
      if (weak) return Promise.resolve(err(new WeakPasswordError()));
      if (newPassword === password) return Promise.resolve(err(new PasswordUnchangedError()));
      password = newPassword;
      return Promise.resolve(ok(undefined));
    },

    markPasswordChanged() {
      calls.push('mark');
      if (markFailures > 0) {
        markFailures -= 1;
        return Promise.reject(new ServiceUnavailableError('database unavailable'));
      }
      if (password === baseline) return Promise.resolve(err(new PasswordUnchangedError()));
      baseline = password;
      pending = false;
      return Promise.resolve(ok(undefined));
    },
  };
}
