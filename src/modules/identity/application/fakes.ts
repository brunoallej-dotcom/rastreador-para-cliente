// In-memory fakes of identity's ports, for the unit tests of the use cases. Imported by tests only.
import { err, ok, ServiceUnavailableError, type Principal } from '@/shared/kernel';
import { InvalidCredentialsError } from '../domain/errors';
import type { AuthGateway, ClientDirectory, Credentials, PrincipalQuery } from '../domain/ports';
import type { ClientSummary } from '../domain/session';

/** The session id every fake sign-in opens. */
export const FAKE_SESSION_ID = '99999999-9999-4999-8999-999999999999';

export type FakeAccount = {
  readonly email: string;
  readonly password: string;
  readonly principal: Principal;
  /** A disabled profile: it can still sign in at the backend, but has no principal. */
  readonly disabled?: boolean;
};

export type FakeIdentity = AuthGateway &
  PrincipalQuery & {
    /** Is a session open right now? */
    readonly sessionOpen: () => boolean;
    readonly calls: string[];
    /** Makes the next calls of that method throw `ServiceUnavailableError`. */
    failWith(method: 'signIn' | 'signOut' | 'current'): void;
  };

/** One object that is both the `AuthGateway` and the `PrincipalQuery`, like the real adapter. */
export function createFakeIdentity(accounts: readonly FakeAccount[]): FakeIdentity {
  const calls: string[] = [];
  const failing = new Set<string>();
  let signedInAs: FakeAccount | null = null;

  const unavailable = (method: string) => {
    if (failing.has(method)) throw new ServiceUnavailableError(`${method} unavailable`);
  };

  return {
    calls,
    sessionOpen: () => signedInAs !== null,
    failWith: (method) => void failing.add(method),
    signInWithPassword({ email, password }: Credentials) {
      calls.push('signIn');
      unavailable('signIn');
      const account = accounts.find((candidate) => candidate.email === email);
      if (account === undefined || account.password !== password) {
        return Promise.resolve(err(new InvalidCredentialsError()));
      }
      signedInAs = account;
      return Promise.resolve(ok({ sessionId: FAKE_SESSION_ID }));
    },
    signOut() {
      calls.push('signOut');
      unavailable('signOut');
      signedInAs = null;
      return Promise.resolve();
    },
    current() {
      calls.push('current');
      unavailable('current');
      if (signedInAs === null || signedInAs.disabled === true) return Promise.resolve(null);
      return Promise.resolve(signedInAs.principal);
    },
  };
}

export type FakeClientDirectory = ClientDirectory & { readonly lookups: string[] };

export function createFakeClientDirectory(clients: readonly ClientSummary[]): FakeClientDirectory {
  const lookups: string[] = [];
  return {
    lookups,
    find(clientId) {
      lookups.push(clientId);
      return Promise.resolve(clients.find((client) => client.id === clientId) ?? null);
    },
  };
}
