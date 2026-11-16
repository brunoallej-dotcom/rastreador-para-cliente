import type { Principal, Result } from '@/shared/kernel';
import type { InvalidCredentialsError } from './errors';
import type { ClientSummary } from './session';

/** What a successful sign-in opened. The id is the session's own, for log lines (never a secret). */
export type SignedIn = { readonly sessionId: string | null };

export type Credentials = {
  /** Already normalized (`normalizeEmail`) and validated. */
  readonly email: string;
  readonly password: string;
};

/**
 * Sign-in and sign-out of the session of the CURRENT request. The session lives in cookies the
 * adapter manages; the use cases never see a token.
 *
 * Every method throws `ServiceUnavailableError` when the auth backend is slow or down (E-21)
 * instead of returning a result: an outage is not an answer about the credentials.
 */
export interface AuthGateway {
  /**
   * Opens a session. `err(InvalidCredentialsError)` for credentials the backend refuses, whatever
   * the reason (unknown e-mail, wrong password, unconfirmed or banned account: SEC-12).
   */
  signInWithPassword(credentials: Credentials): Promise<Result<SignedIn, InvalidCredentialsError>>;

  /**
   * Ends THIS session (scope `local`, E-09: the user's other devices stay signed in) and revokes it
   * on the server, so the tokens stop working even if someone kept a copy. Throws when the
   * revocation could not be confirmed.
   */
  signOut(): Promise<void>;
}

/** The principal of the current session, from the database (`current_principal()`). */
export interface PrincipalQuery {
  /** `null` when there is no active principal: revoked session, disabled or missing profile. */
  current(): Promise<Principal | null>;
}

/** Read access to the tenant of a client user (implemented over `tracking`'s public index). */
export interface ClientDirectory {
  /** `null` when the client does not exist or the session cannot see it. */
  find(clientId: string): Promise<ClientSummary | null>;
}
