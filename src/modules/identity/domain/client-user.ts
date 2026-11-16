/**
 * A login of a client (the tenant user a CEO provisions, RF-07), as the CEO sees it. `email` is the
 * canonical form (E-11). Nothing here is a secret: the temporary password is a separate value that
 * the provisioning and the reset hand back once.
 */
export type ClientUser = {
  readonly id: string;
  readonly email: string;
  readonly displayName: string;
  readonly disabled: boolean;
  /** The temporary password is still the one in use (`CHANGE_PASSWORD` is pending). */
  readonly mustChangePassword: boolean;
  readonly lastSignInAt: Date | null;
  readonly createdAt: Date;
};

/**
 * At most this many logins per client, disabled ones included (E-18). The database trigger of the
 * profile enforces the same number under a lock; the use case checks first to answer 422.
 */
export const MAX_CLIENT_USERS = 10;

/** The display name of a login: 1 to 120 characters, as the profile's CHECK and the contract. */
export const CLIENT_USER_NAME_MAX_LENGTH = 120;

/** What a use case needs to know about the client a login belongs to (read through `tracking`). */
export type ClientStatus = {
  readonly id: string;
  readonly name: string;
  readonly archived: boolean;
};

/** A temporary password and the login it opens. The password is shown once, never stored or logged. */
export type ProvisionedClientUser = {
  readonly user: ClientUser;
  readonly temporaryPassword: string;
};
