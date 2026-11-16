import type { ClientUser, ProvisionedClientUser } from '../domain/client-user';

/** `ClientUser` of the contract. Explicit fields: nothing is spread from a row. */
export type ClientUserDto = {
  readonly id: string;
  readonly email: string;
  readonly displayName: string;
  readonly disabled: boolean;
  readonly mustChangePassword: boolean;
  readonly lastSignInAt: string | null;
  readonly createdAt: string;
};

/** `ProvisionedClientUser` of the contract: the login and its temporary password, shown once. */
export type ProvisionedClientUserDto = {
  readonly user: ClientUserDto;
  readonly temporaryPassword: string;
};

/** `TemporaryPassword` of the contract. */
export type TemporaryPasswordDto = { readonly temporaryPassword: string };

/** `ClientUserList` of the contract. */
export type ClientUserListDto = { readonly items: readonly ClientUserDto[] };

export const toClientUserDto = (user: ClientUser): ClientUserDto => ({
  id: user.id,
  email: user.email,
  displayName: user.displayName,
  disabled: user.disabled,
  mustChangePassword: user.mustChangePassword,
  lastSignInAt: user.lastSignInAt === null ? null : user.lastSignInAt.toISOString(),
  createdAt: user.createdAt.toISOString(),
});

export const toClientUserListDto = (users: readonly ClientUser[]): ClientUserListDto => ({
  items: users.map(toClientUserDto),
});

export const toProvisionedClientUserDto = ({
  user,
  temporaryPassword,
}: ProvisionedClientUser): ProvisionedClientUserDto => ({
  user: toClientUserDto(user),
  temporaryPassword,
});

export const toTemporaryPasswordDto = (temporaryPassword: string): TemporaryPasswordDto => ({
  temporaryPassword,
});
