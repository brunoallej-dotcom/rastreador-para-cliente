import { describe, expect, it } from 'vitest';
import type { ClientUser } from '../domain/client-user';
import {
  toClientUserDto,
  toClientUserListDto,
  toProvisionedClientUserDto,
  toTemporaryPasswordDto,
} from './client-user.dto';

const USER: ClientUser = {
  id: '00000000-0000-4000-8000-0000000000a1',
  email: 'maria@cliente.test',
  displayName: 'Maria',
  disabled: false,
  mustChangePassword: true,
  lastSignInAt: null,
  createdAt: new Date('2026-11-16T11:30:24.984Z'),
};

describe('client login DTOs', () => {
  it('lists exactly the fields of the contract, with ISO timestamps', () => {
    expect(toClientUserDto(USER)).toEqual({
      id: USER.id,
      email: 'maria@cliente.test',
      displayName: 'Maria',
      disabled: false,
      mustChangePassword: true,
      lastSignInAt: null,
      createdAt: '2026-11-16T11:30:24.984Z',
    });
  });

  it('AC-14: a login that signed in shows the instant', () => {
    const dto = toClientUserDto({ ...USER, lastSignInAt: new Date('2026-11-17T08:00:00.000Z') });

    expect(dto.lastSignInAt).toBe('2026-11-17T08:00:00.000Z');
  });

  it('an unknown member of the domain object never leaks (nothing is spread)', () => {
    const leaky = { ...USER, internalFlag: true, hash: 'x' } as unknown as ClientUser;

    expect(Object.keys(toClientUserDto(leaky)).sort()).toEqual(
      [
        'createdAt',
        'disabled',
        'displayName',
        'email',
        'id',
        'lastSignInAt',
        'mustChangePassword',
      ].sort(),
    );
  });

  it('AC-12: the provisioned login carries the user and the temporary password, nothing else', () => {
    const dto = toProvisionedClientUserDto({ user: USER, temporaryPassword: 'p'.repeat(20) });

    expect(Object.keys(dto).sort()).toEqual(['temporaryPassword', 'user']);
    expect(dto.temporaryPassword).toBe('p'.repeat(20));
  });

  it('the reset and the list have the shapes of the contract', () => {
    expect(toTemporaryPasswordDto('p'.repeat(20))).toEqual({ temporaryPassword: 'p'.repeat(20) });
    expect(toClientUserListDto([USER])).toEqual({ items: [toClientUserDto(USER)] });
    expect(toClientUserListDto([])).toEqual({ items: [] });
  });
});
