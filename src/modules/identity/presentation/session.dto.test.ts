import { describe, expect, it } from 'vitest';
import type { Principal } from '@/shared/kernel';
import { toSessionDto } from './session.dto';

const principal: Principal = {
  userId: '11111111-1111-4111-8111-111111111111',
  role: 'client',
  clientId: '22222222-2222-4222-8222-222222222222',
  displayName: 'Maria',
  aal: 'aal1',
  pendingActions: ['CHANGE_PASSWORD'],
};

describe('toSessionDto', () => {
  it('AC-01: maps exactly the fields of Session, with the tenant as {id, name}', () => {
    expect(
      toSessionDto({ principal, client: { id: principal.clientId ?? '', name: 'Cliente A' } }),
    ).toEqual({
      user: { id: principal.userId, role: 'client', displayName: 'Maria' },
      client: { id: '22222222-2222-4222-8222-222222222222', name: 'Cliente A' },
      aal: 'aal1',
      pendingActions: ['CHANGE_PASSWORD'],
    });
  });

  it('a CEO has client null', () => {
    const ceo: Principal = {
      ...principal,
      role: 'ceo',
      clientId: null,
      aal: 'aal2',
      pendingActions: [],
    };
    expect(toSessionDto({ principal: ceo, client: null })).toEqual({
      user: { id: principal.userId, role: 'ceo', displayName: 'Maria' },
      client: null,
      aal: 'aal2',
      pendingActions: [],
    });
  });

  it('SEC-03: never leaks a field that is not in the contract, even if the input carries one', () => {
    const polluted = {
      principal: { ...principal, accessToken: 'secret-token', passwordHash: 'x' },
      client: { id: 'c', name: 'Cliente A', archivedAt: null, internal: true },
      extra: 'x',
    };
    const dto = toSessionDto(polluted);
    expect(Object.keys(dto).sort()).toEqual(['aal', 'client', 'pendingActions', 'user']);
    expect(Object.keys(dto.user).sort()).toEqual(['displayName', 'id', 'role']);
    expect(Object.keys(dto.client ?? {}).sort()).toEqual(['id', 'name']);
    expect(JSON.stringify(dto)).not.toMatch(/token|passwordHash|archivedAt|internal/i);
  });

  it('copies the pending actions, so the response cannot alias the principal', () => {
    const dto = toSessionDto({ principal, client: null });
    expect(dto.pendingActions).toEqual(principal.pendingActions);
    expect(dto.pendingActions).not.toBe(principal.pendingActions);
  });
});
