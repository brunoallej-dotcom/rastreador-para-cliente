import { describe, expect, it } from 'vitest';
import {
  ConflictError,
  ForbiddenError,
  ServiceUnavailableError,
  ValidationError,
} from '@/shared/kernel';
import { ceoPrincipal, clientPrincipal } from './client-fixtures';
import { createClient } from './create-client';
import { createFakeClientRepository } from './fake-client-repository';

describe('createClient', () => {
  it('AC-11: a CEO creates an active client with no processes', async () => {
    const clients = createFakeClientRepository();

    const result = await createClient({ clients }, ceoPrincipal, { name: 'Acme Ltda' });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toMatchObject({
      name: 'Acme Ltda',
      archivedAt: null,
      activeProcessCount: 0,
      processCount: 0,
    });
    expect(clients.clients()).toEqual([result.value]);
  });

  it('SEC-04: a client user is refused before the repository is touched', async () => {
    const clients = createFakeClientRepository();

    const result = await createClient({ clients }, clientPrincipal, { name: 'Acme Ltda' });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(clients.calls).toEqual([]);
  });

  it('returns the refusal of the database as it is (a validation error stays a 400)', async () => {
    const clients = createFakeClientRepository();
    clients.refuseWrites(new ValidationError('the database refused the name'));

    const result = await createClient({ clients }, ceoPrincipal, { name: 'Acme Ltda' });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ValidationError);
    expect(clients.clients()).toEqual([]);
  });

  it('E-40: a name an active client already has comes back as the ConflictError of the database, and nothing is created', async () => {
    const clients = createFakeClientRepository();
    clients.refuseWrites(new ConflictError('the name is taken', { detail: 'taken' }));

    const result = await createClient({ clients }, ceoPrincipal, { name: 'Acme Ltda' });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(ConflictError);
      expect(result.error.detail).toBe('taken');
    }
    expect(clients.clients()).toEqual([]);
  });

  it('E-21: an outage is thrown, not turned into an answer', async () => {
    const clients = createFakeClientRepository();
    clients.failWithOutage();

    await expect(
      createClient({ clients }, ceoPrincipal, { name: 'Acme Ltda' }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
