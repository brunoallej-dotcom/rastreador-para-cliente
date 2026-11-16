import { describe, expect, it } from 'vitest';
import {
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  ValidationError,
} from '@/shared/kernel';
import { ceoPrincipal, clientFixture, clientPrincipal } from './client-fixtures';
import { createFakeClientRepository } from './fake-client-repository';
import { updateClient } from './update-client';

const CLIENT_ID = '00000000-0000-4000-8000-00000000000a';

const repository = () =>
  createFakeClientRepository([clientFixture({ id: CLIENT_ID, name: 'Acme' })]);

describe('updateClient', () => {
  it('AC-11: renames a client', async () => {
    const clients = repository();

    const result = await updateClient({ clients }, ceoPrincipal, {
      clientId: CLIENT_ID,
      patch: { name: 'Acme Brasil' },
    });

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toMatchObject({ name: 'Acme Brasil', archivedAt: null });
  });

  it('AC-11: archives a client and brings it back', async () => {
    const clients = repository();

    const archived = await updateClient({ clients }, ceoPrincipal, {
      clientId: CLIENT_ID,
      patch: { archived: true },
    });
    expect(archived.ok && archived.value.archivedAt !== null).toBe(true);

    const restored = await updateClient({ clients }, ceoPrincipal, {
      clientId: CLIENT_ID,
      patch: { archived: false },
    });
    expect(restored.ok && restored.value.archivedAt === null).toBe(true);
    if (restored.ok) expect(restored.value.name).toBe('Acme');
  });

  it('AC-11: an empty patch is a 400 and never reaches the repository', async () => {
    const clients = repository();

    const result = await updateClient({ clients }, ceoPrincipal, {
      clientId: CLIENT_ID,
      patch: {},
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ValidationError);
    expect(clients.calls).toEqual([]);
  });

  it('AC-11: an unknown client is a NotFoundError (404)', async () => {
    const clients = createFakeClientRepository();

    const result = await updateClient({ clients }, ceoPrincipal, {
      clientId: CLIENT_ID,
      patch: { name: 'Acme' },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(NotFoundError);
  });

  it('SEC-04: a client user is refused before the repository is touched', async () => {
    const clients = repository();

    const result = await updateClient({ clients }, clientPrincipal, {
      clientId: CLIENT_ID,
      patch: { name: 'Meu nome' },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(clients.calls).toEqual([]);
  });

  it('E-21: an outage is thrown', async () => {
    const clients = repository();
    clients.failWithOutage();

    await expect(
      updateClient({ clients }, ceoPrincipal, { clientId: CLIENT_ID, patch: { name: 'Acme 2' } }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
