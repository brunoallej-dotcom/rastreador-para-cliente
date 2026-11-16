import { describe, expect, it } from 'vitest';
import { ForbiddenError, NotFoundError, ServiceUnavailableError } from '@/shared/kernel';
import { ceoPrincipal, clientFixture, clientPrincipal } from './client-fixtures';
import { createFakeClientRepository } from './fake-client-repository';
import { getClient } from './get-client';

const CLIENT_ID = '00000000-0000-4000-8000-00000000000a';

describe('getClient', () => {
  it('AC-11: a CEO reads a client with its counters', async () => {
    const stored = clientFixture({
      id: CLIENT_ID,
      name: 'Acme',
      activeProcessCount: 2,
      processCount: 5,
    });
    const clients = createFakeClientRepository([stored]);

    const result = await getClient({ clients }, ceoPrincipal, { clientId: CLIENT_ID });

    expect(result).toEqual({ ok: true, value: stored });
  });

  it('AC-11: an unknown client is a NotFoundError (404)', async () => {
    const clients = createFakeClientRepository();

    const result = await getClient({ clients }, ceoPrincipal, { clientId: CLIENT_ID });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(NotFoundError);
      expect(result.error.detail).toBe('Client not found.');
    }
  });

  it('SEC-04: a client user is refused before the repository is touched', async () => {
    const clients = createFakeClientRepository([clientFixture({ id: CLIENT_ID })]);

    const result = await getClient({ clients }, clientPrincipal, { clientId: CLIENT_ID });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(clients.calls).toEqual([]);
  });

  it('E-21: an outage is thrown', async () => {
    const clients = createFakeClientRepository();
    clients.failWithOutage();

    await expect(
      getClient({ clients }, ceoPrincipal, { clientId: CLIENT_ID }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
