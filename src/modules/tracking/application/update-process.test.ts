import { describe, expect, it } from 'vitest';
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  ValidationError,
} from '@/shared/kernel';
import { ClientArchivedError, ProcessNotActiveError } from '../domain/errors';
import { ceoPrincipal, clientPrincipal } from './client-fixtures';
import { createFakeProcessRepository } from './fake-process-repository';
import { CLIENT_A, processFixture } from './process-fixtures';
import { updateProcess } from './update-process';

const PROCESS = processFixture({ title: 'Original' });
const OTHER = processFixture({
  id: '00000000-0000-4000-8000-0000000001a2',
  title: 'Site pronto',
});
const ARCHIVED = { id: '00000000-0000-4000-8000-00000000000b', name: 'Cliente B', archived: true };
const ARCHIVED_PROCESS = processFixture({
  id: '00000000-0000-4000-8000-0000000001b1',
  clientId: ARCHIVED.id,
  client: ARCHIVED,
  title: 'Do arquivado',
});

const repository = (process = PROCESS) =>
  createFakeProcessRepository({ clients: [CLIENT_A], processes: [process] });

describe('updateProcess', () => {
  it('AC-19: renames an active process', async () => {
    const processes = repository();

    const result = await updateProcess({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      patch: { title: 'Renomeado' },
    });

    expect(result.ok && result.value).toMatchObject({
      title: 'Renomeado',
      status: 'active',
      version: 2,
    });
  });

  it('AC-19: cancels an active process and leaves its stages as they are', async () => {
    const processes = repository();

    const result = await updateProcess({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      patch: { cancel: true },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toMatchObject({ status: 'cancelled', version: 2 });
    expect(result.value.cancelledAt).toBeInstanceOf(Date);
    expect(result.value.stages).toEqual(PROCESS.stages);
  });

  it('AC-19: a cancelled process refuses the next change with ProcessNotActiveError', async () => {
    const processes = repository();
    await updateProcess({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      patch: { cancel: true },
    });

    const again = await updateProcess({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      patch: { title: 'Tarde demais' },
    });

    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.error).toBeInstanceOf(ProcessNotActiveError);
  });

  it.each([
    ['the same spelling', 'Site pronto'],
    ['another case', 'SITE PRONTO'],
    ['repeated spaces', 'Site   pronto'],
  ])(
    'E-97, F-80: renaming to the title of another active process (%s) is a ConflictError and changes nothing',
    async (_label, title) => {
      const processes = createFakeProcessRepository({
        clients: [CLIENT_A],
        processes: [PROCESS, OTHER],
      });

      const result = await updateProcess({ processes }, ceoPrincipal, {
        processId: PROCESS.id,
        patch: { title },
      });

      expect(!result.ok && result.error).toBeInstanceOf(ConflictError);
      expect(processes.stored()).toEqual([PROCESS, OTHER]);
    },
  );

  it('E-97, F-80: renaming to its own title, or only its case, is allowed (no 409 against itself)', async () => {
    const processes = repository();

    const same = await updateProcess({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      patch: { title: 'Original' },
    });
    const upper = await updateProcess({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      patch: { title: 'ORIGINAL' },
    });

    expect(same.ok && same.value.version).toBe(1);
    expect(upper.ok && upper.value).toMatchObject({ title: 'ORIGINAL', version: 2 });
  });

  it('E-97, F-80: renaming and cancelling together does not contest the title (the final state is cancelled)', async () => {
    const processes = createFakeProcessRepository({
      clients: [CLIENT_A],
      processes: [PROCESS, OTHER],
    });

    const result = await updateProcess({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      patch: { title: 'Site pronto', cancel: true },
    });

    expect(result.ok && result.value).toMatchObject({ title: 'Site pronto', status: 'cancelled' });
  });

  it('E-98, F-80: the title of a cancelled process is free for a rename', async () => {
    const cancelled = processFixture({
      id: '00000000-0000-4000-8000-0000000001a3',
      title: 'Site cancelado',
      status: 'cancelled',
      cancelledAt: new Date('2026-01-02T00:00:00.000Z'),
      statuses: ['in_progress'],
    });
    const processes = createFakeProcessRepository({
      clients: [CLIENT_A],
      processes: [PROCESS, cancelled],
    });

    const result = await updateProcess({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      patch: { title: 'Site cancelado' },
    });

    expect(result.ok && result.value.title).toBe('Site cancelado');
  });

  it.each([
    ['a rename', { title: 'Renomeado' }],
    ['a cancellation', { cancel: true as const }],
    ['a rename to its own title', { title: 'Do arquivado' }],
  ])(
    'E-99, F-87: %s of a process of an archived client is ClientArchivedError and changes nothing',
    async (_label, patch) => {
      const processes = createFakeProcessRepository({
        clients: [ARCHIVED],
        processes: [ARCHIVED_PROCESS],
      });

      const result = await updateProcess({ processes }, ceoPrincipal, {
        processId: ARCHIVED_PROCESS.id,
        patch,
      });

      expect(!result.ok && result.error).toBeInstanceOf(ClientArchivedError);
      expect(processes.stored()).toEqual([ARCHIVED_PROCESS]);
    },
  );

  it('E-99, F-87: the archived client wins over a finished process and over a taken title (the precedence)', async () => {
    const finished = processFixture({
      ...ARCHIVED_PROCESS,
      status: 'cancelled',
      cancelledAt: new Date('2026-01-02T00:00:00.000Z'),
      statuses: ['in_progress'],
    });
    const taken = processFixture({
      id: '00000000-0000-4000-8000-0000000001b2',
      clientId: ARCHIVED.id,
      client: ARCHIVED,
      title: 'Outro do arquivado',
    });
    const processes = createFakeProcessRepository({
      clients: [ARCHIVED],
      processes: [finished, taken],
    });

    const rename = await updateProcess({ processes }, ceoPrincipal, {
      processId: finished.id,
      patch: { title: 'Renomeado' },
    });
    const takenTitle = await updateProcess({ processes }, ceoPrincipal, {
      processId: taken.id,
      patch: { title: 'Do arquivado' },
    });

    expect(!rename.ok && rename.error).toBeInstanceOf(ClientArchivedError);
    expect(!takenTitle.ok && takenTitle.error).toBeInstanceOf(ClientArchivedError);
  });

  it('an empty patch is a 400 and never reaches the repository', async () => {
    const processes = repository();

    const result = await updateProcess({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      patch: {},
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ValidationError);
    expect(processes.calls).toEqual([]);
  });

  it('an unknown process is NotFoundError (404)', async () => {
    const processes = repository();

    const result = await updateProcess({ processes }, ceoPrincipal, {
      processId: '00000000-0000-4000-8000-00000000dead',
      patch: { title: 'Nada' },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(NotFoundError);
  });

  it('SEC-04: a client user is refused before the repository is touched', async () => {
    const processes = repository();

    const result = await updateProcess({ processes }, clientPrincipal, {
      processId: PROCESS.id,
      patch: { cancel: true },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(processes.calls).toEqual([]);
  });

  it('passes on a refusal of the database as it is, and changes nothing', async () => {
    const processes = repository();
    processes.refuseWrites(new ForbiddenError('denied'));

    const result = await updateProcess({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      patch: { title: 'Negado' },
    });

    expect(result.ok).toBe(false);
    expect(processes.stored()).toEqual([PROCESS]);
  });

  it('E-21: an outage is thrown', async () => {
    const processes = repository();
    processes.failWithOutage();

    await expect(
      updateProcess({ processes }, ceoPrincipal, {
        processId: PROCESS.id,
        patch: { cancel: true },
      }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
