import { describe, expect, it } from 'vitest';
import {
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  ValidationError,
} from '@/shared/kernel';
import { ProcessNotActiveError } from '../domain/errors';
import { ceoPrincipal, clientPrincipal } from './client-fixtures';
import { createFakeProcessRepository } from './fake-process-repository';
import { CLIENT_A, processFixture } from './process-fixtures';
import { updateProcess } from './update-process';

const PROCESS = processFixture({ title: 'Original' });

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
