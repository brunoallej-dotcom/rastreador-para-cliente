import { describe, expect, it } from 'vitest';
import {
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  ValidationError,
} from '@/shared/kernel';
import { ClientArchivedError } from '../domain/errors';
import { invariantViolations } from '../domain/process';
import { MAX_STAGES_PER_PROCESS } from '../domain/stage';
import { ceoPrincipal, clientPrincipal } from './client-fixtures';
import { createProcess } from './create-process';
import { createFakeProcessRepository, FAKE_TEMPLATE } from './fake-process-repository';
import { CLIENT_A } from './process-fixtures';

const ARCHIVED = { id: '00000000-0000-4000-8000-00000000000b', name: 'Cliente B', archived: true };

const repository = () => createFakeProcessRepository({ clients: [CLIENT_A, ARCHIVED] });

describe('createProcess', () => {
  it('AC-15: without stages, uses the default template and starts the first stage', async () => {
    const processes = repository();

    const result = await createProcess({ processes }, ceoPrincipal, {
      clientId: CLIENT_A.id,
      title: 'Site novo',
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.stages.map((stage) => stage.name)).toEqual(
      FAKE_TEMPLATE.stages.map((stage) => stage.name),
    );
    expect(result.value.stages.map((stage) => stage.status)).toEqual([
      'in_progress',
      'pending',
      'pending',
    ]);
    expect(result.value).toMatchObject({
      title: 'Site novo',
      status: 'active',
      clientId: CLIENT_A.id,
    });
    expect(invariantViolations(result.value)).toEqual([]);
  });

  it('AC-15: with stages, uses them in order, with their descriptions', async () => {
    const processes = repository();

    const result = await createProcess({ processes }, ceoPrincipal, {
      clientId: CLIENT_A.id,
      title: 'Loja',
      stages: [{ name: 'Desenho', description: 'Telas' }, { name: 'Entrega' }],
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.stages.map((stage) => [stage.name, stage.description])).toEqual([
      ['Desenho', 'Telas'],
      ['Entrega', null],
    ]);
    expect(result.value.stages[0]?.status).toBe('in_progress');
    expect(processes.stored()).toHaveLength(1);
  });

  it.each([
    ['an empty list', []],
    [
      '31 stages',
      Array.from({ length: MAX_STAGES_PER_PROCESS + 1 }, (_v, i) => ({ name: `F${i}` })),
    ],
    ['a stage named with spaces only', [{ name: 'Boa' }, { name: '   ' }]],
  ])('E-20: %s is a 400 and never reaches the repository', async (_label, stages) => {
    const processes = repository();

    const result = await createProcess({ processes }, ceoPrincipal, {
      clientId: CLIENT_A.id,
      title: 'Loja',
      stages,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ValidationError);
    expect(processes.calls).toEqual([]);
  });

  it('E-16: an archived client takes no process: ClientArchivedError, nothing is stored', async () => {
    const processes = repository();

    const result = await createProcess({ processes }, ceoPrincipal, {
      clientId: ARCHIVED.id,
      title: 'Loja',
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ClientArchivedError);
    expect(processes.stored()).toEqual([]);
  });

  it('an unknown client is NotFoundError (404)', async () => {
    const processes = repository();

    const result = await createProcess({ processes }, ceoPrincipal, {
      clientId: '00000000-0000-4000-8000-00000000dead',
      title: 'Loja',
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(NotFoundError);
  });

  it('SEC-04: a client user is refused before the repository is touched', async () => {
    const processes = repository();

    const result = await createProcess({ processes }, clientPrincipal, {
      clientId: CLIENT_A.id,
      title: 'Meu processo',
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(processes.calls).toEqual([]);
  });

  it('passes on a refusal of the database as it is', async () => {
    const processes = repository();
    processes.refuseWrites(new ForbiddenError('denied'));

    const result = await createProcess({ processes }, ceoPrincipal, {
      clientId: CLIENT_A.id,
      title: 'Loja',
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
  });

  it('E-21: an outage is thrown', async () => {
    const processes = repository();
    processes.failWithOutage();

    await expect(
      createProcess({ processes }, ceoPrincipal, { clientId: CLIENT_A.id, title: 'Loja' }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('E-21: creating twice makes two processes (a create has no natural key to dedupe on)', async () => {
    const processes = repository();
    const input = { clientId: CLIENT_A.id, title: 'Mesmo título' };

    const first = await createProcess({ processes }, ceoPrincipal, input);
    const second = await createProcess({ processes }, ceoPrincipal, input);

    expect(first.ok && second.ok).toBe(true);
    expect(processes.stored()).toHaveLength(2);
  });
});
