import { describe, expect, it } from 'vitest';
import {
  ConflictError,
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
import { CLIENT_A, processFixture } from './process-fixtures';

const ARCHIVED = { id: '00000000-0000-4000-8000-00000000000b', name: 'Cliente B', archived: true };
const CLIENT_C = { id: '00000000-0000-4000-8000-00000000000c', name: 'Cliente C' };

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

  it('E-63: a blank description is stored as no description, whoever calls the use case', async () => {
    const processes = repository();

    const result = await createProcess({ processes }, ceoPrincipal, {
      clientId: CLIENT_A.id,
      title: 'Loja',
      stages: [
        { name: 'A', description: '' },
        { name: 'B', description: '   ' },
        { name: 'C', description: null },
        { name: 'D' },
        { name: 'E', description: 'Detalhe' },
      ],
    });

    expect(result.ok && result.value.stages.map((stage) => stage.description)).toEqual([
      null,
      null,
      null,
      null,
      'Detalhe',
    ]);
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

  it('E-21, F-80: creating twice never makes two processes: the repetition is ConflictError (409) and one process exists', async () => {
    const processes = repository();
    const input = { clientId: CLIENT_A.id, title: 'Mesmo título' };

    const first = await createProcess({ processes }, ceoPrincipal, input);
    const second = await createProcess({ processes }, ceoPrincipal, input);

    expect(first.ok).toBe(true);
    expect(!second.ok && second.error).toBeInstanceOf(ConflictError);
    expect(processes.stored()).toHaveLength(1);
  });

  it.each([
    ['upper case', 'SITE NOVO'],
    ['lower case', 'site novo'],
    ['repeated spaces', 'Site   novo'],
    ['spaces at the ends', '  Site novo  '],
    ['full-width letters', '\uFF33\uFF49\uFF54\uFF45 novo'],
    ['an invisible joiner mark', 'Si\u034Fte novo'],
  ])(
    'E-96, F-80: the same title in another spelling (%s) is a ConflictError',
    async (_label, title) => {
      const processes = repository();
      await createProcess({ processes }, ceoPrincipal, {
        clientId: CLIENT_A.id,
        title: 'Site novo',
      });

      const result = await createProcess({ processes }, ceoPrincipal, {
        clientId: CLIENT_A.id,
        title: title.trim(),
      });

      expect(!result.ok && result.error).toBeInstanceOf(ConflictError);
      expect(processes.stored()).toHaveLength(1);
    },
  );

  it('E-98, F-80: another title, and the same title in another client, are free', async () => {
    const processes = createFakeProcessRepository({ clients: [CLIENT_A, CLIENT_C] });
    await createProcess({ processes }, ceoPrincipal, { clientId: CLIENT_A.id, title: 'Site novo' });

    const other = await createProcess({ processes }, ceoPrincipal, {
      clientId: CLIENT_A.id,
      title: 'Site novo 2',
    });
    const otherClient = await createProcess({ processes }, ceoPrincipal, {
      clientId: CLIENT_C.id,
      title: 'Site novo',
    });

    expect(other.ok && otherClient.ok).toBe(true);
    expect(processes.stored()).toHaveLength(3);
  });

  it.each([
    ['completed', { status: 'completed' as const, statuses: ['completed' as const] }],
    ['cancelled', { status: 'cancelled' as const, statuses: ['in_progress' as const] }],
  ])('E-98, F-80: the title of a %s process can be used again', async (_label, state) => {
    const finished = processFixture({
      title: 'Site novo',
      completedAt: state.status === 'completed' ? new Date('2026-01-02T00:00:00.000Z') : null,
      cancelledAt: state.status === 'cancelled' ? new Date('2026-01-02T00:00:00.000Z') : null,
      ...state,
    });
    const processes = createFakeProcessRepository({ clients: [CLIENT_A], processes: [finished] });

    const result = await createProcess({ processes }, ceoPrincipal, {
      clientId: CLIENT_A.id,
      title: 'Site novo',
    });

    expect(result.ok).toBe(true);
    expect(processes.stored()).toHaveLength(2);
  });

  it('F-87, E-16: an archived client is ClientArchivedError even when the title is taken (the archive is checked first)', async () => {
    const taken = processFixture({ clientId: ARCHIVED.id, client: ARCHIVED, title: 'Loja' });
    const processes = createFakeProcessRepository({ clients: [ARCHIVED], processes: [taken] });

    const result = await createProcess({ processes }, ceoPrincipal, {
      clientId: ARCHIVED.id,
      title: 'Loja',
    });

    expect(!result.ok && result.error).toBeInstanceOf(ClientArchivedError);
  });
});
