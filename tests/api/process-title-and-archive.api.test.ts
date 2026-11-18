// API tests of the two product decisions of Wave 10.2 (operationIds `createProcess`, `updateProcess`,
// `approveCurrentStage` and the reads that must keep working): the real route modules, the real pipeline and
// wiring (Postgres rate limiter, Supabase resolver), the local Supabase (Auth + PostgREST + the database
// functions), and every response checked against the OpenAPI contract, headers included.
//
//   F-80 (Q-14): the title of a process is unique among the ACTIVE processes of its client. Creating or
//   renaming to a title that is taken is 409 CONFLICT, whatever the spelling (the key of the client names:
//   case, runs of spaces, Unicode width and compatibility forms, invisible marks); a completed or cancelled
//   process gives its title back; another client's title does not count; and a POST repeated after a lost
//   answer never makes a second process.
//   F-87 (Q-13): an archived client freezes its processes. Approving, renaming and cancelling are 422
//   CLIENT_ARCHIVED, reading is still 200, unarchiving thaws, and an archive in flight and a write to a
//   process of the same client serialize on the client row lock.
//
// The CEOs are real ones: each changed the temporary password, logged in through the API, enrolled TOTP and
// verified a code, so its cookies are an `aal2` session the backend attested (tests/helpers/mfa.ts). A CEO
// has 60 writes a minute, refused ones included, so each group has a CEO of its own.
//
// The concurrency tests do not hope for an interleaving. They do the first write in a second database
// session that stays open (tests/helpers/held-transaction.ts), fire the second request, wait until the
// database says it is parked on a lock of the first, and only then commit. What follows is decided by the
// database, the same on every run, with no sleep.
import { beforeAll, describe, expect, it } from 'vitest';
import { expectToMatchContract } from '../helpers/contract';
import { approveViaApi, listEventsViaApi, type ProcessEventListBody } from '../helpers/approvals';
import { updateClientViaApi } from '../helpers/clients';
import { createClient } from '../helpers/fixtures';
import {
  ceoIdentityOf,
  openHeldTransaction,
  waitForLockWaiters,
} from '../helpers/held-transaction';
import { bodyOf } from '../helpers/http';
import { loginAsCeoWithMfa, type CeoWithMfa } from '../helpers/mfa';
import {
  getMyProcessViaApi,
  listMyProcessesViaApi,
  signedInClientLogin,
  type MyProcessDetailBody,
  type MyProcessListBody,
} from '../helpers/client-panel';
import {
  auditOfProcess,
  createProcessOrFail,
  createProcessViaApi,
  getProcessViaApi,
  listProcessesViaApi,
  processCountOf,
  processRowOf,
  processTitlesOf,
  stageRowsOf,
  uniqueProcessTitle,
  updateProcessViaApi,
  type ProcessDetailBody,
  type ProcessListBody,
} from '../helpers/processes';

const UNKNOWN_ID = '00000000-0000-4000-8000-00000000dead';
const FULL_WIDTH_S = String.fromCodePoint(0xff33);
const NO_BREAK_SPACE = String.fromCodePoint(0x00a0);
const COMBINING_JOINER = String.fromCodePoint(0x034f);
const COMBINING_ACUTE = String.fromCodePoint(0x0301);
const E_ACUTE = String.fromCodePoint(0x00e9);
const CAPITAL_E_ACUTE = String.fromCodePoint(0x00c9);
const TAKEN_DETAIL = 'A process with this title is already active for this client.';
const ARCHIVED_DETAIL = 'The client is archived. Unarchive it to create or change its processes.';

type Problem = {
  code: string;
  requestId?: string;
  detail?: string;
  errors?: { path: string; message: string }[];
  currentStageId?: string | null;
};

/** Parses the body, checks it against the contract (headers too) and returns it. */
async function expectContract<T = unknown>(operationId: string, response: Response): Promise<T> {
  const text = await response.clone().text();
  const body: unknown = text === '' ? undefined : JSON.parse(text);
  expectToMatchContract(operationId, response.status, body, response);
  return body as T;
}

/** The status and the code a refused request answered, for a failure message that says which. */
const outcomeOf = (response: Response, body: Problem) => [response.status, body.code];

/** A 409 `CONFLICT` of `operationId` that names no process and no title. */
async function expectTaken(operationId: string, response: Response, ...secrets: string[]) {
  const body = await expectContract<Problem>(operationId, response);
  expect(outcomeOf(response, body)).toEqual([409, 'CONFLICT']);
  expect(body.detail).toBe(TAKEN_DETAIL);
  for (const secret of secrets) expect(JSON.stringify(body)).not.toContain(secret);
}

/** A 422 `CLIENT_ARCHIVED` of `operationId`. */
async function expectArchived(operationId: string, response: Response) {
  const body = await expectContract<Problem>(operationId, response);
  expect(outcomeOf(response, body)).toEqual([422, 'CLIENT_ARCHIVED']);
  expect(body.detail).toBe(ARCHIVED_DETAIL);
}

/** The stage at `position` (1-based) of a process body; fails the test if there is none. */
function stageAt(process: ProcessDetailBody, position: number) {
  const stage = process.stages[position - 1];
  if (stage === undefined) throw new Error(`the process has no stage at position ${position}`);
  return stage;
}

/** What the database holds of a process, in one comparable value (the refusals must leave it as it was). */
async function stateOf(processId: string) {
  const row = await processRowOf(processId);
  const stages = await stageRowsOf(processId);
  const audit = await auditOfProcess(processId);
  return {
    status: row.status,
    title: row.title,
    version: row.version,
    stages: stages.map((stage) => [stage.position, stage.status]),
    audit: audit.map((event) => event.action),
  };
}

/** Archives the client through the API, as a CEO does. */
async function archiveViaApi(cookies: CeoWithMfa['cookies'], clientId: string) {
  const response = await updateClientViaApi(cookies, clientId, { archived: true });
  await expectContract('updateClient', response);
  expect(response.status).toBe(200);
}

/** Unarchives the client through the API. */
async function unarchiveViaApi(cookies: CeoWithMfa['cookies'], clientId: string) {
  const response = await updateClientViaApi(cookies, clientId, { archived: false });
  await expectContract('updateClient', response);
  expect(response.status).toBe(200);
}

// ------------------------------------------------------------------------------------------ F-80 ----

describe('F-80: creating with a title an active process of the client already has', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await loginAsCeoWithMfa();
  });

  it('F-80, E-96: is 409 CONFLICT, creates nothing, writes no event, and the body names no process and no title', async () => {
    const tenant = await createClient();
    const title = uniqueProcessTitle('Site');
    const first = await createProcessOrFail(ceo.cookies, tenant.id, { title });
    const before = await stateOf(first.id);

    const response = await createProcessViaApi(ceo.cookies, tenant.id, { title });

    await expectTaken('createProcess', response, first.id, title);
    expect(response.headers.get('location')).toBeNull();
    expect(await processCountOf(tenant.id)).toBe(1);
    expect(await stateOf(first.id)).toEqual(before);
    expect(before.audit).toEqual(['process.created']);
  });

  it('F-80, E-96: the same title in another spelling is 409 too: case, runs of spaces, no-break space, the ends, full width, an invisible mark, accents', async () => {
    const tenant = await createClient();
    const suffix = uniqueProcessTitle('').trim();
    const title = `Site novo ${suffix}`;
    const accented = `Caf${E_ACUTE} novo ${suffix}`;
    await createProcessOrFail(ceo.cookies, tenant.id, { title });
    await createProcessOrFail(ceo.cookies, tenant.id, { title: accented });
    const variants: [string, string][] = [
      ['upper case', title.toUpperCase()],
      ['lower case', title.toLowerCase()],
      ['repeated spaces', title.replace(' ', '   ')],
      ['no-break space', title.replace(' ', NO_BREAK_SPACE)],
      ['spaces at the ends', `   ${title}  `],
      ['full-width letter', `${FULL_WIDTH_S}${title.slice(1)}`],
      ['invisible joiner mark', `Si${COMBINING_JOINER}te novo ${suffix}`],
      ['decomposed accent', `Cafe${COMBINING_ACUTE} novo ${suffix}`],
      ['capital accent', `CAF${CAPITAL_E_ACUTE} NOVO ${suffix}`],
    ];

    for (const [label, variant] of variants) {
      const response = await createProcessViaApi(ceo.cookies, tenant.id, { title: variant });
      const body = await expectContract<Problem>('createProcess', response);
      expect(outcomeOf(response, body), label).toEqual([409, 'CONFLICT']);
    }
    expect(await processCountOf(tenant.id)).toBe(2);
  });

  it('F-80, E-96: with the stages sent it is 409 as well, and no stage is left behind', async () => {
    const tenant = await createClient();
    const title = uniqueProcessTitle('Loja');
    const first = await createProcessOrFail(ceo.cookies, tenant.id, { title });

    const response = await createProcessViaApi(ceo.cookies, tenant.id, {
      title: title.toUpperCase(),
      stages: [{ name: 'Desenho' }, { name: 'Entrega', description: 'Fim' }],
    });

    await expectTaken('createProcess', response, first.id);
    expect(await processCountOf(tenant.id)).toBe(1);
    expect((await stageRowsOf(first.id)).length).toBe(first.stages.length);
  });

  it('F-80, E-98: a different title is free, and so is the same title in another client', async () => {
    const tenant = await createClient();
    const other = await createClient();
    const title = uniqueProcessTitle('Site');
    await createProcessOrFail(ceo.cookies, tenant.id, { title });

    const numbered = await createProcessViaApi(ceo.cookies, tenant.id, { title: `${title} 2` });
    await expectContract('createProcess', numbered);
    const elsewhere = await createProcessViaApi(ceo.cookies, other.id, { title });
    await expectContract('createProcess', elsewhere);

    expect([numbered.status, elsewhere.status]).toEqual([201, 201]);
  });

  it('F-80, E-98: the title of a completed process, and of a cancelled one, can be used again; only one active at a time', async () => {
    const tenant = await createClient();
    const finished = uniqueProcessTitle('Concluido');
    const dropped = uniqueProcessTitle('Cancelado');
    const done = await createProcessOrFail(ceo.cookies, tenant.id, {
      title: finished,
      stages: [{ name: 'Unica' }],
    });
    const cancelled = await createProcessOrFail(ceo.cookies, tenant.id, { title: dropped });
    const approval = await approveViaApi(ceo.cookies, done.id, {
      expectedStageId: stageAt(done, 1).id,
    });
    expect((await expectContract<ProcessDetailBody>('approveCurrentStage', approval)).status).toBe(
      'completed',
    );
    const cancelling = await updateProcessViaApi(ceo.cookies, cancelled.id, {
      status: 'cancelled',
    });
    await expectContract('updateProcess', cancelling);
    expect(cancelling.status).toBe(200);

    const again = await createProcessViaApi(ceo.cookies, tenant.id, { title: finished });
    const againBody = await expectContract<ProcessDetailBody>('createProcess', again);
    const sameAsCancelled = await createProcessViaApi(ceo.cookies, tenant.id, {
      title: dropped.toUpperCase(),
    });
    await expectContract('createProcess', sameAsCancelled);
    const third = await createProcessViaApi(ceo.cookies, tenant.id, { title: finished });

    expect([again.status, sameAsCancelled.status]).toEqual([201, 201]);
    expect(againBody.id).not.toBe(done.id);
    await expectTaken('createProcess', third, againBody.id);
    expect(await processCountOf(tenant.id)).toBe(4);
  });

  it('F-80, E-21, E-98: a create whose answer was lost and is repeated is 409, and the process exists once', async () => {
    const tenant = await createClient();
    const title = uniqueProcessTitle('Reenvio');
    const first = await createProcessOrFail(ceo.cookies, tenant.id, { title });

    // the first call was saved (its answer is the one a retry never saw): the repetition is the retry
    const repeated = await createProcessViaApi(ceo.cookies, tenant.id, { title });

    await expectTaken('createProcess', repeated, first.id);
    expect(await processTitlesOf(tenant.id)).toEqual([title]);
    const listed = await listProcessesViaApi(ceo.cookies, tenant.id);
    const list = await expectContract<ProcessListBody>('listClientProcesses', listed);
    expect(list.items.map((item) => item.id)).toEqual([first.id]);
    expect((await auditOfProcess(first.id)).map((event) => event.action)).toEqual([
      'process.created',
    ]);
  });
});

describe('F-80: renaming to a title another active process of the client has', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await loginAsCeoWithMfa();
  });

  it('F-80, E-97: is 409 CONFLICT in every spelling, and the process stays as it was (same version, no event)', async () => {
    const tenant = await createClient();
    const titleOne = uniqueProcessTitle('Site');
    const one = await createProcessOrFail(ceo.cookies, tenant.id, { title: titleOne });
    const two = await createProcessOrFail(ceo.cookies, tenant.id);
    const before = await stateOf(two.id);

    for (const title of [
      titleOne,
      titleOne.toUpperCase(),
      titleOne.replace(' ', '   '),
      `  ${titleOne}  `,
      `${FULL_WIDTH_S}${titleOne.slice(1)}`,
    ]) {
      const response = await updateProcessViaApi(ceo.cookies, two.id, { title });
      await expectTaken('updateProcess', response, one.id, titleOne);
    }

    expect(await stateOf(two.id)).toEqual(before);
    expect(before).toMatchObject({ version: 1, audit: ['process.created'] });
  });

  it('F-80, E-97, E-61: renaming to its own title is a no-op (200, same version), and only the case or the spaces is a rename (200, version + 1)', async () => {
    const tenant = await createClient();
    const title = uniqueProcessTitle('Site');
    const process = await createProcessOrFail(ceo.cookies, tenant.id, { title });

    const same = await updateProcessViaApi(ceo.cookies, process.id, { title });
    const sameBody = await expectContract<ProcessDetailBody>('updateProcess', same);
    const upper = await updateProcessViaApi(ceo.cookies, process.id, {
      title: title.toUpperCase(),
    });
    const upperBody = await expectContract<ProcessDetailBody>('updateProcess', upper);
    const spaced = await updateProcessViaApi(ceo.cookies, process.id, {
      title: `  ${title.toUpperCase().replace(' ', '   ')} `,
    });
    const spacedBody = await expectContract<ProcessDetailBody>('updateProcess', spaced);
    const repeated = await updateProcessViaApi(ceo.cookies, process.id, {
      title: title.toUpperCase().replace(' ', '   '),
    });
    const repeatedBody = await expectContract<ProcessDetailBody>('updateProcess', repeated);

    expect([same.status, upper.status, spaced.status, repeated.status]).toEqual([
      200, 200, 200, 200,
    ]);
    expect([sameBody.version, upperBody.version, spacedBody.version, repeatedBody.version]).toEqual(
      [1, 2, 3, 3],
    );
    expect(upperBody.title).toBe(title.toUpperCase());
    expect((await auditOfProcess(process.id)).map((event) => event.action)).toEqual([
      'process.created',
      'process.updated',
      'process.updated',
    ]);
  });

  it('F-80, E-97: renaming and cancelling in one call is 200 even to a title in use (the final state is cancelled), and then the title is free for a rename', async () => {
    const tenant = await createClient();
    const titleOne = uniqueProcessTitle('Site');
    await createProcessOrFail(ceo.cookies, tenant.id, { title: titleOne });
    const two = await createProcessOrFail(ceo.cookies, tenant.id);
    const three = await createProcessOrFail(ceo.cookies, tenant.id);

    const both = await updateProcessViaApi(ceo.cookies, two.id, {
      title: titleOne,
      status: 'cancelled',
    });
    const bothBody = await expectContract<ProcessDetailBody>('updateProcess', both);
    const taken = await updateProcessViaApi(ceo.cookies, three.id, { title: titleOne });

    expect(both.status).toBe(200);
    expect(bothBody).toMatchObject({ title: titleOne, status: 'cancelled', version: 2 });
    expect((await auditOfProcess(two.id)).map((event) => event.action)).toEqual([
      'process.created',
      'process.updated',
      'process.cancelled',
    ]);
    await expectTaken('updateProcess', taken, two.id);
  });

  it('F-80, E-98: renaming to the title of a completed or cancelled process, or of another client, is 200', async () => {
    const tenant = await createClient();
    const other = await createClient();
    const finished = uniqueProcessTitle('Concluido');
    const dropped = uniqueProcessTitle('Cancelado');
    const abroad = uniqueProcessTitle('Fora');
    const done = await createProcessOrFail(ceo.cookies, tenant.id, {
      title: finished,
      stages: [{ name: 'Unica' }],
    });
    const cancelled = await createProcessOrFail(ceo.cookies, tenant.id, { title: dropped });
    await createProcessOrFail(ceo.cookies, other.id, { title: abroad });
    await approveViaApi(ceo.cookies, done.id, { expectedStageId: stageAt(done, 1).id });
    await updateProcessViaApi(ceo.cookies, cancelled.id, { status: 'cancelled' });
    const mover = await createProcessOrFail(ceo.cookies, tenant.id);

    const toFinished = await updateProcessViaApi(ceo.cookies, mover.id, { title: finished });
    await expectContract('updateProcess', toFinished);
    const toDropped = await updateProcessViaApi(ceo.cookies, mover.id, { title: dropped });
    await expectContract('updateProcess', toDropped);
    const toAbroad = await updateProcessViaApi(ceo.cookies, mover.id, { title: abroad });
    const abroadBody = await expectContract<ProcessDetailBody>('updateProcess', toAbroad);

    expect([toFinished.status, toDropped.status, toAbroad.status]).toEqual([200, 200, 200]);
    expect(abroadBody).toMatchObject({ title: abroad, version: 4 });
  });

  it('F-80: a title that is not text is 400 before the title is looked up (the input comes first)', async () => {
    const tenant = await createClient();
    const process = await createProcessOrFail(ceo.cookies, tenant.id);

    const blank = await updateProcessViaApi(ceo.cookies, process.id, { title: '   ' });
    const body = await expectContract<Problem>('updateProcess', blank);

    expect(outcomeOf(blank, body)).toEqual([400, 'VALIDATION_ERROR']);
  });
});

describe('F-80: simultaneous writes of the same title, decided by the database', () => {
  let ceo: CeoWithMfa;
  let parker: CeoWithMfa;
  let holder: CeoWithMfa;

  beforeAll(async () => {
    ceo = await loginAsCeoWithMfa();
    parker = await loginAsCeoWithMfa();
    holder = await loginAsCeoWithMfa();
  });

  it('F-80, E-98: six creates of the same title fired at once give exactly one 201 and five 409 CONFLICT, and one process', async () => {
    const tenant = await createClient();
    const title = uniqueProcessTitle('Disputa');

    const responses = await Promise.all(
      Array.from({ length: 6 }, () => createProcessViaApi(ceo.cookies, tenant.id, { title })),
    );

    expect(responses.map((response) => response.status).sort()).toEqual([
      201, 409, 409, 409, 409, 409,
    ]);
    for (const response of responses) {
      if (response.status === 201)
        await expectContract<ProcessDetailBody>('createProcess', response);
      else await expectTaken('createProcess', response, title);
    }
    expect(await processTitlesOf(tenant.id)).toEqual([title]);
  });

  it('F-80, E-98: a create parked behind another create of the same title (held, not committed) is 409 once the first commits', async () => {
    const tenant = await createClient();
    const title = uniqueProcessTitle('Preso');
    const identity = ceoIdentityOf(holder);
    const held = await openHeldTransaction();
    let response: Response;
    try {
      // the holder's REAL create_process, not committed: it holds the client row and the title in the index
      await held.createProcess(identity, tenant.id, title);
      const parked = createProcessViaApi(parker.cookies, tenant.id, { title: title.toUpperCase() });
      await waitForLockWaiters(held, 'create_process', 1);
      await held.commit();
      response = await parked;
    } finally {
      await held.abort();
    }

    await expectTaken('createProcess', response, title);
    expect(await processCountOf(tenant.id)).toBe(1);
  });

  it('F-80, E-97: a rename parked behind another rename to the same title (held, not committed) is 409 once the first commits, and the loser keeps its title', async () => {
    const tenant = await createClient();
    const title = uniqueProcessTitle('Alvo');
    const winner = await createProcessOrFail(parker.cookies, tenant.id);
    const loser = await createProcessOrFail(parker.cookies, tenant.id);
    const loserBefore = await stateOf(loser.id);
    const identity = ceoIdentityOf(holder);
    const held = await openHeldTransaction();
    let response: Response;
    try {
      // the winner's REAL update_process, not committed: its title sits in the unique index, uncommitted
      await held.renameProcess(identity, winner.id, title);
      const parked = updateProcessViaApi(parker.cookies, loser.id, { title: title.toLowerCase() });
      await waitForLockWaiters(held, 'update_process', 1);
      await held.commit();
      response = await parked;
    } finally {
      await held.abort();
    }

    await expectTaken('updateProcess', response, winner.id, title);
    expect((await processRowOf(winner.id)).title).toBe(title);
    expect(await stateOf(loser.id)).toEqual(loserBefore);
  });
});

// ------------------------------------------------------------------------------------------ F-87 ----

/** A client with an active process of 3 stages (and one finished one, optionally), before it is archived. */
async function tenantWithProcess(cookies: CeoWithMfa['cookies']) {
  const tenant = await createClient();
  const process = await createProcessOrFail(cookies, tenant.id, {
    title: uniqueProcessTitle('Congelar'),
    stages: [{ name: 'Um' }, { name: 'Dois' }, { name: 'Tres' }],
  });
  return { tenant, process };
}

describe('F-87: the processes of an archived client are frozen', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await loginAsCeoWithMfa();
  });

  it('F-87, E-99: approving the current stage is 422 CLIENT_ARCHIVED, and nothing is written or audited', async () => {
    const { tenant, process } = await tenantWithProcess(ceo.cookies);
    await archiveViaApi(ceo.cookies, tenant.id);
    const before = await stateOf(process.id);

    const response = await approveViaApi(ceo.cookies, process.id, {
      expectedStageId: stageAt(process, 1).id,
    });

    await expectArchived('approveCurrentStage', response);
    expect(await stateOf(process.id)).toEqual(before);
    expect(before).toMatchObject({ status: 'active', version: 1, audit: ['process.created'] });
  });

  it('F-87, E-99: renaming, cancelling, and both together are 422 CLIENT_ARCHIVED, and nothing changes', async () => {
    const { tenant, process } = await tenantWithProcess(ceo.cookies);
    await archiveViaApi(ceo.cookies, tenant.id);
    const before = await stateOf(process.id);

    for (const body of [
      { title: uniqueProcessTitle('Novo') },
      { status: 'cancelled' },
      { title: uniqueProcessTitle('Novo'), status: 'cancelled' },
      { title: process.title },
    ]) {
      await expectArchived(
        'updateProcess',
        await updateProcessViaApi(ceo.cookies, process.id, body),
      );
    }

    expect(await stateOf(process.id)).toEqual(before);
  });

  it('F-87, E-99: the precedence: the archive wins over a finished process, a stale stage and a title in use; a missing process is 404; a bad body is 400; a client login is 403', async () => {
    const { tenant, process } = await tenantWithProcess(ceo.cookies);
    const done = await createProcessOrFail(ceo.cookies, tenant.id, {
      title: uniqueProcessTitle('Feito'),
      stages: [{ name: 'Unica' }],
    });
    const dropped = await createProcessOrFail(ceo.cookies, tenant.id);
    const peer = await createProcessOrFail(ceo.cookies, tenant.id, {
      title: uniqueProcessTitle('Par'),
    });
    await approveViaApi(ceo.cookies, done.id, { expectedStageId: stageAt(done, 1).id });
    await updateProcessViaApi(ceo.cookies, dropped.id, { status: 'cancelled' });
    const login = await signedInClientLogin(ceo.cookies, tenant.id);
    await archiveViaApi(ceo.cookies, tenant.id);

    // a completed process: CLIENT_ARCHIVED, not PROCESS_NOT_ACTIVE
    await expectArchived(
      'approveCurrentStage',
      await approveViaApi(ceo.cookies, done.id, { expectedStageId: stageAt(done, 1).id }),
    );
    await expectArchived(
      'updateProcess',
      await updateProcessViaApi(ceo.cookies, done.id, { title: uniqueProcessTitle('Outro') }),
    );
    // a cancelled one, cancelled again: CLIENT_ARCHIVED, not PROCESS_NOT_ACTIVE
    await expectArchived(
      'updateProcess',
      await updateProcessViaApi(ceo.cookies, dropped.id, { status: 'cancelled' }),
    );
    // a stage that is not the current one: CLIENT_ARCHIVED, not STALE_STAGE
    await expectArchived(
      'approveCurrentStage',
      await approveViaApi(ceo.cookies, process.id, { expectedStageId: stageAt(process, 2).id }),
    );
    // a title another active process of the client has: CLIENT_ARCHIVED, not CONFLICT
    await expectArchived(
      'updateProcess',
      await updateProcessViaApi(ceo.cookies, process.id, { title: peer.title.toUpperCase() }),
    );

    // a missing process is 404 whatever the client says
    const missing = await approveViaApi(ceo.cookies, UNKNOWN_ID, {
      expectedStageId: stageAt(process, 1).id,
    });
    const missingBody = await expectContract<Problem>('approveCurrentStage', missing);
    expect(outcomeOf(missing, missingBody)).toEqual([404, 'NOT_FOUND']);
    const missingUpdate = await updateProcessViaApi(ceo.cookies, UNKNOWN_ID, { title: 'Nada' });
    const missingUpdateBody = await expectContract<Problem>('updateProcess', missingUpdate);
    expect(outcomeOf(missingUpdate, missingUpdateBody)).toEqual([404, 'NOT_FOUND']);

    // a body that is not valid is 400 before the process is looked at
    const noBody = await approveViaApi(ceo.cookies, process.id, {});
    const noBodyBody = await expectContract<Problem>('approveCurrentStage', noBody);
    expect(outcomeOf(noBody, noBodyBody)).toEqual([400, 'VALIDATION_ERROR']);
    const emptyPatch = await updateProcessViaApi(ceo.cookies, process.id, {});
    const emptyPatchBody = await expectContract<Problem>('updateProcess', emptyPatch);
    expect(outcomeOf(emptyPatch, emptyPatchBody)).toEqual([400, 'VALIDATION_ERROR']);

    // the login of the archived client is not a CEO: 403, and the answer does not say the client is archived
    const asClient = await approveViaApi(login.cookies, process.id, {
      expectedStageId: stageAt(process, 1).id,
    });
    const asClientBody = await expectContract<Problem>('approveCurrentStage', asClient);
    expect(outcomeOf(asClient, asClientBody)).toEqual([403, 'FORBIDDEN']);
    const asClientUpdate = await updateProcessViaApi(login.cookies, process.id, {
      status: 'cancelled',
    });
    const asClientUpdateBody = await expectContract<Problem>('updateProcess', asClientUpdate);
    expect(outcomeOf(asClientUpdate, asClientUpdateBody)).toEqual([403, 'FORBIDDEN']);
    expect((await processRowOf(process.id)).version).toBe(1);
  });

  it('F-87, E-16: creating a process for an archived client is still 422 CLIENT_ARCHIVED', async () => {
    const { tenant } = await tenantWithProcess(ceo.cookies);
    await archiveViaApi(ceo.cookies, tenant.id);

    const response = await createProcessViaApi(ceo.cookies, tenant.id, {
      title: uniqueProcessTitle('Novo'),
    });

    await expectArchived('createProcess', response);
    expect(await processCountOf(tenant.id)).toBe(1);
  });
});

describe('F-87: reading is not frozen, and unarchiving thaws', () => {
  let ceo: CeoWithMfa;

  beforeAll(async () => {
    ceo = await loginAsCeoWithMfa();
  });

  it('F-87, E-83: the CEO still reads the list, the detail and the timeline of an archived client, and the client its own panel (200)', async () => {
    const { tenant, process } = await tenantWithProcess(ceo.cookies);
    const login = await signedInClientLogin(ceo.cookies, tenant.id);
    await archiveViaApi(ceo.cookies, tenant.id);

    const listed = await listProcessesViaApi(ceo.cookies, tenant.id);
    const list = await expectContract<ProcessListBody>('listClientProcesses', listed);
    const detail = await getProcessViaApi(ceo.cookies, process.id);
    const detailBody = await expectContract<ProcessDetailBody>('getProcess', detail);
    const events = await listEventsViaApi(ceo.cookies, process.id);
    const timeline = await expectContract<ProcessEventListBody>('listProcessEvents', events);
    const mine = await listMyProcessesViaApi(login.cookies);
    const myList = await expectContract<MyProcessListBody>('listMyProcesses', mine);
    const myDetail = await getMyProcessViaApi(login.cookies, process.id);
    const myDetailBody = await expectContract<MyProcessDetailBody>('getMyProcess', myDetail);

    expect([listed.status, detail.status, events.status, mine.status, myDetail.status]).toEqual([
      200, 200, 200, 200, 200,
    ]);
    expect(list.items.map((item) => item.id)).toEqual([process.id]);
    expect(detailBody).toMatchObject({ id: process.id, status: 'active', version: 1 });
    expect(timeline.items.map((event) => event.action)).toEqual(['process.created']);
    expect(myList.items.map((item) => item.id)).toEqual([process.id]);
    expect(myDetailBody.id).toBe(process.id);
  });

  it('F-87, E-100: unarchiving makes approve, rename and cancel work again, and archiving again freezes again', async () => {
    const { tenant, process } = await tenantWithProcess(ceo.cookies);
    const second = await createProcessOrFail(ceo.cookies, tenant.id, {
      title: uniqueProcessTitle('Segundo'),
    });
    await archiveViaApi(ceo.cookies, tenant.id);
    await expectArchived(
      'approveCurrentStage',
      await approveViaApi(ceo.cookies, process.id, { expectedStageId: stageAt(process, 1).id }),
    );
    expect((await processRowOf(process.id)).version).toBe(1);

    await unarchiveViaApi(ceo.cookies, tenant.id);
    const approved = await approveViaApi(ceo.cookies, process.id, {
      expectedStageId: stageAt(process, 1).id,
    });
    const approvedBody = await expectContract<ProcessDetailBody>('approveCurrentStage', approved);
    const renamed = await updateProcessViaApi(ceo.cookies, process.id, {
      title: uniqueProcessTitle('Renomeado'),
    });
    const renamedBody = await expectContract<ProcessDetailBody>('updateProcess', renamed);
    const cancelled = await updateProcessViaApi(ceo.cookies, process.id, { status: 'cancelled' });
    const cancelledBody = await expectContract<ProcessDetailBody>('updateProcess', cancelled);

    expect([approved.status, renamed.status, cancelled.status]).toEqual([200, 200, 200]);
    expect(approvedBody).toMatchObject({ completedStages: 1, version: 2 });
    expect(renamedBody.version).toBe(3);
    expect(cancelledBody).toMatchObject({ status: 'cancelled', version: 4 });
    // the archive/unarchive never touched the process on its own: the second is still as it was
    expect(await stateOf(second.id)).toMatchObject({ status: 'active', version: 1 });

    await archiveViaApi(ceo.cookies, tenant.id);
    await expectArchived(
      'updateProcess',
      await updateProcessViaApi(ceo.cookies, second.id, { status: 'cancelled' }),
    );
    expect(await stateOf(second.id)).toMatchObject({ status: 'active', version: 1 });
  });
});

describe('F-87: a write and an archive of the same client serialize on the client row', () => {
  let ceo: CeoWithMfa;
  let holder: CeoWithMfa;

  beforeAll(async () => {
    ceo = await loginAsCeoWithMfa();
    holder = await loginAsCeoWithMfa();
  });

  it('F-87, E-101: an approval and a rename parked behind an archive in flight (held, not committed) are 422 CLIENT_ARCHIVED once it commits, and write nothing', async () => {
    const { tenant, process } = await tenantWithProcess(ceo.cookies);
    const other = await createProcessOrFail(ceo.cookies, tenant.id, {
      title: uniqueProcessTitle('Outro'),
    });
    const beforeOne = await stateOf(process.id);
    const beforeTwo = await stateOf(other.id);
    const identity = ceoIdentityOf(holder);
    const held = await openHeldTransaction();
    let responses: Response[];
    try {
      // the holder's REAL update_client, not committed: it holds the client row, FOR NO KEY UPDATE
      await held.archiveClient(identity, tenant.id);
      const approving = approveViaApi(ceo.cookies, process.id, {
        expectedStageId: stageAt(process, 1).id,
      });
      const renaming = updateProcessViaApi(ceo.cookies, other.id, {
        title: uniqueProcessTitle('Renomear'),
      });
      await waitForLockWaiters(held, 'approve_current_stage', 1);
      await waitForLockWaiters(held, 'update_process', 1);
      await held.commit();
      responses = await Promise.all([approving, renaming]);
    } finally {
      await held.abort();
    }

    await expectArchived('approveCurrentStage', responses[0] as Response);
    await expectArchived('updateProcess', responses[1] as Response);
    expect(await stateOf(process.id)).toEqual(beforeOne);
    expect(await stateOf(other.id)).toEqual(beforeTwo);
  });

  it('F-87, E-101: an archive parked behind an approval in flight (held, not committed) waits for it, and then archives: the approval stands and the next one is refused', async () => {
    const { tenant, process } = await tenantWithProcess(ceo.cookies);
    const identity = ceoIdentityOf(holder);
    const held = await openHeldTransaction();
    let archive: Response;
    try {
      // the holder's REAL approve_current_stage, not committed: it holds the client row FOR SHARE
      await held.approveStage(identity, process.id, stageAt(process, 1).id);
      const archiving = updateClientViaApi(ceo.cookies, tenant.id, { archived: true });
      await waitForLockWaiters(held, 'update_client', 1);
      await held.commit();
      archive = await archiving;
    } finally {
      await held.abort();
    }

    const archived = await expectContract<{ archived: boolean }>('updateClient', archive);
    expect(archive.status).toBe(200);
    expect(archived.archived).toBe(true);
    expect(await stateOf(process.id)).toMatchObject({
      status: 'active',
      version: 2,
      stages: [
        [1, 'completed'],
        [2, 'in_progress'],
        [3, 'pending'],
      ],
      audit: ['process.created', 'stage.approved'],
    });
    await expectArchived(
      'approveCurrentStage',
      await approveViaApi(ceo.cookies, process.id, { expectedStageId: stageAt(process, 2).id }),
    );
  });

  it('F-87, E-101: two approvals of processes of the same client do not wait for each other (the client lock is shared)', async () => {
    const { tenant, process } = await tenantWithProcess(ceo.cookies);
    const other = await createProcessOrFail(ceo.cookies, tenant.id, {
      title: uniqueProcessTitle('Paralelo'),
      stages: [{ name: 'Um' }, { name: 'Dois' }],
    });
    const identity = ceoIdentityOf(holder);
    const held = await openHeldTransaction();
    let response: Response;
    try {
      // an approval in flight on one process: it holds the client FOR SHARE and that process
      await held.approveStage(identity, process.id, stageAt(process, 1).id);
      // the approval of ANOTHER process of the same client is not blocked by it: it answers while the first is open
      response = await approveViaApi(ceo.cookies, other.id, {
        expectedStageId: stageAt(other, 1).id,
      });
      await held.commit();
    } finally {
      await held.abort();
    }

    const body = await expectContract<ProcessDetailBody>('approveCurrentStage', response);
    expect(response.status).toBe(200);
    expect(body).toMatchObject({ id: other.id, completedStages: 1 });
    expect(await stateOf(process.id)).toMatchObject({ version: 2 });
    expect(await bodyOf(await getProcessViaApi(ceo.cookies, process.id))).toMatchObject({
      completedStages: 1,
    });
  });
});
