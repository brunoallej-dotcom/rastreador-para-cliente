// API tests of the process operations (operationIds `listClientProcesses`, `createProcess`,
// `getProcess`, `updateProcess`, `getDefaultStageTemplate`): the real route modules, the real pipeline
// and wiring (Postgres rate limiter, Supabase resolver), the local Supabase (Auth + PostgREST + the
// database functions), and every response checked against the OpenAPI contract, headers included.
//
// The CEO is a real one: it changed the temporary password, logged in through the API, enrolled TOTP
// and verified a code, so its cookies are an `aal2` session the backend attested (tests/helpers/mfa.ts).
// One CEO per group that writes: a CEO has 60 writes a minute, refused ones included.
//
// The tests of the "Ok" (AC-16, AC-17, AC-18) and of the timeline are Wave 9's, so no test here carries
// those ids; the read of an approval is checked with an approval made by a fixture.
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { encodeCursor } from '@/shared/http';
import { updateClientViaApi } from '../helpers/clients';
import { expectToMatchContract } from '../helpers/contract';
import {
  adminClient,
  ceoAal2Client,
  createCeo,
  createClient,
  createClientUser,
  directAal2Session,
  publishableClient,
} from '../helpers/fixtures';
import { bodyOf, spyOnSupabaseFetch, type CookieStore } from '../helpers/http';
import {
  completeFirstAccess,
  loginAsCeoReadyToEnroll,
  loginAsCeoWithMfa,
  loginViaApi,
  signInCeoWithMfa,
  type CeoWithMfa,
} from '../helpers/mfa';
import {
  approveStageAsFixture,
  auditOfProcess,
  createProcessesAt,
  createProcessOrFail,
  createProcessViaApi,
  getProcessViaApi,
  getStageTemplateViaApi,
  listAllProcesses,
  listProcessesViaApi,
  processCountOf,
  processRowOf,
  processTitlesOf,
  stageInputs,
  stageRowsOf,
  uniqueProcessTitle,
  updateProcessViaApi,
  type ProcessDetailBody,
  type ProcessListBody,
  type StageTemplateBody,
} from '../helpers/processes';

const COMBINING_ACUTE = String.fromCodePoint(0x0301);
const E_ACUTE = String.fromCodePoint(0x00e9);
const NO_BREAK_SPACE = String.fromCodePoint(0x00a0);
const IDEOGRAPHIC_SPACE = String.fromCodePoint(0x3000);
const HANGUL_FILLER = String.fromCodePoint(0x3164);
const ZERO_WIDTH_SPACE = String.fromCodePoint(0x200b);
const UNKNOWN_ID = '00000000-0000-4000-8000-00000000dead';
const BODY_LIMIT_BYTES = 16 * 1024;
const MAX_STAGES = 30;

let ceo: CeoWithMfa;

beforeAll(async () => {
  ceo = await loginAsCeoWithMfa();
});

/** Parses the body, checks it against the contract (headers too) and returns it. */
async function expectContract<T = unknown>(operationId: string, response: Response): Promise<T> {
  const text = await response.clone().text();
  const body: unknown = text === '' ? undefined : JSON.parse(text);
  expectToMatchContract(operationId, response.status, body, response);
  return body as T;
}

type Problem = {
  code: string;
  requestId?: string;
  detail?: string;
  errors?: { path: string; message: string }[];
  currentStageId?: string | null;
};

/** The statuses and codes a refused request answered, for a failure message that says which. */
const outcomeOf = (response: Response, body: Problem) => [response.status, body.code];

describe('GET /admin/stage-templates/default', () => {
  it('AC-15: a CEO reads the default stages in order, as the table holds them', async () => {
    const response = await getStageTemplateViaApi(ceo.cookies);
    const body = await expectContract<StageTemplateBody>('getDefaultStageTemplate', response);

    const { data, error } = await adminClient()
      .from('default_stage_template')
      .select('position, name, description')
      .order('position', { ascending: true });
    if (error) throw new Error(`reading the template failed: ${error.message}`);

    expect(response.status).toBe(200);
    expect(body.stages.length).toBeGreaterThanOrEqual(1);
    expect(body.stages).toEqual(data);
    expect(body.stages.map((stage) => stage.position)).toEqual(
      [...body.stages.map((stage) => stage.position)].sort((a, b) => a - b),
    );
  });
});

describe('POST /admin/clients/{clientId}/processes', () => {
  let creator: CeoWithMfa;

  beforeAll(async () => {
    creator = await loginAsCeoWithMfa();
  });

  describe('creating', () => {
    it('AC-15: without stages a process gets the default template: 201, a Location header, the first stage in progress', async () => {
      const tenant = await createClient();
      const title = uniqueProcessTitle('Site');
      const template = await expectContract<StageTemplateBody>(
        'getDefaultStageTemplate',
        await getStageTemplateViaApi(creator.cookies),
      );

      const response = await createProcessViaApi(creator.cookies, tenant.id, {
        title: `  ${title}  `,
      });
      const body = await expectContract<ProcessDetailBody>('createProcess', response);

      expect(response.status).toBe(201);
      expect(body).toMatchObject({
        title,
        status: 'active',
        version: 1,
        clientId: tenant.id,
        client: { id: tenant.id, name: tenant.name },
        totalStages: template.stages.length,
        completedStages: 0,
        completedAt: null,
        cancelledAt: null,
        currentStage: { position: 1, name: template.stages[0]?.name },
      });
      expect(body.stages.map((stage) => [stage.position, stage.name, stage.description])).toEqual(
        template.stages.map((stage) => [stage.position, stage.name, stage.description]),
      );
      expect(body.stages.map((stage) => stage.status)).toEqual(
        template.stages.map((_stage, index) => (index === 0 ? 'in_progress' : 'pending')),
      );
      expect(body.stages[0]).toMatchObject({ startedAt: body.createdAt, completedAt: null });
      expect(body.stages.slice(1).every((stage) => stage.startedAt === null)).toBe(true);
      expect(body.stages.every((stage) => stage.approval === null)).toBe(true);
      expect(response.headers.get('location')).toBe(`/api/v1/admin/processes/${body.id}`);
      expect(await processCountOf(tenant.id)).toBe(1);
    });

    it('E-63, AC-15: with stages it uses them in order, with their descriptions; a blank description is no description', async () => {
      const tenant = await createClient();

      const response = await createProcessViaApi(creator.cookies, tenant.id, {
        title: uniqueProcessTitle('Loja'),
        stages: [
          { name: '  Desenho  ', description: 'Telas e fluxo' },
          { name: 'Entrega' },
          { name: 'Revisao', description: '' },
          { name: 'Fim', description: '   ' },
        ],
      });
      const body = await expectContract<ProcessDetailBody>('createProcess', response);

      expect(response.status).toBe(201);
      expect(body.stages.map((stage) => [stage.position, stage.name, stage.description])).toEqual([
        [1, 'Desenho', 'Telas e fluxo'],
        [2, 'Entrega', null],
        [3, 'Revisao', null],
        [4, 'Fim', null],
      ]);
      expect(body.stages.map((stage) => stage.status)).toEqual([
        'in_progress',
        'pending',
        'pending',
        'pending',
      ]);
      expect(body.totalStages).toBe(4);
    });

    it('AC-15: a single stage and 30 stages are fine, and the first one starts in progress', async () => {
      const tenant = await createClient();

      const one = await createProcessViaApi(creator.cookies, tenant.id, {
        title: uniqueProcessTitle('Uma fase'),
        stages: stageInputs(1),
      });
      const thirty = await createProcessViaApi(creator.cookies, tenant.id, {
        title: uniqueProcessTitle('Trinta fases'),
        stages: stageInputs(MAX_STAGES),
      });
      const oneBody = await expectContract<ProcessDetailBody>('createProcess', one);
      const thirtyBody = await expectContract<ProcessDetailBody>('createProcess', thirty);

      expect([one.status, thirty.status]).toEqual([201, 201]);
      expect(oneBody.stages.map((stage) => stage.status)).toEqual(['in_progress']);
      expect(thirtyBody.stages.map((stage) => stage.position)).toEqual(
        Array.from({ length: MAX_STAGES }, (_value, index) => index + 1),
      );
      expect(thirtyBody.stages.filter((stage) => stage.status === 'in_progress')).toHaveLength(1);
      expect(thirtyBody.stages.map((stage) => stage.name)).toEqual(
        stageInputs(MAX_STAGES).map((stage) => stage.name),
      );
    });

    it('AC-15: the process that was created can be read back, identical', async () => {
      const tenant = await createClient();
      const created = await createProcessOrFail(creator.cookies, tenant.id);

      const response = await getProcessViaApi(creator.cookies, created.id);
      const body = await expectContract<ProcessDetailBody>('getProcess', response);

      expect(response.status).toBe(200);
      expect(body).toEqual(created);
    });

    it('AC-15: the new process opens the list of the client, with its current stage and its progress', async () => {
      const tenant = await createClient();
      const created = await createProcessOrFail(creator.cookies, tenant.id, {
        title: uniqueProcessTitle('Na lista'),
        stages: stageInputs(3),
      });

      const listed = await listAllProcesses(creator.cookies, tenant.id);

      expect(listed).toHaveLength(1);
      expect(listed[0]).toEqual({
        id: created.id,
        clientId: tenant.id,
        title: created.title,
        status: 'active',
        currentStage: created.currentStage,
        totalStages: 3,
        completedStages: 0,
        version: 1,
        createdAt: created.createdAt,
        updatedAt: created.updatedAt,
        completedAt: null,
        cancelledAt: null,
      });
      expect(listed[0]).not.toHaveProperty('stages');
    });

    it('E-30: a title and a stage name typed with a combining accent are stored in NFC', async () => {
      const tenant = await createClient();
      const unique = uniqueProcessTitle('Caf');

      const response = await createProcessViaApi(creator.cookies, tenant.id, {
        title: `${unique}e${COMBINING_ACUTE}`,
        stages: [{ name: `Etapa e${COMBINING_ACUTE}` }],
      });
      const body = await expectContract<ProcessDetailBody>('createProcess', response);

      expect(body.title).toBe(`${unique}${E_ACUTE}`);
      expect(body.stages[0]?.name).toBe(`Etapa ${E_ACUTE}`);
      expect((await processRowOf(body.id)).title).toBe(`${unique}${E_ACUTE}`);
      expect((await stageRowsOf(body.id))[0]?.name).toBe(`Etapa ${E_ACUTE}`);
    });

    it('AC-15: an unknown client is 404 NOT_FOUND and creates nothing; a malformed clientId is 400 (E-06)', async () => {
      const title = uniqueProcessTitle('Sem cliente');

      const unknown = await createProcessViaApi(creator.cookies, UNKNOWN_ID, { title });
      const malformed = await createProcessViaApi(creator.cookies, 'not-a-uuid', { title });

      const unknownBody = await expectContract<Problem>('createProcess', unknown);
      const malformedBody = await expectContract<Problem>('createProcess', malformed);
      expect(outcomeOf(unknown, unknownBody)).toEqual([404, 'NOT_FOUND']);
      expect(outcomeOf(malformed, malformedBody)).toEqual([400, 'VALIDATION_ERROR']);
      expect(malformedBody.errors?.map((issue) => issue.path)).toEqual(['params.clientId']);
      const { count } = await adminClient()
        .from('processes')
        .select('id', { count: 'exact', head: true })
        .eq('title', title);
      expect(count).toBe(0);
    });
  });

  describe('E-20: a list of stages that does not hold', () => {
    it.each([
      ['an empty list', [], 'body.stages'],
      ['31 stages', stageInputs(MAX_STAGES + 1), 'body.stages'],
      ['a stage named with spaces only', [{ name: 'Boa' }, { name: '   ' }], 'body.stages[1].name'],
      ['a stage with no name', [{}], 'body.stages[0].name'],
      ['a stage name over 120 characters', [{ name: 'n'.repeat(121) }], 'body.stages[0].name'],
      [
        'a stage name that is only a Hangul filler',
        [{ name: HANGUL_FILLER }],
        'body.stages[0].name',
      ],
      [
        'a description over 2000 characters',
        [{ name: 'A', description: 'd'.repeat(2001) }],
        'body.stages[0].description',
      ],
    ])(
      'E-20: %s is 400 VALIDATION_ERROR on %s and creates nothing',
      async (_label, stages, path) => {
        const tenant = await createClient();

        const response = await createProcessViaApi(creator.cookies, tenant.id, {
          title: uniqueProcessTitle('Fases ruins'),
          stages,
        });
        const body = await expectContract<Problem>('createProcess', response);

        expect(outcomeOf(response, body)).toEqual([400, 'VALIDATION_ERROR']);
        expect(body.errors?.map((issue) => issue.path)).toEqual([path]);
        expect(await processCountOf(tenant.id)).toBe(0);
      },
    );
  });

  describe('E-16: a client that is archived', () => {
    it('E-16: takes no process, with the template or with stages: 422 CLIENT_ARCHIVED, and nothing is created', async () => {
      const tenant = await createClient();
      const archived = await updateClientViaApi(creator.cookies, tenant.id, { archived: true });
      expect(archived.status).toBe(200);

      const withTemplate = await createProcessViaApi(creator.cookies, tenant.id, {
        title: uniqueProcessTitle('Arquivado'),
      });
      const withStages = await createProcessViaApi(creator.cookies, tenant.id, {
        title: uniqueProcessTitle('Arquivado'),
        stages: stageInputs(2),
      });

      const bodies = [
        await expectContract<Problem>('createProcess', withTemplate),
        await expectContract<Problem>('createProcess', withStages),
      ];
      expect([withTemplate.status, withStages.status]).toEqual([422, 422]);
      expect(bodies.map((body) => body.code)).toEqual(['CLIENT_ARCHIVED', 'CLIENT_ARCHIVED']);
      expect(await processCountOf(tenant.id)).toBe(0);
    });

    it('E-16: takes a process again once it is unarchived', async () => {
      const tenant = await createClient();
      await updateClientViaApi(creator.cookies, tenant.id, { archived: true });
      await updateClientViaApi(creator.cookies, tenant.id, { archived: false });

      const response = await createProcessViaApi(creator.cookies, tenant.id, {
        title: uniqueProcessTitle('Desarquivado'),
      });
      await expectContract<ProcessDetailBody>('createProcess', response);

      expect(response.status).toBe(201);
      expect(await processCountOf(tenant.id)).toBe(1);
    });

    it('E-16: keeps the processes it already has, and the list still shows them', async () => {
      const tenant = await createClient();
      const created = await createProcessOrFail(creator.cookies, tenant.id);
      await updateClientViaApi(creator.cookies, tenant.id, { archived: true });

      const listed = await listAllProcesses(creator.cookies, tenant.id);
      const detail = await getProcessViaApi(creator.cookies, created.id);
      await expectContract<ProcessDetailBody>('getProcess', detail);

      expect(listed.map((item) => item.id)).toEqual([created.id]);
      expect(detail.status).toBe(200);
    });
  });

  describe('SEC-16: the audit trail', () => {
    it('SEC-16: creating is audited in the same transaction, with the CEO and the request id, and no title', async () => {
      const tenant = await createClient();
      const title = uniqueProcessTitle('Auditado');

      const response = await createProcessViaApi(creator.cookies, tenant.id, {
        title,
        stages: [{ name: 'Etapa secreta' }],
      });
      const body = await expectContract<ProcessDetailBody>('createProcess', response);
      const audit = await auditOfProcess(body.id);

      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({
        action: 'process.created',
        actor_id: creator.ceo.id,
        actor_role: 'ceo',
        resource_type: 'process',
        resource_id: body.id,
        client_id: tenant.id,
        process_id: body.id,
        // the id the app sent to the database is the one the response carries
        request_id: response.headers.get('x-request-id'),
        metadata: {},
      });
      expect(JSON.stringify(audit)).not.toContain(title);
      expect(JSON.stringify(audit)).not.toContain('Etapa secreta');
    });

    it('SEC-16: a refused creation writes no audit event and no process', async () => {
      const tenant = await createClient();
      await updateClientViaApi(creator.cookies, tenant.id, { archived: true });

      await createProcessViaApi(creator.cookies, tenant.id, {
        title: uniqueProcessTitle('Negado'),
      });

      const { count, error } = await adminClient()
        .from('audit_events')
        .select('id', { count: 'exact', head: true })
        .eq('client_id', tenant.id)
        .like('action', 'process.%');
      expect(error).toBeNull();
      expect(count).toBe(0);
    });
  });
});

describe('the input of the process routes', () => {
  let inputCeo: CeoWithMfa;

  beforeAll(async () => {
    inputCeo = await loginAsCeoWithMfa();
  });

  it('AC-23: a clientId, a status, an id, a version or any other field in the body is 400 (mass assignment) and nothing is written', async () => {
    const tenant = await createClient();
    const title = uniqueProcessTitle('Atribuicao');
    const existing = await createProcessOrFail(inputCeo.cookies, tenant.id);

    const responses = await Promise.all([
      createProcessViaApi(inputCeo.cookies, tenant.id, { title, clientId: UNKNOWN_ID }),
      createProcessViaApi(inputCeo.cookies, tenant.id, { title, status: 'completed' }),
      createProcessViaApi(inputCeo.cookies, tenant.id, { title, id: UNKNOWN_ID }),
      createProcessViaApi(inputCeo.cookies, tenant.id, { title, version: 9 }),
      createProcessViaApi(inputCeo.cookies, tenant.id, {
        title,
        stages: [{ name: 'A', position: 7 }],
      }),
      createProcessViaApi(inputCeo.cookies, tenant.id, {
        title,
        stages: [{ name: 'A', status: 'completed' }],
      }),
      updateProcessViaApi(inputCeo.cookies, existing.id, { title: 'Outro', id: UNKNOWN_ID }),
      updateProcessViaApi(inputCeo.cookies, existing.id, { title: 'Outro', version: 9 }),
      updateProcessViaApi(inputCeo.cookies, existing.id, { title: 'Outro', clientId: UNKNOWN_ID }),
    ]);

    const operations = [
      ...Array<string>(6).fill('createProcess'),
      ...Array<string>(3).fill('updateProcess'),
    ];
    const bodies = await Promise.all(
      responses.map((response, index) =>
        expectContract<Problem>(operations[index] ?? '', response),
      ),
    );
    expect(responses.map((response) => response.status)).toEqual(Array(9).fill(400));
    expect(bodies.map((body) => body.code)).toEqual(Array(9).fill('VALIDATION_ERROR'));
    expect(await processTitlesOf(tenant.id)).toEqual([existing.title]);
    expect((await processRowOf(existing.id)).title).toBe(existing.title);
  });

  it.each([
    ['no title', {}, ['body.title']],
    ['an empty title', { title: '' }, ['body.title']],
    ['a title of spaces', { title: '   ' }, ['body.title']],
    ['a title over 160 characters', { title: 'a'.repeat(161) }, ['body.title']],
    ['a title that is only punctuation', { title: '...' }, ['body.title']],
    ['a title with a lone surrogate', { title: `A${String.fromCharCode(0xd800)}` }, ['body.title']],
    ['a title with a zero-width space', { title: `Zero${ZERO_WIDTH_SPACE}width` }, ['body.title']],
    ['a title that is only a no-break space', { title: NO_BREAK_SPACE }, ['body.title']],
    ['a title that is not text', { title: 42 }, ['body.title']],
  ])('E-30: creating with %s is 400 on %s and creates nothing', async (_label, body, paths) => {
    const tenant = await createClient();

    const response = await createProcessViaApi(inputCeo.cookies, tenant.id, body);
    const problem = await expectContract<Problem>('createProcess', response);

    expect(response.status).toBe(400);
    expect(problem.errors?.map((issue) => issue.path)).toEqual(paths);
    expect(await processCountOf(tenant.id)).toBe(0);
  });

  it('AC-23: a foreign Origin, a wrong Content-Type and a body over 16 KiB are refused before anything is written', async () => {
    const tenant = await createClient();
    const title = uniqueProcessTitle('Transporte');

    const origin = await createProcessViaApi(
      inputCeo.cookies,
      tenant.id,
      { title },
      { origin: 'https://evil.test' },
    );
    const noOrigin = await createProcessViaApi(
      inputCeo.cookies,
      tenant.id,
      { title },
      { origin: null },
    );
    const type = await createProcessViaApi(inputCeo.cookies, tenant.id, undefined, {
      rawBody: JSON.stringify({ title }),
      headers: { 'content-type': 'text/plain' },
    });
    const large = await createProcessViaApi(inputCeo.cookies, tenant.id, undefined, {
      rawBody: JSON.stringify({ title: 'a'.repeat(BODY_LIMIT_BYTES) }),
      headers: { 'content-type': 'application/json' },
    });

    expect([origin.status, noOrigin.status, type.status, large.status]).toEqual([
      403, 403, 415, 413,
    ]);
    expect(await bodyOf(origin)).toMatchObject({ code: 'ORIGIN_NOT_ALLOWED' });
    expect(await bodyOf(noOrigin)).toMatchObject({ code: 'ORIGIN_NOT_ALLOWED' });
    expect(await bodyOf(type)).toMatchObject({ code: 'UNSUPPORTED_MEDIA_TYPE' });
    expect(await bodyOf(large)).toMatchObject({ code: 'PAYLOAD_TOO_LARGE' });
    for (const response of [origin, noOrigin, type, large]) {
      await expectContract('createProcess', response);
    }
    expect(await processCountOf(tenant.id)).toBe(0);
  });

  it('AC-23: a foreign Origin, a wrong Content-Type and a body over 16 KiB are refused on the update too', async () => {
    const tenant = await createClient();
    const existing = await createProcessOrFail(inputCeo.cookies, tenant.id);

    const origin = await updateProcessViaApi(
      inputCeo.cookies,
      existing.id,
      { title: 'Outro' },
      { origin: 'https://evil.test' },
    );
    const type = await updateProcessViaApi(inputCeo.cookies, existing.id, undefined, {
      rawBody: JSON.stringify({ title: 'Outro' }),
      headers: { 'content-type': 'text/plain' },
    });
    const large = await updateProcessViaApi(inputCeo.cookies, existing.id, undefined, {
      rawBody: JSON.stringify({ title: 'a'.repeat(BODY_LIMIT_BYTES) }),
      headers: { 'content-type': 'application/json' },
    });

    expect([origin.status, type.status, large.status]).toEqual([403, 415, 413]);
    for (const response of [origin, type, large]) {
      await expectContract('updateProcess', response);
    }
    expect((await processRowOf(existing.id)).title).toBe(existing.title);
  });
});

describe('GET /admin/clients/{clientId}/processes', () => {
  describe('listing', () => {
    it('AC-15: lists the processes of the client newest first, and no other client’s', async () => {
      const tenant = await createClient();
      const other = await createClient();
      const first = await createProcessOrFail(ceo.cookies, tenant.id);
      const second = await createProcessOrFail(ceo.cookies, tenant.id);
      await createProcessOrFail(ceo.cookies, other.id);

      const response = await listProcessesViaApi(ceo.cookies, tenant.id);
      const body = await expectContract<ProcessListBody>('listClientProcesses', response);

      expect(response.status).toBe(200);
      expect(body.items.map((item) => item.id)).toEqual([second.id, first.id]);
      expect(body.items.every((item) => item.clientId === tenant.id)).toBe(true);
      expect(body.nextCursor).toBeNull();
    });

    it('AC-15: a client with no process is an empty page, not a 404', async () => {
      const tenant = await createClient();

      const response = await listProcessesViaApi(ceo.cookies, tenant.id);
      const body = await expectContract<ProcessListBody>('listClientProcesses', response);

      expect(response.status).toBe(200);
      expect(body).toEqual({ items: [], nextCursor: null });
    });

    it('AC-15: an unknown client is 404 NOT_FOUND; a malformed clientId is 400 (E-06)', async () => {
      const unknown = await listProcessesViaApi(ceo.cookies, UNKNOWN_ID);
      const malformed = await listProcessesViaApi(ceo.cookies, 'not-a-uuid');

      const unknownBody = await expectContract<Problem>('listClientProcesses', unknown);
      const malformedBody = await expectContract<Problem>('listClientProcesses', malformed);

      expect(outcomeOf(unknown, unknownBody)).toEqual([404, 'NOT_FOUND']);
      expect(outcomeOf(malformed, malformedBody)).toEqual([400, 'VALIDATION_ERROR']);
    });

    it('AC-15: pages the list, a tie on the creation instant included, repeating and skipping nothing', async () => {
      const tenant = await createClient();
      const tied = await createProcessesAt(tenant.id, '2026-03-04T05:06:07.123456+00:00', 3);
      const older = await createProcessesAt(tenant.id, '2026-03-03T05:06:07.000000+00:00', 2);
      const expected = [...tied, ...older].map((row) => row.id);

      const seen: string[] = [];
      let cursor: string | undefined;
      for (let page = 0; page < 10; page += 1) {
        const response = await listProcessesViaApi(ceo.cookies, tenant.id, {
          limit: '2',
          ...(cursor === undefined ? {} : { cursor }),
        });
        const body = await expectContract<ProcessListBody>('listClientProcesses', response);
        seen.push(...body.items.map((item) => item.id));
        if (body.nextCursor === null) break;
        cursor = body.nextCursor;
      }

      expect(seen).toEqual(expected);
    });

    it('AC-15: the keyset keeps the microseconds: a position resumes right after its own row', async () => {
      const tenant = await createClient();
      const rows = await createProcessesAt(tenant.id, '2026-03-04T05:06:07.123456+00:00', 3);

      const first = await expectContract<ProcessListBody>(
        'listClientProcesses',
        await listProcessesViaApi(ceo.cookies, tenant.id, { limit: '1' }),
      );
      const second = await expectContract<ProcessListBody>(
        'listClientProcesses',
        await listProcessesViaApi(ceo.cookies, tenant.id, {
          limit: '1',
          cursor: first.nextCursor ?? '',
        }),
      );

      expect(first.items.map((item) => item.id)).toEqual([rows[0]?.id]);
      expect(second.items.map((item) => item.id)).toEqual([rows[1]?.id]);
    });

    it('AC-15: the last page has no nextCursor, and a page that ends exactly there has none either', async () => {
      const tenant = await createClient();
      await createProcessesAt(tenant.id, '2026-03-04T05:06:07.000000+00:00', 2);

      const exact = await expectContract<ProcessListBody>(
        'listClientProcesses',
        await listProcessesViaApi(ceo.cookies, tenant.id, { limit: '2' }),
      );
      const short = await expectContract<ProcessListBody>(
        'listClientProcesses',
        await listProcessesViaApi(ceo.cookies, tenant.id, { limit: '1' }),
      );

      expect(exact.items).toHaveLength(2);
      expect(exact.nextCursor).toBeNull();
      expect(short.nextCursor).not.toBeNull();
    });

    it('AC-15: the status filter keeps only the processes in that status', async () => {
      const tenant = await createClient();
      const active = await createProcessOrFail(ceo.cookies, tenant.id);
      const toCancel = await createProcessOrFail(ceo.cookies, tenant.id);
      const toComplete = await createProcessOrFail(ceo.cookies, tenant.id, {
        title: uniqueProcessTitle('Uma fase'),
        stages: stageInputs(1),
      });
      await updateProcessViaApi(ceo.cookies, toCancel.id, { status: 'cancelled' });
      await approveStageAsFixture(toComplete.id, ceo.ceo.id);

      const idsOf = async (status: string) =>
        (await listAllProcesses(ceo.cookies, tenant.id, { status })).map((item) => item.id);

      expect(await idsOf('active')).toEqual([active.id]);
      expect(await idsOf('cancelled')).toEqual([toCancel.id]);
      expect(await idsOf('completed')).toEqual([toComplete.id]);
      expect(await listAllProcesses(ceo.cookies, tenant.id)).toHaveLength(3);
    });

    it('AC-15: a cancelled process shows where it stopped, and a completed one has no current stage', async () => {
      const tenant = await createClient();
      const cancelled = await createProcessOrFail(ceo.cookies, tenant.id, {
        title: uniqueProcessTitle('Parado'),
        stages: stageInputs(3),
      });
      const completed = await createProcessOrFail(ceo.cookies, tenant.id, {
        title: uniqueProcessTitle('Feito'),
        stages: stageInputs(2),
      });
      await approveStageAsFixture(cancelled.id, ceo.ceo.id);
      await updateProcessViaApi(ceo.cookies, cancelled.id, { status: 'cancelled' });
      await approveStageAsFixture(completed.id, ceo.ceo.id);
      await approveStageAsFixture(completed.id, ceo.ceo.id);

      const listed = await listAllProcesses(ceo.cookies, tenant.id);
      const byId = new Map(listed.map((item) => [item.id, item]));

      expect(byId.get(cancelled.id)).toMatchObject({
        status: 'cancelled',
        currentStage: { position: 2, name: 'Fase 2' },
        totalStages: 3,
        completedStages: 1,
      });
      expect(byId.get(completed.id)).toMatchObject({
        status: 'completed',
        currentStage: null,
        totalStages: 2,
        completedStages: 2,
      });
      expect(byId.get(completed.id)?.completedAt).not.toBeNull();
    });
  });

  describe('E-29: the cursor', () => {
    const POSITION = { c: '2026-11-16T11:30:24.984084+00:00', i: UNKNOWN_ID };

    async function realCursor(): Promise<{ clientId: string; cursor: string }> {
      const tenant = await createClient();
      await createProcessesAt(tenant.id, '2026-03-04T05:06:07.000000+00:00', 2);
      const response = await listProcessesViaApi(ceo.cookies, tenant.id, { limit: '1' });
      const body = await expectContract<ProcessListBody>('listClientProcesses', response);
      if (body.nextCursor === null) throw new Error('two processes must give a next cursor');
      return { clientId: tenant.id, cursor: body.nextCursor };
    }

    async function expectRefused(clientId: string, cursor: string) {
      const response = await listProcessesViaApi(ceo.cookies, clientId, { cursor });
      const body = await expectContract<Problem>('listClientProcesses', response);

      expect(response.status).toBe(400);
      expect(body.code).toBe('VALIDATION_ERROR');
      expect(body.errors?.map((issue) => issue.path)).toEqual(['query.cursor']);
    }

    it('E-29: the cursor the API issued is accepted and gives the next page', async () => {
      const { clientId, cursor } = await realCursor();

      const response = await listProcessesViaApi(ceo.cookies, clientId, { limit: '1', cursor });
      const body = await expectContract<ProcessListBody>('listClientProcesses', response);

      expect(response.status).toBe(200);
      expect(body.items).toHaveLength(1);
      expect(body.nextCursor).toBeNull();
    });

    it('E-29: a tampered cursor (truncated, extended, garbage) is 400 VALIDATION_ERROR', async () => {
      const { clientId, cursor } = await realCursor();

      await expectRefused(clientId, cursor.slice(0, -4));
      await expectRefused(clientId, `${cursor}AAAA`);
      await expectRefused(clientId, 'not-a-cursor');
      await expectRefused(clientId, 'A'.repeat(201));
    });

    it('F-53: a well-formed cursor with a timestamp the database cannot read is 400 on query.cursor, never 500', async () => {
      const { clientId } = await realCursor();

      await expectRefused(
        clientId,
        encodeCursor('admin-client-processes', {
          c: '0000-01-01T00:00:00.000000+00:00',
          i: POSITION.i,
        }),
      );
      await expectRefused(
        clientId,
        encodeCursor('admin-client-processes', {
          c: '2026-01-01T00:00:00.000000+23:59',
          i: POSITION.i,
        }),
      );
    });

    it('E-29: the cursor of another endpoint, or one with a payload of the wrong shape, is 400', async () => {
      const { clientId } = await realCursor();

      await expectRefused(clientId, encodeCursor('admin-clients', POSITION));
      await expectRefused(
        clientId,
        encodeCursor('admin-client-processes', { ...POSITION, extra: 1 }),
      );
      await expectRefused(
        clientId,
        encodeCursor('admin-client-processes', { c: 'yesterday', i: POSITION.i }),
      );
      await expectRefused(
        clientId,
        encodeCursor('admin-client-processes', { c: POSITION.c, i: 'nope' }),
      );
    });

    it.each([
      ['limit=0'],
      ['limit=101'],
      ['limit=abc'],
      ['status=done'],
      ['status='],
      ['clientId=x'],
    ])('AC-15: %s is 400 VALIDATION_ERROR', async (query) => {
      const tenant = await createClient();
      const [key = '', value = ''] = query.split('=');

      const response = await listProcessesViaApi(ceo.cookies, tenant.id, { [key]: value });
      const body = await expectContract<Problem>('listClientProcesses', response);

      expect(outcomeOf(response, body)).toEqual([400, 'VALIDATION_ERROR']);
      expect(body.errors?.map((issue) => issue.path)).toEqual([`query.${key}`]);
    });
  });
});

describe('GET /admin/processes/{processId}', () => {
  it('RF-09: a CEO reads the process of any client, with the client, every stage in order and no approval yet', async () => {
    const tenant = await createClient();
    const created = await createProcessOrFail(ceo.cookies, tenant.id, {
      title: uniqueProcessTitle('Detalhe'),
      stages: [{ name: 'Um', description: 'Primeira' }, { name: 'Dois' }, { name: 'Tres' }],
    });

    const response = await getProcessViaApi(ceo.cookies, created.id);
    const body = await expectContract<ProcessDetailBody>('getProcess', response);

    expect(response.status).toBe(200);
    expect(body).toMatchObject({
      id: created.id,
      clientId: tenant.id,
      client: { id: tenant.id, name: tenant.name },
      totalStages: 3,
      completedStages: 0,
      currentStage: { position: 1, name: 'Um' },
    });
    expect(body.stages.map((stage) => [stage.position, stage.name, stage.status])).toEqual([
      [1, 'Um', 'in_progress'],
      [2, 'Dois', 'pending'],
      [3, 'Tres', 'pending'],
    ]);
    expect(body.stages.every((stage) => stage.approval === null)).toBe(true);
  });

  it('RF-09: a completed stage carries who approved it and when; the next one is the current stage', async () => {
    const tenant = await createClient();
    const created = await createProcessOrFail(ceo.cookies, tenant.id, {
      title: uniqueProcessTitle('Aprovado'),
      stages: stageInputs(3),
    });
    await approveStageAsFixture(created.id, ceo.ceo.id);

    const response = await getProcessViaApi(ceo.cookies, created.id);
    const body = await expectContract<ProcessDetailBody>('getProcess', response);

    expect(body).toMatchObject({
      status: 'active',
      completedStages: 1,
      totalStages: 3,
      currentStage: { position: 2, name: 'Fase 2' },
    });
    expect(body.stages.map((stage) => stage.status)).toEqual([
      'completed',
      'in_progress',
      'pending',
    ]);
    const approval = body.stages[0]?.approval;
    expect(approval?.approvedBy).toEqual({ id: ceo.ceo.id, displayName: ceo.ceo.displayName });
    expect(Number.isNaN(Date.parse(approval?.approvedAt ?? ''))).toBe(false);
    expect(body.stages[0]?.completedAt).not.toBeNull();
    expect(body.stages[1]).toMatchObject({ approval: null, completedAt: null });
    expect(body.stages[2]).toMatchObject({ approval: null, startedAt: null });
  });

  it('RF-09: a process whose last stage was approved is completed, with no current stage', async () => {
    const tenant = await createClient();
    const created = await createProcessOrFail(ceo.cookies, tenant.id, {
      title: uniqueProcessTitle('Concluido'),
      stages: stageInputs(1),
    });
    await approveStageAsFixture(created.id, ceo.ceo.id);

    const body = await expectContract<ProcessDetailBody>(
      'getProcess',
      await getProcessViaApi(ceo.cookies, created.id),
    );

    expect(body).toMatchObject({ status: 'completed', currentStage: null, completedStages: 1 });
    expect(body.completedAt).not.toBeNull();
    expect(body.stages[0]?.approval?.approvedBy.id).toBe(ceo.ceo.id);
  });

  it('AC-15: an unknown process is 404 NOT_FOUND, with the same body as any other unknown id; a malformed one is 400 (E-06)', async () => {
    const first = await getProcessViaApi(ceo.cookies, UNKNOWN_ID);
    const second = await getProcessViaApi(ceo.cookies, '00000000-0000-4000-8000-00000000beef');
    const malformed = await getProcessViaApi(ceo.cookies, 'not-a-uuid');

    const firstBody = await expectContract<Problem>('getProcess', first);
    const secondBody = await expectContract<Problem>('getProcess', second);
    const malformedBody = await expectContract<Problem>('getProcess', malformed);

    expect(outcomeOf(first, firstBody)).toEqual([404, 'NOT_FOUND']);
    expect(secondBody).toEqual({ ...firstBody, requestId: secondBody.requestId });
    expect(outcomeOf(malformed, malformedBody)).toEqual([400, 'VALIDATION_ERROR']);
    expect(malformedBody.errors?.map((issue) => issue.path)).toEqual(['params.processId']);
  });
});

describe('PATCH /admin/processes/{processId}', () => {
  let updater: CeoWithMfa;

  beforeAll(async () => {
    updater = await loginAsCeoWithMfa();
  });

  /** A process of a fresh client, with three stages, created through the API. */
  async function freshProcess() {
    const tenant = await createClient();
    const process = await createProcessOrFail(updater.cookies, tenant.id, {
      title: uniqueProcessTitle('Original'),
      stages: stageInputs(3),
    });
    return { tenant, process };
  }

  describe('renaming', () => {
    it('AC-19: renames an active process: the title is trimmed, the version grows, the stages stay', async () => {
      const { process } = await freshProcess();
      const title = uniqueProcessTitle('Renomeado');

      const response = await updateProcessViaApi(updater.cookies, process.id, {
        title: `  ${title}  `,
      });
      const body = await expectContract<ProcessDetailBody>('updateProcess', response);

      expect(response.status).toBe(200);
      expect(body).toMatchObject({ title, status: 'active', version: 2, cancelledAt: null });
      expect(new Date(body.updatedAt).getTime()).toBeGreaterThan(
        new Date(process.updatedAt).getTime(),
      );
      expect(body.createdAt).toBe(process.createdAt);
      expect(body.stages).toEqual(process.stages);
      expect((await processRowOf(process.id)).title).toBe(title);
    });

    it('E-61, AC-19: a rename to the same title changes nothing: 200, same version, no audit event; a repeated PATCH is safe', async () => {
      const { process } = await freshProcess();
      const title = uniqueProcessTitle('Mesmo');
      await updateProcessViaApi(updater.cookies, process.id, { title });

      const again = await updateProcessViaApi(updater.cookies, process.id, { title: ` ${title} ` });
      const body = await expectContract<ProcessDetailBody>('updateProcess', again);
      const audit = await auditOfProcess(process.id);

      expect(again.status).toBe(200);
      expect(body).toMatchObject({ title, version: 2 });
      expect(audit.map((row) => row.action)).toEqual(['process.created', 'process.updated']);
    });

    it('E-30: renames in NFC', async () => {
      const { process } = await freshProcess();
      const unique = uniqueProcessTitle('Caf');

      const response = await updateProcessViaApi(updater.cookies, process.id, {
        title: `${unique}e${COMBINING_ACUTE}`,
      });
      const body = await expectContract<ProcessDetailBody>('updateProcess', response);

      expect(body.title).toBe(`${unique}${E_ACUTE}`);
    });
  });

  describe('cancelling', () => {
    it('AC-19: cancels an active process: cancelled, with its date, the version up, the stages frozen as they were', async () => {
      const { process } = await freshProcess();
      await approveStageAsFixture(process.id, updater.ceo.id);
      const before = await stageRowsOf(process.id);

      const response = await updateProcessViaApi(updater.cookies, process.id, {
        status: 'cancelled',
      });
      const body = await expectContract<ProcessDetailBody>('updateProcess', response);

      expect(response.status).toBe(200);
      expect(body).toMatchObject({ status: 'cancelled', completedAt: null, title: process.title });
      expect(body.cancelledAt).not.toBeNull();
      expect(body.version).toBeGreaterThan(process.version);
      expect(body.stages.map((stage) => stage.status)).toEqual([
        'completed',
        'in_progress',
        'pending',
      ]);
      expect(await stageRowsOf(process.id)).toEqual(before);
      expect(body.stages[0]?.approval?.approvedBy.id).toBe(updater.ceo.id);
    });

    it('E-60, AC-19: a cancelled process refuses the next change: 422 PROCESS_NOT_ACTIVE, for a cancel, a rename and the same title', async () => {
      const { process } = await freshProcess();
      await updateProcessViaApi(updater.cookies, process.id, { status: 'cancelled' });
      const before = await processRowOf(process.id);

      const cancelAgain = await updateProcessViaApi(updater.cookies, process.id, {
        status: 'cancelled',
      });
      const rename = await updateProcessViaApi(updater.cookies, process.id, {
        title: 'Tarde demais',
      });
      const sameTitle = await updateProcessViaApi(updater.cookies, process.id, {
        title: process.title,
      });

      const bodies = [
        await expectContract<Problem>('updateProcess', cancelAgain),
        await expectContract<Problem>('updateProcess', rename),
        await expectContract<Problem>('updateProcess', sameTitle),
      ];
      expect([cancelAgain.status, rename.status, sameTitle.status]).toEqual([422, 422, 422]);
      expect(bodies.map((body) => body.code)).toEqual(Array(3).fill('PROCESS_NOT_ACTIVE'));
      expect(await processRowOf(process.id)).toEqual(before);
    });

    it('E-60, AC-19: a completed process refuses a rename and a cancellation: 422 PROCESS_NOT_ACTIVE', async () => {
      const tenant = await createClient();
      const process = await createProcessOrFail(updater.cookies, tenant.id, {
        title: uniqueProcessTitle('Uma so'),
        stages: stageInputs(1),
      });
      await approveStageAsFixture(process.id, updater.ceo.id);
      const before = await processRowOf(process.id);
      expect(before.status).toBe('completed');

      const rename = await updateProcessViaApi(updater.cookies, process.id, { title: 'Depois' });
      const cancel = await updateProcessViaApi(updater.cookies, process.id, {
        status: 'cancelled',
      });

      const bodies = [
        await expectContract<Problem>('updateProcess', rename),
        await expectContract<Problem>('updateProcess', cancel),
      ];
      expect([rename.status, cancel.status]).toEqual([422, 422]);
      expect(bodies.map((body) => body.code)).toEqual(['PROCESS_NOT_ACTIVE', 'PROCESS_NOT_ACTIVE']);
      expect(await processRowOf(process.id)).toEqual(before);
    });

    it('E-61, AC-19: renaming and cancelling in one request does both and moves the version once', async () => {
      const { process } = await freshProcess();
      const title = uniqueProcessTitle('Encerrado');

      const response = await updateProcessViaApi(updater.cookies, process.id, {
        title,
        status: 'cancelled',
      });
      const body = await expectContract<ProcessDetailBody>('updateProcess', response);

      expect(response.status).toBe(200);
      expect(body).toMatchObject({ title, status: 'cancelled', version: 2 });
    });
  });

  describe('which process, and which input', () => {
    it('AC-19: an unknown process is 404 NOT_FOUND; a malformed processId is 400 (E-06)', async () => {
      const unknown = await updateProcessViaApi(updater.cookies, UNKNOWN_ID, { title: 'Nada' });
      const malformed = await updateProcessViaApi(updater.cookies, 'not-a-uuid', { title: 'Nada' });

      const unknownBody = await expectContract<Problem>('updateProcess', unknown);
      const malformedBody = await expectContract<Problem>('updateProcess', malformed);

      expect(outcomeOf(unknown, unknownBody)).toEqual([404, 'NOT_FOUND']);
      expect(outcomeOf(malformed, malformedBody)).toEqual([400, 'VALIDATION_ERROR']);
    });

    it.each([
      ['an empty body', {}, ['body']],
      ['a status that is not the one manual transition', { status: 'completed' }, ['body.status']],
      ['an active status', { status: 'active' }, ['body.status']],
      ['a null status', { status: null }, ['body.status']],
      ['an empty title', { title: '' }, ['body.title']],
      ['a title that is only a Hangul filler', { title: HANGUL_FILLER }, ['body.title']],
      ['a title over 160 characters', { title: 'a'.repeat(161) }, ['body.title']],
      [
        'a title with a lone surrogate',
        { title: `A${String.fromCharCode(0xd800)}` },
        ['body.title'],
      ],
    ])('AC-19: updating with %s is 400 on %s and changes nothing', async (_label, body, paths) => {
      const { process } = await freshProcess();
      const before = await processRowOf(process.id);

      const response = await updateProcessViaApi(updater.cookies, process.id, body);
      const problem = await expectContract<Problem>('updateProcess', response);

      expect(response.status).toBe(400);
      expect(problem.code).toBe('VALIDATION_ERROR');
      expect(problem.errors?.map((issue) => issue.path)).toEqual(paths);
      expect(await processRowOf(process.id)).toEqual(before);
    });
  });

  describe('SEC-16: the audit trail', () => {
    it('SEC-16: every real change is audited in the same transaction, with the CEO, the request id and no title', async () => {
      const { tenant, process } = await freshProcess();
      const renamed = uniqueProcessTitle('Renomeado');
      const requestIds: string[] = [];
      const track = (response: Response) => {
        requestIds.push(response.headers.get('x-request-id') ?? '');
        return response;
      };

      track(await updateProcessViaApi(updater.cookies, process.id, { title: renamed }));
      track(await updateProcessViaApi(updater.cookies, process.id, { title: renamed })); // nothing changes
      track(await updateProcessViaApi(updater.cookies, process.id, { status: 'cancelled' }));
      track(await updateProcessViaApi(updater.cookies, process.id, { status: 'cancelled' })); // refused

      const audit = await auditOfProcess(process.id);

      expect(audit.map((row) => row.action)).toEqual([
        'process.created',
        'process.updated',
        'process.cancelled',
      ]);
      for (const row of audit) {
        expect(row).toMatchObject({
          actor_id: updater.ceo.id,
          actor_role: 'ceo',
          resource_type: 'process',
          resource_id: process.id,
          client_id: tenant.id,
          process_id: process.id,
        });
      }
      expect(audit.map((row) => row.metadata)).toEqual([{}, { fields: ['title'] }, {}]);
      // the id the app sent to the database is the one the response carries
      expect(audit.slice(1).map((row) => row.request_id)).toEqual([requestIds[0], requestIds[2]]);
      expect(JSON.stringify(audit)).not.toContain(renamed);
      expect(JSON.stringify(audit)).not.toContain(process.title);
    });
  });
});

describe('the database on its own (F-52)', () => {
  // The API validates with Zod first; a CEO who calls the functions straight through PostgREST skips
  // it, so the database holds the same rules (private.visible_text).
  const REFUSED: [string, string][] = [
    ['only a no-break space', NO_BREAK_SPACE],
    ['only an ideographic space', IDEOGRAPHIC_SPACE],
    ['only a Hangul filler', HANGUL_FILLER],
    ['a filler between letters', `A${HANGUL_FILLER}B`],
    ['only punctuation', '***'],
    ['a zero-width space', `Zero${ZERO_WIDTH_SPACE}width`],
  ];

  it.each(REFUSED)(
    'F-52: create_process refuses %s as a title, a stage name and a description',
    async (_label, text) => {
      const { supabase } = await ceoAal2Client();
      const tenant = await createClient();

      const asTitle = await supabase.rpc('create_process', {
        p_client_id: tenant.id,
        p_title: text,
      });
      const asName = await supabase.rpc('create_process', {
        p_client_id: tenant.id,
        p_title: 'Titulo',
        p_stages: [{ name: text }],
      });
      const asDescription = await supabase.rpc('create_process', {
        p_client_id: tenant.id,
        p_title: 'Titulo',
        p_stages: [{ name: 'Boa', description: text }],
      });

      for (const result of [asTitle, asName, asDescription]) {
        expect(result.data).toBeNull();
        expect(result.error).toMatchObject({ code: 'P0001', message: 'INVALID_INPUT' });
      }
      expect(await processCountOf(tenant.id)).toBe(0);
    },
  );

  it('F-52: update_process refuses the same titles and leaves the process alone', async () => {
    const { supabase } = await ceoAal2Client();
    const tenant = await createClient();
    const created = await createProcessOrFail(ceo.cookies, tenant.id);

    for (const [, text] of REFUSED) {
      const { error } = await supabase.rpc('update_process', {
        p_process_id: created.id,
        p_title: text,
      });
      expect(error).toMatchObject({ code: 'P0001', message: 'INVALID_INPUT' });
    }
    expect((await processRowOf(created.id)).title).toBe(created.title);
  });

  it('F-52: it accepts what the API accepts, trimmed like the API trims it, and refuses the extra keys the API refuses', async () => {
    const { supabase } = await ceoAal2Client();
    const tenant = await createClient();
    const title = uniqueProcessTitle('Direto');

    const padded = await supabase.rpc('create_process', {
      p_client_id: tenant.id,
      p_title: `${NO_BREAK_SPACE}${title}${IDEOGRAPHIC_SPACE}`,
      p_stages: [{ name: ` Etapa ${NO_BREAK_SPACE}`, description: null }],
    });
    const smuggled = await supabase.rpc('create_process', {
      p_client_id: tenant.id,
      p_title: 'Titulo',
      p_stages: [{ name: 'A', status: 'completed' }],
    });

    expect(padded.error).toBeNull();
    expect(padded.data?.title).toBe(title);
    expect((await stageRowsOf(padded.data?.id ?? ''))[0]).toMatchObject({
      name: 'Etapa',
      status: 'in_progress',
    });
    expect(smuggled.error).toMatchObject({ code: 'P0001', message: 'INVALID_INPUT' });
    expect(await processCountOf(tenant.id)).toBe(1);
  });

  it('E-20: straight through PostgREST, an empty list and 31 stages are INVALID_INPUT and the template is the default', async () => {
    const { supabase } = await ceoAal2Client();
    const tenant = await createClient();

    const empty = await supabase.rpc('create_process', {
      p_client_id: tenant.id,
      p_title: 'Titulo',
      p_stages: [],
    });
    const tooMany = await supabase.rpc('create_process', {
      p_client_id: tenant.id,
      p_title: 'Titulo',
      p_stages: stageInputs(MAX_STAGES + 1),
    });
    const template = await supabase.rpc('create_process', {
      p_client_id: tenant.id,
      p_title: 'Titulo do template',
    });

    expect(empty.error).toMatchObject({ code: 'P0001', message: 'INVALID_INPUT' });
    expect(tooMany.error).toMatchObject({ code: 'P0001', message: 'INVALID_INPUT' });
    expect(template.error).toBeNull();
    expect((await stageRowsOf(template.data?.id ?? '')).length).toBeGreaterThanOrEqual(1);
    expect(await processCountOf(tenant.id)).toBe(1);
  });

  it('E-16: straight through PostgREST, an archived client is CLIENT_ARCHIVED and an unknown one NOT_FOUND', async () => {
    const { supabase } = await ceoAal2Client();
    const tenant = await createClient();
    await adminClient()
      .from('clients')
      .update({ archived_at: new Date().toISOString() })
      .eq('id', tenant.id);

    const archived = await supabase.rpc('create_process', {
      p_client_id: tenant.id,
      p_title: 'Titulo',
    });
    const unknown = await supabase.rpc('create_process', {
      p_client_id: UNKNOWN_ID,
      p_title: 'Titulo',
    });

    expect(archived.error).toMatchObject({ code: 'P0001', message: 'CLIENT_ARCHIVED' });
    expect(unknown.error).toMatchObject({ code: 'P0001', message: 'NOT_FOUND' });
    expect(await processCountOf(tenant.id)).toBe(0);
  });
});

describe('who may call the process routes', () => {
  /** Calls the five operations with the cookies (or none) and answers their responses. */
  async function callAll(cookies: CookieStore | undefined, clientId: string, processId: string) {
    return [
      ['listClientProcesses', await listProcessesViaApi(cookies, clientId)],
      [
        'createProcess',
        await createProcessViaApi(cookies, clientId, { title: uniqueProcessTitle('Negado') }),
      ],
      ['getProcess', await getProcessViaApi(cookies, processId)],
      ['updateProcess', await updateProcessViaApi(cookies, processId, { title: 'Negado' })],
      ['getDefaultStageTemplate', await getStageTemplateViaApi(cookies)],
    ] as const;
  }

  async function expectAllRefused(cookies: CookieStore | undefined, status: number, code: string) {
    const tenant = await createClient();
    const process = await createProcessOrFail(ceo.cookies, tenant.id);
    for (const [operationId, response] of await callAll(cookies, tenant.id, process.id)) {
      const body = await expectContract<Problem>(operationId, response);
      expect([operationId, response.status, body.code]).toEqual([operationId, status, code]);
    }
    expect(await processTitlesOf(tenant.id)).toEqual([process.title]);
    expect((await processRowOf(process.id)).title).toBe(process.title);
  }

  it('SEC-01: without a session every operation is 401 UNAUTHENTICATED and nothing is created', async () => {
    await expectAllRefused(undefined, 401, 'UNAUTHENTICATED');
  });

  it('AC-21: a client user is 403 FORBIDDEN on every operation, with processes of its own tenant too, and creates nothing', async () => {
    const tenant = await createClient();
    const own = await createProcessOrFail(ceo.cookies, tenant.id);
    const user = await completeFirstAccess(await createClientUser({ clientId: tenant.id }));
    const cookies = await loginViaApi(user);

    for (const [operationId, response] of await callAll(cookies, tenant.id, own.id)) {
      const body = await expectContract<Problem>(operationId, response);
      expect([operationId, response.status, body.code]).toEqual([operationId, 403, 'FORBIDDEN']);
    }
    expect(await processTitlesOf(tenant.id)).toEqual([own.title]);
    expect((await processRowOf(own.id)).title).toBe(own.title);
  });

  it('AC-21: a client user cannot cancel or rename a process of its own client either', async () => {
    const tenant = await createClient();
    const own = await createProcessOrFail(ceo.cookies, tenant.id);
    const user = await completeFirstAccess(await createClientUser({ clientId: tenant.id }));
    const cookies = await loginViaApi(user);

    const cancel = await updateProcessViaApi(cookies, own.id, { status: 'cancelled' });
    const rename = await updateProcessViaApi(cookies, own.id, { title: 'Meu processo' });

    const bodies = [
      await expectContract<Problem>('updateProcess', cancel),
      await expectContract<Problem>('updateProcess', rename),
    ];
    expect([cancel.status, rename.status]).toEqual([403, 403]);
    expect(bodies.map((body) => body.code)).toEqual(['FORBIDDEN', 'FORBIDDEN']);
    expect(await processRowOf(own.id)).toMatchObject({
      status: 'active',
      title: own.title,
      version: 1,
    });
  });

  it('SEC-11: a CEO whose session is aal1, with a verified factor, is 403 MFA_VERIFICATION_REQUIRED', async () => {
    const cookies = await signInCeoWithMfa(ceo, { verify: false });

    await expectAllRefused(cookies, 403, 'MFA_VERIFICATION_REQUIRED');
  });

  it('SEC-11: a CEO with no TOTP factor is 403 MFA_ENROLLMENT_REQUIRED', async () => {
    const { cookies } = await loginAsCeoReadyToEnroll();

    await expectAllRefused(cookies, 403, 'MFA_ENROLLMENT_REQUIRED');
  });

  it('spec §3.5: a CEO who still has the temporary password is 403 PASSWORD_CHANGE_REQUIRED', async () => {
    const fresh = await createCeo();
    const cookies = await loginViaApi(fresh);

    await expectAllRefused(cookies, 403, 'PASSWORD_CHANGE_REQUIRED');
  });

  it('SEC-04: a CEO token cannot write the tables directly, only through the functions', async () => {
    const tenant = await createClient();
    const supabase = publishableClient();
    const signIn = await supabase.auth.signInWithPassword({
      email: ceo.ceo.email,
      password: ceo.ceo.password,
    });
    expect(signIn.error).toBeNull();

    const insert = await supabase
      .from('processes')
      .insert({ client_id: tenant.id, title: uniqueProcessTitle('Direto') });

    expect(insert.error).not.toBeNull();
    expect(insert.error?.code).toBe('42501');
    expect(await processCountOf(tenant.id)).toBe(0);
  });

  it('F-50 b: an aal2 session obtained straight at Auth, with the password and the publishable key, does not run the CEO functions', async () => {
    const tenant = await createClient();
    const fresh = await createCeo();
    const direct = await directAal2Session(fresh);
    const existing = await createProcessOrFail(ceo.cookies, tenant.id);

    const create = await direct.supabase.rpc('create_process', {
      p_client_id: tenant.id,
      p_title: uniqueProcessTitle('Direto'),
    });
    const update = await direct.supabase.rpc('update_process', {
      p_process_id: existing.id,
      p_cancel: true,
    });
    const read = await direct.supabase.from('processes').select('id').eq('id', existing.id);

    expect(create.error).toMatchObject({ code: '42501' });
    expect(update.error).toMatchObject({ code: '42501' });
    expect(read.data).toEqual([]);
    expect(await processTitlesOf(tenant.id)).toEqual([existing.title]);
    expect(await processRowOf(existing.id)).toMatchObject({ status: 'active', version: 1 });
  });
});

describe('Supabase failing', () => {
  /** Makes the requests whose URL holds `part` fail the way a dead network does. */
  const failing = (part: string) =>
    spyOnSupabaseFetch((url) => (url.includes(part) ? new TypeError('fetch failed') : undefined));

  /** 503 `SERVICE_UNAVAILABLE` with a `Retry-After` of at least a second, as the contract documents. */
  async function expectUnavailable(operationId: string, response: Response) {
    const body = await expectContract<Problem>(operationId, response);

    expect(response.status).toBe(503);
    expect(body.code).toBe('SERVICE_UNAVAILABLE');
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
  }

  let outageCeo: CeoWithMfa;

  beforeAll(async () => {
    outageCeo = await loginAsCeoWithMfa();
  });

  it('E-21: listClientProcesses that cannot reach the database is 503 SERVICE_UNAVAILABLE, not a 500', async () => {
    const tenant = await createClient();
    const spy = failing('/rest/v1/processes');
    try {
      await expectUnavailable(
        'listClientProcesses',
        await listProcessesViaApi(outageCeo.cookies, tenant.id),
      );
    } finally {
      spy.restore();
    }
  });

  it('E-21: getProcess that cannot reach the database is 503 SERVICE_UNAVAILABLE', async () => {
    const spy = failing('/rest/v1/processes');
    try {
      await expectUnavailable('getProcess', await getProcessViaApi(outageCeo.cookies, UNKNOWN_ID));
    } finally {
      spy.restore();
    }
  });

  it('E-21: getDefaultStageTemplate that cannot reach the database is 503 SERVICE_UNAVAILABLE', async () => {
    const spy = failing('/rest/v1/default_stage_template');
    try {
      await expectUnavailable(
        'getDefaultStageTemplate',
        await getStageTemplateViaApi(outageCeo.cookies),
      );
    } finally {
      spy.restore();
    }
  });

  it('E-21: createProcess that cannot reach the database is 503 and nothing is created', async () => {
    const tenant = await createClient();
    const spy = failing('/rest/v1/rpc/create_process');
    try {
      await expectUnavailable(
        'createProcess',
        await createProcessViaApi(outageCeo.cookies, tenant.id, {
          title: uniqueProcessTitle('Fora do ar'),
        }),
      );
    } finally {
      spy.restore();
    }
    expect(await processCountOf(tenant.id)).toBe(0);
  });

  it('E-21: createProcess whose answer was lost (503) and is repeated makes a SECOND process: a create has no natural key, so the CEO checks the list first', async () => {
    const tenant = await createClient();
    const title = uniqueProcessTitle('Reenvio');
    const realFetch = globalThis.fetch;
    // the function runs and commits; what the app never receives is its answer
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input instanceof Request ? input.url : input);
      const answer = await realFetch(input, init);
      if (!url.includes('/rest/v1/rpc/create_process')) return answer;
      void answer.body?.cancel();
      throw new TypeError('fetch failed');
    });
    let lost: Response;
    try {
      lost = await createProcessViaApi(outageCeo.cookies, tenant.id, { title });
    } finally {
      spy.mockRestore();
    }
    await expectUnavailable('createProcess', lost);
    expect(await processCountOf(tenant.id)).toBe(1);

    const repeated = await createProcessViaApi(outageCeo.cookies, tenant.id, { title });
    await expectContract<ProcessDetailBody>('createProcess', repeated);

    expect(repeated.status).toBe(201);
    expect(await processTitlesOf(tenant.id)).toEqual([title, title]);
    const listed = await listAllProcesses(outageCeo.cookies, tenant.id);
    expect(listed.map((item) => item.title)).toEqual([title, title]);
    expect(new Set(listed.map((item) => item.id)).size).toBe(2);
  });

  it('E-21: createProcess that was saved but whose read-back cannot reach the database is 503, and the process exists', async () => {
    const tenant = await createClient();
    const title = uniqueProcessTitle('Gravado');
    const spy = failing('/rest/v1/processes?');
    try {
      await expectUnavailable(
        'createProcess',
        await createProcessViaApi(outageCeo.cookies, tenant.id, { title }),
      );
    } finally {
      spy.restore();
    }
    expect(await processTitlesOf(tenant.id)).toEqual([title]);
  });

  it('E-21: updateProcess that cannot reach the database is 503 and changes nothing', async () => {
    const tenant = await createClient();
    const created = await createProcessOrFail(outageCeo.cookies, tenant.id);
    const spy = failing('/rest/v1/rpc/update_process');
    try {
      await expectUnavailable(
        'updateProcess',
        await updateProcessViaApi(outageCeo.cookies, created.id, { status: 'cancelled' }),
      );
    } finally {
      spy.restore();
    }
    expect(await processRowOf(created.id)).toMatchObject({ status: 'active', version: 1 });
  });

  it('E-21: updateProcess whose answer cannot be read back is 503 too, the change is already made, and repeating it is safe', async () => {
    const tenant = await createClient();
    const created = await createProcessOrFail(outageCeo.cookies, tenant.id);
    const title = uniqueProcessTitle('Gravado');
    const spy = failing('/rest/v1/processes?');
    try {
      await expectUnavailable(
        'updateProcess',
        await updateProcessViaApi(outageCeo.cookies, created.id, { title }),
      );
    } finally {
      spy.restore();
    }
    expect((await processRowOf(created.id)).title).toBe(title);

    const repeated = await updateProcessViaApi(outageCeo.cookies, created.id, { title });
    const body = await expectContract<ProcessDetailBody>('updateProcess', repeated);

    expect(repeated.status).toBe(200);
    expect(body).toMatchObject({ title, version: 2 });
  });

  it('E-60, E-21: a cancel whose answer was lost (503) and is repeated is 422 PROCESS_NOT_ACTIVE: it was saved, the retry undoes nothing', async () => {
    const tenant = await createClient();
    const created = await createProcessOrFail(outageCeo.cookies, tenant.id);
    const realFetch = globalThis.fetch;
    // the function runs and commits; what the app never receives is its answer
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input instanceof Request ? input.url : input);
      const answer = await realFetch(input, init);
      if (!url.includes('/rest/v1/rpc/update_process')) return answer;
      void answer.body?.cancel();
      throw new TypeError('fetch failed');
    });
    let lost: Response;
    try {
      lost = await updateProcessViaApi(outageCeo.cookies, created.id, { status: 'cancelled' });
    } finally {
      spy.mockRestore();
    }
    await expectUnavailable('updateProcess', lost);
    const saved = await processRowOf(created.id);
    expect(saved).toMatchObject({ status: 'cancelled', version: 2 });

    const repeated = await updateProcessViaApi(outageCeo.cookies, created.id, {
      status: 'cancelled',
    });
    const body = await expectContract<Problem>('updateProcess', repeated);

    expect(outcomeOf(repeated, body)).toEqual([422, 'PROCESS_NOT_ACTIVE']);
    expect(await processRowOf(created.id)).toEqual(saved);
    // the CEO reads the process to see what the lost answer would have said
    const detail = await expectContract<ProcessDetailBody>(
      'getProcess',
      await getProcessViaApi(outageCeo.cookies, created.id),
    );
    expect(detail).toMatchObject({ status: 'cancelled', version: 2 });
    expect((await auditOfProcess(created.id)).map((row) => row.action)).toEqual([
      'process.created',
      'process.cancelled',
    ]);
  });
});

describe('the rate limit of the process reads (x-rate-limit: 300 / min per CEO)', () => {
  // A CEO of its own: the 300 reads it spends must not come out of the budget of any other test.
  const READ_LIMIT = 300;
  const BATCH = 30;
  /** More than two windows of reads: a minute boundary in the middle cannot hide the cap. */
  const MAX_READS = READ_LIMIT * 2 + BATCH;

  it('SEC-09: the read after the 300th in a minute is 429 RATE_LIMITED with a Retry-After, and the answer matches the contract', async () => {
    const limited = await loginAsCeoWithMfa();

    const throttled: Response[] = [];
    let ok = 0;
    for (let sent = 0; sent < MAX_READS && throttled.length === 0; sent += BATCH) {
      const batch = await Promise.all(
        Array.from({ length: BATCH }, () => getStageTemplateViaApi(limited.cookies)),
      );
      for (const response of batch) {
        if (response.status === 429) throttled.push(response);
        else if (response.status === 200) ok += 1;
        else throw new Error(`a read answered ${response.status}, neither 200 nor 429`);
      }
    }

    expect(throttled.length).toBeGreaterThanOrEqual(1);
    // the reads that got through are at most the limit of the window they fell in (two windows at most)
    expect(ok).toBeGreaterThanOrEqual(1);
    expect(ok).toBeLessThanOrEqual(READ_LIMIT * 2);
    for (const response of throttled) {
      const body = await expectContract<Problem>('getDefaultStageTemplate', response);
      expect(body.code).toBe('RATE_LIMITED');
      const retryAfter = Number(response.headers.get('retry-after'));
      expect(retryAfter).toBeGreaterThanOrEqual(1);
      expect(retryAfter).toBeLessThanOrEqual(60);
    }
  }, 180_000);

  it('SEC-09: the budget is the CEO’s own: another CEO still reads after the first one is throttled', async () => {
    const other = await loginAsCeoWithMfa();

    const response = await getStageTemplateViaApi(other.cookies);
    await expectContract<StageTemplateBody>('getDefaultStageTemplate', response);

    expect(response.status).toBe(200);
  });
});
