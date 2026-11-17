// API tests of the client operations (operationIds `listClients`, `createClient`, `getClient`,
// `updateClient`): the real route modules, the real pipeline and wiring (Postgres rate limiter,
// Supabase resolver), the local Supabase (Auth + PostgREST + the database functions), and every
// response checked against the OpenAPI contract, headers included.
//
// The CEO is a real one: it changed the temporary password, logged in through the API, enrolled TOTP
// and verified a code, so its cookies are an `aal2` session (tests/helpers/mfa.ts).
import { randomInt } from 'node:crypto';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { encodeCursor } from '@/shared/http';
import { expectToMatchContract } from '../helpers/contract';
import { countClients, countClientsNamed, readClientRow } from '../helpers/db';
import {
  auditOfClient,
  createClientOrFail,
  createClientsAt,
  createClientsWithSameCreationInstant,
  createClientViaApi,
  findInClientList,
  getClientViaApi,
  listClientsViaApi,
  seedProcesses,
  uniqueClientName,
  updateClientViaApi,
  type ClientDetailBody,
  type ClientListBody,
} from '../helpers/clients';
import {
  ceoAal2Client,
  createCeo,
  createClient,
  createClientUser,
  publishableClient,
} from '../helpers/fixtures';
import { bodyOf, spyOnSupabaseFetch, withoutRequestId, type CookieStore } from '../helpers/http';
import {
  completeFirstAccess,
  loginAsCeoReadyToEnroll,
  loginAsCeoWithMfa,
  loginViaApi,
  signInCeoWithMfa,
  type CeoWithMfa,
} from '../helpers/mfa';

const COMBINING_ACUTE = String.fromCodePoint(0x0301);
const E_ACUTE = String.fromCodePoint(0x00e9);
const NO_BREAK_SPACE = String.fromCodePoint(0x00a0);
const IDEOGRAPHIC_SPACE = String.fromCodePoint(0x3000);
const HANGUL_FILLER = String.fromCodePoint(0x3164);
const CYRILLIC_CAPITAL_A = String.fromCodePoint(0x0410);
const COMBINING_GRAPHEME_JOINER = String.fromCodePoint(0x034f);
const VARIATION_SELECTOR_16 = String.fromCodePoint(0xfe0f);
const MONGOLIAN_FREE_VARIATION_SELECTOR_ONE = String.fromCodePoint(0x180b);
const FULLWIDTH_OFFSET = 0xfee0;
const JAPANESE_PREFIX = String.fromCodePoint(0x65e5, 0x672c);
const CJK_FIRST = 0x4e00;
const CJK_SPAN = 0x51a6;
const RANDOM_CJK_LENGTH = 6;
const ZERO_WIDTH_SPACE = String.fromCodePoint(0x200b);
const BIDI_OVERRIDE = String.fromCodePoint(0x202e);
const UNKNOWN_CLIENT_ID = '00000000-0000-4000-8000-00000000dead';
const MAX_NAME_LENGTH = 160;
const BODY_LIMIT_BYTES = 16 * 1024;

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

type Problem = { code: string; detail?: string; errors?: { path: string; message: string }[] };

/** The clients with this exact name, read as the operator (a fixture, not a behavior). */
const clientsNamed = countClientsNamed;

/** Archives a client through the API and checks the answer: a setup step that must not fail silently. */
async function archiveOrFail(cookies: CookieStore, clientId: string): Promise<ClientDetailBody> {
  const response = await updateClientViaApi(cookies, clientId, { archived: true });
  const body = await expectContract<ClientDetailBody>('updateClient', response);
  expect(response.status).toBe(200);
  expect(body.archived).toBe(true);
  return body;
}

/** How many clients there are, read as the operator (a fixture, not a behavior). */
const clientCount = countClients;

/** ASCII to full-width letters and digits, the space to the ideographic space (what NFKC folds back). */
const toFullwidth = (text: string) =>
  [...text]
    .map((char) =>
      char === ' '
        ? IDEOGRAPHIC_SPACE
        : String.fromCodePoint((char.codePointAt(0) ?? 0) + FULLWIDTH_OFFSET),
    )
    .join('');

/** A name made only of ideographs, different on every run (the database is not reset between runs). */
const uniqueJapaneseName = () =>
  JAPANESE_PREFIX +
  Array.from({ length: RANDOM_CJK_LENGTH }, () =>
    String.fromCodePoint(CJK_FIRST + randomInt(CJK_SPAN)),
  ).join('');

const nameOfClient = async (clientId: string): Promise<string | undefined> =>
  (await readClientRow(clientId))?.name;

describe('GET /admin/clients, POST /admin/clients, GET and PATCH /admin/clients/{clientId}', () => {
  describe('creating and reading', () => {
    it('AC-11: a CEO creates a client: 201 with the client, a Location header and no processes', async () => {
      const name = uniqueClientName('Acme');

      const response = await createClientViaApi(ceo.cookies, { name: `  ${name}  ` });
      const body = await expectContract<ClientDetailBody>('createClient', response);

      expect(response.status).toBe(201);
      expect(body).toMatchObject({
        name,
        archived: false,
        archivedAt: null,
        activeProcessCount: 0,
        processCount: 0,
      });
      expect(body.createdAt).toBe(body.updatedAt);
      expect(response.headers.get('location')).toBe(`/api/v1/admin/clients/${body.id}`);
      expect(await clientsNamed(name)).toBe(1);
    });

    it('AC-11: the client that was created can be read back, identical', async () => {
      const created = await createClientOrFail(ceo.cookies);

      const response = await getClientViaApi(ceo.cookies, created.id);
      const body = await expectContract<ClientDetailBody>('getClient', response);

      expect(response.status).toBe(200);
      expect(body).toEqual(created);
    });

    it('E-30: a name typed with a combining accent is stored in NFC', async () => {
      const unique = uniqueClientName('Caf');
      const typed = `${unique}e${COMBINING_ACUTE}`;

      const response = await createClientViaApi(ceo.cookies, { name: typed });
      const body = await expectContract<ClientDetailBody>('createClient', response);

      expect(body.name).toBe(`${unique}${E_ACUTE}`);
      expect(await nameOfClient(body.id)).toBe(`${unique}${E_ACUTE}`);
    });

    it('AC-11: counts the processes of a client, active ones apart', async () => {
      const created = await createClientOrFail(ceo.cookies);
      await seedProcesses(created.id, { active: 2, completed: 1, cancelled: 1 }, ceo.ceo.id);

      const detail = await expectContract<ClientDetailBody>(
        'getClient',
        await getClientViaApi(ceo.cookies, created.id),
      );
      const inList = await findInClientList(ceo.cookies, created.id);

      expect(detail).toMatchObject({ activeProcessCount: 2, processCount: 4 });
      expect(inList).toMatchObject({ id: created.id, activeProcessCount: 2 });
      expect(inList).not.toHaveProperty('processCount');
    });

    it('AC-11: a client with no processes counts zero', async () => {
      const created = await createClientOrFail(ceo.cookies);

      const inList = await findInClientList(ceo.cookies, created.id);

      expect(inList).toMatchObject({ activeProcessCount: 0 });
    });

    it('AC-11: an unknown client is 404 NOT_FOUND on read and on update, with the same body', async () => {
      const read = await getClientViaApi(ceo.cookies, UNKNOWN_CLIENT_ID);
      const update = await updateClientViaApi(ceo.cookies, UNKNOWN_CLIENT_ID, { name: 'Nada' });

      const readBody = await expectContract<Problem>('getClient', read);
      const updateBody = await expectContract<Problem>('updateClient', update);

      expect([read.status, update.status]).toEqual([404, 404]);
      expect(readBody.code).toBe('NOT_FOUND');
      expect(withoutRequestId(updateBody)).toEqual(withoutRequestId(readBody));
    });

    it('E-06: a malformed clientId is 400 VALIDATION_ERROR on read and on update', async () => {
      const read = await getClientViaApi(ceo.cookies, 'not-a-uuid');
      const update = await updateClientViaApi(ceo.cookies, 'not-a-uuid', { name: 'Nada' });

      const readBody = await expectContract<Problem>('getClient', read);
      await expectContract<Problem>('updateClient', update);

      expect([read.status, update.status]).toEqual([400, 400]);
      expect(readBody.code).toBe('VALIDATION_ERROR');
      expect(readBody.errors?.map((issue) => issue.path)).toEqual(['params.clientId']);
    });
  });

  describe('listing', () => {
    it('AC-11: lists the clients newest first, and a new client opens the list', async () => {
      const older = await createClientOrFail(ceo.cookies);
      const newer = await createClientOrFail(ceo.cookies);

      const response = await listClientsViaApi(ceo.cookies);
      const body = await expectContract<ClientListBody>('listClients', response);

      expect(response.status).toBe(200);
      expect(body.items.length).toBeLessThanOrEqual(50);
      expect(body.items.slice(0, 2).map((item) => item.id)).toEqual([newer.id, older.id]);
      const dates = body.items.map((item) => Date.parse(item.createdAt));
      expect(dates).toEqual([...dates].sort((a, b) => b - a));
    });

    it('AC-11: pages the list, a tie on the creation instant included, repeating and skipping nothing', async () => {
      const tied = await createClientsWithSameCreationInstant(5);
      const seen: string[] = [];
      let cursor: string | undefined;

      for (let page = 0; page < 3; page += 1) {
        const response = await listClientsViaApi(ceo.cookies, {
          limit: '2',
          ...(cursor === undefined ? {} : { cursor }),
        });
        const body = await expectContract<ClientListBody>('listClients', response);
        expect(body.items).toHaveLength(2);
        expect(body.nextCursor).not.toBeNull();
        seen.push(...body.items.map((item) => item.id));
        cursor = body.nextCursor ?? undefined;
      }

      // The five were created last, in one statement: the newest in the database, in id order.
      expect(seen.slice(0, 5)).toEqual(tied.map((client) => client.id));
      expect(new Set(seen).size).toBe(seen.length);
    });

    it('AC-11: the keyset keeps the microseconds: a position resumes right after its own row', async () => {
      const stamp = '2001-02-03T04:05:06.123456+00:00';
      const microsecondOlder = '2001-02-03T04:05:06.123455+00:00';
      const [first, second] = await createClientsAt(stamp, 2);
      const [older] = await createClientsAt(microsecondOlder, 1);
      if (first === undefined || second === undefined || older === undefined) {
        throw new Error('the fixtures were not created');
      }

      const response = await listClientsViaApi(ceo.cookies, {
        limit: '100',
        cursor: encodeCursor('admin-clients', { c: stamp, i: first.id }),
      });
      const body = await expectContract<ClientListBody>('listClients', response);

      const mine = [first.id, second.id, older.id];
      expect(body.items.map((item) => item.id).filter((id) => mine.includes(id))).toEqual([
        second.id,
        older.id,
      ]);
      for (const item of body.items) {
        expect(Date.parse(item.createdAt)).toBeLessThanOrEqual(Date.parse(stamp));
      }
    });

    it('AC-11: the last page has no nextCursor', async () => {
      let cursor: string | undefined;
      let pages = 0;

      for (;;) {
        const response = await listClientsViaApi(ceo.cookies, {
          limit: '100',
          ...(cursor === undefined ? {} : { cursor }),
        });
        const body = await expectContract<ClientListBody>('listClients', response);
        pages += 1;
        if (body.nextCursor === null) break;
        cursor = body.nextCursor;
        expect(pages).toBeLessThan(100);
      }

      expect(pages).toBeGreaterThanOrEqual(1);
    });

    it('AC-11: an archived client leaves the list, and includeArchived brings it back', async () => {
      const created = await createClientOrFail(ceo.cookies);
      const archive = await updateClientViaApi(ceo.cookies, created.id, { archived: true });
      expect(archive.status).toBe(200);

      const hidden = await findInClientList(ceo.cookies, created.id);
      const shown = await findInClientList(ceo.cookies, created.id, { includeArchived: true });

      expect(hidden).toBeUndefined();
      expect(shown).toMatchObject({ id: created.id, archived: true });
      expect(shown?.archivedAt).not.toBeNull();
    });

    it.each([
      ['limit=0', { limit: '0' }],
      ['limit=101', { limit: '101' }],
      ['limit=abc', { limit: 'abc' }],
      ['includeArchived=yes', { includeArchived: 'yes' }],
      ['an unknown param', { clientId: UNKNOWN_CLIENT_ID }],
    ])('AC-11: %s is 400 VALIDATION_ERROR', async (_label, query) => {
      const response = await listClientsViaApi(ceo.cookies, query);

      const body = await expectContract<Problem>('listClients', response);

      expect(response.status).toBe(400);
      expect(body.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('E-29: the cursor', () => {
    const POSITION = { c: '2026-11-16T11:30:24.984084+00:00', i: UNKNOWN_CLIENT_ID };

    async function realCursor(): Promise<string> {
      await createClientOrFail(ceo.cookies);
      await createClientOrFail(ceo.cookies);
      const response = await listClientsViaApi(ceo.cookies, { limit: '1' });
      const body = await expectContract<ClientListBody>('listClients', response);
      if (body.nextCursor === null) throw new Error('two clients must give a next cursor');
      return body.nextCursor;
    }

    async function expectRefused(cursor: string) {
      const response = await listClientsViaApi(ceo.cookies, { cursor });
      const body = await expectContract<Problem>('listClients', response);

      expect(response.status).toBe(400);
      expect(body.code).toBe('VALIDATION_ERROR');
      expect(body.errors?.map((issue) => issue.path)).toEqual(['query.cursor']);
    }

    it('E-29: the cursor the API issued is accepted and gives the next page', async () => {
      const cursor = await realCursor();

      const response = await listClientsViaApi(ceo.cookies, { limit: '1', cursor });
      const body = await expectContract<ClientListBody>('listClients', response);

      expect(response.status).toBe(200);
      expect(body.items).toHaveLength(1);
    });

    it('E-29: a tampered cursor (truncated, extended, garbage) is 400 VALIDATION_ERROR', async () => {
      const cursor = await realCursor();

      await expectRefused(cursor.slice(0, -4));
      await expectRefused(`${cursor}AAAA`);
      await expectRefused('not-a-cursor');
      await expectRefused('A'.repeat(201));
    });

    it('F-53: a well-formed cursor with a timestamp the database cannot read is 400 on query.cursor, never 500', async () => {
      // year 0000 (Postgres 22008) and an offset past 15:59 (22009): the cursor schema refuses both
      // before the database sees them; the class-22 backstop of the repository is covered by its unit tests
      await expectRefused(
        encodeCursor('admin-clients', { c: '0000-01-01T00:00:00.000000+00:00', i: POSITION.i }),
      );
      await expectRefused(
        encodeCursor('admin-clients', { c: '2026-01-01T00:00:00.000000+23:59', i: POSITION.i }),
      );
    });

    it('E-29: a cursor of another endpoint, or with a payload of the wrong shape, is 400', async () => {
      await expectRefused(encodeCursor('admin-processes', POSITION));
      await expectRefused(encodeCursor('admin-clients', { ...POSITION, extra: 1 }));
      await expectRefused(encodeCursor('admin-clients', { c: 'yesterday', i: POSITION.i }));
      await expectRefused(encodeCursor('admin-clients', { c: POSITION.c, i: 'nope' }));
    });
  });

  describe('updating', () => {
    it('AC-11: renames a client', async () => {
      const created = await createClientOrFail(ceo.cookies);
      const name = uniqueClientName('Renomeado');

      const response = await updateClientViaApi(ceo.cookies, created.id, { name: ` ${name} ` });
      const body = await expectContract<ClientDetailBody>('updateClient', response);

      expect(response.status).toBe(200);
      expect(body).toMatchObject({ id: created.id, name, archived: false, archivedAt: null });
      expect(Date.parse(body.updatedAt)).toBeGreaterThan(Date.parse(body.createdAt));
      expect(body.createdAt).toBe(created.createdAt);
      expect(await nameOfClient(created.id)).toBe(name);
    });

    it('AC-11: archives a client, keeps the date when archived again, and unarchives it', async () => {
      const created = await createClientOrFail(ceo.cookies);

      const archive = await updateClientViaApi(ceo.cookies, created.id, { archived: true });
      const archived = await expectContract<ClientDetailBody>('updateClient', archive);
      expect(archived).toMatchObject({ name: created.name, archived: true });
      expect(archived.archivedAt).not.toBeNull();

      const again = await updateClientViaApi(ceo.cookies, created.id, { archived: true });
      const archivedAgain = await expectContract<ClientDetailBody>('updateClient', again);
      expect(archivedAgain.archivedAt).toBe(archived.archivedAt);
      expect(archivedAgain.updatedAt).toBe(archived.updatedAt);

      const restore = await updateClientViaApi(ceo.cookies, created.id, { archived: false });
      const restored = await expectContract<ClientDetailBody>('updateClient', restore);
      expect(restored).toMatchObject({ archived: false, archivedAt: null, name: created.name });
    });

    it('AC-11: renames and archives in one request, and keeps the counters', async () => {
      const created = await createClientOrFail(ceo.cookies);
      await seedProcesses(created.id, { active: 1, completed: 2 }, ceo.ceo.id);
      const name = uniqueClientName('Duplo');

      const response = await updateClientViaApi(ceo.cookies, created.id, { name, archived: true });
      const body = await expectContract<ClientDetailBody>('updateClient', response);

      expect(body).toMatchObject({ name, archived: true, activeProcessCount: 1, processCount: 3 });
    });

    it('SEC-16: every real change is audited in the same transaction, with the CEO, the request id and no name', async () => {
      const name = uniqueClientName('Auditado');
      const requestIds: string[] = [];
      const track = (response: Response) => {
        requestIds.push(response.headers.get('x-request-id') ?? '');
        return response;
      };

      const created = await expectContract<ClientDetailBody>(
        'createClient',
        track(await createClientViaApi(ceo.cookies, { name })),
      );
      const renamed = uniqueClientName('Renomeado');
      track(await updateClientViaApi(ceo.cookies, created.id, { name: renamed }));
      track(await updateClientViaApi(ceo.cookies, created.id, { name: renamed })); // nothing changes
      track(await updateClientViaApi(ceo.cookies, created.id, { archived: true }));
      track(await updateClientViaApi(ceo.cookies, created.id, { archived: true })); // nothing changes
      track(await updateClientViaApi(ceo.cookies, created.id, { archived: false }));

      const audit = await auditOfClient(created.id);

      expect(audit.map((row) => row.action)).toEqual([
        'client.created',
        'client.updated',
        'client.archived',
        'client.unarchived',
      ]);
      for (const row of audit) {
        expect(row).toMatchObject({
          actor_id: ceo.ceo.id,
          actor_role: 'ceo',
          resource_type: 'client',
          resource_id: created.id,
          client_id: created.id,
          process_id: null,
        });
      }
      // the id the app sent to the database is the one the response carries
      expect(audit.map((row) => row.request_id)).toEqual([
        requestIds[0],
        requestIds[1],
        requestIds[3],
        requestIds[5],
      ]);
      expect(JSON.stringify(audit)).not.toContain(name);
      expect(JSON.stringify(audit)).not.toContain(renamed);
    });
  });

  describe('input', () => {
    // Its own CEO: the writes of this group (every refused one counts too) would otherwise eat the
    // 60 writes per minute of the CEO the other groups use.
    let inputCeo: CeoWithMfa;

    beforeAll(async () => {
      inputCeo = await loginAsCeoWithMfa();
    });

    const BAD_NAMES: [string, unknown][] = [
      ['empty', ''],
      ['only spaces', '   '],
      ['161 characters', 'a'.repeat(MAX_NAME_LENGTH + 1)],
      ['with a line break', 'Linha\ndupla'],
      ['with a zero-width space', `Zero${ZERO_WIDTH_SPACE}width`],
      ['with a bidi override', `Bidi${BIDI_OVERRIDE}override`],
      ['only symbols', '***'],
      ['only a no-break space', NO_BREAK_SPACE],
      ['only an ideographic space', IDEOGRAPHIC_SPACE],
      ['only a Hangul filler', HANGUL_FILLER],
      ['a Hangul filler between letters', `A${HANGUL_FILLER}B`],
      ['a lone surrogate', `A${String.fromCharCode(0xd800)}`],
      ['a number', 42],
      ['null', null],
    ];

    it.each(BAD_NAMES)(
      'AC-11: a name that is %s is 400 and creates nothing',
      async (_label, name) => {
        const response = await createClientViaApi(inputCeo.cookies, { name });

        const body = await expectContract<Problem>('createClient', response);

        expect(response.status).toBe(400);
        expect(body.code).toBe('VALIDATION_ERROR');
        expect(body.errors?.map((issue) => issue.path)).toEqual(['body.name']);
        expect(JSON.stringify(body)).not.toContain('a'.repeat(MAX_NAME_LENGTH + 1));
      },
    );

    it('AC-11: 160 characters are fine', async () => {
      const name = `${uniqueClientName('x')}`.padEnd(MAX_NAME_LENGTH, 'a');

      const response = await createClientViaApi(inputCeo.cookies, { name });
      const body = await expectContract<ClientDetailBody>('createClient', response);

      expect(response.status).toBe(201);
      expect(body.name).toHaveLength(MAX_NAME_LENGTH);
    });

    it('AC-11: a missing name is 400', async () => {
      const response = await createClientViaApi(inputCeo.cookies, {});

      const body = await expectContract<Problem>('createClient', response);

      expect(response.status).toBe(400);
      expect(body.errors?.map((issue) => issue.path)).toEqual(['body.name']);
    });

    it('AC-23: a clientId, an id or any other field in the body is 400 (mass assignment) and nothing is written', async () => {
      const name = uniqueClientName('Atribuicao');
      const created = await createClient();

      const smuggled = await createClientViaApi(inputCeo.cookies, {
        name,
        clientId: UNKNOWN_CLIENT_ID,
      });
      const archivedAt = await createClientViaApi(inputCeo.cookies, { name, archivedAt: null });
      const onUpdate = await updateClientViaApi(inputCeo.cookies, created.id, {
        name: 'Outro',
        id: UNKNOWN_CLIENT_ID,
      });

      const bodies = [
        await expectContract<Problem>('createClient', smuggled),
        await expectContract<Problem>('createClient', archivedAt),
        await expectContract<Problem>('updateClient', onUpdate),
      ];
      expect([smuggled.status, archivedAt.status, onUpdate.status]).toEqual([400, 400, 400]);
      expect(bodies.map((body) => body.code)).toEqual(Array(3).fill('VALIDATION_ERROR'));
      expect(await clientsNamed(name)).toBe(0);
      expect(await nameOfClient(created.id)).toBe(created.name);
    });

    it.each([
      ['an empty body', {}],
      ['archived as a string', { archived: 'true' }],
      ['archived as null', { archived: null }],
      ['an empty name', { name: '' }],
    ])('AC-11: updating with %s is 400 and changes nothing', async (_label, body) => {
      const created = await createClient();

      const response = await updateClientViaApi(inputCeo.cookies, created.id, body);
      const problem = await expectContract<Problem>('updateClient', response);

      expect(response.status).toBe(400);
      expect(problem.code).toBe('VALIDATION_ERROR');
      expect(await nameOfClient(created.id)).toBe(created.name);
    });

    it.each([
      ['a no-break space', NO_BREAK_SPACE],
      ['a Hangul filler', HANGUL_FILLER],
      ['a lone surrogate', `A${String.fromCharCode(0xd800)}`],
      ['only punctuation', '...'],
    ])(
      'AC-11: renaming to only %s is 400 on body.name and changes nothing',
      async (_label, name) => {
        const created = await createClient();

        const response = await updateClientViaApi(inputCeo.cookies, created.id, { name });
        const problem = await expectContract<Problem>('updateClient', response);

        expect(response.status).toBe(400);
        expect(problem.errors?.map((issue) => issue.path)).toEqual(['body.name']);
        expect(await nameOfClient(created.id)).toBe(created.name);
      },
    );

    it('AC-11: an empty update points at the body, not at a field', async () => {
      const created = await createClient();

      const response = await updateClientViaApi(inputCeo.cookies, created.id, {});
      const problem = await expectContract<Problem>('updateClient', response);

      expect(problem.errors?.map((issue) => issue.path)).toEqual(['body']);
    });

    it('AC-23: a foreign Origin, a wrong Content-Type and a body over 16 KiB are refused before anything is written', async () => {
      const name = uniqueClientName('Transporte');

      const origin = await createClientViaApi(
        inputCeo.cookies,
        { name },
        { origin: 'https://evil.test' },
      );
      const noOrigin = await createClientViaApi(inputCeo.cookies, { name }, { origin: null });
      const type = await createClientViaApi(inputCeo.cookies, undefined, {
        rawBody: JSON.stringify({ name }),
        headers: { 'content-type': 'text/plain' },
      });
      const large = await createClientViaApi(inputCeo.cookies, undefined, {
        rawBody: JSON.stringify({ name: 'a'.repeat(BODY_LIMIT_BYTES) }),
        headers: { 'content-type': 'application/json' },
      });

      expect([origin.status, noOrigin.status, type.status, large.status]).toEqual([
        403, 403, 415, 413,
      ]);
      expect(await bodyOf(origin)).toMatchObject({ code: 'ORIGIN_NOT_ALLOWED' });
      expect(await bodyOf(type)).toMatchObject({ code: 'UNSUPPORTED_MEDIA_TYPE' });
      expect(await bodyOf(large)).toMatchObject({ code: 'PAYLOAD_TOO_LARGE' });
      expect(await bodyOf(noOrigin)).toMatchObject({ code: 'ORIGIN_NOT_ALLOWED' });
      for (const response of [origin, noOrigin, type, large]) {
        await expectContract('createClient', response);
      }
      expect(await clientsNamed(name)).toBe(0);
    });
  });

  describe('the database on its own (F-52)', () => {
    // The API validates with Zod first; a CEO who calls the functions straight through PostgREST
    // skips it, so the database holds the same rules (private.visible_text).
    const REFUSED: [string, string][] = [
      ['only a no-break space', NO_BREAK_SPACE],
      ['only an ideographic space', IDEOGRAPHIC_SPACE],
      ['only a Hangul filler', HANGUL_FILLER],
      ['a filler between letters', `A${HANGUL_FILLER}B`],
      ['only punctuation', '***'],
      ['a zero-width space', `Zero${ZERO_WIDTH_SPACE}width`],
    ];

    it.each(REFUSED)('F-52: create_client refuses %s with INVALID_INPUT', async (_label, name) => {
      const { supabase } = await ceoAal2Client();

      const { data, error } = await supabase.rpc('create_client', { p_name: name });

      expect(data).toBeNull();
      expect(error).toMatchObject({ code: 'P0001', message: 'INVALID_INPUT' });
    });

    it('F-52: update_client refuses the same names and leaves the client alone', async () => {
      const { supabase } = await ceoAal2Client();
      const created = await createClientOrFail(ceo.cookies);

      for (const [, name] of REFUSED) {
        const { error } = await supabase.rpc('update_client', {
          p_client_id: created.id,
          p_name: name,
        });
        expect(error).toMatchObject({ code: 'P0001', message: 'INVALID_INPUT' });
      }
      expect(await nameOfClient(created.id)).toBe(created.name);
    });

    it('F-52: it accepts what the API accepts, trimmed like the API trims it (no-break spaces, NFC, Japanese)', async () => {
      const { supabase } = await ceoAal2Client();
      const unique = uniqueClientName('Direto');

      const padded = await supabase.rpc('create_client', {
        p_name: `${NO_BREAK_SPACE}${unique}${IDEOGRAPHIC_SPACE}`,
      });
      const japaneseName = uniqueJapaneseName();
      const japanese = await supabase.rpc('create_client', { p_name: japaneseName });

      expect(padded.error).toBeNull();
      expect(padded.data?.name).toBe(unique);
      expect(japanese.error).toBeNull();
      expect(japanese.data?.name).toBe(japaneseName);
    });
  });

  describe('a client name is unique among the active clients (F-51)', () => {
    // One CEO per sub-group: the writes (the refused ones count too) of each stay far inside the 60
    // writes per minute of one user (about 20 and 30), whatever is added to either, and apart from
    // the CEOs of the other groups.
    describe('creating, and the key of a name', () => {
      let nameCeo: CeoWithMfa;
      let taken: ClientDetailBody;

      beforeAll(async () => {
        nameCeo = await loginAsCeoWithMfa();
        taken = await createClientOrFail(nameCeo.cookies, uniqueClientName('Acme'));
      });

      const VARIANTS: [string, (name: string) => string][] = [
        ['other letter case (upper)', (name) => name.toUpperCase()],
        ['other letter case (lower)', (name) => name.toLowerCase()],
        ['full-width letters and an ideographic space', toFullwidth],
        ['a no-break space between the words', (name) => name.replace(' ', NO_BREAK_SPACE)],
        ['repeated spaces between the words', (name) => name.replace(' ', '   ')],
        ['spaces around it', (name) => ` ${name} `],
        [
          'a combining grapheme joiner inside a word',
          (name) => name.replace('cm', `c${COMBINING_GRAPHEME_JOINER}m`),
        ],
        [
          'a variation selector (emoji presentation) after a word',
          (name) => name.replace(' ', `${VARIATION_SELECTOR_16} `),
        ],
        [
          'a Mongolian free variation selector after a word',
          (name) => name.replace(' ', `${MONGOLIAN_FREE_VARIATION_SELECTOR_ONE} `),
        ],
      ];

      it('E-40: a second client with the same name is 409 CONFLICT, creates nothing and names no other client', async () => {
        const name = uniqueClientName('Duplicado');
        const first = await createClientOrFail(nameCeo.cookies, name);

        const response = await createClientViaApi(nameCeo.cookies, { name });
        const body = await expectContract<Problem>('createClient', response);

        expect(response.status).toBe(409);
        expect(body).toMatchObject({
          code: 'CONFLICT',
          detail: 'A client with this name already exists.',
        });
        expect(response.headers.get('location')).toBeNull();
        expect(JSON.stringify(body)).not.toContain(first.id);
        expect(JSON.stringify(body)).not.toContain(name);
        expect(await clientsNamed(name)).toBe(1);
        expect((await auditOfClient(first.id)).map((row) => row.action)).toEqual([
          'client.created',
        ]);
      });

      it.each(VARIANTS)(
        'E-40: the same name with %s is 409 CONFLICT and creates nothing',
        async (_label, vary) => {
          const before = await clientCount();

          const response = await createClientViaApi(nameCeo.cookies, { name: vary(taken.name) });
          const body = await expectContract<Problem>('createClient', response);

          expect([response.status, body.code]).toEqual([409, 'CONFLICT']);
          expect(await clientCount()).toBe(before);
        },
      );

      it('E-46: a letter of another alphabet that looks Latin is not folded (residual of T-33)', async () => {
        const lookalike = `${CYRILLIC_CAPITAL_A}${taken.name.slice(1)}`;

        const response = await createClientViaApi(nameCeo.cookies, { name: lookalike });
        const body = await expectContract<ClientDetailBody>('createClient', response);

        expect(response.status).toBe(201);
        expect(body.id).not.toBe(taken.id);
      });

      it('E-40 to E-42: straight through PostgREST the refusal is P0001 CLIENT_NAME_TAKEN, with no detail about the other client', async () => {
        const { supabase } = await ceoAal2Client();
        const active = await createClientOrFail(nameCeo.cookies);
        const archived = await createClientOrFail(nameCeo.cookies);
        await archiveOrFail(nameCeo.cookies, archived.id);
        await createClientOrFail(nameCeo.cookies, archived.name);
        const renamed = await createClientOrFail(nameCeo.cookies);

        const create = await supabase.rpc('create_client', { p_name: active.name.toUpperCase() });
        const rename = await supabase.rpc('update_client', {
          p_client_id: renamed.id,
          p_name: active.name,
        });
        const unarchive = await supabase.rpc('update_client', {
          p_client_id: archived.id,
          p_archived: false,
        });

        for (const { data, error } of [create, rename, unarchive]) {
          expect(data).toBeNull();
          expect(error).toMatchObject({ code: 'P0001', message: 'CLIENT_NAME_TAKEN' });
          const shown = JSON.stringify(error).toLowerCase();
          expect(shown).not.toContain(active.id);
          expect(shown).not.toContain(archived.id);
          expect(shown).not.toContain(active.name.toLowerCase());
        }
        expect(await nameOfClient(renamed.id)).toBe(renamed.name);
      });
    });

    describe('renaming, unarchiving and racing', () => {
      let flowCeo: CeoWithMfa;

      beforeAll(async () => {
        flowCeo = await loginAsCeoWithMfa();
      });

      it('E-41: renaming to the name of another active client is 409 and changes nothing; the own name in another case is fine', async () => {
        const first = await createClientOrFail(flowCeo.cookies);
        const second = await createClientOrFail(flowCeo.cookies);

        const refused = await updateClientViaApi(flowCeo.cookies, second.id, { name: first.name });
        const body = await expectContract<Problem>('updateClient', refused);

        expect(refused.status).toBe(409);
        expect(body).toMatchObject({
          code: 'CONFLICT',
          detail: 'A client with this name already exists.',
        });
        expect(JSON.stringify(body)).not.toContain(first.id);
        expect(await nameOfClient(second.id)).toBe(second.name);
        expect((await auditOfClient(second.id)).map((row) => row.action)).toEqual([
          'client.created',
        ]);

        const upper = first.name.toUpperCase();
        const sameClient = await updateClientViaApi(flowCeo.cookies, first.id, { name: upper });
        expect(sameClient.status).toBe(200);
        await expectContract('updateClient', sameClient);
        expect(await nameOfClient(first.id)).toBe(upper);

        const stillRefused = await updateClientViaApi(flowCeo.cookies, second.id, {
          name: first.name,
        });
        await expectContract('updateClient', stillRefused);
        expect(stillRefused.status).toBe(409);
      });

      it('E-42: unarchiving a client whose name an active client has now is 409 and it stays archived', async () => {
        const first = await createClientOrFail(flowCeo.cookies);
        await archiveOrFail(flowCeo.cookies, first.id);
        const second = await createClientOrFail(flowCeo.cookies, first.name);

        const refused = await updateClientViaApi(flowCeo.cookies, first.id, { archived: false });
        const body = await expectContract<Problem>('updateClient', refused);

        expect(refused.status).toBe(409);
        expect(body.code).toBe('CONFLICT');
        expect(JSON.stringify(body)).not.toContain(second.id);
        const detail = await expectContract<ClientDetailBody>(
          'getClient',
          await getClientViaApi(flowCeo.cookies, first.id),
        );
        expect(detail).toMatchObject({ archived: true, name: first.name });
        expect((await auditOfClient(first.id)).map((row) => row.action)).toEqual([
          'client.created',
          'client.archived',
        ]);

        // a new name along with the unarchive is the way back
        const renamed = uniqueClientName('Volta');
        const back = await updateClientViaApi(flowCeo.cookies, first.id, {
          name: renamed,
          archived: false,
        });
        const backBody = await expectContract<ClientDetailBody>('updateClient', back);
        expect(backBody).toMatchObject({ name: renamed, archived: false });
      });

      it('E-42: renaming to a name in use and archiving in one request is fine: the final state does not compete', async () => {
        const active = await createClientOrFail(flowCeo.cookies);
        const other = await createClientOrFail(flowCeo.cookies);

        const response = await updateClientViaApi(flowCeo.cookies, other.id, {
          name: active.name,
          archived: true,
        });
        const body = await expectContract<ClientDetailBody>('updateClient', response);

        expect(response.status).toBe(200);
        expect(body).toMatchObject({ name: active.name, archived: true });
      });

      it('E-43: archiving frees the name, and archived clients may share one', async () => {
        const name = uniqueClientName('Liberado');
        const first = await createClientOrFail(flowCeo.cookies, name);
        await archiveOrFail(flowCeo.cookies, first.id);

        const second = await createClientOrFail(flowCeo.cookies, name);
        await archiveOrFail(flowCeo.cookies, second.id);
        const third = await createClientViaApi(flowCeo.cookies, { name });
        const thirdBody = await expectContract<ClientDetailBody>('createClient', third);

        expect(third.status).toBe(201);
        expect(new Set([first.id, second.id, thirdBody.id]).size).toBe(3);
        expect(await clientsNamed(name)).toBe(3);
      });

      it('E-44: concurrent creates with the same name: exactly one is 201 and the others are 409', async () => {
        const name = uniqueClientName('Corrida');

        const responses = await Promise.all(
          Array.from({ length: 4 }, () => createClientViaApi(flowCeo.cookies, { name })),
        );

        for (const response of responses) await expectContract('createClient', response);
        expect(responses.map((response) => response.status).sort()).toEqual([201, 409, 409, 409]);
        expect(await clientsNamed(name)).toBe(1);
      });

      it('E-44: a create and a rename to the same name at once: exactly one wins', async () => {
        const other = await createClientOrFail(flowCeo.cookies);
        const name = uniqueClientName('Corrida');

        const [created, renamed] = await Promise.all([
          createClientViaApi(flowCeo.cookies, { name }),
          updateClientViaApi(flowCeo.cookies, other.id, { name }),
        ]);

        await expectContract('createClient', created);
        await expectContract('updateClient', renamed);
        const statuses = [created.status, renamed.status];
        expect(statuses.filter((status) => status === 409)).toHaveLength(1);
        expect(statuses.filter((status) => status < 300)).toHaveLength(1);
        expect(await clientsNamed(name)).toBe(1);
      });

      it('E-45: a create whose answer was lost (503) and is repeated is 409, and the client exists once', async () => {
        const name = uniqueClientName('Reenvio');
        const realFetch = globalThis.fetch;
        // the function runs and commits; what the app never receives is its answer
        const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
          const url = String(input instanceof Request ? input.url : input);
          const answer = await realFetch(input, init);
          if (!url.includes('/rest/v1/rpc/create_client')) return answer;
          void answer.body?.cancel();
          throw new TypeError('fetch failed');
        });
        let lost: Response;
        try {
          lost = await createClientViaApi(flowCeo.cookies, { name });
        } finally {
          spy.mockRestore();
        }
        const lostBody = await expectContract<Problem>('createClient', lost);
        expect([lost.status, lostBody.code]).toEqual([503, 'SERVICE_UNAVAILABLE']);
        expect(await clientsNamed(name)).toBe(1);

        const repeated = await createClientViaApi(flowCeo.cookies, { name });
        const body = await expectContract<Problem>('createClient', repeated);

        expect([repeated.status, body.code]).toEqual([409, 'CONFLICT']);
        expect(await clientsNamed(name)).toBe(1);
      });
    });
  });

  describe('who may call it', () => {
    /** Calls the four operations with the cookies (or none) and answers their responses. */
    async function callAll(cookies: CookieStore | undefined, name: string) {
      return [
        ['listClients', await listClientsViaApi(cookies)],
        ['createClient', await createClientViaApi(cookies, { name })],
        ['getClient', await getClientViaApi(cookies, UNKNOWN_CLIENT_ID)],
        ['updateClient', await updateClientViaApi(cookies, UNKNOWN_CLIENT_ID, { name })],
      ] as const;
    }

    async function expectAllRefused(
      cookies: CookieStore | undefined,
      status: number,
      code: string,
    ) {
      const name = uniqueClientName('Negado');
      for (const [operationId, response] of await callAll(cookies, name)) {
        const body = await expectContract<Problem>(operationId, response);
        expect([operationId, response.status, body.code]).toEqual([operationId, status, code]);
      }
      expect(await clientsNamed(name)).toBe(0);
    }

    it('SEC-01: without a session every operation is 401 UNAUTHENTICATED and nothing is created', async () => {
      await expectAllRefused(undefined, 401, 'UNAUTHENTICATED');
    });

    it('AC-21: a client user is 403 FORBIDDEN on every operation and creates nothing', async () => {
      const tenant = await createClient();
      const user = await completeFirstAccess(await createClientUser({ clientId: tenant.id }));
      const cookies = await loginViaApi(user);

      await expectAllRefused(cookies, 403, 'FORBIDDEN');
    });

    it('AC-21: a client user cannot rename or archive its own client either', async () => {
      const tenant = await createClient();
      const user = await completeFirstAccess(await createClientUser({ clientId: tenant.id }));
      const cookies = await loginViaApi(user);

      const rename = await updateClientViaApi(cookies, tenant.id, { name: 'Meu nome' });
      const archive = await updateClientViaApi(cookies, tenant.id, { archived: true });
      const read = await getClientViaApi(cookies, tenant.id);

      const bodies = [
        await expectContract<Problem>('updateClient', rename),
        await expectContract<Problem>('updateClient', archive),
        await expectContract<Problem>('getClient', read),
      ];
      expect([rename.status, archive.status, read.status]).toEqual([403, 403, 403]);
      expect(bodies.map((body) => body.code)).toEqual(['FORBIDDEN', 'FORBIDDEN', 'FORBIDDEN']);
      expect(await nameOfClient(tenant.id)).toBe(tenant.name);
      expect((await readClientRow(tenant.id))?.archived_at).toBeNull();
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

    it('SEC-04: a CEO token cannot write the table directly, only through the functions', async () => {
      // The PostgREST client of a browser that holds the CEO session: the database says no
      // (the pgTAP file proves it for every role; this is the same fact through the real API).
      const supabase = publishableClient();
      const signIn = await supabase.auth.signInWithPassword({
        email: ceo.ceo.email,
        password: ceo.ceo.password,
      });
      expect(signIn.error).toBeNull();

      const insert = await supabase.from('clients').insert({ name: uniqueClientName('Direto') });

      expect(insert.error).not.toBeNull();
      expect(insert.error?.code).toBe('42501');
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

    it('E-21: listClients that cannot reach the database is 503 SERVICE_UNAVAILABLE, not a 500', async () => {
      const spy = failing('/rest/v1/clients');
      try {
        await expectUnavailable('listClients', await listClientsViaApi(ceo.cookies));
      } finally {
        spy.restore();
      }
    });

    it('E-21: getClient that cannot reach the database is 503 SERVICE_UNAVAILABLE', async () => {
      const spy = failing('/rest/v1/clients');
      try {
        await expectUnavailable('getClient', await getClientViaApi(ceo.cookies, UNKNOWN_CLIENT_ID));
      } finally {
        spy.restore();
      }
    });

    it('E-21: createClient that cannot reach the database is 503 and nothing is created', async () => {
      const name = uniqueClientName('Fora do ar');
      const spy = failing('/rest/v1/rpc/create_client');
      try {
        await expectUnavailable('createClient', await createClientViaApi(ceo.cookies, { name }));
      } finally {
        spy.restore();
      }
      expect(await clientsNamed(name)).toBe(0);
    });

    it('E-21: updateClient that cannot reach the database is 503 and changes nothing', async () => {
      const created = await createClient();
      const spy = failing('/rest/v1/rpc/update_client');
      try {
        await expectUnavailable(
          'updateClient',
          await updateClientViaApi(ceo.cookies, created.id, { name: uniqueClientName('Nada') }),
        );
      } finally {
        spy.restore();
      }
      expect(await nameOfClient(created.id)).toBe(created.name);
    });

    it('E-21: updateClient whose answer cannot be read back is 503 too, and the change is already made', async () => {
      // the function ran; the read of the counters that follows it is what fails. A repeated PATCH
      // with the same body is a no-op, so the 503 is safe to retry.
      const created = await createClient();
      const name = uniqueClientName('Gravado');
      const spy = failing('/rest/v1/clients?');
      try {
        await expectUnavailable(
          'updateClient',
          await updateClientViaApi(ceo.cookies, created.id, { name }),
        );
      } finally {
        spy.restore();
      }
      expect(await nameOfClient(created.id)).toBe(name);
    });
  });
});
