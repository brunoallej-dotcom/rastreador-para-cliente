// API tests of the client operations (operationIds `listClients`, `createClient`, `getClient`,
// `updateClient`): the real route modules, the real pipeline and wiring (Postgres rate limiter,
// Supabase resolver), the local Supabase (Auth + PostgREST + the database functions), and every
// response checked against the OpenAPI contract, headers included.
//
// The CEO is a real one: it changed the temporary password, logged in through the API, enrolled TOTP
// and verified a code, so its cookies are an `aal2` session (tests/helpers/mfa.ts).
import { beforeAll, describe, expect, it } from 'vitest';
import { encodeCursor } from '@/shared/http';
import { expectToMatchContract } from '../helpers/contract';
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
  adminClient,
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

type Problem = { code: string; errors?: { path: string; message: string }[] };

/** The clients with this exact name, read with the secret key (a fixture, not a behavior). */
async function clientsNamed(name: string): Promise<number> {
  const { data, error } = await adminClient().from('clients').select('id').eq('name', name);
  if (error) throw new Error(`reading clients failed: ${error.message}`);
  return data.length;
}

const nameOfClient = async (clientId: string): Promise<string | undefined> => {
  const { data, error } = await adminClient()
    .from('clients')
    .select('name')
    .eq('id', clientId)
    .maybeSingle();
  if (error) throw new Error(`reading a client failed: ${error.message}`);
  return data?.name;
};

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
      await seedProcesses(created.id, { active: 2, completed: 1, cancelled: 1 });

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
      await seedProcesses(created.id, { active: 1, completed: 2 });
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
    const BAD_NAMES: [string, unknown][] = [
      ['empty', ''],
      ['only spaces', '   '],
      ['161 characters', 'a'.repeat(MAX_NAME_LENGTH + 1)],
      ['with a line break', 'Linha\ndupla'],
      ['with a zero-width space', `Zero${ZERO_WIDTH_SPACE}width`],
      ['with a bidi override', `Bidi${BIDI_OVERRIDE}override`],
      ['only symbols', '***'],
      ['a number', 42],
      ['null', null],
    ];

    it.each(BAD_NAMES)(
      'AC-11: a name that is %s is 400 and creates nothing',
      async (_label, name) => {
        const response = await createClientViaApi(ceo.cookies, { name });

        const body = await expectContract<Problem>('createClient', response);

        expect(response.status).toBe(400);
        expect(body.code).toBe('VALIDATION_ERROR');
        expect(body.errors?.map((issue) => issue.path)).toEqual(['body.name']);
        expect(JSON.stringify(body)).not.toContain('a'.repeat(MAX_NAME_LENGTH + 1));
      },
    );

    it('AC-11: 160 characters are fine', async () => {
      const name = `${uniqueClientName('x')}`.padEnd(MAX_NAME_LENGTH, 'a');

      const response = await createClientViaApi(ceo.cookies, { name });
      const body = await expectContract<ClientDetailBody>('createClient', response);

      expect(response.status).toBe(201);
      expect(body.name).toHaveLength(MAX_NAME_LENGTH);
    });

    it('AC-11: a missing name is 400', async () => {
      const response = await createClientViaApi(ceo.cookies, {});

      const body = await expectContract<Problem>('createClient', response);

      expect(response.status).toBe(400);
      expect(body.errors?.map((issue) => issue.path)).toEqual(['body.name']);
    });

    it('AC-23: a clientId, an id or any other field in the body is 400 (mass assignment) and nothing is written', async () => {
      const name = uniqueClientName('Atribuicao');
      const created = await createClientOrFail(ceo.cookies);

      const smuggled = await createClientViaApi(ceo.cookies, { name, clientId: UNKNOWN_CLIENT_ID });
      const archivedAt = await createClientViaApi(ceo.cookies, { name, archivedAt: null });
      const onUpdate = await updateClientViaApi(ceo.cookies, created.id, {
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
      const created = await createClientOrFail(ceo.cookies);

      const response = await updateClientViaApi(ceo.cookies, created.id, body);
      const problem = await expectContract<Problem>('updateClient', response);

      expect(response.status).toBe(400);
      expect(problem.code).toBe('VALIDATION_ERROR');
      expect(await nameOfClient(created.id)).toBe(created.name);
    });

    it('AC-11: an empty update points at the body, not at a field', async () => {
      const created = await createClientOrFail(ceo.cookies);

      const response = await updateClientViaApi(ceo.cookies, created.id, {});
      const problem = await expectContract<Problem>('updateClient', response);

      expect(problem.errors?.map((issue) => issue.path)).toEqual(['body']);
    });

    it('AC-23: a foreign Origin, a wrong Content-Type and a body over 16 KiB are refused before anything is written', async () => {
      const name = uniqueClientName('Transporte');

      const origin = await createClientViaApi(
        ceo.cookies,
        { name },
        { origin: 'https://evil.test' },
      );
      const noOrigin = await createClientViaApi(ceo.cookies, { name }, { origin: null });
      const type = await createClientViaApi(ceo.cookies, undefined, {
        rawBody: JSON.stringify({ name }),
        headers: { 'content-type': 'text/plain' },
      });
      const large = await createClientViaApi(ceo.cookies, undefined, {
        rawBody: JSON.stringify({ name: 'a'.repeat(BODY_LIMIT_BYTES) }),
        headers: { 'content-type': 'application/json' },
      });

      expect([origin.status, noOrigin.status, type.status, large.status]).toEqual([
        403, 403, 415, 413,
      ]);
      expect(await bodyOf(origin)).toMatchObject({ code: 'ORIGIN_NOT_ALLOWED' });
      expect(await bodyOf(type)).toMatchObject({ code: 'UNSUPPORTED_MEDIA_TYPE' });
      expect(await bodyOf(large)).toMatchObject({ code: 'PAYLOAD_TOO_LARGE' });
      for (const response of [origin, type, large]) {
        await expectContract('createClient', response);
      }
      expect(await clientsNamed(name)).toBe(0);
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

      expect([rename.status, archive.status, read.status]).toEqual([403, 403, 403]);
      expect(await nameOfClient(tenant.id)).toBe(tenant.name);
      const { data } = await adminClient()
        .from('clients')
        .select('archived_at')
        .eq('id', tenant.id)
        .single();
      expect(data?.archived_at).toBeNull();
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
    it('E-21: a read that cannot reach the database is 503 SERVICE_UNAVAILABLE, not a 500', async () => {
      const spy = spyOnSupabaseFetch((url) =>
        url.includes('/rest/v1/clients') ? new TypeError('fetch failed') : undefined,
      );
      try {
        const list = await listClientsViaApi(ceo.cookies);
        const get = await getClientViaApi(ceo.cookies, UNKNOWN_CLIENT_ID);

        expect([list.status, get.status]).toEqual([503, 503]);
        expect(await bodyOf(list)).toMatchObject({ code: 'SERVICE_UNAVAILABLE' });
        expect(list.headers.get('retry-after')).not.toBeNull();
      } finally {
        spy.restore();
      }
    });

    it('E-21: a write that cannot reach the database is 503 and nothing is created', async () => {
      const name = uniqueClientName('Fora do ar');
      const spy = spyOnSupabaseFetch((url) =>
        url.includes('/rest/v1/rpc/create_client') ? new TypeError('fetch failed') : undefined,
      );
      try {
        const response = await createClientViaApi(ceo.cookies, { name });

        expect(response.status).toBe(503);
        expect(await bodyOf(response)).toMatchObject({ code: 'SERVICE_UNAVAILABLE' });
      } finally {
        spy.restore();
      }
      expect(await clientsNamed(name)).toBe(0);
    });
  });
});
