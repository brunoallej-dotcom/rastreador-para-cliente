import type { SupabaseClient } from '@supabase/supabase-js';
import { describe, expect, it, vi } from 'vitest';
import type { Database } from '@/shared/db/database.types';
import {
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  ValidationError,
} from '@/shared/kernel';
import { createSupabaseAccountRepository } from './supabase-account-repository';

const CLIENT_ID = '00000000-0000-4000-8000-00000000000a';
const USER_ID = '00000000-0000-4000-8000-0000000000a1';

type Outcome = { data: unknown; error: unknown; status: number };

const answer = (data: unknown = null, status = 200): Outcome => ({ data, error: null, status });
const failure = (code: string, message: string, status = 400): Outcome => ({
  data: null,
  error: { code, message },
  status,
});

const row = (overrides: Record<string, unknown> = {}) => ({
  user_id: USER_ID,
  email: 'pessoa@cliente.test',
  display_name: 'Maria',
  disabled_at: null,
  must_change_password: true,
  last_sign_in_at: null,
  created_at: '2026-11-16T11:30:24.984084+00:00',
  ...overrides,
});

function fakeSupabase(outcome: Outcome) {
  const rpc = vi.fn().mockResolvedValue(outcome);
  const warn = vi.fn();
  const repository = createSupabaseAccountRepository(
    { rpc } as unknown as SupabaseClient<Database>,
    {
      logger: { warn },
    },
  );
  return { rpc, warn, repository };
}

describe('list', () => {
  it('RF-07: calls list_client_users with the client id and returns the logins as the domain sees them', async () => {
    const { rpc, repository } = fakeSupabase(
      answer([
        row(),
        row({
          user_id: '00000000-0000-4000-8000-0000000000a2',
          disabled_at: '2026-11-16T12:00:00+00:00',
          must_change_password: false,
          last_sign_in_at: '2026-11-16T12:30:00.5+00:00',
        }),
      ]),
    );

    const result = await repository.list(CLIENT_ID);

    expect(rpc).toHaveBeenCalledWith('list_client_users', { p_client_id: CLIENT_ID });
    expect(result.ok && result.value).toHaveLength(2);
    if (!result.ok) return;
    expect(result.value[0]).toEqual({
      id: USER_ID,
      email: 'pessoa@cliente.test',
      displayName: 'Maria',
      disabled: false,
      mustChangePassword: true,
      lastSignInAt: null,
      createdAt: new Date('2026-11-16T11:30:24.984Z'),
    });
    expect(result.value[1]).toMatchObject({
      disabled: true,
      mustChangePassword: false,
      lastSignInAt: new Date('2026-11-16T12:30:00.500Z'),
    });
  });

  it('a client that does not exist is NotFound about the CLIENT', async () => {
    const { repository } = fakeSupabase(failure('P0001', 'NOT_FOUND'));

    const result = await repository.list(CLIENT_ID);

    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
    expect(!result.ok && result.error.detail).toBe('Client not found.');
  });

  it('SEC-13: a row the schema does not understand fails closed (500, not a guess)', async () => {
    const { repository } = fakeSupabase(answer([row({ email: 42 })]));

    await expect(repository.list(CLIENT_ID)).rejects.toThrow(/not understood/);
  });

  it('SEC-04: a database that denies the caller is Forbidden and the bypass is logged', async () => {
    const { repository, warn } = fakeSupabase(failure('42501', 'FORBIDDEN'));

    const result = await repository.list(CLIENT_ID);

    expect(!result.ok && result.error).toBeInstanceOf(ForbiddenError);
    expect(warn).toHaveBeenCalledWith(
      { event: 'authz.database_denied', operation: 'list_client_users' },
      'authz.database_denied',
    );
  });

  it('E-21: a dead database (status 0) is a 503', async () => {
    const { repository } = fakeSupabase(failure('', 'TypeError: fetch failed', 0));

    await expect(repository.list(CLIENT_ID)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('an unexpected SQLSTATE is a plain error (500) whose cause is only the code and the status', async () => {
    const { repository } = fakeSupabase(failure('XX000', 'row with pessoa@cliente.test', 400));

    const error = (await repository.list(CLIENT_ID).catch((caught: unknown) => caught)) as Error;

    expect(error).not.toBeInstanceOf(ServiceUnavailableError);
    expect(error.cause).toEqual({ code: 'XX000', status: 400 });
  });
});

describe('recordProvisioned', () => {
  it('F-93: calls record_account_provisioned with the user id only and returns the login as the list shows it', async () => {
    const { rpc, repository } = fakeSupabase(answer([row()]));

    const result = await repository.recordProvisioned(USER_ID);

    expect(rpc).toHaveBeenCalledWith('record_account_provisioned', { p_user_id: USER_ID });
    expect(result.ok && result.value).toEqual({
      id: USER_ID,
      email: 'pessoa@cliente.test',
      displayName: 'Maria',
      disabled: false,
      mustChangePassword: true,
      lastSignInAt: null,
      createdAt: new Date('2026-11-16T11:30:24.984Z'),
    });
  });

  it.each([
    ['no row', []],
    ['two rows', [row(), row()]],
    ['a row the schema does not understand', [row({ email: 42 })]],
    ['no answer at all (the old function)', null],
  ])('SEC-13: %s fails closed (500, not a guess)', async (_label, data) => {
    const { repository } = fakeSupabase(answer(data));

    await expect(repository.recordProvisioned(USER_ID)).rejects.toThrow(/not understood/);
  });

  it('a target that is not a client login is NotFound, a denied caller is Forbidden', async () => {
    const notFound = await fakeSupabase(failure('P0001', 'NOT_FOUND')).repository.recordProvisioned(
      USER_ID,
    );
    const denied = await fakeSupabase(failure('42501', 'FORBIDDEN')).repository.recordProvisioned(
      USER_ID,
    );

    expect(!notFound.ok && notFound.error).toBeInstanceOf(NotFoundError);
    expect(!denied.ok && denied.error).toBeInstanceOf(ForbiddenError);
  });

  it('INVALID_INPUT (the second record of a login) is a 400, a transport failure a 503', async () => {
    const second = await fakeSupabase(
      failure('P0001', 'INVALID_INPUT'),
    ).repository.recordProvisioned(USER_ID);

    expect(!second.ok && second.error).toBeInstanceOf(ValidationError);
    await expect(
      fakeSupabase(failure('', 'TypeError: fetch failed', 0)).repository.recordProvisioned(USER_ID),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});

describe('beginAuthWrite', () => {
  it.each(['ban', 'unban', 'set_password'] as const)(
    'F-92 b: calls begin_client_login_admin with the client, the login and the action %s',
    async (action) => {
      const { rpc, repository } = fakeSupabase(answer(null, 204));

      const result = await repository.beginAuthWrite(CLIENT_ID, USER_ID, action);

      expect(result.ok).toBe(true);
      expect(rpc).toHaveBeenCalledWith('begin_client_login_admin', {
        p_client_id: CLIENT_ID,
        p_user_id: USER_ID,
        p_action: action,
      });
    },
  );

  it('SEC-04: a denied caller is Forbidden and the bypass is logged', async () => {
    const { repository, warn } = fakeSupabase(failure('42501', 'FORBIDDEN'));

    const result = await repository.beginAuthWrite(CLIENT_ID, USER_ID, 'ban');

    expect(!result.ok && result.error).toBeInstanceOf(ForbiddenError);
    expect(warn).toHaveBeenCalledWith(
      { event: 'authz.database_denied', operation: 'begin_client_login_admin' },
      'authz.database_denied',
    );
  });

  it('E-19: a login that is not one of this client is NotFound', async () => {
    const { repository } = fakeSupabase(failure('P0001', 'NOT_FOUND'));

    const result = await repository.beginAuthWrite(CLIENT_ID, USER_ID, 'set_password');

    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
  });

  it('F-86: INVALID_INPUT here is a defect of the app, never the CEO input: a 500 whose cause is only the code and the status', async () => {
    const { repository } = fakeSupabase(failure('P0001', 'INVALID_INPUT', 400));

    const error = (await repository
      .beginAuthWrite(CLIENT_ID, USER_ID, 'ban')
      .catch((caught: unknown) => caught)) as Error;

    expect(error).not.toBeInstanceOf(ServiceUnavailableError);
    expect(error).not.toBeInstanceOf(ValidationError);
    expect(error.cause).toEqual({ code: 'P0001', status: 400 });
  });

  it.each([
    ['a CHECK violation', '23514'],
    ['a value that is too long', '22001'],
  ])(
    '%s is a defect of the app too: a 500, never a 400 or a 422 about the CEO',
    async (_label, code) => {
      const { repository } = fakeSupabase(failure(code, 'row with pessoa@cliente.test', 400));

      const error = (await repository
        .beginAuthWrite(CLIENT_ID, USER_ID, 'set_password')
        .catch((caught: unknown) => caught)) as Error;

      expect(error).toBeInstanceOf(Error);
      expect(error).not.toBeInstanceOf(ServiceUnavailableError);
      expect(error).not.toBeInstanceOf(ValidationError);
      expect(error.cause).toEqual({ code, status: 400 });
    },
  );

  it('a deadlock is a 503 that is safe to repeat, a transport failure too', async () => {
    for (const outcome of [
      failure('40P01', 'deadlock detected', 500),
      failure('', 'TypeError: fetch failed', 0),
    ]) {
      const { repository } = fakeSupabase(outcome);
      await expect(repository.beginAuthWrite(CLIENT_ID, USER_ID, 'ban')).rejects.toBeInstanceOf(
        ServiceUnavailableError,
      );
    }
  });
});

describe.each([
  ['setDisabled', 'set_account_disabled', { p_user_id: USER_ID, p_disabled: true }],
  ['setDisplayName', 'set_account_display_name', { p_user_id: USER_ID, p_display_name: 'Nome' }],
  ['requirePasswordChange', 'require_password_change', { p_user_id: USER_ID }],
  [
    'recordProvisionReverted',
    'record_account_provision_reverted',
    { p_user_id: USER_ID, p_reason: 'record_failed' },
  ],
] as const)('%s', (method, fn, args) => {
  const call = (repository: ReturnType<typeof fakeSupabase>['repository']) => {
    if (method === 'setDisabled') return repository.setDisabled(USER_ID, true);
    if (method === 'setDisplayName') return repository.setDisplayName(USER_ID, 'Nome');
    if (method === 'recordProvisionReverted') {
      return repository.recordProvisionReverted(USER_ID, 'record_failed');
    }
    return repository[method](USER_ID);
  };

  it(`calls ${fn} with exactly the typed arguments`, async () => {
    const { rpc, repository } = fakeSupabase(answer(null, 204));

    const result = await call(repository);

    expect(result.ok).toBe(true);
    expect(rpc).toHaveBeenCalledWith(fn, args);
  });

  it('a target that is not a client login is NotFound', async () => {
    const { repository } = fakeSupabase(failure('P0001', 'NOT_FOUND'));

    const result = await call(repository);

    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
  });

  it('SEC-04: a denied caller is Forbidden', async () => {
    const { repository } = fakeSupabase(failure('42501', 'FORBIDDEN'));

    const result = await call(repository);

    expect(!result.ok && result.error).toBeInstanceOf(ForbiddenError);
  });

  it('a deadlock or a serialization failure is a 503 that is safe to repeat (nothing persisted)', async () => {
    for (const code of ['40P01', '40001']) {
      const { repository } = fakeSupabase(failure(code, 'deadlock detected', 500));
      await expect(call(repository)).rejects.toBeInstanceOf(ServiceUnavailableError);
    }
  });

  it('E-21: a transport failure is a 503', async () => {
    const { repository } = fakeSupabase(failure('', 'TypeError: fetch failed', 0));

    await expect(call(repository)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});

describe('setDisplayName', () => {
  it('INVALID_INPUT and a CHECK violation are a 400, not a 500', async () => {
    for (const outcome of [failure('P0001', 'INVALID_INPUT'), failure('23514', 'check')]) {
      const { repository } = fakeSupabase(outcome);

      const result = await repository.setDisplayName(USER_ID, 'x');

      expect(!result.ok && result.error).toBeInstanceOf(ValidationError);
    }
  });
});
