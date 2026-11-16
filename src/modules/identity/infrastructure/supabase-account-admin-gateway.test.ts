import { describe, expect, it, vi } from 'vitest';
import type { AdminAuthFailure } from '@/shared/db/admin-client';
import { NotFoundError, ServiceUnavailableError } from '@/shared/kernel';
import {
  ClientUserProvisionUnconfirmedError,
  EmailAlreadyRegisteredError,
} from '../domain/client-user-errors';
import { UnexpectedAuthAnswerError } from '../domain/errors';
import {
  createSupabaseAccountAdminGateway,
  type AccountAdminApi,
} from './supabase-account-admin-gateway';

const USER_ID = '00000000-0000-4000-8000-0000000000a1';
const CLIENT_ID = '00000000-0000-4000-8000-00000000000a';
/** Built at run time and low-entropy: never a literal that looks like a credential. */
const PASSWORD = 'p'.repeat(20);
const EMAIL = 'pessoa@cliente.test';

/** What the facade returns for a failed call: the kind, the status and the code, never a message. */
const failure = (name: string, status: number | undefined, code?: string) => ({
  data: null,
  error: { name, status, code } satisfies AdminAuthFailure,
});
const success = <T>(data: T) => ({ data, error: null });

type Fake = {
  createClientUser: ReturnType<typeof vi.fn>;
  deleteUser: ReturnType<typeof vi.fn>;
  setPassword: ReturnType<typeof vi.fn>;
  setBan: ReturnType<typeof vi.fn>;
};

function fakeApi(overrides: Partial<Fake> = {}) {
  const api: Fake = {
    createClientUser: vi.fn().mockResolvedValue(success({ id: USER_ID })),
    deleteUser: vi.fn().mockResolvedValue(success(null)),
    setPassword: vi.fn().mockResolvedValue(success(null)),
    setBan: vi.fn().mockResolvedValue(success(null)),
    ...overrides,
  };
  return { api, gateway: createSupabaseAccountAdminGateway(api as unknown as AccountAdminApi) };
}

const NEW_ACCOUNT = {
  email: EMAIL,
  displayName: 'Maria',
  clientId: CLIENT_ID,
  temporaryPassword: PASSWORD,
};

describe('createClientUser', () => {
  it('AC-12: hands the facade the e-mail, the name, the tenant and the password, and nothing that could name a role', async () => {
    const { api, gateway } = fakeApi();

    const result = await gateway.createClientUser(NEW_ACCOUNT);

    expect(result).toEqual({ ok: true, value: { id: USER_ID } });
    expect(api.createClientUser).toHaveBeenCalledTimes(1);
    // the facade fixes the role to `client`: the gateway has no way to ask for another
    expect(api.createClientUser).toHaveBeenCalledWith({
      email: EMAIL,
      password: PASSWORD,
      displayName: 'Maria',
      clientId: CLIENT_ID,
    });
  });

  it('E-17: email_exists is EMAIL_ALREADY_REGISTERED', async () => {
    const { gateway } = fakeApi({
      createClientUser: vi.fn().mockResolvedValue(failure('AuthApiError', 422, 'email_exists')),
    });

    const result = await gateway.createClientUser(NEW_ACCOUNT);

    expect(!result.ok && result.error).toBeInstanceOf(EmailAlreadyRegisteredError);
  });

  it('user_already_exists is NOT the answer to an admin creation (GoTrue says email_exists): it is an unexpected answer, never a 409', async () => {
    const { gateway } = fakeApi({
      createClientUser: vi
        .fn()
        .mockResolvedValue(failure('AuthApiError', 422, 'user_already_exists')),
    });

    await expect(gateway.createClientUser(NEW_ACCOUNT)).rejects.toBeInstanceOf(
      UnexpectedAuthAnswerError,
    );
  });

  it('E-23: the 500 of a refused profile trigger (AuthRetryableFetchError) is a 503, which the use case then explains', async () => {
    const { gateway } = fakeApi({
      createClientUser: vi.fn().mockResolvedValue(failure('AuthRetryableFetchError', 500)),
    });

    await expect(gateway.createClientUser(NEW_ACCOUNT)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('E-21: a transport failure that throws is a 503', async () => {
    const { gateway } = fakeApi({
      createClientUser: vi.fn().mockRejectedValue(new TypeError('fetch failed')),
    });

    await expect(gateway.createClientUser(NEW_ACCOUNT)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('a 4xx nobody mapped (a rejected key, a stricter password rule) is UnexpectedAuthAnswerError with the status and code, never a 500 or a 409', async () => {
    const { gateway } = fakeApi({
      createClientUser: vi.fn().mockResolvedValue(failure('AuthApiError', 422, 'weak_password')),
    });

    const thrown: unknown = await gateway
      .createClientUser(NEW_ACCOUNT)
      .catch((caught: unknown) => caught);

    expect(thrown).toBeInstanceOf(UnexpectedAuthAnswerError);
    expect(thrown).toMatchObject({ authStatus: 422, authCode: 'weak_password' });
  });

  it('SEC-16: no error carries the e-mail or the password, only the kind, the status and the code', async () => {
    const { gateway } = fakeApi({
      createClientUser: vi
        .fn()
        .mockResolvedValue(failure('AuthApiError', 400, 'validation_failed')),
    });

    const thrown = (await gateway
      .createClientUser(NEW_ACCOUNT)
      .catch((caught: unknown) => caught)) as Error;

    const everything = JSON.stringify({
      message: thrown.message,
      cause: thrown.cause,
      detail: (thrown as { detail?: string }).detail,
    });
    expect(everything).not.toContain(EMAIL);
    expect(everything).not.toContain(PASSWORD);
    expect(thrown.cause).toEqual({ name: 'AuthApiError', status: 400, code: 'validation_failed' });
  });

  it('F-90, E-55: an accepted creation whose answer carries no user id is ClientUserProvisionUnconfirmedError: a 503, never a 500, and not "nothing was created"', async () => {
    const { gateway } = fakeApi({
      createClientUser: vi.fn().mockResolvedValue(success({ id: null })),
    });

    const thrown: unknown = await gateway
      .createClientUser(NEW_ACCOUNT)
      .catch((caught: unknown) => caught);

    expect(thrown).toBeInstanceOf(ClientUserProvisionUnconfirmedError);
    expect(thrown).toBeInstanceOf(UnexpectedAuthAnswerError);
    expect(thrown).toBeInstanceOf(ServiceUnavailableError);
    expect(JSON.stringify({ message: (thrown as Error).message })).not.toContain(EMAIL);
  });

  it('F-90: a facade answer with no data at all is the same unconfirmed error', async () => {
    const { gateway } = fakeApi({
      createClientUser: vi.fn().mockResolvedValue({ data: null, error: null }),
    });

    await expect(gateway.createClientUser(NEW_ACCOUNT)).rejects.toBeInstanceOf(
      ClientUserProvisionUnconfirmedError,
    );
  });
});

describe('deleteUser', () => {
  it('deletes the account (a hard delete: the profile goes with it)', async () => {
    const { api, gateway } = fakeApi();

    await gateway.deleteUser(USER_ID);

    expect(api.deleteUser).toHaveBeenCalledWith(USER_ID);
  });

  it('an account that is already gone is a success', async () => {
    const { gateway } = fakeApi({
      deleteUser: vi.fn().mockResolvedValue(failure('AuthApiError', 404, 'user_not_found')),
    });

    await expect(gateway.deleteUser(USER_ID)).resolves.toBeUndefined();
  });

  it('E-21: an outage is a 503 (so the compensation can try again)', async () => {
    const { gateway } = fakeApi({
      deleteUser: vi.fn().mockResolvedValue(failure('AuthRetryableFetchError', 0)),
    });

    await expect(gateway.deleteUser(USER_ID)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('an unexpected answer keeps its status and code, for the log of the compensation', async () => {
    const { gateway } = fakeApi({
      deleteUser: vi.fn().mockResolvedValue(failure('AuthApiError', 403, 'not_admin')),
    });

    const thrown: unknown = await gateway.deleteUser(USER_ID).catch((caught: unknown) => caught);

    expect(thrown).toMatchObject({ authStatus: 403, authCode: 'not_admin' });
  });
});

describe('setPassword', () => {
  it('AC-14: stores the password through the facade and nothing else', async () => {
    const { api, gateway } = fakeApi();

    const result = await gateway.setPassword(USER_ID, PASSWORD);

    expect(result.ok).toBe(true);
    expect(api.setPassword).toHaveBeenCalledWith(USER_ID, PASSWORD);
  });

  it('a user the Auth server does not have is NotFound', async () => {
    const { gateway } = fakeApi({
      setPassword: vi.fn().mockResolvedValue(failure('AuthApiError', 404, 'user_not_found')),
    });

    const result = await gateway.setPassword(USER_ID, PASSWORD);

    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
  });

  it('E-21: a 5xx is a 503', async () => {
    const { gateway } = fakeApi({
      setPassword: vi.fn().mockResolvedValue(failure('AuthApiError', 502)),
    });

    await expect(gateway.setPassword(USER_ID, PASSWORD)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });
});

describe('setBanned', () => {
  it('AC-13: bans and unbans through the facade', async () => {
    const { api, gateway } = fakeApi();

    await gateway.setBanned(USER_ID, true);
    await gateway.setBanned(USER_ID, false);

    expect(api.setBan).toHaveBeenNthCalledWith(1, USER_ID, true);
    expect(api.setBan).toHaveBeenNthCalledWith(2, USER_ID, false);
  });

  it('a user the Auth server does not have is NotFound', async () => {
    const { gateway } = fakeApi({
      setBan: vi.fn().mockResolvedValue(failure('AuthApiError', 404, 'user_not_found')),
    });

    const result = await gateway.setBanned(USER_ID, true);

    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
  });

  it('E-24: a thrown transport failure is a 503 (the use case turns it into a ban_failed notice)', async () => {
    const { gateway } = fakeApi({
      setBan: vi.fn().mockRejectedValue(new TypeError('fetch failed')),
    });

    await expect(gateway.setBanned(USER_ID, true)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('F-94: an unexpected answer is UnexpectedAuthAnswerError, which the use case reports as `unexpected`', async () => {
    const { gateway } = fakeApi({
      setBan: vi.fn().mockResolvedValue(failure('AuthApiError', 400, 'validation_failed')),
    });

    await expect(gateway.setBanned(USER_ID, true)).rejects.toBeInstanceOf(
      UnexpectedAuthAnswerError,
    );
  });
});
