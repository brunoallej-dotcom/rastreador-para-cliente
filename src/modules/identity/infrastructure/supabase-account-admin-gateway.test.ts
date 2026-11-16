import { describe, expect, it, vi } from 'vitest';
import { NotFoundError, ServiceUnavailableError } from '@/shared/kernel';
import { EmailAlreadyRegisteredError } from '../domain/client-user-errors';
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

/** What auth-js returns for a failed call: `{ data, error }`, the error with a name, a status, a code. */
const authError = (name: string, status: number, code?: string) => ({
  data: { user: null },
  error: { name, status, ...(code === undefined ? {} : { code }), message: `says ${EMAIL}` },
});

type Fake = {
  createUser: ReturnType<typeof vi.fn>;
  deleteUser: ReturnType<typeof vi.fn>;
  updateUserById: ReturnType<typeof vi.fn>;
};

function fakeApi(overrides: Partial<Fake> = {}) {
  const api: Fake = {
    createUser: vi.fn().mockResolvedValue({ data: { user: { id: USER_ID } }, error: null }),
    deleteUser: vi.fn().mockResolvedValue({ data: { user: null }, error: null }),
    updateUserById: vi.fn().mockResolvedValue({ data: { user: { id: USER_ID } }, error: null }),
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
  it('AC-12: creates the account with the password in the SAME call, confirmed, with the role and the tenant in app_metadata only', async () => {
    const { api, gateway } = fakeApi();

    const result = await gateway.createClientUser(NEW_ACCOUNT);

    expect(result).toEqual({ ok: true, value: { id: USER_ID } });
    expect(api.createUser).toHaveBeenCalledTimes(1);
    expect(api.createUser).toHaveBeenCalledWith({
      email: EMAIL,
      password: PASSWORD,
      email_confirm: true,
      app_metadata: { role: 'client', client_id: CLIENT_ID, display_name: 'Maria' },
    });
  });

  it('E-17: email_exists is EMAIL_ALREADY_REGISTERED', async () => {
    const { gateway } = fakeApi({
      createUser: vi.fn().mockResolvedValue(authError('AuthApiError', 422, 'email_exists')),
    });

    const result = await gateway.createClientUser(NEW_ACCOUNT);

    expect(!result.ok && result.error).toBeInstanceOf(EmailAlreadyRegisteredError);
  });

  it('E-23: the 500 of a refused profile trigger (AuthRetryableFetchError) is a 503, which the use case then explains', async () => {
    const { gateway } = fakeApi({
      createUser: vi.fn().mockResolvedValue(authError('AuthRetryableFetchError', 500)),
    });

    await expect(gateway.createClientUser(NEW_ACCOUNT)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('E-21: a transport failure that throws is a 503', async () => {
    const { gateway } = fakeApi({
      createUser: vi.fn().mockRejectedValue(new TypeError('fetch failed')),
    });

    await expect(gateway.createClientUser(NEW_ACCOUNT)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('a 4xx nobody mapped (a rejected key, a stricter password rule) is UnexpectedAuthAnswerError with the status and code, never a 500 or a 409', async () => {
    const { gateway } = fakeApi({
      createUser: vi.fn().mockResolvedValue(authError('AuthApiError', 422, 'weak_password')),
    });

    const failure: unknown = await gateway
      .createClientUser(NEW_ACCOUNT)
      .catch((caught: unknown) => caught);

    expect(failure).toBeInstanceOf(UnexpectedAuthAnswerError);
    expect(failure).toMatchObject({ authStatus: 422, authCode: 'weak_password' });
  });

  it('SEC-16: no error carries the e-mail or the password, only the kind, the status and the code', async () => {
    const { gateway } = fakeApi({
      createUser: vi.fn().mockResolvedValue(authError('AuthApiError', 400, 'validation_failed')),
    });

    const failure = (await gateway
      .createClientUser(NEW_ACCOUNT)
      .catch((caught: unknown) => caught)) as Error;

    const everything = JSON.stringify({
      message: failure.message,
      cause: failure.cause,
      detail: (failure as { detail?: string }).detail,
    });
    expect(everything).not.toContain(EMAIL);
    expect(everything).not.toContain(PASSWORD);
    expect(failure.cause).toEqual({ name: 'AuthApiError', status: 400, code: 'validation_failed' });
  });

  it('an answer without a user id fails closed', async () => {
    const { gateway } = fakeApi({
      createUser: vi.fn().mockResolvedValue({ data: { user: { id: 'not-a-uuid' } }, error: null }),
    });

    await expect(gateway.createClientUser(NEW_ACCOUNT)).rejects.toThrow(/not understood/);
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
      deleteUser: vi.fn().mockResolvedValue(authError('AuthApiError', 404, 'user_not_found')),
    });

    await expect(gateway.deleteUser(USER_ID)).resolves.toBeUndefined();
  });

  it('E-21: an outage is a 503 (so the compensation can try again)', async () => {
    const { gateway } = fakeApi({
      deleteUser: vi.fn().mockResolvedValue(authError('AuthRetryableFetchError', 0)),
    });

    await expect(gateway.deleteUser(USER_ID)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});

describe('setPassword', () => {
  it('AC-14: stores the password through updateUserById and nothing else', async () => {
    const { api, gateway } = fakeApi();

    const result = await gateway.setPassword(USER_ID, PASSWORD);

    expect(result.ok).toBe(true);
    expect(api.updateUserById).toHaveBeenCalledWith(USER_ID, { password: PASSWORD });
  });

  it('a user the Auth server does not have is NotFound', async () => {
    const { gateway } = fakeApi({
      updateUserById: vi.fn().mockResolvedValue(authError('AuthApiError', 404, 'user_not_found')),
    });

    const result = await gateway.setPassword(USER_ID, PASSWORD);

    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
  });

  it('E-21: a 5xx is a 503', async () => {
    const { gateway } = fakeApi({
      updateUserById: vi.fn().mockResolvedValue(authError('AuthApiError', 502)),
    });

    await expect(gateway.setPassword(USER_ID, PASSWORD)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });
});

describe('setBanned', () => {
  it('AC-13: bans for a century and unbans with none', async () => {
    const { api, gateway } = fakeApi();

    await gateway.setBanned(USER_ID, true);
    await gateway.setBanned(USER_ID, false);

    expect(api.updateUserById).toHaveBeenNthCalledWith(1, USER_ID, { ban_duration: '876000h' });
    expect(api.updateUserById).toHaveBeenNthCalledWith(2, USER_ID, { ban_duration: 'none' });
  });

  it('a user the Auth server does not have is NotFound', async () => {
    const { gateway } = fakeApi({
      updateUserById: vi.fn().mockResolvedValue(authError('AuthApiError', 404, 'user_not_found')),
    });

    const result = await gateway.setBanned(USER_ID, true);

    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
  });

  it('E-24: a thrown transport failure is a 503 (the use case turns it into banSynced false)', async () => {
    const { gateway } = fakeApi({
      updateUserById: vi.fn().mockRejectedValue(new TypeError('fetch failed')),
    });

    await expect(gateway.setBanned(USER_ID, true)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
