import { describe, expect, it } from 'vitest';
import { ForbiddenError, NotFoundError, ServiceUnavailableError } from '@/shared/kernel';
import { UnexpectedAuthAnswerError } from './errors';
import { safeCauseOf } from './safe-cause';

describe('safeCauseOf', () => {
  it('SEC-16: a domain error keeps its own code as the kind, and never its message or detail', () => {
    const cause = safeCauseOf(
      new ForbiddenError('denied for pessoa@cliente.test', { detail: 'about pessoa@cliente.test' }),
    );

    expect(cause).toEqual({ kind: 'FORBIDDEN' });
  });

  it('keeps the SQLSTATE and the status the infrastructure left in the cause, and only those', () => {
    const cause = safeCauseOf(
      new ServiceUnavailableError('down', {
        cause: { code: '40P01', status: 500, message: 'row (pessoa@cliente.test)' },
      }),
    );

    expect(cause).toEqual({ kind: 'SERVICE_UNAVAILABLE', status: 500, reason: '40P01' });
  });

  it('an unexpected Auth answer keeps the status and the code it was built with', () => {
    const cause = safeCauseOf(
      new UnexpectedAuthAnswerError('x pessoa@cliente.test', {
        status: 422,
        code: 'weak_password',
      }),
    );

    expect(cause).toEqual({ kind: 'SERVICE_UNAVAILABLE', status: 422, reason: 'weak_password' });
  });

  it('an error nobody classified is UNKNOWN, with the status and code only when it has them', () => {
    expect(safeCauseOf(new TypeError('boom pessoa@cliente.test'))).toEqual({ kind: 'UNKNOWN' });
    expect(safeCauseOf({ status: 404, code: 'user_not_found', message: 'x' })).toEqual({
      kind: 'UNKNOWN',
      status: 404,
      reason: 'user_not_found',
    });
    expect(safeCauseOf('a string')).toEqual({ kind: 'UNKNOWN' });
    expect(safeCauseOf(undefined)).toEqual({ kind: 'UNKNOWN' });
  });

  it('a domain error with no cause has no status or reason', () => {
    expect(safeCauseOf(new NotFoundError('gone'))).toEqual({ kind: 'NOT_FOUND' });
  });

  it('the field is called kind, not code: the log redactor blanks every value under `code`', () => {
    expect(Object.keys(safeCauseOf(new ForbiddenError('x')))).not.toContain('code');
  });
});
