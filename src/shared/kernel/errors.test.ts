import { describe, expect, it } from 'vitest';
import {
  ConflictError,
  DomainError,
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  UnauthenticatedError,
  ValidationError,
} from './errors';

describe('DomainError subclasses', () => {
  it.each([
    [new NotFoundError('x'), 'NOT_FOUND'],
    [new ForbiddenError('x'), 'FORBIDDEN'],
    [new ConflictError('x'), 'CONFLICT'],
    [new UnauthenticatedError('x'), 'UNAUTHENTICATED'],
    [new ServiceUnavailableError('x'), 'SERVICE_UNAVAILABLE'],
    [new ValidationError('x'), 'VALIDATION_ERROR'],
  ])('%o carries its contract code', (error, code) => {
    expect(error.code).toBe(code);
    expect(error).toBeInstanceOf(DomainError);
    expect(error).toBeInstanceOf(Error);
  });

  it('uses the class name as error name and keeps the cause', () => {
    const cause = new Error('root');
    const error = new NotFoundError('missing', { cause });
    expect(error.name).toBe('NotFoundError');
    expect(error.message).toBe('missing');
    expect(error.cause).toBe(cause);
  });

  it('ValidationError carries the list of issues', () => {
    const issues = [{ path: 'body.name', message: 'required' }];
    const error = new ValidationError('invalid', issues);
    expect(error.issues).toEqual(issues);
    expect(new ValidationError('invalid').issues).toEqual([]);
  });
});

describe('DomainError problem members', () => {
  it('carries a client-safe detail and extensions, separate from the log-only message', () => {
    const error = new ConflictError('internal text', {
      detail: 'The stage changed.',
      extensions: { currentStageId: '8f14e45f-ceea-467a-9575-1a4f2f2a2f00' },
    });
    expect(error.message).toBe('internal text');
    expect(error.detail).toBe('The stage changed.');
    expect(error.extensions).toEqual({ currentStageId: '8f14e45f-ceea-467a-9575-1a4f2f2a2f00' });
  });

  it('defaults detail and extensions to undefined', () => {
    const error = new NotFoundError('x');
    expect(error.detail).toBeUndefined();
    expect(error.extensions).toBeUndefined();
  });
});
