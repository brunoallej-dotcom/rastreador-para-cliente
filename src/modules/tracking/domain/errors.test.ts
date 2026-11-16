import { describe, expect, it } from 'vitest';
import { DomainError } from '@/shared/kernel';
import { ClientArchivedError, ProcessNotActiveError, StaleStageError } from './errors';

describe('tracking domain errors', () => {
  it.each([
    [new ProcessNotActiveError(), 'PROCESS_NOT_ACTIVE'],
    [new ClientArchivedError(), 'CLIENT_ARCHIVED'],
    [new StaleStageError('8f14e45f-ceea-467a-9575-1a4f2f2a2f00'), 'STALE_STAGE'],
  ])('%o carries its contract code and a client-safe detail', (error, code) => {
    expect(error.code).toBe(code);
    expect(error).toBeInstanceOf(DomainError);
    expect(error.detail).toEqual(expect.any(String));
  });

  it('E-01: a StaleStageError carries the id of the current stage, or null when there is none', () => {
    const current = '8f14e45f-ceea-467a-9575-1a4f2f2a2f00';

    expect(new StaleStageError(current).extensions).toEqual({ currentStageId: current });
    expect(new StaleStageError(null).extensions).toEqual({ currentStageId: null });
  });

  it('keeps the cause an option carries', () => {
    const cause = { code: '40001' };

    expect(new ProcessNotActiveError({ cause }).cause).toBe(cause);
    expect(new ClientArchivedError({ cause }).cause).toBe(cause);
    expect(new StaleStageError(null, { cause }).cause).toBe(cause);
  });
});
