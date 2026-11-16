import { describe, expect, it } from 'vitest';
import { ValidationError } from '@/shared/kernel';
import { isArchived, requireChange } from './client';

describe('isArchived', () => {
  it('is false while archivedAt is null and true once it has a date', () => {
    expect(isArchived({ archivedAt: null })).toBe(false);
    expect(isArchived({ archivedAt: new Date('2026-01-01T00:00:00Z') })).toBe(true);
  });
});

describe('requireChange', () => {
  it('AC-11: accepts a patch that renames', () => {
    const result = requireChange({ name: 'Novo nome' });
    expect(result).toEqual({ ok: true, value: { name: 'Novo nome' } });
  });

  it('AC-11: accepts a patch that archives and one that unarchives (false is a change)', () => {
    expect(requireChange({ archived: true }).ok).toBe(true);
    expect(requireChange({ archived: false }).ok).toBe(true);
  });

  it('AC-11: accepts a patch that does both', () => {
    expect(requireChange({ name: 'Novo nome', archived: true }).ok).toBe(true);
  });

  it('AC-11: refuses an empty patch with a 400 that points at the body', () => {
    const result = requireChange({});

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(ValidationError);
    expect(result.error.code).toBe('VALIDATION_ERROR');
    expect(result.error.issues).toEqual([
      { path: 'body', message: 'Must name at least one field to change' },
    ]);
  });
});
