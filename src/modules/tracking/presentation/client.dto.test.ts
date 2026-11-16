import { describe, expect, it } from 'vitest';
import type { Client } from '../domain/client';
import { decodeClientCursor } from './client.cursor';
import { toClientDetailDto, toClientListDto, toClientSummaryDto } from './client.dto';

const ACTIVE: Client = {
  id: '00000000-0000-4000-8000-00000000000a',
  name: 'Acme',
  archivedAt: null,
  activeProcessCount: 2,
  processCount: 5,
  createdAt: new Date('2026-01-01T10:00:00.123Z'),
  updatedAt: new Date('2026-01-02T10:00:00.000Z'),
};

const ARCHIVED: Client = { ...ACTIVE, archivedAt: new Date('2026-03-04T05:06:07.000Z') };

describe('toClientSummaryDto', () => {
  it('maps the fields of ClientSummary and nothing else', () => {
    expect(toClientSummaryDto(ACTIVE)).toEqual({
      id: ACTIVE.id,
      name: 'Acme',
      archived: false,
      archivedAt: null,
      activeProcessCount: 2,
      createdAt: '2026-01-01T10:00:00.123Z',
      updatedAt: '2026-01-02T10:00:00.000Z',
    });
  });

  it('does not carry the total process count (that is ClientDetail)', () => {
    expect(toClientSummaryDto(ACTIVE)).not.toHaveProperty('processCount');
  });

  it('turns archivedAt into the flag and an ISO timestamp', () => {
    expect(toClientSummaryDto(ARCHIVED)).toMatchObject({
      archived: true,
      archivedAt: '2026-03-04T05:06:07.000Z',
    });
  });
});

describe('toClientDetailDto', () => {
  it('maps the fields of ClientDetail, the process count included', () => {
    expect(toClientDetailDto(ARCHIVED)).toEqual({
      id: ACTIVE.id,
      name: 'Acme',
      archived: true,
      archivedAt: '2026-03-04T05:06:07.000Z',
      activeProcessCount: 2,
      processCount: 5,
      createdAt: '2026-01-01T10:00:00.123Z',
      updatedAt: '2026-01-02T10:00:00.000Z',
    });
  });
});

describe('toClientListDto', () => {
  it('has no cursor on the last page', () => {
    const dto = toClientListDto({ items: [ACTIVE], next: null });

    expect(dto.nextCursor).toBeNull();
    expect(dto.items).toEqual([toClientSummaryDto(ACTIVE)]);
  });

  it('encodes the position of the next page as an opaque cursor', () => {
    const next = { createdAt: '2026-01-01T10:00:00.123456+00:00', id: ACTIVE.id };

    const dto = toClientListDto({ items: [ACTIVE], next });

    expect(dto.nextCursor).not.toBeNull();
    expect(decodeClientCursor(dto.nextCursor ?? '')).toEqual({ ok: true, value: next });
  });
});
