import { describe, expect, it } from 'vitest';
import { ForbiddenError, NotFoundError, ServiceUnavailableError } from '@/shared/kernel';
import type { ProcessEvent } from '../domain/process-event';
import { ceoPrincipal, clientPrincipal } from './client-fixtures';
import { createFakeProcessEventQueries } from './fake-process-event-queries';
import { listProcessEvents } from './list-process-events';

const PROCESS_ID = '00000000-0000-4000-8000-0000000001a1';
const ACTOR = { id: '11111111-1111-4111-8111-111111111111', displayName: 'CEO' };

const event = (id: number, overrides: Partial<ProcessEvent> = {}): ProcessEvent => ({
  id: String(id),
  occurredAt: new Date('2026-06-01T12:00:00.000Z'),
  action: 'process.created',
  actor: ACTOR,
  details: {},
  ...overrides,
});

const fakeWith = (events: readonly ProcessEvent[]) =>
  createFakeProcessEventQueries({ [PROCESS_ID]: events });

describe('listProcessEvents', () => {
  it('AC-28: lists the events oldest first, with the actor', async () => {
    const events = fakeWith([event(12), event(10), event(11, { action: 'process.updated' })]);

    const result = await listProcessEvents({ events }, ceoPrincipal, {
      processId: PROCESS_ID,
      query: { limit: 50 },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.items.map((item) => item.id)).toEqual(['10', '11', '12']);
    expect(result.value.items.every((item) => item.actor?.displayName === 'CEO')).toBe(true);
    expect(result.value.next).toBeNull();
  });

  it('pages with the id of the last event, and the next page starts right after it', async () => {
    const events = fakeWith([event(1), event(2), event(3), event(4), event(5)]);

    const first = await listProcessEvents({ events }, ceoPrincipal, {
      processId: PROCESS_ID,
      query: { limit: 2 },
    });
    expect(first.ok && first.value.items.map((item) => item.id)).toEqual(['1', '2']);
    expect(first.ok && first.value.next).toEqual({ id: '2' });

    const second = await listProcessEvents({ events }, ceoPrincipal, {
      processId: PROCESS_ID,
      query: { limit: 2, after: { id: '2' } },
    });
    expect(second.ok && second.value.items.map((item) => item.id)).toEqual(['3', '4']);

    const last = await listProcessEvents({ events }, ceoPrincipal, {
      processId: PROCESS_ID,
      query: { limit: 2, after: { id: '4' } },
    });
    expect(last.ok && last.value.items.map((item) => item.id)).toEqual(['5']);
    expect(last.ok && last.value.next).toBeNull();
  });

  it('an unknown process is NotFoundError (404)', async () => {
    const events = fakeWith([event(1)]);

    const result = await listProcessEvents({ events }, ceoPrincipal, {
      processId: '00000000-0000-4000-8000-00000000dead',
      query: { limit: 50 },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(NotFoundError);
  });

  it('SEC-04: a client user is refused before the query service is touched', async () => {
    const events = fakeWith([event(1)]);

    const result = await listProcessEvents({ events }, clientPrincipal, {
      processId: PROCESS_ID,
      query: { limit: 50 },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(events.calls).toEqual([]);
  });

  it('E-21: an outage is thrown', async () => {
    const events = fakeWith([event(1)]);
    events.failWithOutage();

    await expect(
      listProcessEvents({ events }, ceoPrincipal, { processId: PROCESS_ID, query: { limit: 50 } }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
