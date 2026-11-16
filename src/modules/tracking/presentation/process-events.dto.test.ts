import { describe, expect, it } from 'vitest';
import type { ProcessEvent } from '../domain/process-event';
import { decodeProcessEventCursor } from './process-events.cursor';
import { toProcessEventDto, toProcessEventListDto } from './process-events.dto';

const ACTOR = { id: '11111111-1111-4111-8111-111111111111', displayName: 'CEO Um' };
const STAGE_ID = '00000000-0000-4000-8000-000000000201';
const AT = new Date('2026-11-16T12:00:00.500Z');

const event = (overrides: Partial<ProcessEvent> = {}): ProcessEvent => ({
  id: '41',
  occurredAt: AT,
  action: 'process.created',
  actor: ACTOR,
  details: {},
  ...overrides,
});

describe('toProcessEventDto', () => {
  it('AC-28: maps the fields of ProcessEvent: id as text, an ISO instant, the action, the actor and the details', () => {
    const dto = toProcessEventDto(event());

    expect(Object.keys(dto).sort()).toEqual(['action', 'actor', 'details', 'id', 'occurredAt']);
    expect(dto).toEqual({
      id: '41',
      occurredAt: '2026-11-16T12:00:00.500Z',
      action: 'process.created',
      actor: { id: ACTOR.id, displayName: 'CEO Um' },
      details: {},
    });
  });

  it('a stage.approved event carries the stage id, position and name, and nothing else', () => {
    const dto = toProcessEventDto(
      event({
        action: 'stage.approved',
        details: { stageId: STAGE_ID, stagePosition: 2, stageName: 'Briefing' },
      }),
    );

    expect(dto.details).toEqual({ stageId: STAGE_ID, stagePosition: 2, stageName: 'Briefing' });
  });

  it('SEC-16: a process.updated event has no title in its details, whatever the domain object carries', () => {
    const polluted = event({
      action: 'process.updated',
      // a defect upstream must not become a response: the DTO copies the three stage members only
      details: { previousTitle: 'Antes', newTitle: 'Depois' } as never,
    });

    const dto = toProcessEventDto(polluted);

    expect(dto.details).toEqual({});
    expect(JSON.stringify(dto)).not.toMatch(/previousTitle|newTitle|Antes|Depois/);
  });

  it('an event with no actor on record has a null actor, and the actor is reduced to id and display name', () => {
    expect(toProcessEventDto(event({ actor: null })).actor).toBeNull();

    const dto = toProcessEventDto(
      event({ actor: { ...ACTOR, email: 'ceo@example.test' } as never }),
    );
    expect(dto.actor).toEqual({ id: ACTOR.id, displayName: 'CEO Um' });
  });
});

describe('toProcessEventListDto', () => {
  it('has the items in the order given and a null cursor on the last page', () => {
    const dto = toProcessEventListDto({
      items: [event({ id: '1' }), event({ id: '2' })],
      next: null,
    });

    expect(Object.keys(dto).sort()).toEqual(['items', 'nextCursor']);
    expect(dto.items.map((item) => item.id)).toEqual(['1', '2']);
    expect(dto.nextCursor).toBeNull();
  });

  it('turns the position of a full page into an opaque cursor that decodes back to it', () => {
    const dto = toProcessEventListDto({ items: [event({ id: '7' })], next: { id: '7' } });

    expect(typeof dto.nextCursor).toBe('string');
    expect(dto.nextCursor).not.toBe('7');
    expect(decodeProcessEventCursor(dto.nextCursor ?? '')).toEqual({
      ok: true,
      value: { id: '7' },
    });
  });
});
