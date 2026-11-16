import type { ProcessEvent, ProcessEventDetails, ProcessEventPage } from '../domain/process-event';
import { encodeProcessEventCursor } from './process-events.cursor';

/** `ProcessEventDetails` of the contract: only the members that apply, none of them a title. */
export type ProcessEventDetailsDto = {
  readonly stageId?: string;
  readonly stagePosition?: number;
  readonly stageName?: string;
};

/** `ProcessEvent` of the contract. */
export type ProcessEventDto = {
  readonly id: string;
  readonly occurredAt: string;
  readonly action: ProcessEvent['action'];
  readonly actor: { readonly id: string; readonly displayName: string } | null;
  readonly details: ProcessEventDetailsDto;
};

/** `ProcessEventList` of the contract. */
export type ProcessEventListDto = {
  readonly items: readonly ProcessEventDto[];
  readonly nextCursor: string | null;
};

/** Explicit members, nothing spread: a field added to the domain never reaches the response by accident. */
function toDetailsDto(details: ProcessEventDetails): ProcessEventDetailsDto {
  return {
    ...(details.stageId === undefined ? {} : { stageId: details.stageId }),
    ...(details.stagePosition === undefined ? {} : { stagePosition: details.stagePosition }),
    ...(details.stageName === undefined ? {} : { stageName: details.stageName }),
  };
}

export function toProcessEventDto(event: ProcessEvent): ProcessEventDto {
  return {
    id: event.id,
    occurredAt: event.occurredAt.toISOString(),
    action: event.action,
    actor:
      event.actor === null ? null : { id: event.actor.id, displayName: event.actor.displayName },
    details: toDetailsDto(event.details),
  };
}

export function toProcessEventListDto(page: ProcessEventPage): ProcessEventListDto {
  return {
    items: page.items.map(toProcessEventDto),
    nextCursor: page.next === null ? null : encodeProcessEventCursor(page.next),
  };
}
