import { DomainError, type DomainErrorOptions } from '@/shared/kernel';

/**
 * The stage the caller wanted to approve is no longer the current one (I6, E-01, E-02). 409
 * `STALE_STAGE` carrying `currentStageId`, the stage that is current now (`null` when the process
 * has none). The id belongs to the process the caller was already allowed to read, so the response
 * reveals nothing new.
 */
export class StaleStageError extends DomainError {
  readonly code = 'STALE_STAGE';

  constructor(currentStageId: string | null, options?: DomainErrorOptions) {
    super('the stage is no longer the current one', {
      detail: 'The stage is no longer the current one of the process.',
      extensions: { currentStageId },
      ...options,
    });
  }
}

/**
 * The process is `completed` or `cancelled`, and neither accepts a change or an approval (I3, I4,
 * E-03, AC-19). 422 `PROCESS_NOT_ACTIVE`.
 */
export class ProcessNotActiveError extends DomainError {
  readonly code = 'PROCESS_NOT_ACTIVE';

  constructor(options?: DomainErrorOptions) {
    super('the process is not active', {
      detail: 'Only an active process accepts this change.',
      ...options,
    });
  }
}

/**
 * The client is archived, so it takes no new process (E-16) and its processes are frozen: no
 * approval, no rename, no cancellation (F-87, Q-13, E-99). Reading them is still fine (E-83), and
 * unarchiving the client thaws them. 422 `CLIENT_ARCHIVED`. The detail is the same for the four
 * operations, because it says what the CEO has to do (unarchive), not which operation was refused.
 */
export class ClientArchivedError extends DomainError {
  readonly code = 'CLIENT_ARCHIVED';

  constructor(options?: DomainErrorOptions) {
    super('the client is archived', {
      detail: 'The client is archived. Unarchive it to create or change its processes.',
      ...options,
    });
  }
}
