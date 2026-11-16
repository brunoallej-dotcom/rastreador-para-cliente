import { describe, expect, it } from 'vitest';
import { ConflictError, DomainError, ValidationError, type ErrorCode } from '@/shared/kernel';
import { createCapturingLogger } from './testing';
import { errorToResponse } from './error-mapping';
import { PipelineError } from './pipeline-errors';
import { problemBody, problemResponse, RESERVED_PROBLEM_MEMBERS } from './problem';

const REQUEST_ID = 'req-12345678';

/** A domain error with any code, the way later waves will define theirs. */
class CodedError extends DomainError {
  constructor(
    readonly code: ErrorCode,
    options?: ConstructorParameters<typeof ConflictError>[1],
  ) {
    super('coded', options);
  }
}

async function bodyOf(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

describe('problem extensions cannot set reserved members', () => {
  it('the reserved members are exactly the standard ones of the contract', () => {
    expect([...RESERVED_PROBLEM_MEMBERS].sort()).toEqual(
      ['code', 'detail', 'errors', 'requestId', 'status', 'title', 'type'].sort(),
    );
  });

  it.each([...RESERVED_PROBLEM_MEMBERS])(
    'an extension named %s is dropped, whether or not the error sets that member itself',
    (member) => {
      const forged = { [member]: 'forged', currentStageId: 'stage-1' };
      // an error that sets nothing else: detail and errors are absent from the real body
      const bare = problemBody({ code: 'CONFLICT', requestId: REQUEST_ID, extensions: forged });
      expect(bare['currentStageId']).toBe('stage-1');
      expect(bare[member]).not.toBe('forged');
      expect(bare).toMatchObject({
        type: 'about:blank',
        status: 409,
        code: 'CONFLICT',
        requestId: REQUEST_ID,
      });
      if (member === 'detail' || member === 'errors') expect(bare).not.toHaveProperty(member);

      // an error that does set detail and errors itself
      const full = problemBody({
        code: 'VALIDATION_ERROR',
        requestId: REQUEST_ID,
        detail: 'real detail',
        errors: [{ path: 'body.a', message: 'real' }],
        extensions: forged,
      });
      expect(full['detail']).toBe('real detail');
      expect(full['errors']).toEqual([{ path: 'body.a', message: 'real' }]);
      expect(full['code']).toBe('VALIDATION_ERROR');
      expect(full['status']).toBe(400);
    },
  );

  it('keeps non-reserved extensions, and a __proto__ extension stays plain data', () => {
    const extensions = JSON.parse('{"__proto__":{"admin":true},"currentStageId":"s"}') as Record<
      string,
      string
    >;
    const body = problemBody({ code: 'CONFLICT', requestId: REQUEST_ID, extensions });
    expect(body['currentStageId']).toBe('s');
    expect(Object.getPrototypeOf(body)).toBe(Object.prototype);
    expect(({} as Record<string, unknown>)['admin']).toBeUndefined();
  });

  it('holds through the whole error mapping, for a thrown DomainError', async () => {
    const { logger } = createCapturingLogger();
    const error = new ConflictError('stale', {
      extensions: { detail: 'forged detail', errors: 'forged', status: 200, code: 'FORBIDDEN' },
    });
    const body = await bodyOf(errorToResponse(error, REQUEST_ID, logger));
    expect(body).not.toHaveProperty('detail');
    expect(body).not.toHaveProperty('errors');
    expect(body).toMatchObject({ status: 409, code: 'CONFLICT', requestId: REQUEST_ID });
  });
});

describe('problems always carry what the contract requires of their code', () => {
  const { logger } = createCapturingLogger();

  it('a 400 VALIDATION_ERROR always carries errors (an empty list when there is nothing to list)', async () => {
    const empty = await bodyOf(errorToResponse(new ValidationError('x'), REQUEST_ID, logger));
    expect(empty['errors']).toEqual([]);
    const direct = problemBody({ code: 'VALIDATION_ERROR', requestId: REQUEST_ID });
    expect(direct['errors']).toEqual([]);
    const withIssues = await bodyOf(
      errorToResponse(
        new ValidationError('x', [{ path: 'body.a', message: 'bad' }]),
        REQUEST_ID,
        logger,
      ),
    );
    expect(withIssues['errors']).toEqual([{ path: 'body.a', message: 'bad' }]);
  });

  it('a VALIDATION_ERROR from any DomainError class, not only ValidationError, still has errors', async () => {
    const body = await bodyOf(
      errorToResponse(new CodedError('VALIDATION_ERROR'), REQUEST_ID, logger),
    );
    expect(body['errors']).toEqual([]);
  });

  it('other codes do not get an errors member', () => {
    expect(problemBody({ code: 'NOT_FOUND', requestId: REQUEST_ID })).not.toHaveProperty('errors');
  });

  it('a 429 always carries Retry-After, with the real value when the limiter knows it', () => {
    const fallback = problemResponse({ code: 'RATE_LIMITED', requestId: REQUEST_ID });
    expect(fallback.status).toBe(429);
    expect(Number(fallback.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);

    const precise = problemResponse({
      code: 'RATE_LIMITED',
      requestId: REQUEST_ID,
      headers: { 'Retry-After': '17' },
    });
    expect(precise.headers.get('retry-after')).toBe('17');
  });

  it('a RATE_LIMITED from any DomainError class (not RateLimitedError) still has Retry-After', () => {
    const response = errorToResponse(new CodedError('RATE_LIMITED'), REQUEST_ID, logger);
    expect(response.status).toBe(429);
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
  });

  it('a 503 always carries Retry-After', () => {
    const response = errorToResponse(new CodedError('SERVICE_UNAVAILABLE'), REQUEST_ID, logger);
    expect(response.status).toBe(503);
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
  });

  it('other statuses carry no Retry-After', () => {
    expect(
      problemResponse({ code: 'NOT_FOUND', requestId: REQUEST_ID }).headers.get('retry-after'),
    ).toBeNull();
  });

  it('a 409 STALE_STAGE always carries currentStageId (null when the error gave none)', async () => {
    const without = await bodyOf(
      errorToResponse(new CodedError('STALE_STAGE'), REQUEST_ID, logger),
    );
    expect(without['currentStageId']).toBeNull();
    const withId = await bodyOf(
      errorToResponse(
        new CodedError('STALE_STAGE', {
          extensions: { currentStageId: '6f1d5a3e-3b0c-4f43-9a55-0d3f6f6f1a11' },
        }),
        REQUEST_ID,
        logger,
      ),
    );
    expect(withId['currentStageId']).toBe('6f1d5a3e-3b0c-4f43-9a55-0d3f6f6f1a11');
  });
});

describe('PipelineError cannot carry the codes that need a dedicated class', () => {
  it('does not compile with VALIDATION_ERROR, RATE_LIMITED or STALE_STAGE', () => {
    void (() => {
      // @ts-expect-error VALIDATION_ERROR needs errors[]: use ValidationError
      new PipelineError('VALIDATION_ERROR', 'x');
      // @ts-expect-error RATE_LIMITED needs Retry-After: use RateLimitedError
      new PipelineError('RATE_LIMITED', 'x');
      // @ts-expect-error STALE_STAGE needs currentStageId: raised by the tracking module
      new PipelineError('STALE_STAGE', 'x');
    });
    expect(new PipelineError('UNSUPPORTED_MEDIA_TYPE', 'x').code).toBe('UNSUPPORTED_MEDIA_TYPE');
  });
});
