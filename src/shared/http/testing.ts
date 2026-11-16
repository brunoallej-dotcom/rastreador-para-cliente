// Test kit for code built on `withRoute`: fixtures, a capturing logger and a pipeline wired to
// fakes. Imported only by tests; nothing in production code depends on it.
import { NextRequest } from 'next/server';
import type { Principal } from '@/shared/kernel';
import { createLogger, type Logger, type LogLevel } from '@/shared/observability/logger';
import {
  createFakePrincipalResolver,
  type FakePrincipalResolver,
  type FakePrincipalSource,
} from './fake-principal-resolver';
import { createInMemoryRateLimiter } from './rate-limit/in-memory-rate-limiter';
import type { RateLimiter, RateLimitRule } from './rate-limit/rate-limiter';
import type { PipelineDeps } from './pipeline-deps';
import { createWithRoute } from './with-route';
import type { WithRoute } from './route-policy';

export const TEST_APP_ORIGIN = 'http://localhost:3000';
export const TEST_API_BASE = `${TEST_APP_ORIGIN}/api/v1`;

/** Generous rules for tests that are not about rate limiting (every route needs at least one). */
export const TEST_IP_RULE = {
  scope: 'ip',
  group: 'reads',
  limit: 10_000,
  windowSeconds: 60,
} as const satisfies RateLimitRule;
export const TEST_USER_RULE = {
  scope: 'user',
  group: 'reads',
  limit: 10_000,
  windowSeconds: 60,
} as const satisfies RateLimitRule;

/** `{ access: 'public' }` plus the mandatory rate limit. Spread it and add what a test needs. */
export const PUBLIC_POLICY = { access: 'public', rateLimit: [TEST_IP_RULE] } as const;
/** A CEO-only authenticated route with no pending action allowed, plus the mandatory rate limit. */
export const CEO_POLICY = {
  access: 'authenticated',
  roles: ['ceo'],
  allowPending: [],
  rateLimit: [TEST_USER_RULE],
} as const;

export function principalFixture(overrides: Partial<Principal> = {}): Principal {
  return {
    userId: '11111111-1111-4111-8111-111111111111',
    role: 'ceo',
    clientId: null,
    displayName: 'Test CEO',
    aal: 'aal2',
    pendingActions: [],
    ...overrides,
  };
}

export type CapturedLogs = {
  readonly logger: Logger;
  readonly lines: string[];
  records(): Record<string, unknown>[];
  /** Records whose `event` field equals `name`. */
  events(name: string): Record<string, unknown>[];
};

export function createCapturingLogger(level: LogLevel = 'trace'): CapturedLogs {
  const lines: string[] = [];
  const logger = createLogger({
    level,
    destination: {
      write(chunk: string) {
        lines.push(chunk);
      },
    },
  });
  const records = () => lines.map((line) => JSON.parse(line) as Record<string, unknown>);
  return {
    logger,
    lines,
    records,
    events: (name) => records().filter((record) => record['event'] === name),
  };
}

export type TestPipelineOptions = {
  readonly principal?: FakePrincipalSource;
  readonly rateLimiter?: RateLimiter;
  readonly allowedOrigins?: readonly string[];
  /** Production behavior: refuse (503) requests that arrive without a client IP. Default false. */
  readonly requireClientIp?: boolean;
};

export type TestPipeline = {
  readonly withRoute: WithRoute;
  readonly principalResolver: FakePrincipalResolver;
  readonly rateLimiter: RateLimiter;
  readonly logs: CapturedLogs;
};

/** A `withRoute` bound to fakes: in-memory limiter, fake resolver and a capturing logger. */
export function createTestPipeline(options: TestPipelineOptions = {}): TestPipeline {
  const logs = createCapturingLogger();
  const principalResolver = createFakePrincipalResolver(options.principal ?? null);
  const rateLimiter = options.rateLimiter ?? createInMemoryRateLimiter();
  const deps: PipelineDeps = {
    rateLimiter,
    principalResolver,
    allowedOrigins: options.allowedOrigins ?? [TEST_APP_ORIGIN],
    requireClientIp: options.requireClientIp ?? false,
    logger: logs.logger,
  };
  return { withRoute: createWithRoute(() => deps), principalResolver, rateLimiter, logs };
}

export type ApiRequestInit = {
  readonly method?: string;
  readonly headers?: Record<string, string>;
  /** JSON body; sets `Content-Type: application/json`. */
  readonly json?: unknown;
  /** Raw body (string or stream), sent exactly as given. */
  readonly body?: string | ReadableStream<Uint8Array>;
  /** `Origin` header of unsafe requests. Default: the allowed origin. `null` omits the header. */
  readonly origin?: string | null;
};

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/** `NextRequest` for a path under `/api/v1`, with a valid `Origin` on unsafe methods by default. */
export function apiRequest(path: string, init: ApiRequestInit = {}): NextRequest {
  const method = init.method ?? 'GET';
  const headers = new Headers(init.headers);
  const origin = init.origin === undefined ? TEST_APP_ORIGIN : init.origin;
  if (UNSAFE_METHODS.has(method) && origin !== null) headers.set('Origin', origin);

  let body: string | ReadableStream<Uint8Array> | undefined = init.body;
  if (init.json !== undefined) {
    body = JSON.stringify(init.json);
    if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  }

  return new NextRequest(`${TEST_API_BASE}${path}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body, duplex: 'half' }),
  });
}
