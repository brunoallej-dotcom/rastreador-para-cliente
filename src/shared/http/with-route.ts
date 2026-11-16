import type { NextRequest } from 'next/server';
import {
  DomainError,
  ServiceUnavailableError,
  UnauthenticatedError,
  type Principal,
} from '@/shared/kernel';
import { getFallbackLogger, requestLogger, type Logger } from '@/shared/observability/logger';
import { assertAuthorized } from './authorization';
import { readJsonBody, type RequestBody } from './body';
import { clientIp, UNKNOWN_IP } from './client-ip';
import { createCookieJar, type ManagedCookieJar } from './cookies';
import { errorToResponse } from './error-mapping';
import { assertOriginAllowed, isUnsafeMethod } from './origin';
import { AuthorizationDeniedError } from './pipeline-errors';
import { getPipelineDeps, type PipelineDeps } from './pipeline-deps';
import { assertValidPolicy } from './policy-guard';
import { problemResponse } from './problem';
import { enforceRateLimits } from './rate-limit/enforce';
import { REQUEST_ID_HEADER, resolveRequestId } from './request-id';
import type {
  HandlerContext,
  NextRouteContext,
  NextRouteHandler,
  RouteHandlerFn,
  RouteParams,
  RuntimePolicy,
  WithRoute,
} from './route-policy';
import { routeTemplate } from './route-template';
import { withSecurityHeaders } from './security-headers';
import { queryToObject, validateInput } from './validation';

type RuntimeContext = HandlerContext<
  Principal | null,
  RuntimePolicy['body'],
  RuntimePolicy['body'],
  RuntimePolicy['body']
>;
type RuntimeHandler = RouteHandlerFn<RuntimeContext>;

/** What the access log and the `authz.denied` event need to know after a failure. */
type RequestState = { principal: Principal | null };

type PipelineInput = {
  readonly policy: RuntimePolicy;
  readonly handler: RuntimeHandler;
  readonly deps: PipelineDeps;
  readonly request: NextRequest;
  readonly requestId: string;
  readonly rawParams: RouteParams;
  readonly cookies: ManagedCookieJar;
  readonly logger: Logger;
  readonly state: RequestState;
};

/**
 * Steps 2 to 8 of the pipeline (spec §3.3), in the fixed order of SEC-02. Every denial is a throw,
 * and nothing after a failing step runs, so a security step that fails or throws can never let the
 * request reach the handler (fail closed). The caller turns the throw into a problem response.
 */
async function runPipeline(input: PipelineInput): Promise<Response> {
  const { policy, deps, request, requestId, rawParams, cookies, logger, state } = input;

  // 2. CSRF: unsafe methods need an allowed Origin.
  if (isUnsafeMethod(request.method)) assertOriginAllowed(request, deps.allowedOrigins);

  // 3. Body transport checks: size (while streaming), Content-Type, JSON syntax. A route without a
  // body schema ignores the body entirely: it is not read, so it cannot cause 400, 413 or 415
  // (the contract documents none of them for such operations).
  const body: RequestBody =
    policy.body === undefined ? { kind: 'empty' } : await readJsonBody(request);

  // 4. Rate limit by IP, before authentication: it also protects the authentication backend.
  const rules = policy.rateLimit ?? [];
  if (rules.some((rule) => rule.scope === 'ip')) {
    await enforceRateLimits({
      limiter: deps.rateLimiter,
      rules,
      scope: 'ip',
      subject: ipRuleSubject(request, deps),
      logger,
    });
  }

  // 5. Authentication, then the per-user rate limit and 6. authorization.
  if (policy.access === 'authenticated') {
    const principal = await deps.principalResolver.resolve({ request, cookies, requestId });
    if (principal === null) {
      throw new UnauthenticatedError('no valid session', { detail: 'Authentication required.' });
    }
    state.principal = principal;
    await enforceRateLimits({
      limiter: deps.rateLimiter,
      rules,
      scope: 'user',
      subject: principal.userId,
      logger,
    });
    assertAuthorized(principal, {
      roles: policy.roles ?? [],
      allowPending: policy.allowPending ?? [],
    });
  }

  // 7. Validation of params, query and body.
  if (policy.params === undefined && Object.keys(rawParams).length > 0) {
    throw new Error('route has path params but its policy declares no "params" schema');
  }
  const parsed = validateInput(policy, {
    params: rawParams,
    query: queryToObject(request.nextUrl.searchParams),
    body: body.kind === 'json' ? body.value : undefined,
  });

  // Rate limit by account (public routes): after validation, so the key comes from the parsed,
  // normalized body and a malformed body does not spend an account's budget.
  if (policy.access === 'public' && policy.accountKey !== undefined) {
    const accountKey = policy.accountKey as (body: unknown) => string;
    await enforceRateLimits({
      limiter: deps.rateLimiter,
      rules,
      scope: 'account',
      subject: accountKey(parsed.body),
      logger,
    });
  }

  // 8. The use case.
  const output = await input.handler({
    request,
    requestId,
    principal: state.principal,
    params: parsed.params as RuntimeContext['params'],
    query: parsed.query as RuntimeContext['query'],
    body: parsed.body as RuntimeContext['body'],
    cookies,
    logger,
  });
  if (output instanceof DomainError) throw output;
  if (!(output instanceof Response)) {
    throw new TypeError('route handler returned neither a Response nor a DomainError');
  }
  // Cookies go through the jar, which forces HttpOnly/Secure/SameSite=Lax/Path=/. A Set-Cookie
  // written straight on the Response would bypass that, so it is a programming error: fail closed
  // (500, logged with its stack) rather than let a cookie with weaker flags reach the client.
  if (output.headers.has('set-cookie')) {
    throw new Error(
      'route handler set a cookie on the Response; use the cookies jar of the context',
    );
  }
  return output;
}

/**
 * Subject of the `ip` rate-limit rules. Without an IP from the platform helper the request falls
 * into the shared `unknown` bucket in dev and tests, but in production it is refused (503): there
 * every request must come through Vercel's proxy, so a missing IP is a platform fault, and a shared
 * bucket would let one noisy client lock everyone out.
 */
function ipRuleSubject(request: Request, deps: PipelineDeps): string {
  const ip = clientIp(request);
  if (ip !== undefined) return ip;
  if (deps.requireClientIp) {
    throw new ServiceUnavailableError('the platform provided no client IP');
  }
  return UNKNOWN_IP;
}

/** Next resolves `params` to `undefined` (not `{}`) on routes without dynamic segments. */
async function resolveParams(context: NextRouteContext | undefined): Promise<RouteParams> {
  if (context === undefined) return {};
  return (await context.params) ?? {};
}

/**
 * Response for anything that failed in the pipeline or the handler, plus the `authz.denied` event
 * for access denials. If even this fails (e.g. the logger throws), the answer is a bare 500: a
 * failing logger must not turn a denial into a crash or, worse, into an allowance.
 */
function failureResponse(
  error: unknown,
  requestId: string,
  logger: Logger,
  state: RequestState,
): Response {
  if (error instanceof AuthorizationDeniedError) {
    try {
      logger.warn(
        {
          event: 'authz.denied',
          reason: error.reason,
          userId: state.principal?.userId,
          role: state.principal?.role,
        },
        'authz.denied',
      );
    } catch {
      // the denial itself must still be answered with its own status
    }
  }
  try {
    return errorToResponse(error, requestId, logger);
  } catch {
    return problemResponse({ code: 'INTERNAL_ERROR', requestId });
  }
}

/** The access log line. Logging must never break a response, so a failure here is swallowed. */
function logAccess(
  logger: Logger,
  request: NextRequest,
  rawParams: RouteParams,
  final: Response,
  state: RequestState,
  startedAt: number,
): void {
  try {
    logger.info(
      {
        route: routeTemplate(request.nextUrl.pathname, rawParams),
        method: request.method,
        status: final.status,
        durationMs: Math.round(performance.now() - startedAt),
        userId: state.principal?.userId,
        role: state.principal?.role,
      },
      'request completed',
    );
  } catch {
    // nothing sensible to do: the logger itself is what failed
  }
}

/**
 * Last step: security headers and `X-Request-Id` on EVERY response, plus the cookies the request
 * wrote. If even that fails, a bare 500 with the same headers is returned.
 */
function finalize(response: Response, requestId: string, cookies: ManagedCookieJar): Response {
  try {
    const final = withSecurityHeaders(response, requestId);
    cookies.applyTo(final.headers);
    return final;
  } catch {
    return withSecurityHeaders(problemResponse({ code: 'INTERNAL_ERROR', requestId }), requestId);
  }
}

/**
 * What the request needs before the pipeline can run. Building it can fail (invalid env, a broken
 * cookie header); that is a fail-closed 500 with the SEC-14 headers, like any other failure.
 */
type RequestSetup = {
  readonly cookies: ManagedCookieJar;
  readonly deps: PipelineDeps;
  readonly logger: Logger;
};

function bareFailure(requestId: string, cause: unknown): Response {
  try {
    getFallbackLogger().error({ requestId, err: cause }, 'request setup failed');
  } catch {
    // nothing sensible to do: the logger itself is what failed
  }
  return withSecurityHeaders(problemResponse({ code: 'INTERNAL_ERROR', requestId }), requestId);
}

/**
 * Builds `withRoute` bound to a source of platform dependencies. The production `withRoute`
 * below is bound to `pipeline-deps.ts`; unit tests bind their own fakes. No global state: every
 * call to `createWithRoute` yields an independent `withRoute`.
 */
export function createWithRoute(getDeps: () => PipelineDeps): WithRoute {
  function withRoute(policy: RuntimePolicy, handler: RuntimeHandler): NextRouteHandler {
    assertValidPolicy(policy);

    return async (request, context) => {
      const startedAt = performance.now();
      const requestId = resolveRequestId(request.headers.get(REQUEST_ID_HEADER));

      let setup: RequestSetup;
      try {
        const deps = getDeps();
        setup = {
          cookies: createCookieJar(request.cookies.getAll()),
          deps,
          logger: requestLogger(deps.logger, requestId),
        };
      } catch (cause) {
        return bareFailure(requestId, cause);
      }
      const { cookies, deps, logger } = setup;

      const state: RequestState = { principal: null };
      let rawParams: RouteParams = {};
      let response: Response;

      try {
        rawParams = await resolveParams(context);
        response = await runPipeline({
          policy,
          handler,
          deps,
          request,
          requestId,
          rawParams,
          cookies,
          logger,
          state,
        });
      } catch (error) {
        response = failureResponse(error, requestId, logger, state);
      }

      const final = finalize(response, requestId, cookies);
      logAccess(logger, request, rawParams, final, state, startedAt);
      return final;
    };
  }

  // The overloads of `WithRoute` give handlers a typed `principal` and parsed input; at runtime
  // there is a single implementation.
  return withRoute as WithRoute;
}

/**
 * The route wrapper every handler uses: `withRoute(policy, handler)`.
 *
 * `policy` is mandatory and has no default (`{ access: 'public' }` must be explicit). It is the
 * only runtime place that reads the platform dependencies, through `pipeline-deps.ts`.
 */
export const withRoute: WithRoute = createWithRoute(getPipelineDeps);
