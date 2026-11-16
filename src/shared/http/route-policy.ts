import type { NextRequest } from 'next/server';
import type { z } from 'zod';
import type { DomainError, PendingAction, Principal, Role } from '@/shared/kernel';
import type { Logger } from '@/shared/observability/logger';
import type { CookieJar } from './cookies';
import type { RateLimitRule } from './rate-limit/rate-limiter';
import type { InputSchema } from './validation';

/** Output type of an optional schema; `undefined` when the policy declares none. */
export type Parsed<S> = S extends z.ZodType ? z.output<S> : undefined;

type SchemaFields<Pa, Q, B> = {
  /** Path params. `.strict()` object whose limits equal the contract's. */
  readonly params?: Pa;
  /** Query string. `.strict()` object (see `pageQuerySchema` for paginated lists). */
  readonly query?: Q;
  /** JSON body. `.strict()` object: unknown fields → 400 (mass-assignment defense). */
  readonly body?: B;
};

/**
 * Rate limits of the route: REQUIRED and non-empty, because the contract declares `x-rate-limit`
 * on every operation and a route without one would be unlimited. Each rule is equal to the
 * contract's `x-rate-limit` entry and names its counter group (`RATE_LIMIT_GROUPS`, spec §3.9).
 * `ip` rules run before authentication, `user` rules right after it, `account` rules only on
 * public routes and only after the body is validated (see `accountKey`). A public route needs at
 * least one `ip` rule (checked when the route is defined).
 */
type RateLimited = { readonly rateLimit: readonly [RateLimitRule, ...RateLimitRule[]] };

export type PublicPolicy<Pa, Q, B> = SchemaFields<Pa, Q, B> &
  RateLimited & {
    readonly access: 'public';
    /**
     * Subject of the `account` rate-limit rules, derived from the VALIDATED body (login: the
     * normalized e-mail). It runs after validation on purpose: the key must come from the parsed,
     * normalized value (so `A@x.com` and `a@x.com` share a bucket) and a malformed body must not
     * spend the budget of an account. Required when any rule has scope `account`.
     */
    readonly accountKey?: (body: Parsed<B>) => string;
  };

export type AuthenticatedPolicy<Pa, Q, B> = SchemaFields<Pa, Q, B> &
  RateLimited & {
    readonly access: 'authenticated';
    /** Accepted roles (non-empty). Equal to `x-auth-policy.roles`. */
    readonly roles: readonly [Role, ...Role[]];
    /** Pending actions the route stays reachable with. Equal to `x-auth-policy.allowPending`. */
    readonly allowPending: readonly PendingAction[];
  };

/**
 * The policy as the pipeline reads it at runtime (the typed `PublicPolicy | AuthenticatedPolicy`
 * erased of its schema generics). There is no default policy: `{ access: 'public' }` must be
 * written, and `withRoute` does not compile without a policy.
 */
export type RuntimePolicy = {
  readonly access: 'public' | 'authenticated';
  readonly roles?: readonly Role[];
  readonly allowPending?: readonly PendingAction[];
  readonly rateLimit?: readonly RateLimitRule[];
  readonly params?: InputSchema | undefined;
  readonly query?: InputSchema | undefined;
  readonly body?: InputSchema | undefined;
  readonly accountKey?: (body: never) => string;
};

/** What a handler receives. No dependency container: handlers build their own dependencies. */
export type HandlerContext<Pr extends Principal | null, Pa, Q, B> = {
  readonly request: NextRequest;
  readonly requestId: string;
  /** `null` on public routes; never `null` on authenticated ones. */
  readonly principal: Pr;
  readonly params: Parsed<Pa>;
  readonly query: Parsed<Q>;
  readonly body: Parsed<B>;
  /** Session cookies. Writes are applied to the final response, including error responses. */
  readonly cookies: CookieJar;
  /** Child logger that already carries the `requestId`. */
  readonly logger: Logger;
};

/** A response, or a `DomainError` to be turned into problem+json (returned or thrown). */
export type HandlerOutput = Response | DomainError;

export type RouteHandlerFn<Context> = (context: Context) => HandlerOutput | Promise<HandlerOutput>;

export type RouteParams = Record<string, string | string[] | undefined>;

/**
 * The second argument Next 16 passes to a route handler. `params` resolves to `undefined` (not
 * `{}`) on routes without dynamic segments; the pipeline normalizes it.
 */
export type NextRouteContext = { readonly params: Promise<RouteParams | undefined> };

/** What `withRoute` returns: a Next 16 route handler, callable directly in tests. */
export type NextRouteHandler = (
  request: NextRequest,
  context?: NextRouteContext,
) => Promise<Response>;

type SchemaParam = InputSchema | undefined;

/** Signature of `withRoute`: one overload per access mode, so `principal` is typed accordingly. */
export type WithRoute = {
  <
    Pa extends SchemaParam = undefined,
    Q extends SchemaParam = undefined,
    B extends SchemaParam = undefined,
  >(
    policy: PublicPolicy<Pa, Q, B>,
    handler: RouteHandlerFn<HandlerContext<null, Pa, Q, B>>,
  ): NextRouteHandler;
  <
    Pa extends SchemaParam = undefined,
    Q extends SchemaParam = undefined,
    B extends SchemaParam = undefined,
  >(
    policy: AuthenticatedPolicy<Pa, Q, B>,
    handler: RouteHandlerFn<HandlerContext<Principal, Pa, Q, B>>,
  ): NextRouteHandler;
};
