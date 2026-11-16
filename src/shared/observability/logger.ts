import pino, { type DestinationStream, type Logger, type LoggerOptions } from 'pino';
import { getEnv } from '@/shared/config/env';
import { sanitizeLogObject, scrubLogArguments } from './redaction';

export type { Logger };

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error';

export type LoggerConfig = {
  readonly level?: LogLevel;
  /** Defaults to stdout. Tests inject a writable to capture the JSON lines. */
  readonly destination?: DestinationStream;
};

/**
 * pino's default `err` serializer re-labels anything error-like and copies its enumerable
 * properties. Errors are already reduced to a safe shape by `formatters.log` (which runs before
 * serializers), so the serializers must leave them alone.
 */
const passthrough = (value: unknown) => value;

/**
 * JSON logger: one object per line, to stdout, with no transports or worker threads (Vercel
 * captures stdout). Everything it writes goes through `redaction.ts`: sensitive keys at any
 * depth, case- and separator-insensitive; e-mails and tokens cut out of every string, error
 * messages and `cause` chains included; bounded depth; cycle-safe.
 */
export function createLogger({ level = 'info', destination }: LoggerConfig = {}): Logger {
  const options: LoggerOptions = {
    level,
    base: null,
    timestamp: pino.stdTimeFunctions.isoTime,
    serializers: { err: passthrough, error: passthrough },
    formatters: {
      level: (label) => ({ level: label }),
      log: (object) => sanitizeLogObject(object),
    },
    hooks: {
      logMethod(args, method) {
        method.apply(this, scrubLogArguments(args) as Parameters<typeof method>);
      },
    },
  };
  const logger = destination === undefined ? pino(options) : pino(options, destination);

  // pino resets `formatters.bindings` inside `child()` before it reads the bindings, so child
  // bindings would skip the scrubbing. Children (and their children, which inherit this method)
  // go through it explicitly.
  // eslint-disable-next-line @typescript-eslint/unbound-method -- always re-bound with .call(this)
  const originalChild = logger.child;
  logger.child = function child(this: Logger, bindings, childOptions) {
    return originalChild.call(this, sanitizeLogObject({ ...bindings }), childOptions);
  } as Logger['child'];
  return logger;
}

let cached: Logger | undefined;

/** Process-wide logger, level from `LOG_LEVEL`. Lazy: `next build` runs without env. */
export function getLogger(): Logger {
  cached ??= createLogger({ level: getEnv().LOG_LEVEL });
  return cached;
}

let fallback: Logger | undefined;

/**
 * Logger for the moment before the real one can be built (invalid env). Created once, at `error`
 * level, and independent of the environment.
 */
export function getFallbackLogger(): Logger {
  fallback ??= createLogger({ level: 'error' });
  return fallback;
}

/** Child logger that stamps `requestId` on every line of one request. */
export function requestLogger(parent: Logger, requestId: string): Logger {
  return parent.child({ requestId });
}
