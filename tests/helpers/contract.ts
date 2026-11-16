// Validates response bodies against contracts/openapi.v1.yaml (the source of truth of the API).
//
//   expectToMatchContract('getHealth', 200, body)
//   expectToMatchContract('createClient', 429, problemBody)   // $ref to components.responses
//   expectToMatchContract('logout', 204, undefined)           // no body documented
//
// Ajv 2020 + ajv-formats, because OpenAPI 3.1 schemas are JSON Schema 2020-12. Unknown operations
// and statuses that the contract does not document FAIL: a response the contract does not describe
// is a contract violation, not a pass. `additionalProperties: false` in the contract is enforced.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import Ajv2020, { type ValidateFunction } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { parse } from 'yaml';
import { expect } from 'vitest';

const CONTRACT_PATH = fileURLToPath(new URL('../../contracts/openapi.v1.yaml', import.meta.url));
const MAX_REF_DEPTH = 10;
const MAX_BODY_PREVIEW_CHARS = 600;
/** Media types a response may use, in order of preference. */
const JSON_MEDIA_TYPES = ['application/json', 'application/problem+json'] as const;
const HTTP_METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'] as const;
const LOCAL_RESPONSE_REF = /^#\/components\/responses\/([A-Za-z0-9_.-]+)$/;
const LOCAL_HEADER_REF = /^#\/components\/headers\/([A-Za-z0-9_.-]+)$/;

type JsonObject = Record<string, unknown>;
type MediaType = (typeof JSON_MEDIA_TYPES)[number];

type Contract = {
  readonly paths: Readonly<Record<string, JsonObject>>;
  readonly components: JsonObject & { readonly responses?: Readonly<Record<string, JsonObject>> };
};

type OperationEntry = {
  readonly operationId: string;
  readonly method: string;
  readonly path: string;
  readonly responses: Readonly<Record<string, JsonObject>>;
};

type LoadedContract = {
  readonly contract: Contract;
  readonly operations: ReadonlyMap<string, OperationEntry>;
};

const isObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

let loaded: LoadedContract | undefined;

function loadContract(): LoadedContract {
  if (loaded !== undefined) return loaded;

  const document: unknown = parse(readFileSync(CONTRACT_PATH, 'utf8'));
  if (!isObject(document) || !isObject(document['paths']) || !isObject(document['components'])) {
    throw new Error(`${CONTRACT_PATH} is not an OpenAPI document (paths/components missing)`);
  }
  const contract = document as unknown as Contract;

  const operations = new Map<string, OperationEntry>();
  for (const [path, item] of Object.entries(contract.paths)) {
    for (const method of HTTP_METHODS) {
      const operation = item[method];
      if (!isObject(operation)) continue;
      const operationId = operation['operationId'];
      if (typeof operationId !== 'string') continue;
      if (operations.has(operationId)) throw new Error(`duplicate operationId "${operationId}"`);
      const responses = isObject(operation['responses']) ? operation['responses'] : {};
      operations.set(operationId, {
        operationId,
        method: method.toUpperCase(),
        path,
        responses: responses as Readonly<Record<string, JsonObject>>,
      });
    }
  }

  loaded = { contract, operations };
  return loaded;
}

/** Follows `$ref: '#/components/responses/<Name>'` (the only response refs the contract uses). */
function resolveResponse(contract: Contract, response: JsonObject, where: string): JsonObject {
  let current = response;
  for (let depth = 0; depth < MAX_REF_DEPTH; depth += 1) {
    const ref = current['$ref'];
    if (ref === undefined) return current;
    const name = typeof ref === 'string' ? LOCAL_RESPONSE_REF.exec(ref)?.[1] : undefined;
    const target = name === undefined ? undefined : contract.components.responses?.[name];
    if (target === undefined) {
      expect.fail(`${where}: cannot resolve response $ref ${JSON.stringify(ref)}`);
    }
    current = target;
  }
  return expect.fail(`${where}: response $ref chain is too deep (loop?)`);
}

const ajv = new Ajv2020({ allErrors: true, strict: true, strictTypes: false });
addFormats(ajv);
// The schema under test is compiled together with `components` so its `$ref: '#/components/…'`
// pointers resolve; Ajv has to be told that this extra keyword is deliberate.
ajv.addKeyword('components');

const validators = new Map<string, ValidateFunction>();

function validatorFor(cacheKey: string, schema: JsonObject, contract: Contract): ValidateFunction {
  const cached = validators.get(cacheKey);
  if (cached !== undefined) return cached;
  const compiled = ajv.compile({ ...schema, components: contract.components });
  validators.set(cacheKey, compiled);
  return compiled;
}

const preview = (body: unknown) => {
  const text = JSON.stringify(body) ?? String(body);
  return text.length > MAX_BODY_PREVIEW_CHARS ? `${text.slice(0, MAX_BODY_PREVIEW_CHARS)}…` : text;
};

/** Follows `$ref: '#/components/headers/<Name>'`. */
function resolveHeader(contract: Contract, header: JsonObject, where: string): JsonObject {
  const ref = header['$ref'];
  if (ref === undefined) return header;
  const name = typeof ref === 'string' ? LOCAL_HEADER_REF.exec(ref)?.[1] : undefined;
  const headers = contract.components['headers'];
  const target = name === undefined || !isObject(headers) ? undefined : headers[name];
  if (!isObject(target)) {
    return expect.fail(`${where}: cannot resolve header $ref ${JSON.stringify(ref)}`);
  }
  return target;
}

/** A header value the way its schema types it: integers and numbers arrive as text. */
function typedHeaderValue(value: string, schema: JsonObject): unknown {
  const type = schema['type'];
  if ((type === 'integer' || type === 'number') && /^-?\d+(\.\d+)?$/.test(value)) {
    return Number(value);
  }
  return value;
}

/**
 * Checks a real `Response` against what the contract declares for that status: the status itself,
 * the media type of the body, and every declared header (present, and valid against its schema:
 * the `X-Request-Id` pattern, `Retry-After` an integer of at least 1, `Set-Cookie` present...).
 * A declared header is required unless the contract says `required: false`.
 */
function expectResponseEnvelope(
  contract: Contract,
  operationId: string,
  status: number,
  declared: JsonObject,
  mediaType: MediaType | undefined,
  response: Response,
  where: string,
): void {
  if (response.status !== status) {
    return expect.fail(`${where}: the Response has status ${response.status}`);
  }

  if (mediaType !== undefined) {
    const actual = (response.headers.get('content-type') ?? '').split(';')[0]?.trim().toLowerCase();
    if (actual !== mediaType) {
      return expect.fail(
        `${where}: the contract documents Content-Type ${mediaType}, the Response has ${JSON.stringify(actual ?? '')}`,
      );
    }
  }

  const headers = isObject(declared['headers']) ? declared['headers'] : {};
  for (const [name, raw] of Object.entries(headers)) {
    if (!isObject(raw)) continue;
    const header = resolveHeader(contract, raw, `${where}, header ${name}`);
    const values =
      name.toLowerCase() === 'set-cookie'
        ? response.headers.getSetCookie()
        : [response.headers.get(name)].filter((value): value is string => value !== null);

    if (values.length === 0) {
      if (header['required'] === false) continue;
      return expect.fail(
        `${where}: the contract declares the header ${name}, the Response has none`,
      );
    }

    const schema = header['schema'];
    if (!isObject(schema)) continue;
    const validate = validatorFor(`${operationId}:${status}:header:${name}`, schema, contract);
    for (const value of values) {
      if (validate(typedHeaderValue(value, schema))) continue;
      const problems = ajv.errorsText(validate.errors, { separator: '; ', dataVar: name });
      return expect.fail(
        `${where}: header ${name} does not match the contract (${problems}); value: ${preview(value)}`,
      );
    }
  }
}

function expectBodyMatches(
  contract: Contract,
  operationId: string,
  status: number,
  content: JsonObject,
  mediaType: MediaType | undefined,
  body: unknown,
  where: string,
): void {
  if (mediaType === undefined) {
    if (Object.keys(content).length > 0) {
      return expect.fail(
        `${where}: the response only documents media types this helper cannot check`,
      );
    }
    if (body === undefined || body === null || body === '') return;
    return expect.fail(`${where}: the contract documents no response body, got ${preview(body)}`);
  }

  const mediaTypeObject = content[mediaType];
  const schema = isObject(mediaTypeObject) ? mediaTypeObject['schema'] : undefined;
  if (!isObject(schema)) {
    return expect.fail(`${where}: ${mediaType} has no schema in the contract`);
  }

  const validate = validatorFor(`${operationId}:${status}:${mediaType}`, schema, contract);
  if (validate(body)) return;

  const problems = ajv.errorsText(validate.errors, { separator: '\n  - ', dataVar: 'body' });
  return expect.fail(
    `${where}: body does not match the ${mediaType} schema\n  - ${problems}\n  body: ${preview(body)}`,
  );
}

/**
 * Fails the test unless `body` (already parsed) is a valid response of `operationId` with HTTP
 * `status` according to the contract.
 *
 * - unknown `operationId`, or a status the operation does not document (and no `default`) → fail;
 * - the response schema is taken from `application/json` or `application/problem+json`, after
 *   resolving `$ref`s to `components.responses`;
 * - a response without `content` (204…) must have no body (`undefined`, `null` or `''`);
 * - when the real `response` is passed too, its status, its `Content-Type` and the headers the
 *   contract declares for that status are checked as well (the body is NOT read from it: pass the
 *   parsed `body`, e.g. `await response.clone().json()`).
 */
export function expectToMatchContract(
  operationId: string,
  status: number,
  body: unknown,
  response?: Response,
): void {
  const { contract, operations } = loadContract();

  const operation = operations.get(operationId);
  if (operation === undefined) {
    const known = [...operations.keys()].sort().join(', ');
    return expect.fail(`unknown operation "${operationId}" (the contract defines: ${known})`);
  }

  const where = `${operation.method} ${operation.path} (${operationId}) → ${status}`;
  const declared = operation.responses[String(status)] ?? operation.responses['default'];
  if (declared === undefined) {
    const documented = Object.keys(operation.responses).join(', ');
    return expect.fail(
      `${where}: the contract documents no such status (documented: ${documented})`,
    );
  }

  const resolved = resolveResponse(contract, declared, where);
  const content = isObject(resolved['content']) ? resolved['content'] : {};
  const mediaType: MediaType | undefined = JSON_MEDIA_TYPES.find((type) => isObject(content[type]));

  expectBodyMatches(contract, operationId, status, content, mediaType, body, where);
  if (response !== undefined) {
    expectResponseEnvelope(contract, operationId, status, resolved, mediaType, response, where);
  }
}
