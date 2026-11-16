import { ValidationError } from '@/shared/kernel';
import { PipelineError } from './pipeline-errors';

/** SEC-17: request bodies are at most 16 KiB. */
export const MAX_BODY_BYTES = 16 * 1024;

const JSON_MEDIA_TYPE = 'application/json';
const UTF8_CHARSETS: ReadonlySet<string> = new Set(['utf-8', 'utf8']);
const DIGITS_ONLY = /^\d+$/;

export type RequestBody =
  { readonly kind: 'empty' } | { readonly kind: 'json'; readonly value: unknown };

const payloadTooLarge = () =>
  new PipelineError('PAYLOAD_TOO_LARGE', 'request body above the limit', {
    detail: `The request body must not exceed ${MAX_BODY_BYTES / 1024} KiB.`,
  });

const unsupportedMediaType = () =>
  new PipelineError('UNSUPPORTED_MEDIA_TYPE', 'body is not application/json', {
    detail: 'The request body must be application/json (UTF-8).',
  });

const malformedJson = () =>
  new ValidationError('malformed JSON body', [{ path: 'body', message: 'Malformed JSON' }]);

/** `application/json` with no charset or a UTF-8 one (the only encoding the decoder accepts). */
function isJsonContentType(header: string | null): boolean {
  if (header === null) return false;
  const [mediaType, ...parameters] = header.split(';').map((part) => part.trim().toLowerCase());
  if (mediaType !== JSON_MEDIA_TYPE) return false;
  return parameters.every((parameter) => {
    const [name, value] = parameter.split('=').map((part) => part.trim());
    if (name !== 'charset') return true;
    return value !== undefined && UTF8_CHARSETS.has(value.replace(/^"|"$/g, ''));
  });
}

/** Reads at most MAX_BODY_BYTES; stops consuming the stream as soon as the limit is crossed. */
async function readLimited(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw payloadTooLarge();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

/**
 * Transport checks on the body (spec §3.3 step 3), before anything is parsed:
 * - a declared `Content-Length` above the limit → 413 without reading;
 * - the stream is counted while it is read, so a lying or absent `Content-Length` cannot get past
 *   the limit → 413;
 * - a non-empty body must be `application/json` → 415, and valid UTF-8 JSON → 400.
 * An empty body (or none) is `{ kind: 'empty' }`. Throws `PipelineError`/`ValidationError`.
 */
export async function readJsonBody(request: Request): Promise<RequestBody> {
  if (request.body === null) return { kind: 'empty' };

  const declared = request.headers.get('content-length');
  if (declared !== null && DIGITS_ONLY.test(declared) && Number(declared) > MAX_BODY_BYTES) {
    throw payloadTooLarge();
  }

  const bytes = await readLimited(request.body);
  if (bytes.byteLength === 0) return { kind: 'empty' };

  if (!isJsonContentType(request.headers.get('content-type'))) throw unsupportedMediaType();

  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw malformedJson();
  }
  try {
    return { kind: 'json', value: JSON.parse(text) as unknown };
  } catch {
    throw malformedJson();
  }
}
