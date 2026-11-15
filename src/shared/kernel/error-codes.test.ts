import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { ERROR_CODES } from './error-codes';

type Contract = { components: { schemas: { ErrorCode: { enum: string[] } } } };

describe('ERROR_CODES', () => {
  it('equals components.schemas.ErrorCode of the contract, in order', () => {
    const file = resolve(process.cwd(), 'contracts/openapi.v1.yaml');
    const contract = parse(readFileSync(file, 'utf8')) as Contract;
    expect([...ERROR_CODES]).toEqual(contract.components.schemas.ErrorCode.enum);
  });

  it('has no duplicates', () => {
    expect(new Set(ERROR_CODES).size).toBe(ERROR_CODES.length);
  });
});
