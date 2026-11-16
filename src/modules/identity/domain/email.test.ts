import { describe, expect, it } from 'vitest';
import { normalizeEmail } from './email';

describe('normalizeEmail', () => {
  it('E-11: trims, lowercases and keeps the address otherwise', () => {
    expect(normalizeEmail('  Maria@Cliente.COM ')).toBe('maria@cliente.com');
    expect(normalizeEmail('maria@cliente.com')).toBe('maria@cliente.com');
  });

  it('E-11: trims every kind of surrounding whitespace', () => {
    expect(normalizeEmail('\t\n maria@cliente.com \r\n')).toBe('maria@cliente.com');
  });

  it('E-11: composes to NFC, so "e" + combining acute equals the precomposed letter', () => {
    const decomposed = 'josé@cliente.com';
    const precomposed = 'josé@cliente.com';
    expect(decomposed).not.toBe(precomposed);
    expect(normalizeEmail(decomposed)).toBe(precomposed);
  });

  it('is idempotent', () => {
    const once = normalizeEmail('  JOSÉ@Cliente.COM ');
    expect(normalizeEmail(once)).toBe(once);
  });

  it('does not touch the inside of the address', () => {
    expect(normalizeEmail('a.b+tag@Sub.Cliente.com')).toBe('a.b+tag@sub.cliente.com');
  });
});
