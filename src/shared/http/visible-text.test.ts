// Every special character in this file is built from its code point: a literal invisible
// character in a test is invisible to reviewers, which is exactly the problem E-30 is about.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { ValidationError } from '@/shared/kernel';
import { validateInput, visibleText } from './validation';

const ch = (codePoint: number) => String.fromCodePoint(codePoint);

const C_CEDILLA = ch(0x00e7);
const A_TILDE = ch(0x00e3);
const EM_DASH = ch(0x2014);
const COMBINING_CEDILLA = ch(0x0327);
const COMBINING_TILDE = ch(0x0303);

/** The sentence "Acao & Cia - Producao" with its accents, precomposed (NFC). */
const ACAO_NFC = `A${C_CEDILLA}${A_TILDE}o`;
const PRODUCAO_NFC = `Produ${C_CEDILLA}${A_TILDE}o`;
const SENTENCE = `${ACAO_NFC} & Cia ${EM_DASH} ${PRODUCAO_NFC}`;
/** "Acao" with its accents as base letters followed by combining marks (NFD). */
const ACAO_NFD = `Ac${COMBINING_CEDILLA}a${COMBINING_TILDE}o`;

/** The class as it must read in validation.ts: Unicode property escapes, not glyphs. */
const EXPECTED_CLASS_SOURCE = '/[\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}]/u';

const name = visibleText({ min: 1, max: 120 });

function issuesOf(run: () => unknown) {
  try {
    run();
  } catch (error) {
    if (error instanceof ValidationError) return error.issues;
    throw error;
  }
  throw new Error('expected a ValidationError');
}

describe('visibleText (E-30)', () => {
  it('E-30: rejects a bidi override (U+202E)', () => {
    expect(name.safeParse(`Acme ${ch(0x202e)}txt.exe`).success).toBe(false);
  });

  it('E-30: rejects a zero-width space (U+200B)', () => {
    expect(name.safeParse(`Ac${ch(0x200b)}me`).success).toBe(false);
  });

  it('E-30: rejects a newline inside the text', () => {
    expect(name.safeParse('line one\nline two').success).toBe(false);
  });

  it('E-30: rejects a "tag" character (U+E0020, a Cf outside the BMP)', () => {
    const tag = String.fromCodePoint(0xe0020);
    expect(tag.length).toBe(2); // a surrogate pair: the check works on code points, not UTF-16 units
    expect(name.safeParse(`Acme${tag}Ltda`).success).toBe(false);
  });

  it('E-30: rejects the line separator (U+2028)', () => {
    expect(name.safeParse(`line one${ch(0x2028)}line two`).success).toBe(false);
  });

  it('E-30: rejects an interlinear annotation anchor (U+FFF9)', () => {
    expect(name.safeParse(`Acme${ch(0xfff9)}Ltda`).success).toBe(false);
  });

  it.each([
    ['NUL', 0x0000],
    ['US (last C0 control)', 0x001f],
    ['TAB', 0x0009],
    ['CR', 0x000d],
    ['DEL', 0x007f],
    ['NEL (C1)', 0x0085],
    ['APC (last C1 control)', 0x009f],
    ['soft hyphen', 0x00ad],
    ['Arabic letter mark', 0x061c],
    ['Mongolian vowel separator', 0x180e],
    ['zero-width space (first of the 200B range)', 0x200b],
    ['zero-width non-joiner', 0x200c],
    ['zero-width joiner', 0x200d],
    ['left-to-right mark', 0x200e],
    ['right-to-left mark (last of the range)', 0x200f],
    ['LRE (first bidi embedding)', 0x202a],
    ['RLO (bidi override)', 0x202e],
    ['word joiner (first of the 2060 range)', 0x2060],
    ['invisible plus (last of the range)', 0x2064],
    ['LRI (first bidi isolate)', 0x2066],
    ['PDI (last bidi isolate)', 0x2069],
    ['BOM / zero-width no-break space', 0xfeff],
    ['Arabic number sign (Cf)', 0x0600],
    ['deprecated format character U+206A (Cf)', 0x206a],
    ['line separator (Zl)', 0x2028],
    ['paragraph separator (Zp)', 0x2029],
    ['interlinear annotation anchor', 0xfff9],
    ['interlinear annotation separator', 0xfffa],
    ['interlinear annotation terminator', 0xfffb],
    ['language tag (U+E0001)', 0xe0001],
    ['tag space (U+E0020)', 0xe0020],
    ['cancel tag (U+E007F)', 0xe007f],
  ])('E-30: rejects %s in the middle of the text', (_label, codePoint) => {
    expect(name.safeParse(`ab${ch(codePoint)}cd`).success).toBe(false);
  });

  it.each([
    ['Hangul filler (U+3164)', 0x3164],
    ['braille pattern blank (U+2800)', 0x2800],
    ['Hangul choseong filler (U+115F)', 0x115f],
    ['Hangul jungseong filler (U+1160)', 0x1160],
    ['Khmer inherent vowel Aq (U+17B4)', 0x17b4],
    ['Khmer inherent vowel Aa (U+17B5)', 0x17b5],
    ['halfwidth Hangul filler (U+FFA0)', 0xffa0],
  ])('E-30: rejects the invisible filler %s', (_label, codePoint) => {
    const filler = ch(codePoint);
    expect(name.safeParse(`Acme${filler}Ltda`).success).toBe(false);
    // also at the edges, where trim() does not remove it
    expect(name.safeParse(`${filler}Acme`).success).toBe(false);
    expect(name.safeParse(`Acme${filler}`).success).toBe(false);
    // and alone, where it would otherwise pass as "a letter" (most are classified as letters)
    expect(name.safeParse(filler.repeat(3)).success).toBe(false);
  });

  it.each([
    ['a lone high surrogate (the JSON text "\\ud800")', 0xd800],
    ['a lone low surrogate', 0xdc00],
  ])('F-54: rejects %s, which Postgres would refuse with a 500', (_label, unit) => {
    const lone = String.fromCharCode(unit);
    expect(lone.length).toBe(1);

    for (const text of [`A${lone}`, `${lone}A`, `Ac${lone}me`]) {
      expect(name.safeParse(text).success, JSON.stringify(text)).toBe(false);
    }
    const schema = z.object({ name }).strict();
    const issues = issuesOf(() =>
      validateInput({ body: schema }, { params: {}, query: {}, body: { name: `A${lone}` } }),
    );
    expect(issues).toEqual([{ path: 'body.name', message: 'Must be valid Unicode text' }]);
  });

  it('F-54: accepts a well-formed surrogate PAIR (an emoji, a rare ideograph)', () => {
    const pair = String.fromCodePoint(0x1f600);
    const ideograph = String.fromCodePoint(0x20bb7);
    expect(pair.length).toBe(2);

    expect(name.parse(`Acme ${pair}`)).toBe(`Acme ${pair}`);
    expect(name.parse(ideograph)).toBe(ideograph);
  });

  it('E-30: a name of only fillers looks blank and is rejected', () => {
    const blank = [0x3164, 0x2800, 0x115f, 0x1160, 0x17b4, 0x17b5, 0xffa0].map(ch).join('');
    expect(name.safeParse(blank).success).toBe(false);
  });

  it.each([
    ['only symbols', '@#$%'],
    ['only punctuation', '...---'],
    ['only an emoji', ch(0x1f600)],
    ['only an em dash and spaces', `${ch(0x2014)} ${ch(0x2014)}`],
    ['only math symbols', '+=<>'],
  ])('E-30: requires a letter or a number: rejects %s', (_label, text) => {
    const result = name.safeParse(text);
    expect(result.success).toBe(false);
    expect(JSON.stringify(result.error?.issues)).toContain('letter or number');
  });

  it.each([
    ['a letter among symbols', '#a#'],
    ['a number among symbols', '#1#'],
    ['only digits', '2026'],
    ['a letter from another script', `${ch(0x4e2d)}${ch(0x6587)}`],
    ['an accented letter', ch(0x00e7)],
  ])('E-30: accepts %s', (_label, text) => {
    expect(name.safeParse(text).success).toBe(true);
  });

  it('E-30: the letter-or-number rule does not apply to an empty value allowed by min: 0', () => {
    const optional = visibleText({ min: 0, max: 10 });
    expect(optional.safeParse('').success).toBe(true);
    expect(optional.safeParse('   ').success).toBe(true);
    expect(optional.safeParse('---').success).toBe(false);
  });

  it('E-30: accepts accented text, punctuation and an em dash', () => {
    const parsed = name.safeParse(SENTENCE);
    expect(parsed.success).toBe(true);
    expect(parsed.data).toBe(SENTENCE);
  });

  it('E-30: accepts the characters right outside each rejected range', () => {
    const justOutside = [
      0x0020, // space (after the C0 controls)
      0x00a0, // NBSP (after the C1 controls)
      0x00ac, // before the soft hyphen
      0x00ae, // after the soft hyphen
      0x200a, // hair space (Zs), before 200B
      0x2010, // hyphen (Pd), after 200F
      0x2027, // hyphenation point (Po), before the line separator
      0x202f, // narrow no-break space (Zs), after 202E
      0x205f, // medium mathematical space (Zs), before 2060
      0x2065, // unassigned, between 2064 and 2066
      0xfefe, // unassigned, before the BOM
      0xfffc, // object replacement character (So), after the annotation characters
    ];
    for (const codePoint of justOutside) {
      const result = name.safeParse(`ab${ch(codePoint)}cd`);
      expect(result.success, `U+${codePoint.toString(16).toUpperCase()}`).toBe(true);
    }
  });

  it('E-30: NFD input comes out NFC', () => {
    expect(ACAO_NFD).not.toBe(ACAO_NFC);
    const parsed = name.parse(ACAO_NFD);
    expect(parsed).toBe(ACAO_NFC);
    expect(parsed).toBe(parsed.normalize('NFC'));
  });

  it('E-30: surrounding spaces are trimmed', () => {
    expect(name.parse('   Acme Ltda  ')).toBe('Acme Ltda');
  });

  it('E-30: a leading or trailing newline is trimmed away, an inner one is rejected', () => {
    expect(name.parse('Acme\n')).toBe('Acme');
    expect(name.safeParse('Ac\nme').success).toBe(false);
  });

  it('E-30: an all-space string fails min: 1', () => {
    for (const blank of ['', ' ', '     ', '\t \n', ch(0x00a0)]) {
      expect(name.safeParse(blank).success, JSON.stringify(blank)).toBe(false);
    }
  });

  it('E-30: the bounds apply to the trimmed value, counted in code points', () => {
    const short = visibleText({ min: 2, max: 5 });
    expect(short.safeParse('  a  ').success).toBe(false);
    expect(short.safeParse('  ab  ').success).toBe(true);
    expect(short.safeParse('abcde').success).toBe(true);
    expect(short.safeParse('abcdef').success).toBe(false);
    // 4 emoji and a letter are 9 UTF-16 units but 5 characters
    expect(short.safeParse(`${ch(0x1f600).repeat(4)}a`).success).toBe(true);
    expect(short.safeParse(`${ch(0x1f600).repeat(5)}a`).success).toBe(false);
    // padding does not count against max
    expect(short.safeParse(`   abcde${' '.repeat(50)}`).success).toBe(true);
  });

  it('E-30: the length is measured after NFC (a composed letter counts once)', () => {
    const three = visibleText({ min: 1, max: 4 });
    // the NFD form has 6 code points, its NFC form 4
    expect(three.safeParse(ACAO_NFD).success).toBe(true);
  });

  it('E-30: rejects non-strings and never echoes the rejected value', () => {
    expect(name.safeParse(42).success).toBe(false);
    expect(name.safeParse(null).success).toBe(false);
    const result = name.safeParse(`top${ch(0x200b)}secret-value`);
    expect(result.success).toBe(false);
    expect(JSON.stringify(result.error?.issues)).not.toContain('secret-value');
  });

  it('E-30: works inside a strict body schema and reports the field path', () => {
    const schema = z.object({ name: visibleText({ min: 1, max: 10 }) }).strict();
    const run = (value: unknown) =>
      validateInput({ body: schema }, { params: {}, query: {}, body: { name: value } });
    expect(issuesOf(() => run(`a${ch(0x200b)}b`)).map((issue) => issue.path)).toEqual([
      'body.name',
    ]);
    expect(run(' ok ').body).toEqual({ name: 'ok' });
  });

  it('E-30: refuses invalid bounds when the schema is built', () => {
    expect(() => visibleText({ min: 5, max: 2 })).toThrow(RangeError);
    expect(() => visibleText({ min: -1, max: 2 })).toThrow(RangeError);
    expect(() => visibleText({ min: 1.5, max: 2 })).toThrow(RangeError);
  });

  it('E-30: validation.ts has the character class as escapes, with no literal invisible characters', () => {
    const source = readFileSync(fileURLToPath(new URL('./validation.ts', import.meta.url)), 'utf8');
    // Newlines are the only control characters a source file may contain.
    const withoutNewlines = source.replaceAll('\n', '');
    expect(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(withoutNewlines)).toBe(false);
    expect(source).toContain(EXPECTED_CLASS_SOURCE);
  });
});
