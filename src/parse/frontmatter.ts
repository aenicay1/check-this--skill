import YAML from 'yaml';
import type { ParsedFrontmatter } from '../types.js';

/**
 * Split and parse YAML frontmatter from raw lines. Returns undefined when the
 * file has no frontmatter block. A malformed block still returns (with
 * `error` set) because malformed frontmatter is itself a signal.
 */
export function parseFrontmatter(lines: string[]): ParsedFrontmatter | undefined {
  if ((lines[0] ?? '').trim() !== '---') return undefined;
  let closeIdx = -1;
  for (let i = 1; i < lines.length; i++) {
    const trimmed = (lines[i] ?? '').trim();
    if (trimmed === '---' || trimmed === '...') {
      closeIdx = i;
      break;
    }
  }
  if (closeIdx === -1) {
    return { data: {}, raw: '', bodyStartLine: 1, error: 'unterminated frontmatter block' };
  }
  const raw = lines.slice(1, closeIdx).join('\n');
  const bodyStartLine = closeIdx + 2;
  try {
    // maxAliasCount guards against YAML alias-expansion bombs.
    const data = YAML.parse(raw, { maxAliasCount: 100 });
    if (data === null || typeof data !== 'object' || Array.isArray(data)) {
      return { data: {}, raw, bodyStartLine, error: 'frontmatter is not a YAML mapping' };
    }
    return { data: data as Record<string, unknown>, raw, bodyStartLine };
  } catch (err) {
    return { data: {}, raw, bodyStartLine, error: (err as Error).message };
  }
}
