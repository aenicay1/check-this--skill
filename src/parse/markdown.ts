import remarkParse from 'remark-parse';
import { unified } from 'unified';
import type { Root as MdastRoot } from 'mdast';
import type { ParsedFrontmatter } from '../types.js';

/**
 * Parse markdown to mdast with positions that match the raw file's line
 * numbers exactly. Frontmatter lines are blanked (not removed) before parsing
 * so nothing shifts.
 */
export function parseMarkdown(lines: string[], frontmatter?: ParsedFrontmatter): MdastRoot | undefined {
  let body = lines;
  if (frontmatter) {
    const fmEnd = frontmatter.bodyStartLine - 1; // number of leading lines to blank
    body = lines.map((line, i) => (i < fmEnd ? '' : line));
  }
  try {
    return unified().use(remarkParse).parse(body.join('\n')) as MdastRoot;
  } catch {
    return undefined;
  }
}
