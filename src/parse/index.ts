import { analyzeLines } from '../text/unicode.js';
import type { Bundle, BundleModel, ParsedFile } from '../types.js';
import { parseFrontmatter } from './frontmatter.js';
import { parseJavaScriptFile } from './javascript.js';
import { parseManifest } from './manifests.js';
import { parseMarkdown } from './markdown.js';

export function splitLines(text: string): string[] {
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
}

const MARKDOWN_KINDS = new Set(['skill-md', 'reference-md', 'markdown']);

/**
 * Build the parsed view of every text file in the bundle. The baseline every
 * rule can count on is raw lines plus the normalized (NFKC,
 * invisibles-stripped) lines with stable line numbers; markdown additionally
 * gets frontmatter and mdast, JavaScript gets a best-effort ESTree, and
 * manifests get a structural package list.
 */
export function parseBundle(bundle: Bundle): BundleModel {
  const parsed = new Map<string, ParsedFile>();
  for (const file of bundle.files) {
    if (file.text === undefined) continue;
    const lines = splitLines(file.text);
    const entry: ParsedFile = {
      relPath: file.relPath,
      lines,
      normalized: analyzeLines(lines),
    };
    if (MARKDOWN_KINDS.has(file.kind)) {
      entry.frontmatter = parseFrontmatter(lines);
      entry.mdast = parseMarkdown(lines, entry.frontmatter);
    }
    if (file.kind === 'javascript') {
      const result = parseJavaScriptFile(file.relPath, file.text);
      entry.estree = result.program;
      entry.estreeError = result.error;
    }
    if (file.kind === 'manifest') {
      entry.manifest = parseManifest(file.relPath, file.text);
    }
    parsed.set(file.relPath, entry);
  }
  return { ...bundle, parsed };
}
