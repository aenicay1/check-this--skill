import { analyzeLines } from '../text/unicode.js';
import type { Bundle, BundleModel, ParsedFile } from '../types.js';

export function splitLines(text: string): string[] {
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
}

/**
 * Build the parsed view of every text file in the bundle. Richer per-kind
 * parsing (frontmatter, mdast, estree, manifests) is layered on here by the
 * rule stages; the baseline every rule can count on is raw lines plus the
 * normalized (NFKC, invisibles-stripped) lines with stable line numbers.
 */
export function parseBundle(bundle: Bundle): BundleModel {
  const parsed = new Map<string, ParsedFile>();
  for (const file of bundle.files) {
    if (file.text === undefined) continue;
    const lines = splitLines(file.text);
    parsed.set(file.relPath, {
      relPath: file.relPath,
      lines,
      normalized: analyzeLines(lines),
    });
  }
  return { ...bundle, parsed };
}
