import { parse as acornParse, type Program } from 'acorn';
import path from 'node:path';

// Only plain JavaScript is fed to acorn. TypeScript/JSX flavors are still
// line-scanned by the code rules, but a parse failure there is expected and
// not a signal, so they are excluded here.
const ACORN_PARSEABLE_EXTS = new Set(['.js', '.mjs', '.cjs', '']);

export function parseJavaScriptFile(relPath: string, text: string): { program?: Program; error?: string } {
  const ext = path.posix.extname(relPath).toLowerCase();
  if (!ACORN_PARSEABLE_EXTS.has(ext)) return {};
  try {
    return { program: acornParse(text, { ecmaVersion: 'latest', sourceType: 'module', locations: true, allowHashBang: true }) };
  } catch {
    try {
      return { program: acornParse(text, { ecmaVersion: 'latest', sourceType: 'script', locations: true, allowHashBang: true }) };
    } catch (err) {
      return { error: (err as Error).message };
    }
  }
}
