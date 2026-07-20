import { readFile } from 'node:fs/promises';

/** Read the package version at runtime; works from both src/ and dist/. */
export async function scannerVersion(): Promise<string> {
  try {
    const raw = await readFile(new URL('../package.json', import.meta.url), 'utf8');
    const parsed = JSON.parse(raw) as { version?: string };
    return parsed.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}
