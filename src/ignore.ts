import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { parseAllowEntries, type AllowEntry } from './rules/engine.js';

export const IGNORE_FILENAME = '.checkmyskillignore';

/**
 * Suppressions come from two places, merged: --allow flags and a
 * .checkmyskillignore file in the invoking directory (one RULE-ID or
 * RULE-ID:path/prefix per line, # comments).
 */
export async function loadAllowEntries(cliAllow: string[] | undefined, cwd: string): Promise<AllowEntry[]> {
  const specs: string[] = [...(cliAllow ?? [])];
  try {
    const raw = await readFile(path.join(cwd, IGNORE_FILENAME), 'utf8');
    specs.push(...raw.split('\n'));
  } catch {
    // no ignore file; fine
  }
  return parseAllowEntries(specs);
}
