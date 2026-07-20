import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { ScanError, type BundleSource } from '../types.js';

export async function acquireLocal(target: string): Promise<{ rootDir: string; source: BundleSource }> {
  const resolved = path.resolve(target);
  let real: string;
  try {
    real = await realpath(resolved);
  } catch {
    throw new ScanError(`target not found: ${target}`);
  }
  const st = await lstat(real);
  if (st.isDirectory()) {
    return { rootDir: real, source: { type: 'local', target: resolved } };
  }
  if (st.isFile() && path.basename(real).toLowerCase() === 'skill.md') {
    return { rootDir: path.dirname(real), source: { type: 'local', target: resolved } };
  }
  throw new ScanError(`target must be a skill directory or a SKILL.md file: ${target}`);
}
