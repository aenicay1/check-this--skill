import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { execa, type Result } from 'execa';

export const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const CLI_PATH = path.join(PROJECT_ROOT, 'dist', 'cli.js');
export const FIXTURES = path.join(PROJECT_ROOT, 'tests', 'fixtures', 'skills');

export function fixture(name: string): string {
  return path.join(FIXTURES, name);
}

export interface CliOptions {
  env?: Record<string, string>;
  cwd?: string;
}

export async function runCli(args: string[], options: CliOptions = {}): Promise<Result> {
  return execa('node', [CLI_PATH, ...args], {
    reject: false,
    cwd: options.cwd ?? PROJECT_ROOT,
    env: options.env,
  });
}
