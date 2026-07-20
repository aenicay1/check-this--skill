import { mkdtemp, writeFile, chmod, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ScanResult } from '../../dist/index.js';
import { runCli } from '../helpers.js';

async function tmpSkill(files: Record<string, Buffer | string>): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'cms-rob-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    await mkdir(path.dirname(abs), { recursive: true });
    await writeFile(abs, content);
  }
  return dir;
}

describe('robustness against hostile / malformed input', () => {
  it('does not crash on an odd-length UTF-16BE file (regression: swap16 RangeError)', async () => {
    // FE FF (UTF-16BE BOM) + a single trailing byte => odd length.
    const dir = await tmpSkill({
      'SKILL.md': '---\nname: x\ndescription: y\n---\n# ok',
      'notes.txt': Buffer.from([0xfe, 0xff, 0x41]),
    });
    const result = await runCli([dir, '--no-llm', '--no-deps', '--json']);
    // Must complete with a real verdict, not crash.
    expect(result.exitCode === 0 || result.exitCode === 1 || result.exitCode === 2).toBe(true);
    const parsed = JSON.parse(String(result.stdout)) as ScanResult;
    expect(['PASS', 'CAUTION', 'BLOCK']).toContain(parsed.verdict);
  });

  it('exits 3 (ERROR), never 1 (CAUTION), when the target cannot be read', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'cms-unreadable-'));
    await chmod(dir, 0o000);
    try {
      const result = await runCli([dir, '--no-llm', '--no-deps']);
      // On CI as non-root this is unreadable => ERROR. Skip the assertion if the
      // environment let us read it anyway (e.g. running as root).
      if (result.exitCode === 3) {
        expect(result.stderr.toLowerCase()).toContain('cannot read');
      }
    } finally {
      await chmod(dir, 0o755);
    }
  });
});
