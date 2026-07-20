import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ScanResultSchema } from '../../dist/index.js';
import { fixture, runCli } from '../helpers.js';

describe('check-my-skill CLI', () => {
  it('passes an empty directory', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'cms-empty-'));
    const result = await runCli([dir, '--no-llm', '--no-deps']);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('VERDICT: PASS');
  });

  it('passes a clean minimal skill', async () => {
    const result = await runCli([fixture('clean-minimal'), '--no-llm', '--no-deps']);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('VERDICT: PASS');
  });

  it('exits 3 on a missing target', async () => {
    const result = await runCli(['/nonexistent/definitely-not-a-skill', '--no-llm', '--no-deps']);
    expect(result.exitCode).toBe(3);
    expect(result.stderr).toContain('target not found');
  });

  it('rejects a non-GitHub remote URL without a network call', async () => {
    const result = await runCli(['https://evil.example.invalid/owner/repo', '--no-llm', '--no-deps']);
    expect(result.exitCode).toBe(3);
    expect(result.stderr).toContain('not a recognized GitHub URL');
  });

  it('emits schema-valid JSON with --json', async () => {
    const result = await runCli([fixture('clean-minimal'), '--json', '--no-llm', '--no-deps']);
    expect(result.exitCode).toBe(0);
    const parsed = ScanResultSchema.parse(JSON.parse(String(result.stdout)));
    expect(parsed.verdict).toBe('PASS');
    expect(parsed.stats.files).toBe(1);
    expect(parsed.llm.ran).toBe(false);
    expect(parsed.deps.ran).toBe(false);
  });
});
