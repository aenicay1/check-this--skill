import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ScanResult } from '../../dist/index.js';
import { fixture, PROJECT_ROOT, runCli } from '../helpers.js';

const STUB = path.join(PROJECT_ROOT, 'tests', 'stub', 'claude-stub.mjs');

function withStub(mode: string): Record<string, string> {
  return {
    ...process.env,
    CHECK_MY_SKILL_CLAUDE_BIN: STUB,
    STUB_MODE: mode,
  } as Record<string, string>;
}

async function scanWithStub(fixtureName: string, mode: string): Promise<ScanResult> {
  const proc = await runCli([fixture(fixtureName), '--json', '--no-deps'], { env: withStub(mode) });
  return JSON.parse(String(proc.stdout)) as ScanResult;
}

describe('LLM review via stubbed claude binary', () => {
  it('runs and merges a valid finding additively', async () => {
    const result = await scanWithStub('mal-exfil-prose', 'finding');
    expect(result.llm.ran).toBe(true);
    expect(result.llm.tampered).toBe(false);
    const llmFindings = result.findings.filter((f) => f.source === 'llm');
    expect(llmFindings.length).toBeGreaterThan(0);
    expect(llmFindings[0]!.confidence).toBe('medium'); // LLM never claims high confidence
  });

  it('reports a clean skill as PASS when the stub finds nothing', async () => {
    const result = await scanWithStub('clean-minimal', 'clean');
    expect(result.llm.ran).toBe(true);
    expect(result.findings.filter((f) => f.source === 'llm')).toHaveLength(0);
    expect(result.verdict).toBe('PASS');
  });

  it('raises a tamper finding when the canary is wrong (skill cannot talk its way to PASS)', async () => {
    // Even against a clean skill, a diverted reviewer must not lower the verdict.
    const result = await scanWithStub('clean-minimal', 'tamper');
    expect(result.llm.tampered).toBe(true);
    const tamper = result.findings.find((f) => f.id === 'CMS-LLM-TAMPER');
    expect(tamper).toBeDefined();
    expect(tamper!.severity).toBe('high');
    expect(result.verdict).toBe('BLOCK');
    // The stub's (bad-canary) findings must be discarded entirely.
    expect(result.findings.filter((f) => f.id.startsWith('CMS-LLM-') && f.id !== 'CMS-LLM-TAMPER')).toHaveLength(0);
  });

  it('drops hallucinated findings whose evidence is not in the bundle', async () => {
    const result = await scanWithStub('clean-minimal', 'hallucinate');
    expect(result.llm.ran).toBe(true);
    expect(result.findings.filter((f) => f.source === 'llm')).toHaveLength(0);
    expect(result.verdict).toBe('PASS');
  });

  it('skips gracefully when the model returns non-JSON', async () => {
    const result = await scanWithStub('clean-minimal', 'nonjson');
    expect(result.llm.ran).toBe(false);
    expect(result.llm.skippedReason).toBeTruthy();
    expect(result.verdict).toBe('PASS');
  });

  it('skips gracefully when the claude binary is absent', async () => {
    const result = await scanWithStub('clean-minimal', 'clean');
    // Override with a nonexistent binary path.
    const proc = await runCli([fixture('clean-minimal'), '--json', '--no-deps'], {
      env: { ...process.env, CHECK_MY_SKILL_CLAUDE_BIN: '/nonexistent/claude-binary' } as Record<string, string>,
    });
    const absent = JSON.parse(String(proc.stdout)) as ScanResult;
    expect(absent.llm.ran).toBe(false);
    expect(absent.llm.skippedReason).toContain('not runnable');
    // sanity: the stub path itself did run in the first scan
    expect(result.llm.ran).toBe(true);
  });
});
