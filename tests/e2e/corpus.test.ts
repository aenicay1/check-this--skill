import { existsSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ScanResult } from '../../dist/index.js';
import { FIXTURES, PROJECT_ROOT, runCli } from '../helpers.js';

const GENERATED = path.join(PROJECT_ROOT, 'tests', 'fixtures', 'generated');

interface Expectation {
  name: string;
  dir: string;
  verdict: 'PASS' | 'CAUTION' | 'BLOCK';
  /** Rule ids that must appear. */
  expectRules?: string[];
  /** Rule ids that must NOT appear (false-positive guards). */
  forbidRules?: string[];
}

const CLEAN: Expectation[] = [
  { name: 'clean-minimal', dir: FIXTURES, verdict: 'PASS' },
  { name: 'clean-git-helper', dir: FIXTURES, verdict: 'PASS' },
  { name: 'clean-node-tool', dir: FIXTURES, verdict: 'PASS' },
  {
    name: 'clean-security-tool',
    dir: FIXTURES,
    verdict: 'PASS',
    // The canonical false-positive guard: legitimately mentions ~/.ssh,
    // ~/.aws/credentials, .env, and curl|sh in an example block.
    forbidRules: ['CMS-CODE-001', 'CMS-CODE-002', 'CMS-NL-003'],
  },
  {
    // Reads/seeds .env locally with cp/cat, no egress: must not hard-BLOCK.
    name: 'clean-env-loader',
    dir: FIXTURES,
    verdict: 'PASS',
  },
];

const MALICIOUS: Expectation[] = [
  { name: 'mal-exfil-prose', dir: FIXTURES, verdict: 'BLOCK', expectRules: ['CMS-NL-003', 'CMS-NL-001'] },
  { name: 'mal-llm-injection', dir: FIXTURES, verdict: 'BLOCK', expectRules: ['CMS-NL-002', 'CMS-HID-004'] },
  { name: 'mal-curl-pipe-sh', dir: FIXTURES, verdict: 'BLOCK', expectRules: ['CMS-CODE-001'] },
  { name: 'mal-cred-access', dir: FIXTURES, verdict: 'BLOCK', expectRules: ['CMS-CODE-002'] },
  { name: 'mal-destructive', dir: FIXTURES, verdict: 'BLOCK', expectRules: ['CMS-CODE-003'] },
  { name: 'mal-rm-home', dir: FIXTURES, verdict: 'BLOCK', expectRules: ['CMS-CODE-003'] },
  { name: 'mal-env-exfil', dir: FIXTURES, verdict: 'BLOCK', expectRules: ['CMS-CODE-002'] },
  { name: 'mal-eval-obfuscated', dir: FIXTURES, verdict: 'BLOCK', expectRules: ['CMS-CODE-004'] },
  { name: 'mal-reverse-shell', dir: FIXTURES, verdict: 'BLOCK', expectRules: ['CMS-CODE-005'] },
  { name: 'mal-settings-write', dir: FIXTURES, verdict: 'BLOCK', expectRules: ['CMS-PERSIST-001'] },
  { name: 'mal-mcp-inject', dir: FIXTURES, verdict: 'BLOCK', expectRules: ['CMS-PERSIST-002'] },
  { name: 'mal-cron-persist', dir: FIXTURES, verdict: 'BLOCK', expectRules: ['CMS-PERSIST-004'] },
  { name: 'mal-broad-perms', dir: FIXTURES, verdict: 'CAUTION', expectRules: ['CMS-FM-001'] },
  { name: 'mal-zerowidth', dir: GENERATED, verdict: 'BLOCK', expectRules: ['CMS-HID-001'] },
  { name: 'mal-bidi', dir: GENERATED, verdict: 'BLOCK', expectRules: ['CMS-HID-002'] },
  { name: 'mal-homoglyph', dir: GENERATED, verdict: 'CAUTION', expectRules: ['CMS-HID-003'] },
  { name: 'mal-base64-blob', dir: GENERATED, verdict: 'BLOCK', expectRules: ['CMS-HID-005'] },
  { name: 'mal-base64-wrapped', dir: GENERATED, verdict: 'BLOCK', expectRules: ['CMS-HID-005'] },
];

async function scanFixture(exp: Expectation): Promise<{ result: ScanResult; exitCode: number | undefined }> {
  const target = path.join(exp.dir, exp.name);
  const proc = await runCli([target, '--json', '--no-llm', '--no-deps']);
  return { result: JSON.parse(String(proc.stdout)) as ScanResult, exitCode: proc.exitCode ?? undefined };
}

function ruleIds(result: ScanResult): Set<string> {
  return new Set(result.findings.map((f) => f.id));
}

describe('clean fixtures pass without false positives', () => {
  for (const exp of CLEAN) {
    it(exp.name, async () => {
      const { result, exitCode } = await scanFixture(exp);
      const highOrCritical = result.findings.filter((f) => f.severity === 'high' || f.severity === 'critical');
      expect(highOrCritical, `unexpected high/critical: ${JSON.stringify(highOrCritical)}`).toHaveLength(0);
      expect(result.verdict).toBe(exp.verdict);
      expect(exitCode).toBe(0);
      const ids = ruleIds(result);
      for (const forbidden of exp.forbidRules ?? []) {
        expect(ids.has(forbidden), `false positive ${forbidden}`).toBe(false);
      }
    });
  }
});

describe('malicious fixtures are caught', () => {
  for (const exp of MALICIOUS) {
    it(exp.name, async () => {
      expect(existsSync(path.join(exp.dir, exp.name)), `fixture missing: ${exp.name}`).toBe(true);
      const { result, exitCode } = await scanFixture(exp);
      expect(result.verdict, `verdict for ${exp.name}`).toBe(exp.verdict);
      expect(exitCode).toBe(exp.verdict === 'BLOCK' ? 2 : exp.verdict === 'CAUTION' ? 1 : 0);
      const ids = ruleIds(result);
      for (const ruleId of exp.expectRules ?? []) {
        expect(ids.has(ruleId), `expected ${ruleId} in ${exp.name}; got ${[...ids].join(', ')}`).toBe(true);
      }
    });
  }
});

describe('corpus coverage metric', () => {
  it('every malicious fixture reaches at least CAUTION', async () => {
    const results = await Promise.all(MALICIOUS.map(scanFixture));
    const missed = MALICIOUS.filter((_, i) => results[i]!.result.verdict === 'PASS');
    expect(missed.map((m) => m.name)).toEqual([]);
  });
});
