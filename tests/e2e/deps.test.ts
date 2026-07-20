import { describe, expect, it } from 'vitest';
import type { ScanResult } from '../../dist/index.js';
import { fixture, runCli } from '../helpers.js';

describe('dependency rules (offline, --no-deps skips the network audit)', () => {
  it('flags install-script and non-registry dependency without any network call', async () => {
    const proc = await runCli([fixture('mal-install-script'), '--json', '--no-llm', '--no-deps']);
    const result = JSON.parse(String(proc.stdout)) as ScanResult;
    const ids = new Set(result.findings.map((f) => f.id));
    expect(ids.has('CMS-DEP-002')).toBe(true); // postinstall runs curl|bash
    expect(ids.has('CMS-DEP-003')).toBe(true); // git+https dependency
    expect(result.verdict).toBe('BLOCK'); // DEP-002 is high
    expect(result.deps.ran).toBe(false);
    expect(result.deps.skippedReason).toContain('--no-deps');
  });
});
