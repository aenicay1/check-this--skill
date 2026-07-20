import { describe, expect, it } from 'vitest';
import { auditDependencies } from '../../dist/deps/osv.js';
import type { ParsedManifest } from '../../dist/index.js';

const manifest = (): { relPath: string; manifest: ParsedManifest } => ({
  relPath: 'package.json',
  manifest: {
    ecosystem: 'npm',
    fileType: 'package.json',
    packages: [
      { name: 'safe-pkg', version: '1.0.0' },
      { name: 'vuln-pkg', version: '0.1.0' },
      { name: 'floating', version: '^2.0.0' }, // no concrete version → not queried
    ],
  },
});

function mockFetch(handler: (url: string, init?: RequestInit) => unknown): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const body = handler(url, init);
    return { ok: true, status: 200, json: async () => body } as Response;
  }) as typeof fetch;
}

describe('auditDependencies', () => {
  it('reports a vulnerable package with mapped severity and skips unpinned versions', async () => {
    const fetchImpl = mockFetch((url) => {
      if (url.includes('querybatch')) {
        return { results: [{}, { vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz' }] }] };
      }
      return {
        id: 'GHSA-xxxx-yyyy-zzzz',
        summary: 'Prototype pollution',
        database_specific: { severity: 'CRITICAL' },
      };
    });
    const result = await auditDependencies([manifest()], { fetchImpl });
    expect(result.packagesQueried).toBe(2); // floating (^2.0.0) not queried
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.severity).toBe('critical');
    expect(result.findings[0]!.detail).toContain('vuln-pkg@0.1.0');
    expect(result.findings[0]!.detail).toContain('GHSA-xxxx-yyyy-zzzz');
  });

  it('degrades gracefully when the network fails', async () => {
    const fetchImpl = (async () => {
      throw new Error('ENOTFOUND');
    }) as typeof fetch;
    const result = await auditDependencies([manifest()], { fetchImpl });
    expect(result.findings).toHaveLength(0);
    expect(result.skippedReason).toContain('OSV query failed');
  });

  it('skips cleanly when there are no pinned dependencies', async () => {
    const empty: ParsedManifest = { ecosystem: 'npm', fileType: 'package.json', packages: [] };
    const result = await auditDependencies([{ relPath: 'package.json', manifest: empty }]);
    expect(result.packagesQueried).toBe(0);
    expect(result.skippedReason).toContain('no pinned dependencies');
  });
});
