import type { Finding, ManifestPackage, ParsedManifest, Severity } from '../types.js';

const OSV_ENDPOINT = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN = 'https://api.osv.dev/v1/vulns';

interface OsvQuery {
  package: { name: string; ecosystem: string };
  version?: string;
}

interface OsvBatchResponse {
  results: Array<{ vulns?: Array<{ id: string; modified?: string }> }>;
}

interface OsvVuln {
  id: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
}

const ECOSYSTEM: Record<ParsedManifest['ecosystem'], string> = { npm: 'npm', pypi: 'PyPI' };

/** An exact, pinned version like 1.2.3 or 1.2.3-beta.1 (no range operators). */
function isExactVersion(version: string): boolean {
  return /^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$/.test(version.trim());
}

/** Map a CVSS vector or qualitative label to our severity scale. */
function osvSeverity(vuln: OsvVuln): Severity {
  const label = vuln.database_specific?.severity?.toUpperCase();
  if (label === 'CRITICAL') return 'critical';
  if (label === 'HIGH') return 'high';
  if (label === 'MODERATE' || label === 'MEDIUM') return 'medium';
  if (label === 'LOW') return 'low';
  // OSV's severity[].score is a CVSS vector string (e.g. "CVSS:3.1/AV:N/..."),
  // not a number, so compute the base score from the vector.
  const cvss = vuln.severity?.find((s) => s.type.startsWith('CVSS'))?.score;
  const score = cvss ? cvssBaseScore(cvss) : undefined;
  if (score !== undefined) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    if (score > 0) return 'low';
  }
  return 'high'; // a vuln with no usable score: fail toward caution
}

const roundUp1 = (x: number): number => Math.ceil(x * 10) / 10;

/**
 * Compute a CVSS v3.0/3.1 base score from a vector string. Returns undefined
 * for CVSS v2 or unparseable vectors. Implements the standard formula so an
 * OSV entry that only carries a vector still maps to the right severity band.
 */
export function cvssBaseScore(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;
  const m = new Map<string, string>();
  for (const part of vector.split('/').slice(1)) {
    const [k, v] = part.split(':');
    if (k && v) m.set(k, v);
  }
  const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const AC: Record<string, number> = { L: 0.77, H: 0.44 };
  const UI: Record<string, number> = { N: 0.85, R: 0.62 };
  const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
  const scopeChanged = m.get('S') === 'C';
  const PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
  const PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
  const av = AV[m.get('AV') ?? ''];
  const ac = AC[m.get('AC') ?? ''];
  const ui = UI[m.get('UI') ?? ''];
  const pr = (scopeChanged ? PR_C : PR_U)[m.get('PR') ?? ''];
  const c = CIA[m.get('C') ?? ''];
  const iC = CIA[m.get('I') ?? ''];
  const a = CIA[m.get('A') ?? ''];
  if ([av, ac, ui, pr, c, iC, a].some((x) => x === undefined)) return undefined;

  const iss = 1 - (1 - c!) * (1 - iC!) * (1 - a!);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return roundUp1(raw);
}

export interface DepsAuditResult {
  findings: Finding[];
  packagesQueried: number;
  skippedReason?: string;
}

async function fetchVulnDetail(
  doFetch: typeof fetch,
  id: string,
  signal: AbortSignal,
): Promise<OsvVuln | undefined> {
  try {
    const res = await doFetch(`${OSV_VULN}/${encodeURIComponent(id)}`, { signal });
    if (!res.ok) return undefined;
    return (await res.json()) as OsvVuln;
  } catch {
    return undefined;
  }
}

/**
 * Query OSV.dev for known vulnerabilities in the bundle's declared
 * dependencies. Network-optional: any failure degrades to a skip note rather
 * than failing the scan.
 */
export async function auditDependencies(
  manifests: Array<{ relPath: string; manifest: ParsedManifest }>,
  options: { timeoutMs?: number; fetchImpl?: typeof fetch } = {},
): Promise<DepsAuditResult> {
  const doFetch = options.fetchImpl ?? fetch;
  const queries: OsvQuery[] = [];
  const index: Array<{ relPath: string; pkg: ManifestPackage }> = [];
  for (const { relPath, manifest } of manifests) {
    for (const pkg of manifest.packages) {
      // OSV matches against an exact version; semver ranges (^, ~, >, *, ...)
      // cannot be matched reliably, so we only query pinned versions.
      if (!pkg.version || !isExactVersion(pkg.version)) continue;
      queries.push({ package: { name: pkg.name, ecosystem: ECOSYSTEM[manifest.ecosystem] }, version: pkg.version });
      index.push({ relPath, pkg });
    }
  }
  if (queries.length === 0) {
    return { findings: [], packagesQueried: 0, skippedReason: 'no pinned dependencies to check' };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 15_000);
  try {
    const res = await doFetch(OSV_ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries }),
      signal: controller.signal,
    });
    if (!res.ok) {
      return { findings: [], packagesQueried: queries.length, skippedReason: `OSV returned HTTP ${res.status}` };
    }
    const body = (await res.json()) as OsvBatchResponse;
    const findings: Finding[] = [];
    for (let i = 0; i < body.results.length; i++) {
      const vulns = body.results[i]?.vulns ?? [];
      if (vulns.length === 0) continue;
      const entry = index[i]!;
      for (const v of vulns) {
        const detail = await fetchVulnDetail(doFetch, v.id, controller.signal);
        const severity: Severity = detail ? osvSeverity(detail) : 'high';
        findings.push({
          id: 'CMS-DEP-001',
          source: 'deps',
          severity,
          confidence: 'high',
          title: 'Known-vulnerable dependency',
          detail: `${entry.pkg.name}@${entry.pkg.version} is affected by ${v.id}${detail?.summary ? `: ${detail.summary}` : ''}.`,
          file: entry.relPath,
          tags: ['deps'],
          remediation: `Update ${entry.pkg.name} to a version outside the ${v.id} affected range.`,
        });
      }
    }
    return { findings, packagesQueried: queries.length };
  } catch (err) {
    const reason = (err as Error).name === 'AbortError' ? 'OSV query timed out' : `OSV query failed: ${(err as Error).message}`;
    return { findings: [], packagesQueried: queries.length, skippedReason: reason };
  } finally {
    clearTimeout(timer);
  }
}
