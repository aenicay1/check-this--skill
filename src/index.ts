import { acquireLocal } from './acquire/local.js';
import { walkBundle } from './bundle/walk.js';
import { auditDependencies } from './deps/osv.js';
import { isAllowed } from './rules/engine.js';
import { loadAllowEntries } from './ignore.js';
import { parseBundle } from './parse/index.js';
import { runRules } from './rules/engine.js';
import { allRules } from './rules/index.js';
import { computeVerdict } from './report/verdict.js';
import { ScanError, type Finding, type ParsedManifest, type ScanOptions, type ScanResult } from './types.js';
import { scannerVersion } from './version.js';

export * from './types.js';
export { exitCodeFor } from './report/verdict.js';
export { renderTerminal } from './report/terminal.js';
export { renderJson } from './report/json.js';

function isRemoteTarget(target: string): boolean {
  return /^(https?:\/\/|git@)/.test(target) || /^github\.com\//.test(target);
}

/**
 * Scan a skill bundle. Read-only: nothing from the bundle is ever executed.
 */
export async function scan(target: string, options: ScanOptions = {}): Promise<ScanResult> {
  if (isRemoteTarget(target)) {
    throw new ScanError('remote targets are not supported yet; clone-free GitHub fetching lands in an upcoming release');
  }

  const { rootDir, source } = await acquireLocal(target);
  const bundle = await walkBundle(rootDir, source);
  const model = parseBundle(bundle);
  const allow = await loadAllowEntries(options.allow, process.cwd());

  const findings = runRules(model, allRules, allow);

  // Dependency audit (network). Additive: OSV findings can only add to the
  // verdict, and are subject to the same allow-list as rule findings.
  let deps = {
    ran: false,
    packagesQueried: 0,
    skippedReason: options.deps === false ? 'disabled via --no-deps' : undefined,
  };
  if (options.deps !== false) {
    const manifests: Array<{ relPath: string; manifest: ParsedManifest }> = [];
    for (const parsed of model.parsed.values()) {
      if (parsed.manifest) manifests.push({ relPath: parsed.relPath, manifest: parsed.manifest });
    }
    const audit = await auditDependencies(manifests);
    for (const f of audit.findings) {
      if (!isAllowed(f, allow)) findings.push(f);
    }
    deps = { ran: audit.skippedReason === undefined, packagesQueried: audit.packagesQueried, skippedReason: audit.skippedReason };
  }

  const llm = {
    ran: false,
    skippedReason: options.llm === false ? 'disabled via --no-llm' : 'LLM review not yet implemented',
  };

  sortFindings(findings);

  return {
    schemaVersion: 1,
    scannerVersion: await scannerVersion(),
    target: { path: source.target, source: source.type, sha: source.sha },
    stats: {
      files: bundle.files.length,
      bytes: bundle.totalBytes,
      notes: bundle.notes,
    },
    findings,
    llm,
    deps,
    verdict: computeVerdict(findings, { strict: options.strict }),
  };
}

function sortFindings(findings: Finding[]): void {
  findings.sort(
    (a, b) =>
      (a.file ?? '').localeCompare(b.file ?? '') || (a.line ?? 0) - (b.line ?? 0) || a.id.localeCompare(b.id),
  );
}
