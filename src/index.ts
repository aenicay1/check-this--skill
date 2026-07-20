import { acquireLocal } from './acquire/local.js';
import { walkBundle } from './bundle/walk.js';
import { loadAllowEntries } from './ignore.js';
import { parseBundle } from './parse/index.js';
import { runRules } from './rules/engine.js';
import { allRules } from './rules/index.js';
import { computeVerdict } from './report/verdict.js';
import { ScanError, type ScanOptions, type ScanResult } from './types.js';
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

  const llm = {
    ran: false,
    skippedReason: options.llm === false ? 'disabled via --no-llm' : 'LLM review not yet implemented',
  };
  const deps = {
    ran: false,
    packagesQueried: 0,
    skippedReason: options.deps === false ? 'disabled via --no-deps' : 'dependency audit not yet implemented',
  };

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
