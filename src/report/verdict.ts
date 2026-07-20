import { severityRank, type Finding, type Severity, type Verdict } from '../types.js';

/**
 * The severity a finding actually contributes to the verdict. Noise damping: a
 * lone low-confidence heuristic should make you look, not hard-stop the install,
 * so its effective severity is capped at medium. --strict removes the damping.
 * Every consumer (verdict and exit code) uses this so they never disagree.
 */
export function effectiveSeverity(finding: Finding, strict: boolean): Severity {
  if (!strict && finding.confidence === 'low' && severityRank(finding.severity) >= severityRank('high')) {
    return 'medium';
  }
  return finding.severity;
}

function verdictPower(finding: Finding, strict: boolean): Verdict {
  const rank = severityRank(effectiveSeverity(finding, strict));
  return rank >= severityRank('high') ? 'BLOCK' : rank >= severityRank('medium') ? 'CAUTION' : 'PASS';
}

export function computeVerdict(findings: Finding[], options: { strict?: boolean } = {}): Verdict {
  let verdict: Verdict = 'PASS';
  for (const finding of findings) {
    const power = verdictPower(finding, options.strict ?? false);
    if (power === 'BLOCK') return 'BLOCK';
    if (power === 'CAUTION') verdict = 'CAUTION';
  }
  return verdict;
}

/**
 * Exit codes: 0 PASS, 1 CAUTION, 2 BLOCK, 3 ERROR.
 * --fail-on overrides the CI threshold: exit is non-zero only when a finding
 * at or above the given severity exists.
 */
export function exitCodeFor(
  verdict: Verdict,
  findings: Finding[],
  options: { failOn?: Severity; strict?: boolean } = {},
): number {
  if (verdict === 'ERROR') return 3;
  const { failOn, strict = false } = options;
  if (failOn !== undefined) {
    // Gate on effective (post-damping) severity so the exit code cannot
    // contradict the printed verdict.
    const threshold = severityRank(failOn);
    const triggered = findings.filter((f) => severityRank(effectiveSeverity(f, strict)) >= threshold);
    if (triggered.length === 0) return 0;
    return triggered.some((f) => severityRank(effectiveSeverity(f, strict)) >= severityRank('high')) ? 2 : 1;
  }
  if (verdict === 'BLOCK') return 2;
  if (verdict === 'CAUTION') return 1;
  return 0;
}
