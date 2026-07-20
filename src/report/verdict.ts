import { severityRank, type Finding, type Severity, type Verdict } from '../types.js';

function verdictPower(finding: Finding, strict: boolean): Verdict {
  const rank = severityRank(finding.severity);
  let power: Verdict = rank >= severityRank('high') ? 'BLOCK' : rank >= severityRank('medium') ? 'CAUTION' : 'PASS';
  // Noise damping: a low-confidence heuristic on its own should make you
  // look, not hard-stop the install. --strict removes the damping.
  if (power === 'BLOCK' && finding.confidence === 'low' && !strict) power = 'CAUTION';
  return power;
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
export function exitCodeFor(verdict: Verdict, findings: Finding[], failOn?: Severity): number {
  if (verdict === 'ERROR') return 3;
  if (failOn !== undefined) {
    const threshold = severityRank(failOn);
    const triggered = findings.filter((f) => severityRank(f.severity) >= threshold);
    if (triggered.length === 0) return 0;
    return triggered.some((f) => severityRank(f.severity) >= severityRank('high')) ? 2 : 1;
  }
  if (verdict === 'BLOCK') return 2;
  if (verdict === 'CAUTION') return 1;
  return 0;
}
