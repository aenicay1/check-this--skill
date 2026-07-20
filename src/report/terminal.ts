import pc from 'picocolors';
import { SEVERITIES, type Finding, type ScanResult, type Severity, type Verdict } from '../types.js';

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

function paintSeverity(severity: Severity, text: string): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return pc.red(text);
    case 'medium':
      return pc.yellow(text);
    case 'low':
      return pc.cyan(text);
    case 'info':
      return pc.dim(text);
  }
}

function verdictBanner(verdict: Verdict): string {
  switch (verdict) {
    case 'PASS':
      return pc.bold(pc.green('VERDICT: PASS  ✔'));
    case 'CAUTION':
      return pc.bold(pc.yellow('VERDICT: CAUTION  ⚠'));
    case 'BLOCK':
      return pc.bold(pc.red('VERDICT: BLOCK  ✖'));
    case 'ERROR':
      return pc.bold(pc.red('VERDICT: ERROR'));
  }
}

function verdictHint(verdict: Verdict, findingCount: number): string {
  switch (verdict) {
    case 'PASS':
      return findingCount === 0
        ? 'No findings. This scan is a strong signal, not a guarantee.'
        : 'Only low-severity findings. Review them, then proceed if they make sense for this skill.';
    case 'CAUTION':
      return 'Review the findings above before installing this skill.';
    case 'BLOCK':
      return 'Do not install this skill.';
    case 'ERROR':
      return 'The scan could not complete; no verdict was reached.';
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function renderFinding(finding: Finding): string[] {
  const icon = finding.severity === 'medium' ? '⚠' : finding.severity === 'low' || finding.severity === 'info' ? '·' : '✖';
  const location = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ''}` : '(bundle)';
  const confidenceNote = finding.confidence === 'low' ? pc.dim(' (low confidence)') : '';
  const lines = [
    `  ${paintSeverity(finding.severity, icon)} ${pc.bold(finding.id)}  ${finding.title}${confidenceNote}`,
    `    ${pc.dim(location)}  ${finding.detail}`,
  ];
  if (finding.snippet) lines.push(`    ${pc.dim('»')} ${pc.dim(finding.snippet)}`);
  if (finding.remediation) lines.push(`    ${pc.dim(`fix: ${finding.remediation}`)}`);
  return lines;
}

export function renderTerminal(result: ScanResult): string {
  const out: string[] = [];
  const shaSuffix = result.target.sha ? ` @ ${result.target.sha.slice(0, 7)}` : '';
  out.push(pc.bold(`check-my-skill v${result.scannerVersion}`));
  out.push(
    `Target: ${result.target.path}${shaSuffix} ${pc.dim(`(${result.stats.files} files, ${formatBytes(result.stats.bytes)})`)}`,
  );
  out.push('');
  out.push(`  ${verdictBanner(result.verdict)}`);
  out.push('');

  if (result.findings.length === 0) {
    out.push(pc.dim('  No findings.'));
  } else {
    for (const severity of SEVERITIES) {
      const group = result.findings.filter((f) => f.severity === severity);
      if (group.length === 0) continue;
      out.push(`  ${paintSeverity(severity, pc.bold(SEVERITY_LABEL[severity]))}`);
      for (const finding of group) out.push(...renderFinding(finding));
      out.push('');
    }
  }

  const llmStatus = result.llm.ran
    ? result.llm.tampered
      ? pc.red('ran (tamper attempt detected)')
      : 'ran'
    : `skipped${result.llm.skippedReason ? ` (${result.llm.skippedReason})` : ''}`;
  const depsStatus = result.deps.ran
    ? `${result.deps.packagesQueried} packages checked`
    : `skipped${result.deps.skippedReason ? ` (${result.deps.skippedReason})` : ''}`;

  out.push(
    pc.dim(
      `  ${result.findings.length} finding${result.findings.length === 1 ? '' : 's'} · LLM review: ${llmStatus} · deps: ${depsStatus}`,
    ),
  );
  for (const note of result.stats.notes) out.push(pc.dim(`  note: ${note}`));
  out.push(`  ${verdictHint(result.verdict, result.findings.length)}`);
  return out.join('\n');
}
