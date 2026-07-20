import { sanitizeSnippet } from '../text/sanitize.js';
import type { BundleModel, Finding, Rule, RuleFinding } from '../types.js';

export interface AllowEntry {
  ruleId: string;
  pathPrefix?: string;
}

export function parseAllowEntries(specs: string[]): AllowEntry[] {
  const entries: AllowEntry[] = [];
  for (const spec of specs) {
    const trimmed = spec.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const colon = trimmed.indexOf(':');
    if (colon === -1) {
      entries.push({ ruleId: trimmed });
    } else {
      entries.push({ ruleId: trimmed.slice(0, colon), pathPrefix: trimmed.slice(colon + 1) });
    }
  }
  return entries;
}

export function isAllowed(finding: Finding, entries: AllowEntry[]): boolean {
  return entries.some((entry) => {
    if (entry.ruleId.toUpperCase() !== finding.id.toUpperCase()) return false;
    if (!entry.pathPrefix) return true;
    return (finding.file ?? '').startsWith(entry.pathPrefix);
  });
}

function toFinding(rule: Rule, raw: RuleFinding, defaultFile?: string): Finding {
  return {
    id: rule.id,
    source: 'rule',
    severity: raw.severity ?? rule.defaultSeverity,
    confidence: raw.confidence ?? rule.confidence,
    title: rule.title,
    detail: raw.detail,
    file: raw.file ?? defaultFile,
    line: raw.line,
    snippet: raw.snippet === undefined ? undefined : sanitizeSnippet(raw.snippet),
    tags: [...rule.tags],
    remediation: raw.remediation ?? rule.remediation,
  };
}

/**
 * Run every rule against the bundle. Deterministic: file order and finding
 * order are stable, and rules cannot see or influence each other's output.
 */
export function runRules(model: BundleModel, rules: Rule[], allow: AllowEntry[] = []): Finding[] {
  const findings: Finding[] = [];

  for (const rule of rules) {
    if (rule.type === 'bundle') {
      for (const raw of rule.check(model)) {
        findings.push(toFinding(rule, raw));
      }
      continue;
    }
    for (const file of model.files) {
      if (!rule.appliesTo.includes(file.kind)) continue;
      const parsed = model.parsed.get(file.relPath);
      if (!parsed) continue;
      for (const raw of rule.check({ file, parsed, bundle: model })) {
        findings.push(toFinding(rule, raw, file.relPath));
      }
    }
  }

  const kept = findings.filter((f) => !isAllowed(f, allow));
  kept.sort(
    (a, b) =>
      (a.file ?? '').localeCompare(b.file ?? '') || (a.line ?? 0) - (b.line ?? 0) || a.id.localeCompare(b.id),
  );
  return kept;
}
