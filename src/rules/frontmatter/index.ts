import path from 'node:path';
import type { FileRule, FileRuleContext, RuleFinding } from '../../types.js';

const SKILL_ONLY = ['skill-md'] as const;

function allowedTools(ctx: FileRuleContext): string[] {
  const data = ctx.parsed.frontmatter?.data;
  if (!data) return [];
  const raw = data['allowed-tools'] ?? data['allowedTools'] ?? data['tools'];
  if (typeof raw === 'string') return raw.split(',').map((s) => s.trim()).filter(Boolean);
  if (Array.isArray(raw)) return raw.filter((t): t is string => typeof t === 'string');
  return [];
}

export const fmBroadPermissions: FileRule = {
  type: 'file',
  id: 'CMS-FM-001',
  title: 'Broad or unscoped tool permissions',
  description: 'Frontmatter requests unscoped Bash, wildcards, or permission-skipping flags.',
  defaultSeverity: 'medium',
  confidence: 'high',
  tags: ['permissions'],
  appliesTo: SKILL_ONLY,
  remediation: 'Scope Bash to specific commands, e.g. `Bash(git status)`, instead of granting it wholesale.',
  check: (ctx) => {
    const tools = allowedTools(ctx);
    const out: RuleFinding[] = [];
    const line = frontmatterLine(ctx, /allowed[_-]?tools|allowedTools|\btools\b/i);
    for (const tool of tools) {
      if (/dangerously-skip-permissions|bypasspermissions/i.test(tool)) {
        out.push({ detail: `Permission-skipping flag in tools: \`${tool}\`.`, line, snippet: tool, severity: 'high' });
        continue;
      }
      // Unscoped: bare `Bash`, or a whole-tool wildcard `Bash(*)` / `*`.
      // The documented scoped syntax like `Bash(git add:*)` is fine and must
      // NOT be treated as a wildcard.
      if (/^bash$/i.test(tool) || /^bash\s*\(\s*\*\s*\)$/i.test(tool)) {
        out.push({ detail: `Requests unscoped \`${tool}\` (any shell command).`, line, snippet: tool });
      } else if (tool === '*') {
        out.push({ detail: 'Wildcard tool permission `*` grants every tool.', line, snippet: tool });
      }
    }
    return out;
  },
};

export const fmPurposeMismatch: FileRule = {
  type: 'file',
  id: 'CMS-FM-002',
  title: 'Permissions exceed the stated purpose',
  description: 'Declares powerful tools while the description implies a read-only or formatting task.',
  defaultSeverity: 'low',
  confidence: 'low',
  tags: ['permissions'],
  appliesTo: SKILL_ONLY,
  remediation: 'If the skill only formats or explains, it likely does not need Bash, Write, or network tools.',
  check: (ctx) => {
    const data = ctx.parsed.frontmatter?.data;
    if (!data) return [];
    const description = String(data['description'] ?? '');
    const tools = allowedTools(ctx).map((t) => t.toLowerCase());
    const powerful = tools.filter((t) => /^(bash|write|edit|webfetch|websearch|execute)/.test(t));
    if (powerful.length === 0) return [];
    const readOnlyIntent = /\b(format|explain|describe|summar|convert|lint|style|template|greet|rename|display|render)\b/i;
    const actionIntent = /\b(run|execute|install|deploy|fetch|download|commit|push|build|test|delete|modify|write|scan)\b/i;
    if (readOnlyIntent.test(description) && !actionIntent.test(description)) {
      return [
        {
          detail: `Description sounds read-only but the skill requests: ${powerful.join(', ')}.`,
          line: frontmatterLine(ctx, /description/i),
          snippet: description.slice(0, 120),
        },
      ];
    }
    return [];
  },
};

export const fmMalformed: FileRule = {
  type: 'file',
  id: 'CMS-FM-003',
  title: 'Malformed or suspicious frontmatter',
  description: 'Missing/unparseable frontmatter, name/directory mismatch, or injection tokens in metadata.',
  defaultSeverity: 'medium',
  confidence: 'medium',
  tags: ['permissions', 'injection'],
  appliesTo: SKILL_ONLY,
  remediation: 'Frontmatter should be a clean YAML mapping with a name matching the skill directory.',
  check: (ctx) => {
    const fm = ctx.parsed.frontmatter;
    const out: RuleFinding[] = [];
    if (!fm) {
      out.push({ detail: 'SKILL.md has no YAML frontmatter block.', line: 1, confidence: 'high' });
      return out;
    }
    if (fm.error) {
      out.push({ detail: `Frontmatter did not parse: ${fm.error}`, line: 1, confidence: 'high' });
    }
    const name = fm.data['name'];
    const dir = path.posix.basename(path.posix.dirname(ctx.file.relPath));
    if (typeof name === 'string' && dir && dir !== '.' && name.toLowerCase() !== dir.toLowerCase()) {
      out.push({
        detail: `Frontmatter name "${name}" does not match the skill directory "${dir}".`,
        line: frontmatterLine(ctx, /^\s*name\s*:/i),
        confidence: 'low',
      });
    }
    // "system prompt" alone is normal skill vocabulary; only flag genuine
    // injection phrasings in metadata.
    const injection = /\b(ignore (previous|all|prior)|you are now a|report no (issues|problems|vulnerabilities)|disregard (the|all|previous))\b/i;
    // A security/defensive skill legitimately describes these phrases as things
    // it detects; damp to CAUTION rather than BLOCK when that framing is present.
    const defensive =
      /\b(detect|scan|scanner|flag|reject|block|refuse|guard|audit|review|find|catch|prevent|protect against|test for|check for|that (try|attempt|tries|attempts) to)\b/i;
    for (const key of ['name', 'description'] as const) {
      const value = fm.data[key];
      if (typeof value === 'string' && injection.test(value)) {
        const isDefensive = defensive.test(value);
        out.push({
          detail: isDefensive
            ? `Frontmatter "${key}" mentions injection phrasing (reads as defensive; verify).`
            : `Frontmatter "${key}" contains prompt-injection text.`,
          line: frontmatterLine(ctx, new RegExp(`^\\s*${key}\\s*:`, 'i')),
          snippet: value.slice(0, 120),
          severity: 'high',
          confidence: isDefensive ? 'low' : undefined,
        });
      }
    }
    return out;
  },
};

function frontmatterLine(ctx: FileRuleContext, pattern: RegExp): number | undefined {
  const lines = ctx.parsed.lines;
  const end = (ctx.parsed.frontmatter?.bodyStartLine ?? lines.length + 1) - 1;
  for (let i = 0; i < Math.min(end, lines.length); i++) {
    if (pattern.test(lines[i] ?? '')) return i + 1;
  }
  return 1;
}

export const frontmatterRules: FileRule[] = [fmBroadPermissions, fmPurposeMismatch, fmMalformed];
