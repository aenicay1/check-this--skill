import { codeBlockRanges, isExampleBlock, rangeAt } from '../util/context.js';
import type { FileRule, FileRuleContext, RuleFinding } from '../../types.js';

const NL_KINDS = ['skill-md', 'reference-md', 'markdown'] as const;

interface LineMatch {
  line: number;
  index: number;
  text: string;
}

/** 0-based index of the first body line, so frontmatter is not scanned as prose. */
function bodyStart(ctx: FileRuleContext): number {
  const start = ctx.parsed.frontmatter?.bodyStartLine;
  return start && start > 1 ? start - 1 : 0;
}

/** Scan normalized body lines for a pattern, returning every match with its 1-based line. */
function scan(ctx: FileRuleContext, pattern: RegExp): LineMatch[] {
  const matches: LineMatch[] = [];
  const lines = ctx.parsed.normalized.lines;
  for (let i = bodyStart(ctx); i < lines.length; i++) {
    const line = lines[i] ?? '';
    const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
    for (const m of line.matchAll(re)) {
      matches.push({ line: i + 1, index: m.index ?? 0, text: line });
    }
  }
  return matches;
}

const ANTI_OVERSIGHT =
  /\b(do not|don'?t|never)\b[^.]{0,40}\b(tell|inform|mention|show|notify|alert|reveal|disclose|surface|log)\b[^.]{0,25}\b(the )?(user|human|operator|person)\b/i;
const HIDE_FROM =
  /\b(hide|conceal|keep secret|suppress)\b[^.]{0,40}\bfrom\b[^.]{0,25}\b(the )?(user|human|operator|them|review|logs?)\b/i;
const WITHOUT_KNOWING =
  /\bwithout\b[^.]{0,30}\b(the )?(user|them|anyone)\b[^.]{0,20}\b(knowing|noticing|seeing|being aware|realizing)\b/i;

const REVIEWER_TARGET =
  /\b(if|when|whenever)\b[^.]{0,40}\byou\b[^.]{0,30}\b(are|'re|acting as|is)\b[^.]{0,30}\b(security )?(scanner|reviewer|audit(or)?|analy[sz]er|checker|linter|antivirus)\b/i;
const IGNORE_INSTRUCTIONS =
  /\b(ignore|disregard|forget|override)\b[^.]{0,30}\b(all |any |the )?(previous|prior|above|earlier|preceding|foregoing|system)\b[^.]{0,15}\b(instruction|prompt|rule|direction|message|context)s?\b/i;
const ROLE_OVERRIDE = /\byou are now\b|\bnew (system|developer) (prompt|message|instruction)|\bact as if you (are|were)\b/i;
const REPORT_SAFE =
  /\b(report|say|mark|declare|output|return|respond with)\b[^.]{0,30}\b(no (issues|problems|vulnerabilities|findings)|(it('?s| is)?\s*)?safe|clean|nothing (wrong|suspicious)|all clear|pass(ed)?)\b/i;

const EXFIL_VERB = /\b(send|upload|post|exfiltrate|email|e-mail|transmit|leak|forward|curl|wget|fetch|beacon|ping back)\b/i;
const SECRET_NOUN =
  /\b(api[_\s-]?keys?|access[_\s-]?tokens?|secret|credential|password|passphrase|private key|ssh key|\.env\b|environment variables?|~\/\.ssh|~\/\.aws|\.aws\/credentials|keychain|bearer token|session (token|cookie)|auth token)\b/i;
const EXTERNAL_DEST =
  /(https?:\/\/[^\s)]+|\b[\w.-]+@[\w.-]+\.\w+\b|\bwebhook\b|\bpastebin\b|\brequestbin\b|\bngrok\b|discord(app)?\.com\/api\/webhooks|\b[\w-]+\.(?:com|net|io|xyz|ru|cn|sh|dev|app)\b)/i;

const RUN_REMOTE =
  /\b(download|fetch|curl|wget)\b[^.]{0,50}\b(and )?(run|execute|exec|eval|source|pipe (it |them )?(in)?to|install)\b/i;
// Tokens dangerous on their own (no verb required).
const PERMISSION_WEAKEN_STRONG =
  /(--dangerously-skip-permissions|bypass[_\s-]?permissions?|auto[_\s-]?approve|skip (the )?(permission|confirmation)|disable (the )?(permission|safety|guard))/i;
// Config surfaces that are only suspicious when the prose tells you to change them.
const PERMISSION_SURFACE = /\b(settings\.json|allowed[_-]?tools|disallowed[_-]?tools|permission mode)\b/i;
const MODIFY_VERB = /\b(edit|modify|change|add|append|set|update|write|grant|expand|widen|enable|insert)\b/i;

function exampleConfidence(ctx: FileRuleContext, line: number): 'high' | 'medium' | 'low' | undefined {
  const range = rangeAt(line, codeBlockRanges(ctx.parsed));
  if (!range) return undefined;
  return isExampleBlock(range) ? 'low' : 'medium';
}

function findingsFor(
  ctx: FileRuleContext,
  patterns: RegExp[],
  detail: string,
): RuleFinding[] {
  const out: RuleFinding[] = [];
  const seen = new Set<number>();
  for (const pattern of patterns) {
    for (const match of scan(ctx, pattern)) {
      if (seen.has(match.line)) continue;
      seen.add(match.line);
      const finding: RuleFinding = { detail, line: match.line, snippet: match.text.trim() };
      const downgraded = exampleConfidence(ctx, match.line);
      if (downgraded) finding.confidence = downgraded;
      out.push(finding);
    }
  }
  return out;
}

export const nlAntiOversight: FileRule = {
  type: 'file',
  id: 'CMS-NL-001',
  title: 'Instruction to hide activity from the user',
  description: 'Prose telling the agent not to tell, show, or notify the user, or to hide activity from them.',
  defaultSeverity: 'high',
  confidence: 'high',
  tags: ['injection'],
  appliesTo: NL_KINDS,
  remediation: 'A legitimate skill has no reason to instruct the agent to conceal what it is doing from the user.',
  check: (ctx) =>
    findingsFor(ctx, [ANTI_OVERSIGHT, HIDE_FROM, WITHOUT_KNOWING], 'Instructs the agent to conceal its activity from the user.'),
};

export const nlReviewerTargeting: FileRule = {
  type: 'file',
  id: 'CMS-NL-002',
  title: 'Instruction aimed at a reviewing agent or system',
  description: 'Prompt-injection text targeting a reviewer/scanner, or telling the agent to ignore prior instructions.',
  defaultSeverity: 'high',
  confidence: 'high',
  tags: ['injection'],
  appliesTo: NL_KINDS,
  remediation: 'Skill instructions should never address a reviewer or attempt to override the host system prompt.',
  check: (ctx) => {
    const out = findingsFor(
      ctx,
      [IGNORE_INSTRUCTIONS, ROLE_OVERRIDE],
      'Attempts to override prior/system instructions (prompt injection).',
    );
    // Reviewer-targeting + "report safe" is the strongest signal: flag it critical.
    for (const match of scan(ctx, REVIEWER_TARGET)) {
      const nearby = ctx.parsed.normalized.lines
        .slice(Math.max(0, match.line - 2), match.line + 2)
        .join(' ');
      const critical = REPORT_SAFE.test(nearby);
      out.push({
        detail: critical
          ? 'Directs a security scanner/reviewer to report the skill as safe (attempted reviewer manipulation).'
          : 'Contains instructions addressed to a security scanner or reviewer.',
        line: match.line,
        snippet: match.text.trim(),
        severity: critical ? 'critical' : undefined,
      });
    }
    return out;
  },
};

export const nlExfiltration: FileRule = {
  type: 'file',
  id: 'CMS-NL-003',
  title: 'Exfiltration directive in instructions',
  description: 'A sentence combining an exfiltration verb, a secret, and an external destination.',
  defaultSeverity: 'critical',
  confidence: 'high',
  tags: ['injection', 'malcode'],
  appliesTo: NL_KINDS,
  remediation: 'Sending secrets or credentials to an external destination is exfiltration; do not install this skill.',
  check: (ctx) => {
    const out: RuleFinding[] = [];
    const lines = ctx.parsed.normalized.lines;
    for (let i = 0; i < lines.length; i++) {
      // Look within a small window so a verb and its object can span a sentence.
      const window = lines.slice(i, i + 2).join(' ');
      if (EXFIL_VERB.test(window) && SECRET_NOUN.test(window) && EXTERNAL_DEST.test(window)) {
        const finding: RuleFinding = {
          detail: 'Instruction combines sending/uploading, a secret, and an external destination.',
          line: i + 1,
          snippet: (lines[i] ?? '').trim(),
        };
        const downgraded = exampleConfidence(ctx, i + 1);
        // Exfil prose in an example block is still high-severity; only nudge confidence.
        if (downgraded === 'low') finding.confidence = 'medium';
        out.push(finding);
      }
    }
    return out;
  },
};

export const nlPermissionWeakening: FileRule = {
  type: 'file',
  id: 'CMS-NL-004',
  title: 'Instruction to weaken permissions or safety controls',
  description: 'Prose referencing settings.json, allowed-tools, or skipping/bypassing permission prompts.',
  defaultSeverity: 'high',
  confidence: 'medium',
  tags: ['permissions', 'persistence'],
  appliesTo: NL_KINDS,
  remediation: 'Skills should request the least privilege they need, never instruct the agent to disable safety prompts.',
  check: (ctx) => {
    const out: RuleFinding[] = [];
    const seen = new Set<number>();
    const push = (match: LineMatch, detail: string) => {
      if (seen.has(match.line)) return;
      seen.add(match.line);
      const finding: RuleFinding = { detail, line: match.line, snippet: match.text.trim() };
      const downgraded = exampleConfidence(ctx, match.line);
      if (downgraded) finding.confidence = downgraded;
      out.push(finding);
    };
    for (const match of scan(ctx, PERMISSION_WEAKEN_STRONG)) {
      push(match, 'Instructs bypassing or disabling permission/safety prompts.');
    }
    for (const match of scan(ctx, PERMISSION_SURFACE)) {
      if (MODIFY_VERB.test(match.text)) push(match, 'Instructs modifying a permissions configuration surface.');
    }
    return out;
  },
};

export const nlRunRemote: FileRule = {
  type: 'file',
  id: 'CMS-NL-005',
  title: 'Instruction to download and run remote code',
  description: 'Prose telling the agent to fetch and execute code from a remote location.',
  defaultSeverity: 'medium',
  confidence: 'medium',
  tags: ['malcode'],
  appliesTo: NL_KINDS,
  remediation: 'Fetching and running remote code hides the payload from this scan; review what would actually run.',
  check: (ctx) => findingsFor(ctx, [RUN_REMOTE], 'Instructs the agent to download and execute remote code.'),
};

export const nlRules: FileRule[] = [
  nlAntiOversight,
  nlReviewerTargeting,
  nlExfiltration,
  nlPermissionWeakening,
  nlRunRemote,
];
