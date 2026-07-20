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
    const raw = lines[i] ?? '';
    // Bound the regex input so a hostile long line cannot drive backtracking.
    const line = raw.length > MAX_SCAN_LINE ? raw.slice(0, MAX_SCAN_LINE) : raw;
    const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
    for (const m of line.matchAll(re)) {
      matches.push({ line: i + 1, index: m.index ?? 0, text: line });
    }
  }
  return matches;
}

const MAX_SCAN_LINE = 4000;

const ANTI_OVERSIGHT =
  /\b(do not|don'?t|never)\b[^.]{0,40}\b(tell|inform|mention|show|notify|alert|reveal|disclose|surface|log)\b[^.]{0,25}\b(the )?(user|human|operator|person)\b/i;
// Require the hidden thing to be an action/fact/output, not a UI element, so
// "hide the spinner from the user" does not match.
const HIDE_FROM =
  /\b(hide|conceal|keep secret|suppress)\b[^.]{0,30}\b(this|that|the fact|what|the action|the command|the output|the file|the change|the step|your|it|these)\b[^.]{0,30}\bfrom\b[^.]{0,20}\b(the )?(user|human|operator|them|review|logs?)\b/i;
const WITHOUT_KNOWING =
  /\bwithout\b[^.]{0,30}\b(the )?(user|them|anyone)\b[^.]{0,20}\b(knowing|noticing|being aware|realizing|finding out)\b/i;

const REVIEWER_TARGET =
  /\b(if|when|whenever)\b[^.]{0,40}\byou\b[^.]{0,30}\b(are|'re|acting as|is)\b[^.]{0,30}\b(security )?(scanner|reviewer|audit(or)?|analy[sz]er|checker|linter|antivirus)\b/i;
const IGNORE_INSTRUCTIONS =
  /\b(ignore|disregard|forget|override)\b[^.]{0,30}\b(all |any |the )?(previous|prior|above|earlier|preceding|foregoing)\b[^.]{0,15}\b(instruction|prompt|rule|direction|message|context)s?\b/i;
// "you are now <role>" (a role reassignment) / "act as if you were"; a bare
// "you are now ready/done" is common English and is not matched.
const ROLE_OVERRIDE =
  /\byou are now (a |an |the |in |going to be )?(?!ready|done|able|set|good|all)\w+|\bact as if you (are|were)\b|\bnew (system|developer) (prompt|message) (that )?(says|reads|is)\b/i;
const REPORT_SAFE =
  /\b(report|say|mark|declare|output|return|respond with)\b[^.]{0,30}\b(no (issues|problems|vulnerabilities|findings)|(it('?s| is)?\s*)?safe|clean|nothing (wrong|suspicious)|all clear|pass(ed)?)\b/i;

const EXFIL_VERB = /\b(send|upload|post|exfiltrate|email|e-mail|transmit|leak|forward|beacon|ping back)\b/i;
// Strong credential/secret indicators. Deliberately excludes bare "access
// token" / "Authorization header" / "bearer token", which appear in normal
// first-party API authentication and are not by themselves exfiltration.
const SECRET_NOUN =
  /\b(\.env\b|~\/\.ssh|~\/\.aws|\.aws\/credentials|id_(rsa|ed25519|ecdsa)|private key|ssh key|keychain|\.npmrc|credentials file|secret key|password|passphrase|api[_\s-]?keys?)\b/i;
const EXTERNAL_DEST =
  /(https?:\/\/[^\s)]+|\b[\w.-]+@[\w.-]+\.\w+\b|\bwebhook\b|\bpastebin\b|\brequestbin\b|\bngrok\b|discord(app)?\.com\/api\/webhooks)/i;

// Requires a concrete remote target (URL or script file) between the fetch and
// the execute verb, so prose like "fetch the deployment run" does not match.
const RUN_REMOTE =
  /\b(download|fetch|curl|wget)\b[^.\n]{0,60}?(https?:\/\/\S+|\S+\.(sh|py|js|command|ps1|exe|bin)\b|\bremote (script|code|payload|installer)\b)[^.\n]{0,40}?\b(and\s+)?(run|execute|exec|eval|source|bash|sh|install)\b/i;
// Tokens dangerous on their own (no verb required). Bare mode names like
// "auto-approve" are intentionally excluded: they are legitimate feature names
// and only matter with an enabling verb (handled via the surface path below).
const PERMISSION_WEAKEN_STRONG =
  /(--dangerously-skip-permissions|bypass[_\s-]?permissions?|skip (the )?(permission|confirmation) (prompt|check)|disable (the )?(permission|safety|guard))/i;
// Config surfaces that are only suspicious when the prose tells you to change
// them. "settings.json" is qualified with .claude/ so a mention of VS Code's
// settings.json does not match.
const PERMISSION_SURFACE = /\b(\.claude\/settings|allowed[_-]?tools|disallowed[_-]?tools|permission mode)\b/i;
const MODIFY_VERB = /\b(edit|modify|change|add|append|set|update|write|grant|expand|widen|insert)\b/i;

// Cues that the matched phrase is being discussed or quoted as an example
// rather than issued as an instruction (documentation about these patterns).
const DISCUSSION_CUE = /\b(avoid|don'?t|do not|never|instead of|rather than|e\.g\.|for example|such as|anti-pattern)\b/i;

function isDiscussed(line: string, index: number): boolean {
  if (DISCUSSION_CUE.test(line)) return true;
  // Match wrapped in quotes or backticks nearby.
  const before = line.slice(Math.max(0, index - 2), index);
  return /["'`“”]/.test(before);
}

type BlockContext = 'prose' | 'code' | 'example';

/**
 * Where a line sits relative to fenced code:
 *  - 'example': a block explicitly labeled example/sample; prose rules skip it,
 *    since it documents a pattern rather than instructing the agent.
 *  - 'code': any other fenced block; likely a command example, so prose rules
 *    report it at low confidence (damped to CAUTION unless --strict).
 *  - 'prose': ordinary instruction text; full confidence.
 */
function blockContext(ctx: FileRuleContext, line: number): BlockContext {
  const range = rangeAt(line, codeBlockRanges(ctx.parsed));
  if (!range) return 'prose';
  return isExampleBlock(range) ? 'example' : 'code';
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
      const ctxKind = blockContext(ctx, match.line);
      if (ctxKind === 'example') continue;
      const finding: RuleFinding = { detail, line: match.line, snippet: match.text.trim() };
      if (ctxKind === 'code' || isDiscussed(match.text, match.index)) finding.confidence = 'low';
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
      const ctxKind = blockContext(ctx, match.line);
      if (ctxKind === 'example') continue;
      const nearby = ctx.parsed.normalized.lines
        .slice(Math.max(0, match.line - 2), match.line + 2)
        .join(' ');
      const critical = REPORT_SAFE.test(nearby);
      const damped = ctxKind === 'code' || isDiscussed(match.text, match.index);
      out.push({
        detail: critical
          ? 'Directs a security scanner/reviewer to report the skill as safe (attempted reviewer manipulation).'
          : 'Contains instructions addressed to a security scanner or reviewer.',
        line: match.line,
        snippet: match.text.trim(),
        severity: critical ? 'critical' : undefined,
        confidence: damped ? 'low' : undefined,
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
      const window = lines.slice(i, i + 2).join(' ').slice(0, MAX_SCAN_LINE * 2);
      if (EXFIL_VERB.test(window) && SECRET_NOUN.test(window) && EXTERNAL_DEST.test(window)) {
        const ctxKind = blockContext(ctx, i + 1);
        if (ctxKind === 'example') continue;
        const finding: RuleFinding = {
          detail: 'Instruction combines sending/uploading, a secret, and an external destination.',
          line: i + 1,
          snippet: (lines[i] ?? '').trim(),
        };
        // Exfil prose is the real signal; a match inside a code fence, or one
        // that reads as documentation/quotation, is dropped to low confidence
        // (which damps the verdict to CAUTION unless --strict).
        if (ctxKind === 'code' || isDiscussed(window, 0)) finding.confidence = 'low';
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
      const ctxKind = blockContext(ctx, match.line);
      if (ctxKind === 'example') return;
      const finding: RuleFinding = { detail, line: match.line, snippet: match.text.trim() };
      if (ctxKind === 'code') finding.confidence = 'low';
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
