import type { Html, Node } from 'mdast';
import { codePointLabel } from '../../text/unicode.js';
import { findEncodedRuns, tryDecodeToText } from '../util/base64.js';
import { shannonEntropy } from '../util/entropy.js';
import type { FileRule, FileRuleContext, RuleFinding } from '../../types.js';

const ALL_TEXT = ['skill-md', 'reference-md', 'markdown', 'shell', 'python', 'javascript', 'manifest', 'other'] as const;
const MARKDOWN_KINDS = ['skill-md', 'reference-md', 'markdown'] as const;

// Scripts and confusable-letter tables: Latin plus the scripts most used for
// homoglyph attacks against ASCII identifiers.
const CYRILLIC = /[Ѐ-ӿ]/;
const GREEK = /[Ͱ-Ͽ]/;
const LATIN = /[A-Za-z]/;

export const hidInvisible: FileRule = {
  type: 'file',
  id: 'CMS-HID-001',
  title: 'Invisible or zero-width characters',
  description: 'Format/invisible code points that hide text from a human reader.',
  defaultSeverity: 'high',
  confidence: 'high',
  tags: ['hidden'],
  appliesTo: ALL_TEXT,
  remediation: 'Invisible characters in instructions are almost always an attempt to hide content from review.',
  check: (ctx) => {
    const hits = ctx.parsed.normalized.invisibles;
    if (hits.length === 0) return [];
    const byLine = new Map<number, number[]>();
    for (const hit of hits) {
      const arr = byLine.get(hit.line) ?? [];
      arr.push(hit.codePoint);
      byLine.set(hit.line, arr);
    }
    const out: RuleFinding[] = [];
    for (const [line, cps] of [...byLine.entries()].sort((a, b) => a[0] - b[0])) {
      const labels = [...new Set(cps.map(codePointLabel))].join(', ');
      out.push({
        detail: `${cps.length} invisible character${cps.length === 1 ? '' : 's'} (${labels}) hidden in the text.`,
        line,
        snippet: (ctx.parsed.lines[line - 1] ?? '').trim(),
      });
    }
    return out;
  },
};

export const hidBidi: FileRule = {
  type: 'file',
  id: 'CMS-HID-002',
  title: 'Bidirectional control characters (Trojan Source)',
  description: 'Bidi override/isolate code points that can reorder how text is displayed.',
  defaultSeverity: 'critical',
  confidence: 'high',
  tags: ['hidden'],
  appliesTo: ALL_TEXT,
  remediation: 'Bidi controls let displayed text differ from what executes; treat as a deliberate obfuscation attack.',
  check: (ctx) => {
    const hits = ctx.parsed.normalized.bidi;
    if (hits.length === 0) return [];
    const byLine = new Map<number, number[]>();
    for (const hit of hits) {
      const arr = byLine.get(hit.line) ?? [];
      arr.push(hit.codePoint);
      byLine.set(hit.line, arr);
    }
    const out: RuleFinding[] = [];
    for (const [line, cps] of [...byLine.entries()].sort((a, b) => a[0] - b[0])) {
      const labels = [...new Set(cps.map(codePointLabel))].join(', ');
      out.push({
        detail: `Bidirectional control character${cps.length === 1 ? '' : 's'} (${labels}) present.`,
        line,
        snippet: (ctx.parsed.lines[line - 1] ?? '').trim(),
      });
    }
    return out;
  },
};

export const hidHomoglyph: FileRule = {
  type: 'file',
  id: 'CMS-HID-003',
  title: 'Mixed-script homoglyphs',
  description: 'ASCII-looking words containing letters from another script (e.g. Cyrillic "а").',
  defaultSeverity: 'medium',
  confidence: 'medium',
  tags: ['hidden'],
  appliesTo: ALL_TEXT,
  remediation: 'Mixed-script words can disguise a command or domain as a familiar one; verify the real characters.',
  check: (ctx) => {
    const out: RuleFinding[] = [];
    const lines = ctx.parsed.lines;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      for (const word of line.split(/[^\p{L}]+/u)) {
        if (word.length < 3) continue;
        if (!LATIN.test(word)) continue;
        if (CYRILLIC.test(word) || GREEK.test(word)) {
          out.push({
            detail: `Word "${word}" mixes Latin with another script (possible homoglyph disguise).`,
            line: i + 1,
            snippet: line.trim(),
          });
          break; // one finding per line is enough
        }
      }
    }
    return out;
  },
};

interface HtmlNode extends Node {
  value?: string;
  children?: HtmlNode[];
}

export const hidHtmlComment: FileRule = {
  type: 'file',
  id: 'CMS-HID-004',
  title: 'Hidden HTML comment with instructions',
  description: 'HTML comments in markdown containing imperative verbs or URLs (invisible when rendered).',
  defaultSeverity: 'medium',
  confidence: 'medium',
  tags: ['hidden', 'injection'],
  appliesTo: MARKDOWN_KINDS,
  remediation: 'Comments are invisible in rendered markdown but read by the agent; review what they instruct.',
  check: (ctx) => {
    const root = ctx.parsed.mdast as HtmlNode | undefined;
    if (!root) return [];
    const out: RuleFinding[] = [];
    const stack: HtmlNode[] = [root];
    // Keyed on genuinely instruction/injection-shaped content, not everyday
    // words like "run"/"install"/"http" that appear in most real comments.
    const imperative =
      /<!--[\s\S]*?(\bignore (all|previous|prior)\b|\byou are (a|an|now)\b|\bsystem prompt\b|\bdo not (tell|mention|reveal|show)\b|\bexfiltrat|\|\s*(ba|z)?sh\b|\bcurl\b[^\n]*\|\s*sh|~\/\.(ssh|aws)|\.env\b)[\s\S]*?-->/i;
    while (stack.length > 0) {
      const node = stack.pop() as HtmlNode;
      if (node.type === 'html' && typeof node.value === 'string' && node.value.includes('<!--')) {
        if (imperative.test(node.value)) {
          const pos = (node as Html).position;
          out.push({
            detail: 'HTML comment (hidden in rendered output) contains instructions or a URL.',
            line: pos?.start.line,
            snippet: node.value,
          });
        }
      }
      if (node.children) stack.push(...node.children);
    }
    return out;
  },
};

export const hidEncodedBlob: FileRule = {
  type: 'file',
  id: 'CMS-HID-005',
  title: 'Large high-entropy encoded blob',
  description: 'A long base64/hex run with high entropy; escalates if it decodes to shell/URL content.',
  defaultSeverity: 'medium',
  confidence: 'medium',
  tags: ['hidden', 'malcode'],
  appliesTo: ALL_TEXT,
  remediation: 'Encoded blobs hide their payload from review; decode and inspect before trusting the skill.',
  check: (ctx) => {
    const out: RuleFinding[] = [];
    const lines = ctx.parsed.lines;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      for (const run of findEncodedRuns(line)) {
        if (shannonEntropy(run.text) < 4.0) continue;
        const decoded = tryDecodeToText(run);
        // Escalate only on executable content, not a bare URL: base64 data URIs
        // for small SVG/HTML assets legitimately contain URLs.
        const dangerous =
          decoded !== undefined &&
          /(\b(curl|wget)\b[^\n]*\|\s*(ba|z)?sh|\beval\s*\(|\bexec\s*\(|\/dev\/tcp\/|\bsubprocess\b|\bos\.system\b|\bimport\s+socket\b|\|\s*(ba|z)?sh\b)/i.test(decoded);
        out.push({
          detail: dangerous
            ? `Encoded ${run.encoding} blob decodes to shell/URL content.`
            : `Long high-entropy ${run.encoding} blob (${run.text.length} chars) hides its content from review.`,
          line: i + 1,
          severity: dangerous ? 'high' : undefined,
          snippet: `${run.text.slice(0, 60)}… (${run.text.length} chars)`,
        });
      }
    }
    return out;
  },
};

export const hidCssHiding: FileRule = {
  type: 'file',
  id: 'CMS-HID-006',
  title: 'Visually hidden content',
  description: 'Inline HTML/CSS that hides text (display:none, font-size:0, white-on-white).',
  defaultSeverity: 'low',
  confidence: 'medium',
  tags: ['hidden'],
  appliesTo: MARKDOWN_KINDS,
  remediation: 'Content styled to be invisible to a human reader is still read by the agent.',
  check: (ctx) => {
    const out: RuleFinding[] = [];
    const lines = ctx.parsed.lines;
    const pattern =
      /(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*#?(fff(fff)?|white)\b|opacity\s*:\s*0)/i;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (pattern.test(line)) {
        out.push({ detail: 'Inline style hides content from a human reader.', line: i + 1, snippet: line.trim() });
      }
    }
    return out;
  },
};

export const hiddenRules: FileRule[] = [
  hidInvisible,
  hidBidi,
  hidHomoglyph,
  hidHtmlComment,
  hidEncodedBlob,
  hidCssHiding,
];
