import { codePointLabel, isBidiControl, isInvisibleFormat } from './unicode.js';

// CSI, OSC, and single-character escape sequences.
const ANSI_PATTERN = /\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-Z\\-_])/g;

/**
 * Make untrusted text safe to print in a terminal or embed in a report:
 * strip ANSI escapes, render control and invisible characters visibly
 * (e.g. a zero-width space becomes ⟨U+200B⟩), and cap the length.
 */
export function sanitizeSnippet(raw: string, maxLen = 200): string {
  let s = raw.replace(/\r?\n/g, ' ⏎ ');
  s = s.replace(ANSI_PATTERN, '');
  let out = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp === 0x09) {
      out += ' ';
      continue;
    }
    if (cp < 0x20 || cp === 0x7f || isBidiControl(cp) || isInvisibleFormat(cp)) {
      out += `⟨${codePointLabel(cp)}⟩`;
      continue;
    }
    out += ch;
  }
  if (out.length > maxLen) out = `${out.slice(0, maxLen - 1)}…`;
  return out;
}
