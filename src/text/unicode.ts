import type { InvisibleHit, NormalizedText } from '../types.js';

// Only the embedding/override/isolate controls used in Trojan-Source attacks.
// The plain directional marks (LRM/RLM/ALM, U+200E/200F/061C) are excluded:
// they are normal, ubiquitous in legitimate Arabic/Hebrew text, and flagging
// them would block any RTL-containing skill.
const BIDI_CONTROLS = new Set([
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // embedding/override controls
  0x2066, 0x2067, 0x2068, 0x2069, // isolate controls
]);

export function isBidiControl(codePoint: number): boolean {
  return BIDI_CONTROLS.has(codePoint);
}

/**
 * Invisible/format characters that can hide text from a human reader.
 * Bidi controls are excluded here because they are reported as their own,
 * more severe category (Trojan-Source style attacks).
 */
export function isInvisibleFormat(codePoint: number): boolean {
  if (BIDI_CONTROLS.has(codePoint)) return false;
  if (codePoint === 0x00ad) return true; // soft hyphen
  if (codePoint === 0x034f) return true; // combining grapheme joiner
  if (codePoint === 0x180e) return true; // mongolian vowel separator
  // ZWSP only. ZWNJ (U+200C) and ZWJ (U+200D) are excluded: they are legitimate
  // in emoji sequences and Indic/Arabic/Persian scripts, and flagging ZWJ would
  // trip on any composite emoji. ZWSP has essentially no benign use in prose.
  if (codePoint === 0x200b) return true; // zero-width space
  if (codePoint === 0x2028 || codePoint === 0x2029) return true; // line/paragraph separator
  if (codePoint >= 0x2060 && codePoint <= 0x2064) return true; // word joiner, invisible operators
  if (codePoint === 0x115f || codePoint === 0x1160) return true; // hangul choseong/jungseong filler
  if (codePoint === 0x3164 || codePoint === 0xffa0) return true; // hangul filler forms
  if (codePoint >= 0xfff9 && codePoint <= 0xfffb) return true; // interlinear annotation
  if (codePoint === 0xfeff) return true; // ZWNBSP / stray BOM
  if (codePoint >= 0xe0000 && codePoint <= 0xe007f) return true; // tag characters
  return false;
}

export function codePointLabel(codePoint: number): string {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`;
}

/**
 * Produce the normalized view rules match against: per-line NFKC with
 * invisibles stripped, plus a record of every invisible/bidi character found.
 * Normalizing per line keeps line numbers stable for findings.
 */
export function analyzeLines(rawLines: string[]): NormalizedText {
  const invisibles: InvisibleHit[] = [];
  const bidi: InvisibleHit[] = [];
  const lines: string[] = [];
  let changed = false;

  for (let i = 0; i < rawLines.length; i++) {
    const raw = rawLines[i] ?? '';
    let kept = '';
    let column = 0;
    for (const ch of raw) {
      column += 1;
      const cp = ch.codePointAt(0) ?? 0;
      if (isBidiControl(cp)) {
        bidi.push({ codePoint: cp, line: i + 1, column });
        changed = true;
        continue;
      }
      if (isInvisibleFormat(cp)) {
        invisibles.push({ codePoint: cp, line: i + 1, column });
        changed = true;
        continue;
      }
      kept += ch;
    }
    const normalized = kept.normalize('NFKC');
    if (normalized !== raw) changed = true;
    lines.push(normalized);
  }

  return { lines, invisibles, bidi, changed };
}
