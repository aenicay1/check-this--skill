export interface EncodedRun {
  /** 1-based column where the run starts. */
  column: number;
  text: string;
  encoding: 'base64' | 'hex';
}

const BASE64_RUN = /[A-Za-z0-9+/]{40,}={0,2}/g;
const HEX_RUN = /(?:[0-9a-fA-F]{2}){20,}/g;

/** Find long base64/hex-looking runs on a single line. */
export function findEncodedRuns(line: string, minLen = 200): EncodedRun[] {
  const runs: EncodedRun[] = [];
  for (const match of line.matchAll(BASE64_RUN)) {
    if (match[0].length >= minLen) runs.push({ column: (match.index ?? 0) + 1, text: match[0], encoding: 'base64' });
  }
  for (const match of line.matchAll(HEX_RUN)) {
    if (match[0].length >= minLen) runs.push({ column: (match.index ?? 0) + 1, text: match[0], encoding: 'hex' });
  }
  return runs;
}

/**
 * Decode a base64/hex run to UTF-8 if the result is mostly printable text;
 * returns undefined for binary payloads.
 */
export function tryDecodeToText(run: EncodedRun): string | undefined {
  let buf: Buffer;
  try {
    buf = run.encoding === 'base64' ? Buffer.from(run.text, 'base64') : Buffer.from(run.text, 'hex');
  } catch {
    return undefined;
  }
  if (buf.length === 0) return undefined;
  const text = buf.toString('utf8');
  let printable = 0;
  let total = 0;
  for (const ch of text) {
    total += 1;
    const cp = ch.codePointAt(0) ?? 0;
    if (cp === 0x09 || cp === 0x0a || cp === 0x0d || (cp >= 0x20 && cp < 0x7f)) printable += 1;
  }
  if (total === 0 || printable / total < 0.9) return undefined;
  return text;
}
