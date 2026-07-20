import type { Node } from 'mdast';
import type { ParsedFile } from '../../types.js';

export interface CodeBlockRange {
  start: number;
  end: number;
  lang?: string;
  meta?: string;
}

interface PositionedNode extends Node {
  children?: PositionedNode[];
  lang?: string | null;
  meta?: string | null;
}

/**
 * Line ranges (1-based, inclusive) of fenced/indented code blocks in a
 * markdown file. Used to downgrade confidence for matches that live inside
 * example blocks rather than instruction prose.
 */
export function codeBlockRanges(parsed: ParsedFile): CodeBlockRange[] {
  const ranges: CodeBlockRange[] = [];
  const root = parsed.mdast as PositionedNode | undefined;
  if (!root) return ranges;
  const stack: PositionedNode[] = [root];
  while (stack.length > 0) {
    const node = stack.pop() as PositionedNode;
    if (node.type === 'code' && node.position) {
      ranges.push({
        start: node.position.start.line,
        end: node.position.end.line,
        lang: node.lang ?? undefined,
        meta: node.meta ?? undefined,
      });
    }
    if (node.children) stack.push(...node.children);
  }
  ranges.sort((a, b) => a.start - b.start);
  return ranges;
}

export function rangeAt(line: number, ranges: CodeBlockRange[]): CodeBlockRange | undefined {
  return ranges.find((r) => line >= r.start && line <= r.end);
}

/** A code block explicitly marked as illustrative rather than operative. */
export function isExampleBlock(range: CodeBlockRange): boolean {
  const label = `${range.lang ?? ''} ${range.meta ?? ''}`;
  return /\b(example|sample|illustration|do-not-run|donotrun)\b/i.test(label);
}
