import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import type { Readable } from 'node:stream';
import { Parser } from 'tar';
import { ScanError } from '../types.js';

export interface ExtractCaps {
  maxEntries: number;
  maxTotalBytes: number;
  maxEntryBytes: number;
}

export const DEFAULT_EXTRACT_CAPS: ExtractCaps = {
  maxEntries: 5000,
  maxTotalBytes: 100 * 1024 * 1024,
  maxEntryBytes: 5 * 1024 * 1024,
};

function safeJoin(root: string, entryPath: string): string | undefined {
  // Reject absolute paths and any traversal that escapes the root, rather than
  // silently containing it, so an escape attempt is recorded as skipped.
  if (path.isAbsolute(entryPath)) return undefined;
  const resolved = path.resolve(root, entryPath);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) return undefined;
  return resolved;
}

/**
 * Extract a gzipped tar stream into destDir with hostile-archive defenses:
 *  - path traversal (zip-slip) rejected via realpath-prefix check
 *  - symlink, hardlink, and device/fifo entries dropped entirely (a skill
 *    bundle never needs them, and they are classic escape vectors)
 *  - entry-count, per-entry, and total-size caps to stop tar bombs
 * Strips the leading path component (GitHub tarballs nest under a top dir).
 */
export async function extractTarball(
  source: Readable,
  destDir: string,
  caps: ExtractCaps = DEFAULT_EXTRACT_CAPS,
): Promise<{ entries: number; skipped: string[] }> {
  await mkdir(destDir, { recursive: true });
  const root = path.resolve(destDir);
  const skipped: string[] = [];
  let entries = 0;
  let totalBytes = 0;

  const parser = new Parser({
    gzip: true,
    filter: (entryPath, entry) => {
      const type = (entry as { type?: string }).type ?? 'File';
      if (type === 'SymbolicLink' || type === 'Link') {
        skipped.push(`${entryPath} (link entry rejected)`);
        return false;
      }
      if (type !== 'File' && type !== 'Directory') {
        skipped.push(`${entryPath} (non-regular entry rejected)`);
        return false;
      }
      return true;
    },
  });

  // Each entry's write is tracked here and awaited AFTER the parse stream
  // completes: pipeline(source, parser) resolves when the archive bytes are
  // consumed, not when the per-entry writes have flushed, so returning without
  // this join would hand walkBundle truncated files.
  const pending: Promise<void>[] = [];
  let aborted = false;

  parser.on('entry', (entry) => {
    pending.push(handleEntry(entry));
  });

  async function handleEntry(entry: {
    path: string;
    type: string;
    size?: number;
    resume: () => void;
  }): Promise<void> {
    try {
      // Strip the top-level directory GitHub wraps everything in.
      const stripped = entry.path.split('/').slice(1).join('/');
      if (!stripped) {
        entry.resume();
        return;
      }
      if (entries >= caps.maxEntries || totalBytes >= caps.maxTotalBytes) {
        if (!aborted) {
          aborted = true;
          skipped.push(`archive caps reached (${caps.maxEntries} entries / ${caps.maxTotalBytes} bytes); extraction stopped`);
          source.destroy();
        }
        entry.resume();
        return;
      }
      if ((entry.size ?? 0) > caps.maxEntryBytes) {
        skipped.push(`${stripped} (entry exceeds size cap)`);
        entry.resume();
        return;
      }
      const dest = safeJoin(root, stripped);
      if (!dest) {
        skipped.push(`${entry.path} (path traversal rejected)`);
        entry.resume();
        return;
      }
      if (entry.type === 'Directory') {
        await mkdir(dest, { recursive: true });
        entry.resume();
        return;
      }
      await mkdir(path.dirname(dest), { recursive: true });
      entries += 1;
      totalBytes += entry.size ?? 0;
      await pipeline(entry as unknown as NodeJS.ReadableStream, createWriteStream(dest));
    } catch (err) {
      // Record rather than swallow, so a file missing from the scan is visible.
      skipped.push(`${entry.path} (write failed: ${(err as Error).message})`);
      entry.resume();
    }
  }

  try {
    await pipeline(source, parser);
  } catch (err) {
    // A destroy() we initiated on hitting the caps surfaces here as a premature
    // close; that is an intentional stop, not an extraction failure.
    if (!aborted) throw new ScanError(`failed to extract archive: ${(err as Error).message}`, { cause: err });
  }
  await Promise.all(pending);
  return { entries, skipped };
}
