import { createHash } from 'node:crypto';
import { lstat, readFile, readdir, readlink } from 'node:fs/promises';
import path from 'node:path';
import type { Bundle, BundleFile, BundleSource, FileKind, SymlinkEntry } from '../types.js';

export interface WalkCaps {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  maxDepth: number;
}

export const DEFAULT_CAPS: WalkCaps = {
  maxFiles: 2000,
  maxFileBytes: 1024 * 1024,
  maxTotalBytes: 50 * 1024 * 1024,
  maxDepth: 32,
};

// Vendored/VCS content is inventoried as a note, not scanned file-by-file.
// Dependency risk is covered by the manifest/lockfile audit instead.
const SKIP_DIRS = new Set(['.git', '.hg', '.svn', 'node_modules', '.venv', 'venv', '__pycache__']);

const MANIFEST_NAMES = new Set([
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'pyproject.toml',
  'pipfile',
  'pipfile.lock',
  'poetry.lock',
]);

const SHELL_EXTS = new Set(['.sh', '.bash', '.zsh']);
const JS_EXTS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts']);
const MD_EXTS = new Set(['.md', '.markdown', '.mdx']);
const BINARY_EXTS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.pdf',
  '.zip', '.gz', '.tgz', '.tar', '.7z',
  '.woff', '.woff2', '.ttf', '.eot',
  '.mp3', '.mp4', '.mov', '.wasm',
  '.exe', '.dll', '.so', '.dylib', '.pyc', '.class', '.jar', '.bin',
]);

function classifyByPath(relPath: string): FileKind | undefined {
  const base = path.posix.basename(relPath).toLowerCase();
  const ext = path.posix.extname(base);
  if (base === 'skill.md') return 'skill-md';
  if (MANIFEST_NAMES.has(base) || /^requirements[^/]*\.txt$/.test(base)) return 'manifest';
  if (MD_EXTS.has(ext)) {
    const dirs = relPath.toLowerCase().split('/').slice(0, -1);
    return dirs.includes('references') || dirs.includes('reference') ? 'reference-md' : 'markdown';
  }
  if (SHELL_EXTS.has(ext)) return 'shell';
  if (ext === '.py') return 'python';
  if (JS_EXTS.has(ext)) return 'javascript';
  if (BINARY_EXTS.has(ext)) return 'binary';
  return undefined;
}

function classifyByShebang(text: string): FileKind | undefined {
  if (!text.startsWith('#!')) return undefined;
  const nl = text.indexOf('\n');
  const first = nl === -1 ? text : text.slice(0, nl);
  if (/\bpython[0-9.]*\b/.test(first)) return 'python';
  if (/\b(node|deno|bun)\b/.test(first)) return 'javascript';
  // Any other shebang still marks an executable script; treat as shell.
  return 'shell';
}

function hasUtf16Bom(buf: Buffer): boolean {
  return buf.length >= 2 && ((buf[0] === 0xff && buf[1] === 0xfe) || (buf[0] === 0xfe && buf[1] === 0xff));
}

function looksBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

function decodeText(buf: Buffer): { text: string; encoding: 'utf8' | 'utf16le' | 'utf16be' } {
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return { text: buf.subarray(2).toString('utf16le'), encoding: 'utf16le' };
  }
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    const swapped = Buffer.from(buf.subarray(2));
    swapped.swap16();
    return { text: swapped.toString('utf16le'), encoding: 'utf16be' };
  }
  let text = buf.toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return { text, encoding: 'utf8' };
}

/**
 * Inventory a bundle directory. Read-only by construction: never follows
 * symlinks, never executes anything, and enforces hard caps so a hostile
 * bundle cannot exhaust the scanner.
 */
export async function walkBundle(
  rootDir: string,
  source: BundleSource,
  caps: WalkCaps = DEFAULT_CAPS,
): Promise<Bundle> {
  const files: BundleFile[] = [];
  const symlinks: SymlinkEntry[] = [];
  const notes: string[] = [];
  let totalBytes = 0;
  let stopped = false;

  async function visit(dir: string, depth: number): Promise<void> {
    if (stopped) return;
    if (depth > caps.maxDepth) {
      notes.push(`skipped ${path.relative(rootDir, dir) || '.'}: exceeds max directory depth (${caps.maxDepth})`);
      return;
    }
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch (err) {
      notes.push(`could not read directory ${path.relative(rootDir, dir) || '.'}: ${(err as Error).message}`);
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (stopped) return;
      const abs = path.join(dir, entry.name);
      const rel = path.relative(rootDir, abs).split(path.sep).join('/');

      if (entry.isSymbolicLink()) {
        let target = '';
        try {
          target = await readlink(abs);
        } catch {
          // unreadable link target; still record the link itself
        }
        const resolved = path.resolve(dir, target);
        const escapes = resolved !== rootDir && !resolved.startsWith(rootDir + path.sep);
        symlinks.push({ relPath: rel, target, escapesBundle: escapes });
        continue;
      }

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) {
          notes.push(`skipped directory ${rel}/ (vendored or VCS content is not scanned file-by-file)`);
          continue;
        }
        await visit(abs, depth + 1);
        continue;
      }

      if (!entry.isFile()) {
        notes.push(`skipped ${rel}: not a regular file`);
        continue;
      }

      if (files.length >= caps.maxFiles) {
        notes.push(`file cap reached (${caps.maxFiles}); remaining files were not scanned`);
        stopped = true;
        return;
      }

      let size = 0;
      try {
        size = (await lstat(abs)).size;
      } catch (err) {
        notes.push(`could not stat ${rel}: ${(err as Error).message}`);
        continue;
      }

      const pathKind = classifyByPath(rel);
      if (size > caps.maxFileBytes) {
        files.push({
          relPath: rel,
          absPath: abs,
          kind: pathKind ?? 'other',
          size,
          skippedReason: `file exceeds the per-file scan cap (${caps.maxFileBytes} bytes)`,
        });
        continue;
      }

      if (totalBytes + size > caps.maxTotalBytes) {
        notes.push(`total size cap reached (${caps.maxTotalBytes} bytes); scan stopped early`);
        stopped = true;
        return;
      }

      let buf: Buffer;
      try {
        buf = await readFile(abs);
      } catch (err) {
        notes.push(`could not read ${rel}: ${(err as Error).message}`);
        continue;
      }
      totalBytes += buf.length;
      const sha256 = createHash('sha256').update(buf).digest('hex');

      if (pathKind === 'binary' || (!hasUtf16Bom(buf) && looksBinary(buf))) {
        files.push({
          relPath: rel,
          absPath: abs,
          kind: 'binary',
          size,
          sha256,
          skippedReason: 'binary content is inventoried but not text-scanned',
        });
        continue;
      }

      const { text, encoding } = decodeText(buf);
      const kind = pathKind ?? classifyByShebang(text) ?? 'other';
      const file: BundleFile = { relPath: rel, absPath: abs, kind, size, sha256, text };
      if (encoding !== 'utf8') file.encoding = encoding;
      files.push(file);
    }
  }

  await visit(rootDir, 0);
  files.sort((a, b) => a.relPath.localeCompare(b.relPath));
  return { rootDir, source, files, symlinks, notes, totalBytes };
}
