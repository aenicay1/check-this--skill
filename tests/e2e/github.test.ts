import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createGzip } from 'node:zlib';
import { Readable } from 'node:stream';
import { pack as tarPack } from 'tar-stream';
import { describe, expect, it } from 'vitest';
import { parseGithubUrl, acquireGithub } from '../../dist/acquire/github.js';
import { extractTarball } from '../../dist/acquire/extract.js';

describe('parseGithubUrl', () => {
  it('parses the common URL forms', () => {
    expect(parseGithubUrl('https://github.com/owner/repo')).toMatchObject({ owner: 'owner', repo: 'repo' });
    expect(parseGithubUrl('github.com/owner/repo.git')).toMatchObject({ owner: 'owner', repo: 'repo' });
    expect(parseGithubUrl('git@github.com:owner/repo.git')).toMatchObject({ owner: 'owner', repo: 'repo' });
    expect(parseGithubUrl('https://github.com/owner/repo/tree/main/skills/foo')).toMatchObject({
      owner: 'owner',
      repo: 'repo',
      ref: 'main',
      subdir: 'skills/foo',
    });
  });

  it('rejects non-github URLs', () => {
    expect(parseGithubUrl('https://evil.example.invalid/owner/repo')).toBeUndefined();
    expect(parseGithubUrl('not a url')).toBeUndefined();
  });
});

/** Build a gzipped tar stream from a list of entries (name → content). */
function makeTarball(entries: Array<{ name: string; content?: string; type?: 'file' | 'symlink'; linkname?: string }>): Readable {
  const p = tarPack();
  for (const e of entries) {
    if (e.type === 'symlink') {
      p.entry({ name: e.name, type: 'symlink', linkname: e.linkname ?? '/etc/passwd' });
    } else {
      p.entry({ name: e.name }, e.content ?? '');
    }
  }
  p.finalize();
  return p.pipe(createGzip());
}

describe('extractTarball hostile-archive defenses', () => {
  it('extracts safe entries and strips the top-level directory', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'cms-ext-'));
    const stream = makeTarball([
      { name: 'repo-main/SKILL.md', content: '# hi' },
      { name: 'repo-main/nested/file.txt', content: 'x' },
    ]);
    const { entries } = await extractTarball(stream, dir);
    expect(entries).toBe(2);
    expect(existsSync(path.join(dir, 'SKILL.md'))).toBe(true);
    expect(existsSync(path.join(dir, 'nested', 'file.txt'))).toBe(true);
  });

  it('rejects path traversal (zip-slip) entries', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'cms-ext-'));
    const stream = makeTarball([
      { name: 'repo-main/ok.txt', content: 'ok' },
      { name: 'repo-main/../../../../tmp/cms-escape.txt', content: 'pwned' },
    ]);
    const { skipped } = await extractTarball(stream, dir);
    expect(existsSync(path.join(dir, 'ok.txt'))).toBe(true);
    expect(existsSync('/tmp/cms-escape.txt')).toBe(false);
    expect(skipped.some((s) => s.includes('traversal'))).toBe(true);
  });

  it('has fully flushed every file when it returns (regression: async write race)', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'cms-ext-'));
    const big = 'x'.repeat(300_000);
    const stream = makeTarball([
      { name: 'repo-main/a.txt', content: 'a' },
      { name: 'repo-main/big-last.txt', content: big },
    ]);
    await extractTarball(stream, dir);
    // If writes were not awaited, this file would be short or missing.
    const written = await readFile(path.join(dir, 'big-last.txt'), 'utf8');
    expect(written.length).toBe(big.length);
  });

  it('rejects symlink entries entirely', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'cms-ext-'));
    const stream = makeTarball([
      { name: 'repo-main/real.txt', content: 'real' },
      { name: 'repo-main/evil-link', type: 'symlink', linkname: '/etc/passwd' },
    ]);
    const { skipped } = await extractTarball(stream, dir);
    expect(existsSync(path.join(dir, 'real.txt'))).toBe(true);
    expect(existsSync(path.join(dir, 'evil-link'))).toBe(false);
    expect(skipped.some((s) => s.includes('link'))).toBe(true);
  });
});

describe('acquireGithub with mocked fetch', () => {
  it('downloads and extracts a skill, ready to scan', async () => {
    const tarball = makeTarball([
      { name: 'repo-main/SKILL.md', content: '---\nname: repo\ndescription: test\n---\n# ok' },
    ]);
    const fetchImpl = (async () =>
      ({ ok: true, status: 200, body: Readable.toWeb(tarball) }) as unknown as Response) as typeof fetch;
    const { rootDir, source } = await acquireGithub('https://github.com/owner/repo', { fetchImpl });
    expect(source.type).toBe('github');
    expect(source.target).toBe('github.com/owner/repo');
    const skill = await readFile(path.join(rootDir, 'SKILL.md'), 'utf8');
    expect(skill).toContain('name: repo');
  });
});
