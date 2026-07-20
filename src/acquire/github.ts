import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { ScanError, type BundleSource } from '../types.js';
import { extractTarball } from './extract.js';

export interface GithubRef {
  owner: string;
  repo: string;
  ref?: string;
  /** Subdirectory within the repo that holds the skill, if any. */
  subdir?: string;
}

/**
 * Parse the GitHub forms we accept:
 *   https://github.com/owner/repo
 *   https://github.com/owner/repo/tree/<ref>/<subdir...>
 *   github.com/owner/repo
 *   git@github.com:owner/repo.git
 */
export function parseGithubUrl(input: string): GithubRef | undefined {
  const cleaned = input.trim();
  const ssh = /^git@github\.com:([^/]+)\/(.+?)(?:\.git)?$/.exec(cleaned);
  if (ssh) return { owner: ssh[1]!, repo: ssh[2]! };

  let url: URL;
  try {
    url = new URL(cleaned.startsWith('http') ? cleaned : `https://${cleaned}`);
  } catch {
    return undefined;
  }
  if (url.hostname !== 'github.com' && url.hostname !== 'www.github.com') return undefined;
  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length < 2) return undefined;
  const owner = parts[0]!;
  const repo = parts[1]!.replace(/\.git$/, '');
  // /owner/repo/tree/<ref>/<subdir...>
  if (parts[2] === 'tree' && parts[3]) {
    return { owner, repo, ref: parts[3], subdir: parts.slice(4).join('/') || undefined };
  }
  return { owner, repo };
}

async function fetchTarball(ref: GithubRef, refName: string, doFetch: typeof fetch): Promise<Response> {
  const url = `https://codeload.github.com/${ref.owner}/${ref.repo}/tar.gz/${refName}`;
  const res = await doFetch(url, { redirect: 'follow' });
  if (res.ok && res.body) return res;
  throw new ScanError(`could not download ${ref.owner}/${ref.repo}@${refName} (HTTP ${res.status})`);
}

/**
 * Fetch a GitHub repo as a tarball and extract it read-only. Never clones, so
 * no git hooks, filters, or submodule fetches can execute. Returns the local
 * directory (optionally the skill subdirectory) and the source metadata.
 */
export async function acquireGithub(
  input: string,
  options: { fetchImpl?: typeof fetch } = {},
): Promise<{ rootDir: string; source: BundleSource }> {
  const ref = parseGithubUrl(input);
  if (!ref) throw new ScanError(`not a recognized GitHub URL: ${input}`);
  const doFetch = options.fetchImpl ?? fetch;

  const dir = await mkdtemp(path.join(tmpdir(), 'cms-gh-'));
  // Try the explicit ref, then main, then master.
  const candidates = ref.ref ? [ref.ref] : ['HEAD', 'main', 'master'];
  let res: Response | undefined;
  let usedRef = '';
  let lastErr: unknown;
  for (const candidate of candidates) {
    try {
      res = await fetchTarball(ref, candidate, doFetch);
      usedRef = candidate;
      break;
    } catch (err) {
      lastErr = err;
    }
  }
  if (!res || !res.body) throw (lastErr instanceof Error ? lastErr : new ScanError('download failed'));

  const nodeStream = Readable.fromWeb(res.body as Parameters<typeof Readable.fromWeb>[0]);
  await extractTarball(nodeStream, dir);

  const rootDir = ref.subdir ? path.join(dir, ref.subdir) : dir;
  const source: BundleSource = {
    type: 'github',
    target: `github.com/${ref.owner}/${ref.repo}${ref.subdir ? `/${ref.subdir}` : ''}`,
    sha: usedRef,
  };
  return { rootDir, source };
}
