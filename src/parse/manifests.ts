import path from 'node:path';
import type { ManifestPackage, ParsedManifest } from '../types.js';

const NPM_LIFECYCLE = new Set(['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack']);

function isRemoteSource(version: string): boolean {
  return /^(git(\+|:)|github:|https?:|file:|link:)/.test(version);
}

function parsePackageJson(text: string): ParsedManifest | undefined {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (data === null || typeof data !== 'object') return undefined;
  const obj = data as Record<string, unknown>;
  const packages: ManifestPackage[] = [];
  for (const key of ['dependencies', 'devDependencies', 'optionalDependencies'] as const) {
    const deps = obj[key];
    if (deps === null || typeof deps !== 'object') continue;
    for (const [name, version] of Object.entries(deps as Record<string, unknown>)) {
      if (typeof version !== 'string') continue;
      const pkg: ManifestPackage = { name, version };
      if (isRemoteSource(version)) pkg.source = version;
      packages.push(pkg);
    }
  }
  const lifecycleScripts: Record<string, string> = {};
  const scripts = obj['scripts'];
  if (scripts !== null && typeof scripts === 'object') {
    for (const [name, cmd] of Object.entries(scripts as Record<string, unknown>)) {
      if (NPM_LIFECYCLE.has(name) && typeof cmd === 'string') lifecycleScripts[name] = cmd;
    }
  }
  return {
    ecosystem: 'npm',
    fileType: 'package.json',
    packages,
    lifecycleScripts: Object.keys(lifecycleScripts).length > 0 ? lifecycleScripts : undefined,
  };
}

function parsePackageLock(text: string): ParsedManifest | undefined {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (data === null || typeof data !== 'object') return undefined;
  const obj = data as Record<string, unknown>;
  const packages: ManifestPackage[] = [];
  const entries = obj['packages'];
  if (entries !== null && typeof entries === 'object') {
    for (const [key, value] of Object.entries(entries as Record<string, unknown>)) {
      if (!key.startsWith('node_modules/')) continue;
      const name = key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      const version = (value as Record<string, unknown> | null)?.['version'];
      packages.push({ name, version: typeof version === 'string' ? version : undefined });
    }
  }
  return { ecosystem: 'npm', fileType: 'package-lock.json', packages };
}

function parseRequirementsTxt(text: string, fileType: string): ParsedManifest {
  const packages: ManifestPackage[] = [];
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/(^|\s)#.*$/, '').trim();
    if (!line || line.startsWith('-r') || line.startsWith('--')) continue;
    if (/^(git\+|https?:|-e\s)/.test(line)) {
      packages.push({ name: line.replace(/^-e\s+/, ''), source: line });
      continue;
    }
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:(==|>=|<=|~=|!=|>|<)\s*([^\s;]+))?/.exec(line);
    if (!match || !match[1]) continue;
    const pkg: ManifestPackage = { name: match[1] };
    if (match[2] === '==' && match[3]) pkg.version = match[3];
    packages.push(pkg);
  }
  return { ecosystem: 'pypi', fileType, packages };
}

/**
 * Structurally parse the manifests the deps audit understands. Lockfile
 * formats we do not parse yet (yarn.lock, pnpm-lock.yaml, poetry.lock,
 * pyproject.toml) return undefined; the audit reports them as unchecked.
 */
export function parseManifest(relPath: string, text: string): ParsedManifest | undefined {
  const base = path.posix.basename(relPath).toLowerCase();
  if (base === 'package.json') return parsePackageJson(text);
  if (base === 'package-lock.json') return parsePackageLock(text);
  if (/^requirements[^/]*\.txt$/.test(base)) return parseRequirementsTxt(text, base);
  return undefined;
}
