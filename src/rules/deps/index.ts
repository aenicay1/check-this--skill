import type { FileRule, FileRuleContext, RuleFinding } from '../../types.js';

const MANIFEST_ONLY = ['manifest'] as const;

// Lifecycle scripts routinely run local build steps (node build.js, husky
// install, tsc). The dangerous shapes are fetching remote code or piping to a
// shell, so require those specifically rather than any shell usage.
const NETWORK_OR_SHELL =
  /\b(curl|wget)\b|\|\s*(ba|z)?sh\b|\bnode\s+-e\b|\beval\b|https?:\/\/|\bchild_process\b|base64\s+(-d|--decode)/i;

export const depInstallScript: FileRule = {
  type: 'file',
  id: 'CMS-DEP-002',
  title: 'Dependency install/lifecycle script runs code',
  description: 'A package.json lifecycle script (preinstall/install/postinstall) that runs network or shell commands.',
  defaultSeverity: 'high',
  confidence: 'high',
  tags: ['deps', 'malcode'],
  appliesTo: MANIFEST_ONLY,
  remediation: 'Lifecycle scripts run automatically on `npm install`; review what this one does before installing.',
  check: (ctx: FileRuleContext) => {
    const scripts = ctx.parsed.manifest?.lifecycleScripts;
    if (!scripts) return [];
    const out: RuleFinding[] = [];
    for (const [name, cmd] of Object.entries(scripts)) {
      if (NETWORK_OR_SHELL.test(cmd)) {
        out.push({
          detail: `Lifecycle script "${name}" runs network/shell code on install: ${cmd}`,
          line: lineOfScript(ctx, name),
          snippet: `"${name}": "${cmd}"`,
        });
      }
    }
    return out;
  },
};

export const depUnpinnedRemote: FileRule = {
  type: 'file',
  id: 'CMS-DEP-003',
  title: 'Unpinned or non-registry dependency',
  description: 'A dependency sourced from a git URL, http tarball, or local/link path rather than a pinned registry version.',
  defaultSeverity: 'medium',
  confidence: 'medium',
  tags: ['deps'],
  appliesTo: MANIFEST_ONLY,
  remediation: 'Non-registry sources can change or serve different code over time; pin to a registry version.',
  check: (ctx: FileRuleContext) => {
    const manifest = ctx.parsed.manifest;
    if (!manifest) return [];
    const out: RuleFinding[] = [];
    for (const pkg of manifest.packages) {
      if (pkg.source) {
        out.push({
          detail: `Dependency "${pkg.name}" is sourced from a non-registry location: ${pkg.source}`,
          line: lineOfPackage(ctx, pkg.name),
          snippet: `${pkg.name}: ${pkg.source}`,
        });
      }
    }
    return out;
  },
};

function lineOfScript(ctx: FileRuleContext, name: string): number | undefined {
  return lineMatching(ctx, new RegExp(`"${name}"\\s*:`));
}

function lineOfPackage(ctx: FileRuleContext, name: string): number | undefined {
  return lineMatching(ctx, new RegExp(`["']?${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']?\\s*[:=]`));
}

function lineMatching(ctx: FileRuleContext, pattern: RegExp): number | undefined {
  const lines = ctx.parsed.lines;
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i] ?? '')) return i + 1;
  }
  return undefined;
}

export const depRules: FileRule[] = [depInstallScript, depUnpinnedRemote];
