import type { BundleRule, RuleFinding } from '../../types.js';

export const bundleEscapingSymlink: BundleRule = {
  type: 'bundle',
  id: 'CMS-BUNDLE-001',
  title: 'Symlink escaping the bundle',
  description: 'A symlink whose target resolves outside the bundle directory or into a sensitive path.',
  defaultSeverity: 'high',
  confidence: 'high',
  tags: ['malcode'],
  remediation: 'A skill has no reason to link outside its own directory; this can read or expose host files.',
  check: (bundle) => {
    const out: RuleFinding[] = [];
    const sensitive = /(\.ssh|\.aws|\.env|\/etc\/|\.config\/gh|id_rsa|credentials)/i;
    for (const link of bundle.symlinks) {
      if (link.escapesBundle) {
        const intoSensitive = sensitive.test(link.target);
        out.push({
          detail: `Symlink "${link.relPath}" points outside the bundle to "${link.target}".`,
          file: link.relPath,
          severity: intoSensitive ? 'critical' : undefined,
          remediation: intoSensitive
            ? 'The target is a sensitive host location; treat this as an attempt to read credentials.'
            : undefined,
        });
      }
    }
    return out;
  },
};

export const bundleNoSkillMd: BundleRule = {
  type: 'bundle',
  id: 'CMS-BUNDLE-002',
  title: 'No SKILL.md found',
  description: 'The bundle has no SKILL.md, so it may not be a skill (or the entry point is disguised).',
  defaultSeverity: 'info',
  confidence: 'high',
  tags: ['permissions'],
  remediation: 'Confirm this directory is actually the skill you intend to install.',
  check: (bundle) => {
    const hasSkill = bundle.files.some((f) => f.kind === 'skill-md');
    if (hasSkill) return [];
    if (bundle.files.length === 0) return [];
    return [{ detail: 'No SKILL.md is present in this bundle.' }];
  },
};

export const bundleRules: BundleRule[] = [bundleEscapingSymlink, bundleNoSkillMd];
