import type { Rule } from '../types.js';
import { bundleRules } from './bundle/index.js';
import { codeRules } from './code/index.js';
import { depRules } from './deps/index.js';
import { frontmatterRules } from './frontmatter/index.js';
import { hiddenRules } from './hidden/index.js';
import { nlRules } from './nl/index.js';
import { persistRules } from './persist/index.js';

/**
 * The deterministic rule registry. Rule modules are grouped by threat family:
 *   nl/       malicious natural-language instructions (CMS-NL-*)
 *   hidden/   hidden or obfuscated content (CMS-HID-*)
 *   code/     dangerous bundled code (CMS-CODE-*)
 *   persist/  persistence and privilege escalation (CMS-PERSIST-*)
 *   frontmatter/  skill frontmatter and permissions (CMS-FM-*)
 *   bundle/   whole-bundle signals such as escaping symlinks (CMS-BUNDLE-*)
 */
export const allRules: Rule[] = [
  ...nlRules,
  ...hiddenRules,
  ...codeRules,
  ...persistRules,
  ...frontmatterRules,
  ...depRules,
  ...bundleRules,
];
