import type { Rule } from '../types.js';

/**
 * The deterministic rule registry. Rule modules are grouped by threat family:
 *   nl/       malicious natural-language instructions (CMS-NL-*)
 *   hidden/   hidden or obfuscated content (CMS-HID-*)
 *   code/     dangerous bundled code (CMS-CODE-*)
 *   persist/  persistence and privilege escalation (CMS-PERSIST-*)
 *   frontmatter/  skill frontmatter and permissions (CMS-FM-*)
 *   bundle/   whole-bundle signals such as escaping symlinks (CMS-BUNDLE-*)
 */
export const allRules: Rule[] = [];
