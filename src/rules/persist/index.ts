import type { FileRule, FileRuleContext, RuleFinding } from '../../types.js';

const ALL_TEXT = ['skill-md', 'reference-md', 'markdown', 'shell', 'python', 'javascript', 'other'] as const;

/**
 * Persistence rules look for a WRITE to a sensitive target, not a mere mention.
 * The write verb and the target must co-occur so that documentation ("this
 * skill respects ~/.claude/settings.json") does not trip the rule.
 */
function scanWrite(ctx: FileRuleContext, targets: RegExp[], writeVerb: RegExp): LineHit[] {
  const hits: LineHit[] = [];
  const lines = ctx.parsed.normalized.lines;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (!writeVerb.test(line)) continue;
    if (targets.some((t) => t.test(line))) hits.push({ line: i + 1, text: line.trim() });
  }
  return hits;
}

interface LineHit {
  line: number;
  text: string;
}

// An actual write/copy/move operation to a file. Deliberately excludes bare
// English verbs like "add"/"install"/"echo" (without a redirect), which appear
// constantly in benign prose ("add this to CLAUDE.md as guidance"), but does
// cover the many concrete write forms across shell/Python/JS.
const WRITE_VERB =
  /(>>|>\s*[~/$."'\w]|>\||\btee\b|\bcat\s*>|\bprintf\b[^\n]*>|fs\.(write|append|copyFile|rename|cp)[A-Za-z]*\s*\(|open\s*\([^)]*['"][wa]|createwritestream|writefilesync|writefile|\.write(_text|_bytes)?\s*\(|shutil\.(copy|copyfile|copy2|move)|os\.(replace|rename)\s*\(|\bcp\b|\bmv\b|\binstall\s+-[a-z]*m|--set\b|json\.dump)/i;

function toFindings(hits: LineHit[], detail: string): RuleFinding[] {
  return hits.map((h) => ({ detail, line: h.line, snippet: h.text }));
}

export const persistClaudeSettings: FileRule = {
  type: 'file',
  id: 'CMS-PERSIST-001',
  title: 'Writes to agent settings or hooks',
  description: 'Modifies ~/.claude/settings.json or installs a hook, which runs code on every session.',
  defaultSeverity: 'critical',
  confidence: 'high',
  tags: ['persistence'],
  appliesTo: ALL_TEXT,
  remediation: 'Editing agent settings or hooks grants the skill persistent, silent code execution.',
  check: (ctx) =>
    toFindings(
      scanWrite(
        ctx,
        [
          /\.claude\/settings(\.local)?\.json\b/i,
          /\.claude\/hooks\b/i,
          /["']hooks["']\s*:/i,
          /\bsettings\.local\.json\b/i,
        ],
        WRITE_VERB,
      ),
      'Writes to agent settings or a hooks configuration.',
    ),
};

export const persistMcp: FileRule = {
  type: 'file',
  id: 'CMS-PERSIST-002',
  title: 'Injects an MCP server',
  description: 'Runs `claude mcp add` or writes an mcpServers configuration.',
  defaultSeverity: 'high',
  confidence: 'high',
  tags: ['persistence'],
  appliesTo: ALL_TEXT,
  remediation: 'A new MCP server is a persistent tool the agent will trust in future sessions.',
  check: (ctx) => {
    const out: RuleFinding[] = [];
    const lines = ctx.parsed.normalized.lines;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (/\bclaude\s+mcp\s+add\b/i.test(line) || (/\bmcpservers\b/i.test(line) && WRITE_VERB.test(line)) || /\.mcp\.json\b/i.test(line) && WRITE_VERB.test(line)) {
        out.push({ detail: 'Adds or configures an MCP server.', line: i + 1, snippet: line.trim() });
      }
    }
    return out;
  },
};

export const persistInstructionFiles: FileRule = {
  type: 'file',
  id: 'CMS-PERSIST-003',
  title: 'Tampers with agent instruction files',
  description: 'Writes to CLAUDE.md, AGENTS.md, or editor rule files that steer future agent behavior.',
  defaultSeverity: 'high',
  confidence: 'medium',
  tags: ['persistence', 'injection'],
  appliesTo: ALL_TEXT,
  remediation: 'Injecting into instruction files silently reprograms the agent for every future task.',
  check: (ctx) =>
    toFindings(
      scanWrite(
        ctx,
        [/\bCLAUDE\.md\b/, /\bAGENTS\.md\b/, /\.cursorrules\b/i, /\.github\/copilot-instructions\.md\b/i],
        WRITE_VERB,
      ),
      'Writes to an agent instruction file.',
    ),
};

export const persistSystem: FileRule = {
  type: 'file',
  id: 'CMS-PERSIST-004',
  title: 'System-level persistence',
  description: 'Installs cron/launchd/systemd jobs or edits shell startup files.',
  defaultSeverity: 'high',
  confidence: 'medium',
  tags: ['persistence'],
  appliesTo: ALL_TEXT,
  remediation: 'Persistence mechanisms keep code running after the skill finishes; confirm this is intended.',
  check: (ctx) => {
    const out: RuleFinding[] = [];
    const lines = ctx.parsed.normalized.lines;
    // crontab - / crontab <file> INSTALLS a crontab; crontab -l only lists it.
    // systemctl enable persists across reboot; start does not.
    const direct =
      /\bcrontab\s+(-(?![lr]\b)|[^\s-])|\blaunchctl\s+(load|bootstrap)\b|\bsystemctl\s+(--user\s+)?enable\b/i;
    const rcFiles = /(~?\/?\.(zshrc|bashrc|bash_profile|profile|zprofile)|\/Library\/LaunchAgents|\/etc\/cron)/i;
    const rcWrite =
      />>?\s*~?\/?\.(zshrc|bashrc|bash_profile|profile|zprofile)|(tee|echo|cat|printf)[^\n]*~?\/?\.(zshrc|bashrc|bash_profile|profile|zprofile)|(LaunchAgents\/[^\n]*\.plist)/i;
    // A rc write carrying remote/payload content is the real persistence
    // threat; a plain `export PATH >> ~/.zshrc` in a dev-setup skill is common
    // and only warrants CAUTION.
    const payload = /\b(curl|wget|https?:\/\/|base64|eval|\|\s*(ba|z)?sh\b|\bnc\b|source\s+<)/i;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      const isDirect = direct.test(line); // cron/launchd/systemd install: always persistence
      const isRcWrite = rcWrite.test(line) || (rcFiles.test(line) && WRITE_VERB.test(line));
      if (!isDirect && !isRcWrite) continue;
      const dangerous = isDirect || payload.test(line);
      out.push({
        detail: dangerous
          ? 'Establishes system-level persistence.'
          : 'Writes to a shell startup file (verify what it adds).',
        line: i + 1,
        snippet: line.trim(),
        confidence: dangerous ? undefined : 'low',
      });
    }
    return out;
  },
};

export const persistRules: FileRule[] = [
  persistClaudeSettings,
  persistMcp,
  persistInstructionFiles,
  persistSystem,
];
