import { simple as walkSimple } from 'acorn-walk';
import type { CallExpression, NewExpression, Node } from 'acorn';
import type { FileRule, FileRuleContext, RuleFinding } from '../../types.js';

const CODE_KINDS = ['shell', 'python', 'javascript'] as const;

interface LineHit {
  line: number;
  text: string;
}

// Cap the input any rule regex runs against. A hostile single-line file could
// otherwise drive catastrophic/quadratic backtracking; bounding the input keeps
// even a quadratic pattern well under a millisecond. Lines this long are data
// blobs, which the entropy rule (CMS-HID-005) covers separately.
const MAX_SCAN_LINE = 4000;

/**
 * Line-level scan over the normalized text. Comment-only lines are skipped:
 * the code rules detect executable behavior, and a comment neither executes nor
 * should be flagged for documenting a dangerous pattern.
 */
function scanCode(ctx: FileRuleContext, patterns: RegExp[]): LineHit[] {
  const hits: LineHit[] = [];
  const lines = ctx.parsed.normalized.lines;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? '';
    if (/^\s*(#|\/\/)/.test(raw)) continue; // comment-only line: not executable
    const line = raw.length > MAX_SCAN_LINE ? raw.slice(0, MAX_SCAN_LINE) : raw;
    for (const pattern of patterns) {
      const re = new RegExp(pattern.source, pattern.flags.replace('g', ''));
      if (re.test(line)) {
        hits.push({ line: i + 1, text: raw.trim().slice(0, 300) });
        break;
      }
    }
  }
  return hits;
}

function toFindings(hits: LineHit[], detail: string, extra?: Partial<RuleFinding>): RuleFinding[] {
  return hits.map((h) => ({ detail, line: h.line, snippet: h.text, ...extra }));
}

export const codePipeToShell: FileRule = {
  type: 'file',
  id: 'CMS-CODE-001',
  title: 'Pipe-to-shell execution',
  description: 'Downloading a remote script and piping it straight into a shell interpreter.',
  defaultSeverity: 'critical',
  confidence: 'high',
  tags: ['malcode'],
  appliesTo: CODE_KINDS,
  remediation: 'Piping a downloaded script into a shell runs unreviewed remote code with your privileges.',
  check: (ctx) =>
    toFindings(
      scanCode(ctx, [
        /\b(curl|wget|fetch)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b/i,
        /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?python[0-9.]*\b/i,
        /\b(iwr|invoke-webrequest|curl)\b[^\n|]*\|\s*(iex|invoke-expression)\b/i,
        /\bcurl\b[^\n]*-o\s*\S+[^\n]*&&\s*(ba|z)?sh\b/i,
      ]),
      'Downloads and executes a remote script in one step (pipe-to-shell).',
    ),
};

export const codeCredentialAccess: FileRule = {
  type: 'file',
  id: 'CMS-CODE-002',
  title: 'Access to credential or secret files',
  description: 'Reads well-known secret locations (SSH/AWS keys, .env, keychains, npm/docker/kube configs).',
  defaultSeverity: 'critical',
  confidence: 'high',
  tags: ['malcode'],
  appliesTo: CODE_KINDS,
  remediation: 'A skill reading credential stores is exfiltration-adjacent; confirm it genuinely needs them.',
  check: (ctx) =>
    toFindings(
      scanCode(ctx, [
        /(^|[\s'"`(=])~?\/?\.ssh\/(id_[a-z0-9]+|authorized_keys|known_hosts|config)\b/i,
        /\bid_(rsa|ed25519|ecdsa|dsa)\b/,
        /~?\/?\.aws\/(credentials|config)\b/i,
        /(^|[\s'"`(=/])\.env(\.[a-z]+)?\b/i,
        /~?\/?\.config\/gh\/hosts\.yml\b/i,
        /~?\/?\.npmrc\b/,
        /~?\/?\.docker\/config\.json\b/i,
        /~?\/?\.kube\/config\b/i,
        /\bsecurity\s+find-(generic|internet)-password\b/i,
        /~?\/?\.netrc\b/,
      ]),
      'References a credential or secret file location.',
    ),
};

export const codeDestructive: FileRule = {
  type: 'file',
  id: 'CMS-CODE-003',
  title: 'Destructive command',
  description: 'Commands that irreversibly destroy data or the system (rm -rf ~, dd to a device, fork bomb).',
  defaultSeverity: 'critical',
  confidence: 'high',
  tags: ['malcode'],
  appliesTo: CODE_KINDS,
  remediation: 'These commands can wipe files or the machine; a skill should never ship them.',
  check: (ctx) =>
    toFindings(
      scanCode(ctx, [
        /\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(-[a-z-]+\s+)*(~|\/|\$HOME|\/\*|\.\s|\.\/\*)/i,
        /\brm\s+-[a-z]*f[a-z]*r[a-z]*\s+(~|\/|\$HOME)/i,
        /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
        /\bmkfs\.[a-z0-9]+\b/i,
        /\bdd\b[^\n]*\bof=\/dev\/(sd|nvme|disk|hd)/i,
        />\s*\/dev\/(sd|nvme|disk|hd)[a-z0-9]*\b/i,
      ]),
      'Contains a destructive command.',
    ),
};

interface CallLike extends Node {
  callee?: Node & { type: string; name?: string; property?: { name?: string }; object?: { name?: string } };
  arguments?: Node[];
}

// Bare identifiers that, when called, almost always mean code/command
// execution (eval, or a child_process function pulled in by destructuring).
const BARE_SINKS = new Set(['eval', 'Function', 'exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync']);
// Method names that are only a sink when invoked on a child_process-like object.
const MEMBER_SINKS = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync']);
const CHILD_PROCESS_OBJECT = /^(cp|child_process|childprocess|execa|shell|proc|subprocess)$/i;

function resolveSink(node: CallLike): { name: string; label: string } | undefined {
  const callee = node.callee;
  if (!callee) return undefined;
  if (callee.type === 'Identifier' && callee.name && BARE_SINKS.has(callee.name)) {
    return { name: callee.name, label: callee.name };
  }
  if (callee.type === 'MemberExpression' && callee.property?.name && MEMBER_SINKS.has(callee.property.name)) {
    const objName = callee.object?.name ?? '';
    if (CHILD_PROCESS_OBJECT.test(objName)) {
      return { name: callee.property.name, label: `${objName}.${callee.property.name}` };
    }
  }
  return undefined;
}

export const codeObfuscatedExec: FileRule = {
  type: 'file',
  id: 'CMS-CODE-004',
  title: 'Dynamic or obfuscated code execution',
  description: 'eval/exec/Function/child_process/os.system called with a non-literal (computed) argument.',
  defaultSeverity: 'high',
  confidence: 'medium',
  tags: ['malcode'],
  appliesTo: CODE_KINDS,
  remediation: 'Executing a computed string hides the real command from review; make it a literal or remove it.',
  check: (ctx) => {
    const out: RuleFinding[] = [];

    // JavaScript: use the AST to distinguish literal from computed arguments,
    // and to avoid flagging benign methods that share a sink name (e.g. a
    // RegExp's .exec()). A member call only counts when its object looks like
    // child_process; bare identifiers like eval/exec/spawn are treated as sinks.
    if (ctx.parsed.estree) {
      const flag = (node: CallExpression | NewExpression) => {
        const sink = resolveSink(node as CallLike);
        if (!sink) return;
        // For Function, the code is the LAST argument; for the rest it is first.
        const codeArg = sink.name === 'Function' ? node.arguments[node.arguments.length - 1] : node.arguments[0];
        const isLiteral = codeArg?.type === 'Literal' || codeArg?.type === 'TemplateLiteral';
        if (codeArg && !isLiteral) {
          const line = (node as unknown as { loc?: { start: { line: number } } }).loc?.start.line;
          out.push({
            detail: `${sink.label}() is called with a computed (non-literal) argument.`,
            line,
            snippet: (ctx.parsed.lines[(line ?? 1) - 1] ?? '').trim(),
          });
        }
      };
      walkSimple(ctx.parsed.estree, {
        CallExpression: (n) => flag(n as CallExpression),
        NewExpression: (n) => flag(n as NewExpression),
      });
    }

    // Shell/Python and JS text fallbacks for obfuscation idioms.
    out.push(
      ...toFindings(
        scanCode(ctx, [
          /\b(base64\s+(-d|--decode)|xxd\s+-r)\b[^\n|]*\|\s*(ba|z|da)?sh\b/i,
          /\b(python[0-9.]*)\s+-c\s+['"][^'"]*\bexec\(/i,
          /\beval\s*\(\s*(atob|Buffer\.from|base64|String\.fromCharCode|\$\()/i,
          /\bexec\s*\(\s*(compile|__import__|base64|codecs\.decode)/i,
          /\becho\b[^\n|]*\|\s*base64\s+(-d|--decode)[^\n|]*\|\s*(ba|z)?sh\b/i,
        ]),
        'Obfuscated execution idiom (decode-then-run or dynamic exec).',
      ),
    );
    return out;
  },
};

export const codeReverseShell: FileRule = {
  type: 'file',
  id: 'CMS-CODE-005',
  title: 'Reverse shell',
  description: 'Signatures that open an interactive shell back to a remote host.',
  defaultSeverity: 'high',
  confidence: 'high',
  tags: ['malcode'],
  appliesTo: CODE_KINDS,
  remediation: 'Reverse shells hand remote control of the machine to an attacker.',
  check: (ctx) =>
    toFindings(
      scanCode(ctx, [
        /\b(ba|z)?sh\b\s+-i\b[^\n]*(>&|>|<)\s*\/dev\/tcp\//i,
        /\/dev\/tcp\/[0-9a-z.]+\/\d+/i,
        /\bnc(at)?\b[^\n]*\s-[a-z]*e[a-z]*\s+\/(bin\/)?(ba|z)?sh\b/i,
        /\bsocat\b[^\n]*\bexec[:=]/i,
        // Python reverse-shell idioms, matched per line since they span lines.
        /\bpty\.spawn\s*\(\s*["'][^"']*\/(ba|z)?sh\b/i,
        /\bos\.dup2\s*\(\s*\w+\.fileno\s*\(\s*\)/i,
        /\bsubprocess\.call\s*\(\s*\[?\s*["']\/(bin\/)?(ba|z)?sh/i,
      ]),
      'Reverse-shell signature.',
    ),
};

export const codeNetworkExfil: FileRule = {
  type: 'file',
  id: 'CMS-CODE-006',
  title: 'Network exfiltration primitive',
  description: 'DNS exfil, raw TCP, or posting data to a paste/webhook host.',
  defaultSeverity: 'medium',
  confidence: 'medium',
  tags: ['malcode'],
  appliesTo: CODE_KINDS,
  remediation: 'These primitives move local data off the machine; confirm the destination is expected.',
  check: (ctx) =>
    toFindings(
      scanCode(ctx, [
        /\b(dig|nslookup|host)\b[^\n]*\$\(/i,
        /\b(pastebin\.com|requestbin|hookb\.in|webhook\.site|ngrok\.io|discord(app)?\.com\/api\/webhooks|telegram\.org\/bot)\b/i,
        // curl uploading file contents or command output (not inline literals).
        /\bcurl\b[^\n]*(--data[=\s]|--data-binary[=\s]|-d\s|-F\s|--form[=\s]|-T\s|--upload-file[=\s])[^\n]*(@|\$\()[^\n]*https?:\/\//i,
        /\bcurl\b[^\n]*https?:\/\/[^\n]*(--data[=\s]|-d\s)[^\n]*(@|\$\()/i,
        /\brequests\.(post|put)\s*\([^\n]*(open\(|\.read\(|environ|getenv)/i,
      ]),
      'Network exfiltration primitive.',
    ),
};

export const codeFetchExecute: FileRule = {
  type: 'file',
  id: 'CMS-CODE-007',
  title: 'Runtime fetch-and-execute',
  description: 'Fetches a remote resource and writes it somewhere executable or runs it.',
  defaultSeverity: 'medium',
  confidence: 'medium',
  tags: ['malcode'],
  appliesTo: CODE_KINDS,
  remediation: 'Code fetched at runtime is invisible to this scan; review the remote source.',
  check: (ctx) =>
    toFindings(
      scanCode(ctx, [
        /\b(curl|wget)\b[^\n]*-o\s+\S+\.(sh|py|js|command)\b/i,
        /\b(urllib\.request\.urlretrieve|requests\.get)\s*\([^\n]*\)[^\n]*(exec|os\.system|subprocess)/i,
        /\bchmod\s+\+x\b[^\n]*&&[^\n]*\.\//i,
      ]),
      'Fetches remote content and makes it executable or runs it.',
    ),
};

export const codeEnvHarvest: FileRule = {
  type: 'file',
  id: 'CMS-CODE-008',
  title: 'Environment-variable harvesting',
  description: 'Iterating the full environment and sending or writing it out.',
  defaultSeverity: 'low',
  confidence: 'low',
  tags: ['malcode'],
  appliesTo: CODE_KINDS,
  remediation: 'Bulk-reading the environment can capture secrets; a single named variable read is fine.',
  check: (ctx) =>
    toFindings(
      scanCode(ctx, [
        /\b(JSON\.stringify\s*\(\s*process\.env|Object\.(keys|entries)\s*\(\s*process\.env)\b/i,
        /\bfor\b[^\n]*\bin\b[^\n]*\bos\.environ\b/i,
        /\b(printenv|env)\b[^\n|]*\|\s*(curl|nc|wget)\b/i,
      ]),
      'Reads the full environment (potential secret harvest).',
    ),
};

export const codeRules: FileRule[] = [
  codePipeToShell,
  codeCredentialAccess,
  codeDestructive,
  codeObfuscatedExec,
  codeReverseShell,
  codeNetworkExfil,
  codeFetchExecute,
  codeEnvHarvest,
];
