import { z } from 'zod';
import type { Root as MdastRoot } from 'mdast';
import type { Program } from 'acorn';

// ---------- severity / verdict ----------

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export const SeveritySchema = z.enum(SEVERITIES);
export type Severity = (typeof SEVERITIES)[number];

const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function severityRank(severity: Severity): number {
  return SEVERITY_RANK[severity];
}

export const VERDICTS = ['PASS', 'CAUTION', 'BLOCK', 'ERROR'] as const;
export const VerdictSchema = z.enum(VERDICTS);
export type Verdict = (typeof VERDICTS)[number];

export const CONFIDENCES = ['high', 'medium', 'low'] as const;
export const ConfidenceSchema = z.enum(CONFIDENCES);
export type Confidence = (typeof CONFIDENCES)[number];

export const THREAT_TAGS = ['injection', 'hidden', 'malcode', 'persistence', 'deps', 'permissions'] as const;
export const ThreatTagSchema = z.enum(THREAT_TAGS);
export type ThreatTag = (typeof THREAT_TAGS)[number];

// ---------- findings ----------

export const FindingSchema = z.object({
  id: z.string(),
  source: z.enum(['rule', 'llm', 'deps']),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  title: z.string(),
  detail: z.string(),
  file: z.string().optional(),
  line: z.number().int().positive().optional(),
  snippet: z.string().optional(),
  tags: z.array(ThreatTagSchema),
  remediation: z.string().optional(),
});
export type Finding = z.infer<typeof FindingSchema>;

// ---------- bundle ----------

export const FILE_KINDS = [
  'skill-md',
  'reference-md',
  'markdown',
  'shell',
  'python',
  'javascript',
  'manifest',
  'binary',
  'other',
] as const;
export type FileKind = (typeof FILE_KINDS)[number];

export interface BundleFile {
  relPath: string;
  absPath: string;
  kind: FileKind;
  size: number;
  sha256?: string;
  /** Decoded text content; absent for binary files and files over the scan cap. */
  text?: string;
  encoding?: 'utf8' | 'utf16le' | 'utf16be';
  skippedReason?: string;
}

export interface SymlinkEntry {
  relPath: string;
  target: string;
  escapesBundle: boolean;
}

export interface BundleSource {
  type: 'local' | 'github';
  target: string;
  sha?: string;
}

export interface Bundle {
  rootDir: string;
  source: BundleSource;
  files: BundleFile[];
  symlinks: SymlinkEntry[];
  /** Walk-level notes: caps hit, directories skipped, unreadable entries. */
  notes: string[];
  totalBytes: number;
}

// ---------- parsed views ----------

export interface InvisibleHit {
  codePoint: number;
  line: number;
  column: number;
}

export interface NormalizedText {
  /** Per-line NFKC-normalized text with invisibles stripped; line numbers stay stable. */
  lines: string[];
  invisibles: InvisibleHit[];
  bidi: InvisibleHit[];
  changed: boolean;
}

export interface ParsedFrontmatter {
  data: Record<string, unknown>;
  raw: string;
  /** 1-indexed line where the markdown body starts. */
  bodyStartLine: number;
  error?: string;
}

export interface ManifestPackage {
  name: string;
  version?: string;
  /** Non-registry source (git URL, http tarball, local path) when declared. */
  source?: string;
}

export interface ParsedManifest {
  ecosystem: 'npm' | 'pypi';
  fileType: string;
  packages: ManifestPackage[];
  lifecycleScripts?: Record<string, string>;
}

export interface ParsedFile {
  relPath: string;
  lines: string[];
  normalized: NormalizedText;
  frontmatter?: ParsedFrontmatter;
  mdast?: MdastRoot;
  estree?: Program;
  estreeError?: string;
  manifest?: ParsedManifest;
}

export interface BundleModel extends Bundle {
  parsed: Map<string, ParsedFile>;
}

// ---------- rules ----------

export interface RuleFinding {
  detail: string;
  severity?: Severity;
  confidence?: Confidence;
  file?: string;
  line?: number;
  snippet?: string;
  remediation?: string;
}

interface RuleBase {
  id: string;
  title: string;
  description: string;
  defaultSeverity: Severity;
  confidence: Confidence;
  tags: ThreatTag[];
  remediation?: string;
}

export interface FileRuleContext {
  file: BundleFile;
  parsed: ParsedFile;
  bundle: BundleModel;
}

export interface FileRule extends RuleBase {
  type: 'file';
  appliesTo: readonly FileKind[];
  check(ctx: FileRuleContext): RuleFinding[];
}

export interface BundleRule extends RuleBase {
  type: 'bundle';
  check(bundle: BundleModel): RuleFinding[];
}

export type Rule = FileRule | BundleRule;

// ---------- scan API ----------

export interface ScanOptions {
  /** Semantic review via the local claude binary. Default true. */
  llm?: boolean;
  /** Model passed to the local claude binary for the review stage. */
  llmModel?: string;
  /** OSV.dev dependency audit. Default true. */
  deps?: boolean;
  /** Let low-confidence findings escalate the verdict past CAUTION. */
  strict?: boolean;
  failOn?: Severity;
  /** Suppressions: "RULE-ID" or "RULE-ID:path/prefix". */
  allow?: string[];
}

export const ScanResultSchema = z.object({
  schemaVersion: z.literal(1),
  scannerVersion: z.string(),
  target: z.object({
    path: z.string(),
    source: z.enum(['local', 'github']),
    sha: z.string().optional(),
  }),
  stats: z.object({
    files: z.number().int(),
    bytes: z.number().int(),
    notes: z.array(z.string()),
  }),
  findings: z.array(FindingSchema),
  llm: z.object({
    ran: z.boolean(),
    model: z.string().optional(),
    skippedReason: z.string().optional(),
    tampered: z.boolean().optional(),
  }),
  deps: z.object({
    ran: z.boolean(),
    packagesQueried: z.number().int(),
    skippedReason: z.string().optional(),
  }),
  verdict: VerdictSchema,
});
export type ScanResult = z.infer<typeof ScanResultSchema>;

export class ScanError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'ScanError';
  }
}
