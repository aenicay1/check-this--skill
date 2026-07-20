import { z } from 'zod';
import type { Finding, Severity, ThreatTag } from '../types.js';

const LlmFindingSchema = z.object({
  category: z.enum(['injection', 'exfiltration', 'deception', 'persistence', 'permission-mismatch', 'other']),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  file: z.string().optional(),
  evidence: z.string(),
  rationale: z.string(),
});

const LlmResponseSchema = z.object({
  canary: z.string(),
  findings: z.array(LlmFindingSchema).max(50),
});

export type LlmResponse = z.infer<typeof LlmResponseSchema>;

const CATEGORY_TAG: Record<z.infer<typeof LlmFindingSchema>['category'], ThreatTag> = {
  injection: 'injection',
  exfiltration: 'malcode',
  deception: 'injection',
  persistence: 'persistence',
  'permission-mismatch': 'permissions',
  other: 'malcode',
};

export interface ValidationOutcome {
  /** True when the model returned a schema-valid response we could act on. */
  ran: boolean;
  findings: Finding[];
  tampered: boolean;
  skippedReason?: string;
}

/** Strip a leading/trailing markdown code fence if the model wrapped its JSON. */
function stripFence(text: string): string {
  const trimmed = text.trim();
  const fence = /^```(?:json)?\s*\n([\s\S]*?)\n```$/.exec(trimmed);
  return fence ? fence[1]!.trim() : trimmed;
}

/** Normalize for evidence matching: collapse whitespace, drop our escape markers. */
function normalizeForMatch(s: string): string {
  return s.replace(/⟨U\+[0-9A-F]+⟩/g, '').replace(/\s+/g, ' ').trim().toLowerCase();
}

/**
 * Validate and bind the model's response.
 *  - Wrong/missing canary => the model was diverted: discard all its findings
 *    and raise our own tamper finding (never lets a skill talk its way to PASS).
 *  - Unparseable / schema-invalid => graceful skip, no findings.
 *  - Each surviving finding must quote text that actually appears in what we
 *    sent, which drops hallucinations.
 * LLM findings are always additive and capped at 'medium' confidence; the
 * deterministic rules own high-confidence verdicts.
 */
export function validateResponse(rawText: string, expectedCanary: string, sentText: string): ValidationOutcome {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stripFence(rawText));
  } catch {
    return { ran: false, findings: [], tampered: false, skippedReason: 'LLM response was not valid JSON' };
  }

  const result = LlmResponseSchema.safeParse(parsed);
  if (!result.success) {
    return { ran: false, findings: [], tampered: false, skippedReason: 'LLM response did not match the expected schema' };
  }

  if (result.data.canary !== expectedCanary) {
    return {
      ran: true,
      tampered: true,
      findings: [
        {
          id: 'CMS-LLM-TAMPER',
          source: 'llm',
          severity: 'high',
          confidence: 'high',
          title: 'Skill manipulated the automated reviewer',
          detail:
            'The skill diverted the LLM reviewer (the expected integrity canary was not returned), which indicates an embedded prompt-injection attack.',
          tags: ['injection'],
          remediation: 'A skill that attacks the reviewer is hostile by construction; do not install it.',
        },
      ],
    };
  }

  const haystack = normalizeForMatch(sentText);
  const findings: Finding[] = [];
  let dropped = 0;
  for (const f of result.data.findings) {
    const needle = normalizeForMatch(f.evidence);
    if (needle.length < 4 || !haystack.includes(needle)) {
      dropped += 1;
      continue; // unlocatable evidence => likely hallucinated
    }
    findings.push({
      id: `CMS-LLM-${f.category.toUpperCase()}`,
      source: 'llm',
      severity: f.severity as Severity,
      confidence: 'medium',
      title: `LLM review: ${f.category}`,
      detail: f.rationale,
      file: f.file && f.file !== 'unknown' ? f.file : undefined,
      snippet: f.evidence,
      tags: [CATEGORY_TAG[f.category]],
    });
  }

  const outcome: ValidationOutcome = { ran: true, findings, tampered: false };
  if (dropped > 0) outcome.skippedReason = `${dropped} LLM finding(s) dropped for unverifiable evidence`;
  return outcome;
}
