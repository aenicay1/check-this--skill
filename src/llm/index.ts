import { detectClaude } from './detect.js';
import { invokeReviewer } from './invoke.js';
import { buildReviewPayload } from './prompt.js';
import { validateResponse } from './validate.js';
import type { BundleModel, Finding } from '../types.js';

export interface LlmReviewResult {
  findings: Finding[];
  ran: boolean;
  model?: string;
  tampered?: boolean;
  skippedReason?: string;
}

export interface LlmReviewOptions {
  model?: string;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
}

/**
 * Run the injection-hardened LLM review. Every failure mode degrades to a
 * clean skip (rules-only) except reviewer tampering, which produces a finding.
 * The returned findings are always additive to the deterministic ones.
 */
export async function runLlmReview(
  model: BundleModel,
  ruleFindings: Finding[],
  options: LlmReviewOptions = {},
): Promise<LlmReviewResult> {
  const detection = await detectClaude(options.env);
  if (!detection.binary) {
    return { findings: [], ran: false, skippedReason: detection.skippedReason };
  }

  const payload = buildReviewPayload(model, ruleFindings);
  const invocation = await invokeReviewer(detection.binary, payload, {
    model: options.model,
    timeoutMs: options.timeoutMs,
  });
  if (invocation.text === undefined) {
    return { findings: [], ran: false, skippedReason: invocation.skippedReason };
  }

  const outcome = validateResponse(invocation.text, payload.canary, payload.sentText);
  return {
    findings: outcome.findings,
    ran: outcome.ran,
    model: outcome.ran ? invocation.model ?? detection.binary.version : undefined,
    tampered: outcome.tampered,
    skippedReason: outcome.skippedReason,
  };
}
