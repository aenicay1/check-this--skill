import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execa } from 'execa';
import type { ClaudeBinary } from './detect.js';
import type { ReviewPayload } from './prompt.js';

export interface InvokeResult {
  /** Raw model response text (the inner result), or undefined on failure. */
  text?: string;
  skippedReason?: string;
  model?: string;
}

interface ClaudeJsonEnvelope {
  result?: string;
  subtype?: string;
  is_error?: boolean;
}

/**
 * Run the reviewer as a single headless completion. Hardening applied here:
 *  - --system-prompt fully replaces the coding-agent prompt with our analyzer
 *  - --allowedTools "" grants zero tools
 *  - cwd is a throwaway empty directory, so even a tool call cannot reach the skill
 *  - the payload is delivered on stdin, never on argv
 *  - a wall-clock timeout kills a hung or stalling model
 */
export async function invokeReviewer(
  binary: ClaudeBinary,
  payload: ReviewPayload,
  options: { model?: string; timeoutMs?: number } = {},
): Promise<InvokeResult> {
  const sandbox = await mkdtemp(path.join(tmpdir(), 'cms-llm-'));
  try {
    const args = [
      '-p',
      '--output-format',
      'json',
      '--system-prompt',
      payload.systemPrompt,
      '--allowedTools',
      '',
    ];
    if (options.model) args.push('--model', options.model);

    const proc = await execa(binary.path, args, {
      input: payload.userPrompt,
      cwd: sandbox,
      timeout: options.timeoutMs ?? 60_000,
      reject: false,
    });

    if (proc.failed || proc.exitCode !== 0) {
      const reason = proc.timedOut ? 'LLM review timed out' : `claude exited with code ${proc.exitCode}`;
      return { skippedReason: reason };
    }

    let envelope: ClaudeJsonEnvelope;
    try {
      envelope = JSON.parse(String(proc.stdout)) as ClaudeJsonEnvelope;
    } catch {
      return { skippedReason: 'could not parse claude output envelope' };
    }
    if (envelope.is_error || typeof envelope.result !== 'string') {
      return { skippedReason: 'claude returned an error result' };
    }
    return { text: envelope.result, model: options.model };
  } catch (err) {
    return { skippedReason: `LLM review failed: ${(err as Error).message}` };
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
}
