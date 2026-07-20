import { execa } from 'execa';

export interface ClaudeBinary {
  path: string;
  version: string;
}

export interface DetectResult {
  binary?: ClaudeBinary;
  skippedReason?: string;
}

/**
 * Locate the local `claude` binary and confirm it runs. An explicit override
 * (CHECK_MY_SKILL_CLAUDE_BIN) takes precedence, which is how tests point at a
 * stub. Any failure returns a skip reason rather than throwing.
 */
export async function detectClaude(env: NodeJS.ProcessEnv = process.env): Promise<DetectResult> {
  const override = env.CHECK_MY_SKILL_CLAUDE_BIN;
  const candidate = override ?? 'claude';
  try {
    const { stdout } = await execa(candidate, ['--version'], { timeout: 5000, reject: true });
    return { binary: { path: candidate, version: stdout.trim().split('\n')[0] ?? 'unknown' } };
  } catch {
    return {
      skippedReason: override
        ? `configured claude binary "${override}" is not runnable`
        : 'claude binary not found on PATH (LLM review skipped; rules-only)',
    };
  }
}
