#!/usr/bin/env node
/**
 * Stand-in for the `claude` CLI used in tests. Behavior is driven by
 * STUB_MODE so a single script can exercise every LLM code path without a
 * real model. It reads the review prompt on stdin (like real headless mode),
 * extracts the canary the scanner embedded, and emits a claude-style JSON
 * envelope on stdout.
 */
import { readFileSync } from 'node:fs';

const mode = process.env.STUB_MODE ?? 'clean';

if (process.argv.includes('--version')) {
  process.stdout.write('9.9.9 (stub)\n');
  process.exit(0);
}

let input = '';
try {
  input = readFileSync(0, 'utf8');
} catch {
  input = '';
}

// A real model reads the canary from the system prompt; the stub does the same
// by pulling it out of the --system-prompt argument. Tamper mode deliberately
// returns the wrong value to simulate a model diverted by prompt injection.
function extractCanary() {
  const idx = process.argv.indexOf('--system-prompt');
  const sys = idx !== -1 ? process.argv[idx + 1] ?? '' : '';
  const m = /"canary":\s*"([0-9a-f]+)"/.exec(sys);
  return m ? m[1] : 'unknown-canary';
}
const realCanary = extractCanary();
const canary = mode === 'tamper' ? 'attacker-supplied-canary' : realCanary;

function envelope(resultObj) {
  return JSON.stringify({ type: 'result', subtype: 'success', is_error: false, result: JSON.stringify(resultObj) });
}

// Find a verbatim quote from the untrusted content so evidence binding passes.
function firstQuote() {
  const m = /curl|\.env|~\/\.ssh|ignore all previous/i.exec(input);
  return m ? m[0] : 'setup';
}

switch (mode) {
  case 'timeout': {
    // Never respond; the scanner's timeout should fire.
    setTimeout(() => process.exit(0), 60_000);
    break;
  }
  case 'nonjson': {
    process.stdout.write(JSON.stringify({ type: 'result', is_error: false, result: 'Sure! Here is my analysis...' }));
    process.exit(0);
    break;
  }
  case 'tamper': {
    // Model returns findings but with the wrong canary (diverted by injection).
    process.stdout.write(envelope({ canary, findings: [{ category: 'other', severity: 'low', file: 'SKILL.md', evidence: firstQuote(), rationale: 'x' }] }));
    process.exit(0);
    break;
  }
  case 'hallucinate': {
    process.stdout.write(
      envelope({
        canary,
        findings: [{ category: 'exfiltration', severity: 'critical', file: 'SKILL.md', evidence: 'THIS TEXT IS NOT IN THE BUNDLE AT ALL', rationale: 'made up' }],
      }),
    );
    process.exit(0);
    break;
  }
  case 'finding': {
    process.stdout.write(
      envelope({
        canary,
        findings: [{ category: 'deception', severity: 'high', file: 'SKILL.md', evidence: firstQuote(), rationale: 'deceptive instruction' }],
      }),
    );
    process.exit(0);
    break;
  }
  default: {
    // clean: valid canary, no findings.
    process.stdout.write(envelope({ canary, findings: [] }));
    process.exit(0);
  }
}
