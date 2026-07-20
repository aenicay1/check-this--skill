#!/usr/bin/env node
import { Command, InvalidArgumentError } from 'commander';
import pc from 'picocolors';
import { exitCodeFor, renderJson, renderTerminal, scan, ScanError, SEVERITIES, type Severity } from './index.js';
import { scannerVersion } from './version.js';

function parseSeverity(value: string): Severity {
  const lower = value.toLowerCase() as Severity;
  if (!SEVERITIES.includes(lower)) {
    throw new InvalidArgumentError(`must be one of: ${SEVERITIES.join(', ')}`);
  }
  return lower;
}

async function main(): Promise<void> {
  const program = new Command();
  program
    .name('check-my-skill')
    .description('Scan an agent skill for malicious instructions, hidden content, and dangerous code before you install it.')
    .version(await scannerVersion())
    .argument('<target>', 'path to a skill directory or its SKILL.md')
    .option('--json', 'output the machine-readable JSON report')
    .option('--no-llm', 'skip the LLM semantic review stage')
    .option('--llm-model <model>', 'model to use for the LLM review (passed to the local claude binary)')
    .option('--no-deps', 'skip the dependency vulnerability audit')
    .option('--strict', 'let low-confidence findings escalate the verdict past CAUTION')
    .option('--fail-on <severity>', 'exit non-zero only for findings at or above this severity', parseSeverity)
    .option('--allow <rule...>', 'suppress findings by rule id (RULE-ID or RULE-ID:path/prefix)')
    .allowExcessArguments(false);

  program.parse();
  const target = program.args[0] ?? '';
  const opts = program.opts<{
    json?: boolean;
    llm: boolean;
    llmModel?: string;
    deps: boolean;
    strict?: boolean;
    failOn?: Severity;
    allow?: string[];
  }>();

  try {
    const result = await scan(target, {
      llm: opts.llm,
      llmModel: opts.llmModel,
      deps: opts.deps,
      strict: opts.strict,
      failOn: opts.failOn,
      allow: opts.allow,
    });
    process.stdout.write(`${opts.json ? renderJson(result) : renderTerminal(result)}\n`);
    process.exitCode = exitCodeFor(result.verdict, result.findings, opts.failOn);
  } catch (err) {
    if (err instanceof ScanError) {
      process.stderr.write(`${pc.red('error:')} ${err.message}\n`);
      process.exitCode = 3;
      return;
    }
    throw err;
  }
}

await main();
