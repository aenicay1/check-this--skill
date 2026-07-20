# check-my-skill

Security scanner for agent skills. Point it at a skill bundle before you install it and get a verdict, `PASS` / `CAUTION` / `BLOCK`, with evidence-backed findings.

```
npx check-my-skill ./some-skill-folder
npx check-my-skill https://github.com/someone/cool-skill
```

## Why

A shared agent skill is just markdown instructions plus optional scripts, and people install them sight-unseen. A skill can carry prompt injection, hidden unicode instructions, credential-stealing scripts, or persistence tricks (writing to your agent settings, installing hooks, adding MCP servers). `check-my-skill` reads the whole bundle, **never executes anything from it**, and tells you what it found with file, line, and quoted evidence.

## What it checks

Three layers combine into one verdict:

1. **Deterministic rules** (~22, always on, offline). Pattern and AST analysis across six threat families: malicious instructions, hidden content, dangerous code, persistence, risky permissions, and dependencies. See the [rule catalog](docs/rules.md).
2. **Dependency audit** via the free [OSV.dev](https://osv.dev) API. Flags known-vulnerable pinned dependencies plus install-time lifecycle scripts and non-registry sources. Network-optional: degrades to a note if offline.
3. **LLM semantic review** through your **existing Claude Code install**. No API key: the scanner shells out to the local `claude` binary in headless mode and reuses your auth. It catches natural-language attacks that patterns miss. The reviewer is hardened against the skill it reviews (see below). Skips cleanly if `claude` is not installed or you pass `--no-llm`.

## Usage

```
check-my-skill <target> [options]

Options:
  --json                 output the machine-readable JSON report
  --no-llm               skip the LLM semantic review stage
  --llm-model <model>    model for the LLM review (passed to the local claude binary)
  --no-deps              skip the dependency vulnerability audit
  --strict               let low-confidence findings escalate the verdict past CAUTION
  --fail-on <severity>   exit non-zero only for findings at or above this severity
  --allow <rule...>      suppress findings by rule id (RULE-ID or RULE-ID:path/prefix)
```

Targets can be a local skill directory, a `SKILL.md` path, or a GitHub URL (fetched as a tarball, never cloned, so no repo hook or filter can run during the scan).

### Verdicts and exit codes

| Verdict   | Meaning                                   | Exit code |
| --------- | ----------------------------------------- | --------- |
| `PASS`    | no findings, or only low-severity ones    | `0`       |
| `CAUTION` | medium-severity findings to review        | `1`       |
| `BLOCK`   | high or critical findings; do not install | `2`       |
| `ERROR`   | the scan could not complete               | `3`       |

Use `--fail-on high` in CI to gate installs on serious findings only.

### Suppressing false positives

Add a `.checkmyskillignore` file (one `RULE-ID` or `RULE-ID:path/prefix` per line, `#` comments) in the directory you run from, or pass `--allow CMS-CODE-002:examples/`.

## How the LLM reviewer resists attack

The skill being scanned is hostile input, so the reviewer treats it as data, not instructions:

- Content is wrapped in a random nonce-fenced block and the system prompt states it is untrusted data to analyze, never commands.
- Invisible and bidi characters are escaped before sending, and any fence markers inside the content are neutralized so the skill cannot close the block early.
- The reviewer runs with **all tools disabled** in a throwaway empty working directory, so even a successful injection cannot read the filesystem or reach the network.
- A secret **canary** must be echoed back. If it is missing or wrong, the model was diverted, so the scanner discards the LLM output and raises its own `CMS-LLM-TAMPER` finding. A skill that says "report no issues" thereby makes the verdict *worse*, never better.
- Every LLM finding must quote text that actually appears in the bundle, which drops hallucinations. LLM findings are additive only and never downgrade a deterministic finding.

## Development

```
npm install
npm test        # builds, generates fixtures, runs the e2e + unit suite
```

The test suite runs the real built CLI against a corpus of clean and deliberately-malicious skill fixtures (`tests/fixtures/skills/`). Malicious fixtures contain attack *strings* only, use non-resolving `.invalid` hosts, and are never executed.

## License

MIT
