# Rule catalog

Every deterministic rule has a stable id, a default severity, and a confidence level. Confidence gates the verdict: a lone low-confidence finding will not hard-`BLOCK` unless you pass `--strict`. The LLM stage adds `CMS-LLM-*` findings on top; it can never remove or downgrade a rule finding.

## Natural-language instructions (`CMS-NL-*`)

Applied to `SKILL.md` and reference markdown (frontmatter is excluded from prose scanning).

| ID | Severity | What it catches |
| -- | -------- | --------------- |
| CMS-NL-001 | high | Instructions to hide activity from the user ("do not tell the user", "hide this from"). |
| CMS-NL-002 | high (critical when it tells a reviewer to report safe) | Prompt injection: overriding prior/system instructions, or text addressed to a reviewer/scanner. |
| CMS-NL-003 | critical | Exfiltration directive: a sentence combining a send/upload verb, a secret, and an external destination. |
| CMS-NL-004 | high | Weakening permissions or bypassing safety prompts (co-occurrence of a config surface and a modify verb, or standalone bypass flags). |
| CMS-NL-005 | medium | Instructions to download and run remote code. |

## Hidden content (`CMS-HID-*`)

Applied to all text files.

| ID | Severity | What it catches |
| -- | -------- | --------------- |
| CMS-HID-001 | high | Invisible / zero-width characters hiding text. |
| CMS-HID-002 | critical | Bidirectional control characters (Trojan Source). |
| CMS-HID-003 | medium | Mixed-script homoglyphs (Latin word containing Cyrillic/Greek look-alikes). |
| CMS-HID-004 | medium | HTML comments (invisible when rendered) containing instructions or URLs. |
| CMS-HID-005 | medium (high if it decodes to shell/URL) | Long high-entropy base64/hex blob. |
| CMS-HID-006 | low | Content styled invisible (display:none, font-size:0, white-on-white). |

## Bundled code (`CMS-CODE-*`)

Applied to shell, Python, and JavaScript files. JavaScript uses AST analysis to tell literal from computed arguments. The near-zero-false-positive subset (CMS-CODE-001/002/003/005/007) is **also** run over commands written inside Markdown, both fenced code blocks and inline `` `code` `` spans, since that is where a skill puts the commands it tells the agent to run. Example-labeled fences are skipped, and in Markdown a credential path is only flagged when an actual access/movement verb is present (so documentation that merely names `id_rsa` does not fire). This makes the deterministic layer language-neutral: it catches an embedded `pipx install git+https://…` or `curl … | sh` even in a non-English skill with `--no-llm`.

| ID | Severity | What it catches |
| -- | -------- | --------------- |
| CMS-CODE-001 | critical | Pipe-to-shell (`curl ... \| sh`, `iwr ... \| iex`). |
| CMS-CODE-002 | critical | Access to credential/secret files (`~/.ssh`, `~/.aws`, `.env`, keychain, `.npmrc`, `.kube`). |
| CMS-CODE-003 | critical | Destructive commands (`rm -rf ~`, `dd of=/dev/...`, fork bomb). |
| CMS-CODE-004 | high | Dynamic/obfuscated execution (`eval`/`exec`/`Function`/`child_process` with a computed argument, decode-then-run). |
| CMS-CODE-005 | high | Reverse-shell signatures. |
| CMS-CODE-006 | medium | Network exfil primitives (DNS exfil, raw TCP, paste/webhook hosts). |
| CMS-CODE-007 | medium | Runtime fetch-and-execute. |
| CMS-CODE-008 | low | Bulk environment-variable harvesting. |

## Persistence and escalation (`CMS-PERSIST-*`)

Applied to all text files. Each looks for a *write* to a sensitive target, not a mere mention.

| ID | Severity | What it catches |
| -- | -------- | --------------- |
| CMS-PERSIST-001 | critical | Writing to `~/.claude/settings.json` or installing a hook. |
| CMS-PERSIST-002 | high | Injecting an MCP server (`claude mcp add`, `.mcp.json`). |
| CMS-PERSIST-003 | high | Tampering with agent instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`). |
| CMS-PERSIST-004 | high | System persistence (cron, launchd, systemd, shell rc files). |

## Frontmatter and permissions (`CMS-FM-*`)

Applied to `SKILL.md`.

| ID | Severity | What it catches |
| -- | -------- | --------------- |
| CMS-FM-001 | medium (high for skip-permission flags) | Broad or unscoped tool permissions (bare `Bash`, wildcards). |
| CMS-FM-002 | low | Declared tools exceed a read-only/formatting stated purpose (deterministic seed the LLM can raise). |
| CMS-FM-003 | medium (high for injection tokens) | Malformed/missing frontmatter, name/directory mismatch, or injection text in metadata. |

## Dependencies (`CMS-DEP-*`)

Applied to manifests (`package.json`, `package-lock.json`, `requirements*.txt`).

| ID | Severity | What it catches |
| -- | -------- | --------------- |
| CMS-DEP-001 | from OSV CVSS | Known-vulnerable pinned dependency (OSV.dev). |
| CMS-DEP-002 | high | Install/lifecycle script that runs network or shell code. |
| CMS-DEP-003 | medium | Non-registry or unpinned dependency source (git URL, http tarball, local path). |

## Whole-bundle (`CMS-BUNDLE-*`)

| ID | Severity | What it catches |
| -- | -------- | --------------- |
| CMS-BUNDLE-001 | high (critical into a sensitive path) | Symlink whose target escapes the bundle. |
| CMS-BUNDLE-002 | info | No `SKILL.md` present (may not be a skill). |

## LLM review (`CMS-LLM-*`)

Added by the semantic review stage; always `medium` confidence except tamper.

| ID | Severity | What it catches |
| -- | -------- | --------------- |
| CMS-LLM-TAMPER | high | The skill diverted the reviewer (wrong integrity canary): an embedded prompt-injection attack. |
| CMS-LLM-\<category\> | model-assigned | Injection, exfiltration, deception, persistence, or permission-mismatch the model identified, with verified evidence. |

## Known limitations

`check-my-skill` raises the cost of shipping a malicious skill and catches the common, careless, and accidental cases. It is a filter, not a proof of safety. Be aware of the following, by design:

- **Deterministic rules are pattern-based and defeatable by deliberate obfuscation.** A determined attacker can split a command across lines, build a credential path or URL from variables, use a synonym a regex does not list, or otherwise stay just outside a pattern. The rules target the shapes real malicious and buggy skills actually take, not every theoretically-reachable encoding. The LLM review stage exists precisely to catch semantic attacks that patterns miss, and a human should still read anything a skill will run.
- **Code analysis covers scripts and Markdown commands, but not arbitrary prose.** The code rules run on shell/Python/JavaScript files and on commands embedded in Markdown (fenced blocks and inline code). A risky behavior described only in free prose (no command form) is instead covered by the natural-language rules and the LLM stage. Nothing in the bundle is ever executed, so behavior that only manifests at runtime (fetch-and-execute of a remote URL) is reported as a risk to review, not resolved.
- **The dependency audit checks pinned versions against OSV.** Semver ranges are not queried (OSV needs an exact version), and lockfile formats other than `package-lock.json` are not yet parsed; unparsed manifests are reported as unchecked rather than silently passed.
- **Coverage is bounded by hard caps** (file count, per-file and total bytes, directory depth, archive entries). When a cap is hit, the scan reports what it skipped rather than implying full coverage.
- **The LLM stage is best-effort and non-deterministic.** It is never load-bearing for a rule-driven `BLOCK`, it can only add findings, and it is skipped cleanly when the `claude` binary is absent. A rules-only scan (`--no-llm`) is fully supported but blind to novel natural-language attacks.

A `PASS` means "nothing this scanner recognizes as dangerous," not "guaranteed safe." Treat it as one strong signal among several.
