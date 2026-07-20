# What 180 public agent skills actually look like to a security scanner

A tweet claimed "1 in 4 shared skills/repos have a vulnerability baked in." That's what prompted `check-my-skill`. So I turned the tool on the ecosystem: I scanned **180 public agent-skill repositories** and looked at what it found, honestly, including where the tool itself is wrong.

TL;DR: **about half (47.8%) trip a high-severity flag** , but "flagged" is not "malicious." The single biggest category is known-vulnerable bundled dependencies (accidental), followed by `curl | bash` installers and persistence actions skills legitimately use. Roughly **1 in 5 flags is a false positive**. Genuinely *intentional*-looking attacks were rare. The real problem the data shows isn't malware, it's that people install these blind.

## Method (reproducible)

- **Corpus**: 180 unique public GitHub repos, discovered via GitHub search (`filename:SKILL.md`, plus repo search for "claude skill" / "agent skill"). This is a convenience sample of what's searchable, not a random sample of all skills.
- **Scan**: each repo fetched as a tarball (never cloned) and scanned with `check-my-skill <url> --no-llm`. The LLM review layer was **excluded on purpose** so results are deterministic and reproducible , every number here comes from the rule engine + the OSV.dev dependency check, not a model.
- **39,380 files** scanned across the 180 repos. 0 scan errors.
- A finding is a *risk signal*, ranked by severity and confidence. "High/critical" is the bar for a `BLOCK` verdict.

## Headline numbers

| Metric | Result |
| --- | --- |
| Repos with ≥1 finding | **77.2%** (139/180) |
| Repos with a high/critical finding (`BLOCK`) | **47.8%** (86/180) |
| Repos with a critical finding | **29.4%** (53/180) |
| Verdict split | PASS 65 · CAUTION 29 · BLOCK 86 |

### Which risk families show up (share of repos)

| Family | Repos | What it is |
| --- | --- | --- |
| Dangerous code (`CODE`) | 42.2% | pipe-to-shell, credential access, destructive commands |
| Frontmatter/permissions (`FM`) | 31.1% | broad/unscoped tool grants |
| Instructions (`NL`) | 31.1% | hide-from-user, injection, exfil-shaped prose |
| Persistence (`PERSIST`) | 28.3% | writes to agent settings/hooks, MCP installs, cron/launchd |
| Hidden content (`HID`) | 27.8% | invisible unicode, CSS hiding, encoded blobs |
| Vulnerable deps (`DEP`) | 19.4% | OSV-confirmed CVEs in bundled manifests |

## The honest part: I hand-audited a sample

Aggregate flag rates are easy to turn into clickbait ("half of all skills are dangerous!"). They shouldn't be. I hand-checked a representative sample of **28 high/critical findings** and bucketed them:

- **~10 , confirmed vulnerable dependencies** (OSV database hits: `axios` header-injection/ReDoS, `jinja2` sandbox breakout, `react-router` DoS, `multer` DoS, …). These are real and unambiguous, but they're **accidental hygiene**, a skill bundled a Node/Python project with a stale lockfile. Precision here is ~100%.
- **~12 , accurate flags of real behavior**: `curl … | bash` installers (foundry, deno), `claude mcp add …`, writing hooks into `~/.claude/`, `systemctl enable`, `launchctl load`, writing `CLAUDE.md`/`AGENTS.md`. These are correctly detected. Most have benign intent, but they're exactly the things you'd want to *consciously accept* rather than run blind.
- **~6 , false positives (~21%)**: test fixtures that pass `rm -rf /var/data` as data, a safety hook whose `grep` pattern *blocks* `rm -rf`, prose that mis-matched a rule, and , the fun one , other **skill-scanner tools** whose test fixtures contain attack strings by design.

So: **precision on the sample ≈ 79%**, and of the accurate flags, the overwhelming majority are hygiene or expected-behavior, not intent to harm.

## What this means

- The "1 in 4 has a vulnerability" claim is **directionally right** if you count vulnerable dependencies and risky patterns , the rate is actually higher. But **"vulnerability" ≠ "malware."** Almost nothing in this corpus looked like a deliberate attack.
- The real, boring risk is **blind trust**: skills routinely bundle vulnerable deps, ship `curl | bash` installers, and modify your agent's settings/hooks , and people install them without reading. A skill is instructions plus scripts your agent will run with your privileges.
- A scanner is a **filter, not an oracle**. ~1 in 5 high-severity flags here was a false positive; that's why the tool separates severity from confidence, damps heuristics, and offers an LLM review layer for intent. A `PASS` means "nothing recognized as dangerous," not "safe."

## Notes and limitations

- Deterministic layer only (no LLM); the semantic layer would add findings this run didn't count.
- GitHub-search convenience sample; not random, and it includes security-tooling repos whose fixtures deliberately contain attack strings.
- Findings are risk signals requiring human review, not confirmed exploits.
- **I'm not naming individual repos.** Many flags are benign or false positives, and the point is the pattern, not shaming maintainers.

Run it yourself before you install your next skill:

```
npx check-my-skill <path-or-github-url>
```
