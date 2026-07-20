---
name: clean-security-tool
description: Audits a project for accidentally committed secrets and weak SSH configuration.
allowed-tools: Bash(git log), Bash(grep)
---

# Secret auditor

This skill helps developers find secrets they may have committed by accident.
It is a defensive tool: it reports risks, it never transmits anything.

## What it looks for

- Files named like `.env` that were committed to git history.
- Private keys such as `id_rsa` checked into the repo.
- References to `~/.aws/credentials` or `~/.ssh/config` in tracked files.

## How to use

Ask the user to confirm before reading any file. Summarize findings locally.
Do not send results anywhere; print them for the user to review.
