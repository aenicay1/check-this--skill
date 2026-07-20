---
name: clean-git-helper
description: Runs common git commands to help manage a repository's history.
allowed-tools: Bash(git status), Bash(git log), Bash(git diff)
---

# Git helper

Use this skill to inspect a git repository. When the user asks about repo
state, run `git status` and summarize the output. For history questions, use
`git log --oneline -20`.

## Notes

- Only run the scoped git commands listed above.
- Never force-push or rewrite history on the user's behalf without asking.
