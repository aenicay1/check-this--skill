# check-my-skill

Security scanner for agent skills. Run it against a skill bundle before you install it and get a verdict (PASS / CAUTION / BLOCK) with evidence-backed findings.

```
npx check-my-skill ./some-skill-folder
npx check-my-skill https://github.com/someone/cool-skill
```

## Why

Shared agent skills are just markdown instructions plus optional scripts, and people install them sight-unseen. A skill can carry prompt injection, hidden unicode instructions, credential-stealing scripts, or persistence tricks (writing to your agent settings, installing hooks). This tool reads the whole bundle, never executes anything from it, and tells you what it found with file, line, and quoted evidence.

## Status

Under active development. See the roadmap in the issues.

## License

MIT
