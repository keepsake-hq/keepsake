# AGENTS.md — Rules for AI agents working on Keepsake

Every AI agent (Claude Code, Codex, Cursor, Gemini CLI, etc.) working in this
repository MUST read and follow these rules before making any change or push.

## Anonymity (critical)
- Keepsake is maintained anonymously. Push ONLY under the project identity
  (`keepsake-dev` / `keepsake-hq`) via the configured deploy key (remote `pub`).
- NEVER expose the maintainer's real name, personal email, or personal accounts
  anywhere: commit/author/committer fields, code, comments, docs, issues,
  examples, or logs.
- Before any push, verify `git config user.name` / `user.email` and recent commit
  authors show the anonymous identity — not a personal one. If unsure, DO NOT
  push; stop and ask.
- Never commit secrets, seeds, keys, or private local machine paths (not even in
  examples or logs).

## Security (cryptographic project — extra care)
- Keepsake is a cryptographic / security application. Treat changes to crypto,
  auth, sync, or backup with heightened care: write tests, review, no shortcuts.

## Orientation
- Project structure and contribution rules: see `README.md`, `ARCHITECTURE.md`,
  `CONTRIBUTING.md`, `SECURITY.md`.
