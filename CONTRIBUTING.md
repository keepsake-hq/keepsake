# Contributing to Keepsake

Thanks for being here. Keepsake ships **anonymously on purpose** — the whole pitch is "trust the code, not a person" — and that extends to contributors: you are welcome to contribute under a pseudonym. What matters is the code.

## Two non-negotiables

Keepsake holds people's most private data. Before anything else:

1. **No network by default, no telemetry, ever.** Nothing phones home. If a change introduces a network call, it must be off by default, user-initiated, and obvious.
2. **`forget` stays cryptographically final.** Key material must never leak into the append-only content plane, Memory Receipts, event logs, or synced history. If your change touches storage, crypto, or sync, keep the invariant tests green and add new ones.

When in doubt, read [`ARCHITECTURE.md`](ARCHITECTURE.md) — especially "the one invariant everything protects."

## Test-driven, always

This codebase is built test-first, and pull requests are expected to be too: **write the failing test, watch it fail, then make it pass.** A feature or bugfix without a test that would have caught it is incomplete.

```sh
cargo test                                    # full suite — must pass
cargo clippy --all-targets -- -D warnings     # lint — must be clean
cargo fmt --all                               # format before committing
```

Green tests + clean clippy is the bar for "done."

## Getting set up

You need the [Rust toolchain](https://rustup.rs). For the local-model path, [Ollama](https://ollama.com) (`ollama pull llama3.2:1b`). The desktop app additionally needs Node + pnpm and the Tauri CLI — see [README → Build it yourself](README.md#build-it-yourself).

```sh
git clone https://github.com/keepsake-hq/keepsake
cd keepsake
cargo build
cargo test
```

Start at `keepsake-cli` → `keepsake-vault` to see a memory round-trip end to end.

## Reporting bugs & requesting features

Open an [issue](https://github.com/keepsake-hq/keepsake/issues). A good bug report has: what you did, what you expected, what actually happened, and your OS + how you installed (release `.dmg` or built from source).

## Reporting security vulnerabilities — privately

**Do not open a public issue for a security problem.** This is an encryption tool; a public 0-day helps attackers first.

Use GitHub's **private vulnerability reporting** instead: the repo's **Security → Report a vulnerability** tab. It stays private between you and the maintainers, you can report under your GitHub pseudonym, and we'll confirm, fix, and credit you in the release notes (or keep you anonymous — your call).

## Pull requests

- Branch from `main`; keep each PR focused on one logical change.
- Small, meaningful commits with clear English messages.
- Match the style of the surrounding code; avoid `unwrap()` on fallible paths in production code; document the *why* for anything subtle.
- Tests green, clippy clean, `cargo fmt` applied.
- By submitting a PR you agree to license your contribution under **Apache-2.0**, the project's license.

New here? Open something small first to get a feel for the review loop — a doc fix or an extra test counts. Welcome aboard. 🛡️
