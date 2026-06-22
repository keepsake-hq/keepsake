# Architecture

Keepsake is a single Rust workspace. The design goal is a **small, auditable security core** with everything else layered thinly on top — so the part that has to be correct (the key math and the erasure mechanics) is a handful of crates you can read in an afternoon, not a monolith.

This is the map. For *what* Keepsake is and how to run it, see the [README](README.md).

## Dependency layering

Crates depend strictly **downward** — lower layers never import higher ones. `keepsake-crypto` is a leaf with no internal dependencies; everything ultimately rests on it.

```
Entry points      keepsake-cli      apps/desktop + keepsake-desktop-core
                        \                    |
Surfaces          keepsake-proxy   keepsake-mcp        keepsake-firewall  (policy leaf)
                        \________________|________________/
Orchestration                    keepsake-vault
                        ____________|____________
Storage & recall   keepsake-store-sqlite   keepsake-retrieval      keepsake-sync -> keepsake-relay
                        \____________|____________/                       |
Vault model                   keepsake-core  <----------------------------+
                                    |
Trust root                   keepsake-crypto   (leaf: pure key math, no I/O)
```

If you only read one crate, read `keepsake-crypto`. Everything else assumes it is correct.

## The crates

**Trust root**
- **`keepsake-crypto`** — BIP-39 → HKDF domain-separated roots; random-DEK AES-256-GCM envelope encryption (the basis for *real* erasure); X25519 + ML-KEM-768 hybrid sharing; ML-DSA-65 (FIPS-204) signatures; Shamir social recovery; device pairing. No storage, no I/O — just key math.

**Vault core & storage**
- **`keepsake-core`** — the two-plane store model (append-only *content* plane vs. erasable *key-manifest* plane) and the erasure mechanics. Where "forget destroys the key, not just a row" lives.
- **`keepsake-store-sqlite`** — the durable backend on SQLCipher (full-DB encryption at rest). `forget` = key-row delete + `secure_delete` + WAL truncation, so nothing survives on disk.
- **`keepsake-retrieval`** — local embeddings (Nomic via fastembed/ONNX), an in-RAM vector index, and per-cell encrypted embeddings (the index is the leakiest artifact, so it never hits disk in the clear).

**Orchestration**
- **`keepsake-vault`** — ties crypto + core + store + retrieval into the semantic `remember` / `recall` / `forget` / `share` operations. The `MemoryVault` every surface talks to.

**Surfaces** (how the outside world reaches the vault)
- **`keepsake-proxy`** — an OpenAI-compatible gateway (axum): RAG memory injection, write-back, and localhost-only security (loopback bind, ≥256-bit bearer, Host/Origin allowlists).
- **`keepsake-mcp`** — the eight `saihm_*` MCP tools over stdio (Claude / Cursor), with capability-token enforcement.
- **`keepsake-firewall`** — the Context-Firewall: Privacy Dial, PII redaction, HMAC-chained Memory Receipts, capability tokens. A dependency-free policy leaf the surfaces pull in; every byte that could leave the device passes through it.

**Sync** (optional, multi-device)
- **`keepsake-sync`** — state-based, erasure-safe snapshot sync; key material is never placed into synced history.
- **`keepsake-relay`** — a dumb, file-backed (SQLite), zero-knowledge HTTP relay you self-host; it sees only opaque encrypted blobs.

**Entry points**
- **`keepsake-cli`** — init a seed, remember/recall/forget from the terminal. The smallest way to watch the whole pipeline run.
- **`keepsake-desktop-core`** + **`apps/desktop`** — a Tauri v2 app: vault operations as testable, frontend-friendly command functions, plus a local, offline, Tailwind-v4 UI.

## Two data flows worth understanding

**A — fully local (the default).**
client → `keepsake-proxy` → `keepsake-retrieval` embeds the query locally → in-RAM vector search → cell ids → `keepsake-vault` loads cells and `keepsake-crypto` unwraps their DEKs in RAM → prompt assembled → **local model (Ollama)** → answer → write-back as a new encrypted cell. Nothing touches the network.

**B — explicit cloud request (through the firewall).**
Same up to retrieval (embeddings and index never leave the device). Then `keepsake-firewall` reads the Privacy Dial, applies `never_send_to_cloud` filters and PII redaction, enforces the consent gate, sends the *minimized* context, and writes a signed Memory Receipt (provider, model, exact cell ids, redaction hash, byte count). Egress happens **only** here.

## The one invariant everything protects

`forget` must be **cryptographically final**. That is why:

1. every cell's DEK is *random*, never derived from the seed — so seed + an old backup still cannot recover a forgotten cell;
2. wrapped keys live only in the erasable key-manifest plane, never in append-only content, Memory Receipts, event logs, or synced history;
3. `forget` deletes the key rows, `secure_delete`s the pages, truncates the WAL, and destroys the per-cell embedding key.

Any change that could put key material into the content, sync, or receipt planes breaks the product. There are CI tests guarding exactly this — keep them green.

## Where to start reading

- **How does a memory round-trip?** `keepsake-cli` → `keepsake-vault`.
- **Touching crypto?** `keepsake-crypto` first, then the erasure notes in the README.
- **Adding a new client integration?** Model it on `keepsake-proxy` or `keepsake-mcp`.

Tests are TDD throughout: `cargo test`. Lint clean: `cargo clippy --all-targets -- -D warnings`.
