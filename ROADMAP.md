# Keepsake — Roadmap

Keepsake is a sovereign, local-first, zero-knowledge long-term memory for LLMs/AI
agents — owned by the user like a crypto wallet (BIP-39 seed) and usable as a proxy
in front of any model. Pure OSS (Apache-2.0), no token, no telemetry.

Guiding truth: **zero-knowledge at rest is achievable; zero-knowledge during cloud
inference is not.** Local inference = full sovereignty; cloud inference exposes the
selected context to the provider. We make that limit explicit, minimized, and audited
rather than hiding it.

---

## Status (2026-06)

Shipped (TDD, 64 tests, `clippy`/`rustfmt` clean) — the full local path works end-to-end,
now with a desktop shell:

- **`keepsake-crypto`** — BIP-39 → HKDF roots; random-DEK AES-256-GCM envelope (erasure
  proven by test); X25519 sealed-box sharing.
- **`keepsake-core`** — two-plane store (§4a invariant #1 proven); Contradiction Ledger.
- **`keepsake-store-sqlite`** — durable store; §4a invariant #2 proven (wrapped DEK
  physically gone from db + WAL after `forget`).
- **`keepsake-retrieval`** — local embeddings + in-RAM index; real BGE/Nomic behind `fastembed`.
- **`keepsake-vault`** — semantic remember/recall/forget/share/rebuild.
- **`keepsake-firewall`** — Privacy Dial, PII redaction, HMAC-chained Memory Receipts.
- **`keepsake-proxy`** — OpenAI-compatible gateway → Ollama (e2e verified) + localhost P0.
- **`keepsake-mcp`** — SAIHM tool router (8 `saihm_*` tools).
- **`keepsake-cli`** — `keepsake` terminal app.
- **`keepsake-sync` + `keepsake-relay`** — encrypted snapshot sync over a dumb HTTP relay.
- **`keepsake-desktop-core` + `apps/desktop`** — Tauri v2 desktop app: testable vault
  commands wired to a clean, light Tailwind frontend.

---

## MVP — "Smallest Lovable Vault" (single-device, local-only)

One binary; point any OpenAI-compatible client at `localhost`; the AI remembers
across sessions; nothing leaves the machine.

- [x] `keepsake-crypto` (key hierarchy, random-DEK envelope, erasure)
- [x] `keepsake-core` (two-plane store, forget mechanics)
- [x] **SQLCipher full-DB encryption at rest** + §4a invariant #2 (`secure_delete=ON`
      + `wal_checkpoint(TRUNCATE)`, key-row hard-delete; tested: no plaintext header on disk).
- [x] Local embeddings + in-RAM index, per-cell encrypted embeddings.
      **Real Nomic model is the default** in proxy/CLI (BGE via `KEEPSAKE_EMBED=bge`); `MockEmbedder` in tests.
- [x] `keepsake-proxy` — OpenAI gateway, RAG injection + write-back → Ollama; localhost P0. (e2e verified)
- [x] `keepsake-mcp` — SAIHM tool router + **MCP stdio server** (JSON-RPC 2.0; Claude/Cursor
      can connect) + **capability-token enforcement** (scoped third-party access).
- [x] Seed init + remember/recall/forget UX via `keepsake-cli`.

**First acceptance criterion:** local RAG injection measurably improves answers
without blowing the token budget or poisoning context.

---

## v1 — Multi-device + Context-Firewall

- [x] `keepsake-firewall` — **Privacy Dial** + PII redaction + HMAC-chained **Memory Receipts**,
      wired into the proxy. *Consented cloud routing to actual cloud providers: pending.*
- [x] Sharing crypto — **X25519** sealed-box + `MemoryVault::share`; **ML-DSA-65** PQC
      signatures; **ML-KEM-768 hybrid** (X25519 + PQ KEM) sealing; **SAIHM sharing
      contracts** (TEMPORARY ≤24h / PERMANENT / SYNDICATE multi-party).
- [x] **Contradiction Ledger** (bi-temporal `valid_from`/`superseded_at`).
      *Consolidation, decay/salience, injection-guard hardening: pending.*
- [x] `keepsake-sync` + **`keepsake-relay`** — state-based snapshot sync (encrypted records
      + tombstones) over a dumb, bearer-auth HTTP relay (e2e-tested); erasure-safe (forget
      drops the key from the next snapshot).
      *Automerge field-level CRDT merge + persistent/multi-slot relay + device pairing UX: pending.*
- [x] **Tauri desktop** (`apps/desktop`) — production, offline-first macOS app.
      Mockup-matched UI (green "secure & local" design): first-run onboarding (24-word
      seed), unlock, dashboard (secure card + privacy slider + "remember" input +
      date-grouped E2E-encrypted timeline), semantic search ("via Nomic"). Logic in the
      tauri-free, unit-tested `keepsake-desktop-core`. **Fully offline**: Tailwind v4
      compiled locally (no CDN), strict CSP (`default-src 'self'`, `connect-src ipc:`),
      Nomic loaded from local files (no hf-hub). Verified end-to-end in the built `.app`
      (onboard → remember → semantic recall → forget) and with Wi-Fi OFF. Ships as an
      **unsigned** `.dmg` (15 MB). *Pending (external/CEO): Apple Developer ID signing +
      notarization for frictionless distribution; bundling the 529 MB model into the DMG
      for offline-on-any-machine (vs. one-time download); cell/receipt browser, consent
      prompts, recovery UX.*
- [x] Opt-in recovery — **Shamir social recovery** (`keepsake recovery split/combine`,
      threshold-of-n over GF(2^8)) + **device pairing** (CLI flow `keepsake pair
      new/offer/accept`; seal the seed to a new device's one-time code).
      *Full SLIP-39 word mnemonics + WebAuthn-PRF unlock: pending.*
- [x] **Capability tokens** (`keepsake_firewall::capability`) — macaroon-style, attenuable
      (narrow-only), offline-verifiable; **enforced in the MCP tool router and the proxy**
      (`X-Keepsake-Capability` header scopes/limits third-party retrieval).

---

## v2 — Ecosystem + Mobile + Hardening

- [ ] iOS/Android SDKs (uniffi); mobile companion.
- [ ] Entity/relation graph layer.
- [ ] **Memory Passport** export/import + interop demo with other SAIHM implementations.
- [ ] Optional chain-audit adapter (off by default; the core stays token-/chain-free).
- [ ] External security audit of `keepsake-crypto` / `keepsake-firewall`; fuzzing; reproducible builds.

---

## Research Horizon / North-Star (cryptographic frontier)

Forward-looking primitives. Not committed scope — tracked here so we adopt them the
moment they're practical. Both are honestly **not** drop-in today; notes below.

### 1. OPRF — Oblivious Pseudorandom Functions 🕶️ *(target: v2)*

**Goal.** An *optional, encrypted cloud backup* where a server can validate a
password / authorize access to a manifest **without ever seeing the password, the
keys, or the plaintext** — and without enabling offline brute-force of the password.

**Primitive.** OPRF (RFC 9497) and OPRF-based PAKE such as **OPAQUE** (asymmetric
password-authenticated key exchange). The client and server jointly evaluate a
pseudorandom function so the server learns nothing about the input or output; the
server stores only blinded material and rate-limits *online* guesses, killing the
offline-cracking threat that plagues "encrypted blob + password" backups.

**Where it plugs in.** A zero-knowledge backup/sync endpoint (self-hostable; never a
paywall) that gates access to encrypted key-manifest blobs. Fits the existing stance:
the relay/server stays "dumb" and key-blind; OPRF just lets it *authenticate* without
*learning*.

**Feasibility.** Practical today (Rust OPAQUE/OPRF crates exist). The real cost is
protocol/UX care (recovery, server compromise model), not performance.

### 2. FHE — Fully Homomorphic Encryption 🔬 *(target: long-term / north-star)*

**Goal.** Let semantic search run over the memory **while every vector and record
stays encrypted on disk AND in RAM** — eliminating the current "decrypt-to-RAM
working set" entirely. The model could query an always-encrypted index.

**Where it plugs in.** Replaces §5's decrypt-to-RAM ANN with computation on
ciphertext: encrypted dot-products / similarity over encrypted embeddings.

**Feasibility (honest).** Not practical today. Per our research, FHE similarity ops
run ~10⁶× slower than plaintext (seconds per operation); even partial/somewhat-HE
schemes are ~10²–10³× and viable only for tiny indices. Treat as a **north-star**:
track scheme maturity (CKKS/TFHE, hardware accel), and consider a narrow PHE path
(e.g., encrypted dot-product over small candidate sets surfaced by a cheaper filter)
as an intermediate step. Until then, the practical sovereignty lever remains
**local embeddings + encrypted-at-rest index + decrypt-to-locked-RAM**.

---

*Full architecture & decisions: design dossier (private planning doc). This file is
the public, durable roadmap.*
