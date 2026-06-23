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

Shipped (TDD, **127 tests**, `clippy`/`rustfmt` clean) — the full local path works end-to-end,
now with a desktop shell, a shared hub, quality recall, cloud routing, a knowledge graph,
portable backups, and a zero-knowledge cloud-backup core:

- **`keepsake-crypto`** — BIP-39 → HKDF roots; random-DEK AES-256-GCM envelope (erasure
  proven by test); X25519 sealed-box sharing.
- **`keepsake-core`** — two-plane store (§4a invariant #1 proven); Contradiction Ledger.
- **`keepsake-store-sqlite`** — durable store; §4a invariant #2 proven (wrapped DEK
  physically gone from db + WAL after `forget`).
- **`keepsake-retrieval`** — local embeddings + in-RAM index; real BGE/Nomic behind `fastembed`.
- **`keepsake-vault`** — semantic remember/recall/forget/share/rebuild; **recency-weighted recall**,
  **ledger-backed supersession** (superseded facts hidden), per-memory **provenance**,
  **knowledge-graph** integration, and portable **Passport** export/import.
- **`keepsake-firewall`** — Privacy Dial, PII redaction, HMAC-chained Memory Receipts.
- **`keepsake-proxy`** — OpenAI-compatible gateway → a local model **or a selected cloud provider**
  (under the Privacy Dial: redaction + signed receipt before egress); graph-enriched recall;
  optional auto-extraction of facts & graph triples; localhost P0.
- **`keepsake-mcp`** — SAIHM tool router (8 `saihm_*` tools).
- **`keepsake-cli`** — `keepsake` terminal app.
- **`keepsake-sync` + `keepsake-relay`** — encrypted snapshot sync over a dumb HTTP relay.
- **`keepsake-desktop-core` + `apps/desktop`** — Tauri v2 desktop app: testable vault
  commands wired to a clean, light Tailwind frontend; **hosts the shared hub** on unlock.
- **`keepsake-daemon`** — the shared **hub**: one unlocked vault + live index served to all
  clients (MCP/proxy/desktop) over a Unix socket + optional TCP (token-required for the network);
  **write-time dedup + background consolidation** (anti-bloat); one-command onboarding
  (`keepsake serve|token|mcp-config`); Linux binaries + Dockerfile for VPS hosting.
- **`keepsake-graph`** — knowledge-graph layer: `(subject, relation, object)` triples distilled
  from memories, **erasure-aware edges** (forget cascades), and **graph-enriched recall** that
  surfaces connected memories a pure vector search misses.
- **`keepsake-backup`** — **OPAQUE** (aPAKE) zero-knowledge cloud-backup core: the server validates
  a password and stores an encrypted backup **without ever seeing the password, seed, or plaintext**
  (Ristretto255 + Triple-DH + Argon2); a server-blind export key locks the Passport blob.

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

## v2 — Quality, Reach & Hardening  *(shipped this round)*

- [x] **Quality recall** — recency-weighted ranking, bi-temporal **Contradiction Ledger** wired
      into recall (superseded facts hidden), per-memory **provenance**.
- [x] **Cloud-model routing** — forward to a selected OpenAI-compatible cloud provider under the
      Privacy Dial (PII redaction + signed receipt before egress); keys stay in the operator's env.
      *Native Anthropic Messages adapter: follow-up.*
- [x] **Entity/relation knowledge graph** (`keepsake-graph`) — triples, erasure-aware edges,
      graph-enriched recall; exposed over the hub.
- [x] **Memory Passport** — portable, encrypted vault export/import (`keepsake export|import`).
      *Interop demo with another SAIHM implementation: follow-up.*
- [x] **OPAQUE zero-knowledge cloud-backup core** (`keepsake-backup`). *HTTP endpoint over the
      dumb relay: mechanical follow-up.*

Deferred / not built (deliberate or external):

- [ ] iOS/Android SDKs (uniffi) + mobile companion → **v3** (app-store accounts tie to a legal
      identity, which conflicts with anonymous distribution — a CEO decision).
- [ ] External security audit of `keepsake-crypto` / `keepsake-firewall` / `keepsake-backup`;
      `cargo-fuzz` targets; reproducible builds. *(Audit needs budget + a firm.)*
- [ ] Optional chain-audit adapter — deliberately deferred; the core stays token-/chain-free.
- [ ] Considered & **rejected: ORE / OPE** (order-revealing / -preserving encryption) — they leak
      ordering/distribution and solve a problem a local-first, *semantic* store does not have. The
      "compute on ciphertext" goal stays **FHE** (north-star).

---

## Research Horizon / North-Star (cryptographic frontier)

Forward-looking primitives. Not committed scope — tracked here so we adopt them the
moment they're practical. Both are honestly **not** drop-in today; notes below.

### 1. OPRF / OPAQUE — Oblivious PRF & aPAKE 🕶️ *(core shipped — `keepsake-backup`)*

> **Status (this round):** the OPAQUE handshake + export-key locker are implemented and tested in
> `keepsake-backup` (Ristretto255 + Triple-DH + Argon2): register→login yields the same server-blind
> export key, a wrong password fails, and that key locks the backup blob. Remaining: the relay HTTP
> endpoint (upload/download the locked blob, gated by OPAQUE login) and an external crypto review.


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
