# Security Policy

Keepsake is a young (v0.x), anonymously-published project. We take security
seriously **and** try to be honest about what is and isn't protected — see the
threat model below before relying on it.

## Reporting a vulnerability

Please report privately, **not** in a public issue:

- **GitHub:** open a [private security advisory](https://github.com/keepsake-hq/keepsake/security/advisories/new).
- **Email:** keepsake-vault@proton.me

Include a description, the affected version or commit, and a reproduction if you
have one. We aim to acknowledge within a few days and to fix confirmed,
high-severity issues before public disclosure. There is no bug-bounty budget
(anonymous OSS), but we credit reporters who want it.

## Supported versions

Only the **latest release** (and `main`) receive fixes. Always run the newest
release — older binaries do not get backported patches.

## Threat model — honest scope

**What Keepsake protects**

- **At rest.** The vault is SQLCipher-encrypted; each memory is sealed with a
  random per-memory key (AES-256-GCM envelope). `forget` destroys that key, so
  the ciphertext becomes mathematically undecryptable (cryptographic erasure).
- **Sharing & signatures.** X25519 + ML-KEM-768 hybrid sealing and ML-DSA-65
  signatures (post-quantum).
- **Delegation.** Third-party agents receive **capability tokens** (macaroon-style,
  attenuable, offline-verifiable) that scope read / write / admin, a record limit,
  a topic, and an expiry — enforced in the MCP server, the proxy, and the daemon.
- **Cloud disclosure.** Every cloud egress is gated by the Privacy Dial and
  written to a signed, local Memory Receipt.

**What Keepsake does NOT protect (by design, or not yet)**

- **Cloud inference is not zero-knowledge.** Anything sent to a cloud model is
  plaintext to that provider. Keepsake makes local the default and logs every
  disclosure — it does not hide this. (Routing to actual cloud providers through
  the proxy is still on the roadmap; today the proxy targets a local model.)
- **The seed on a trusted machine.** In local CLI/MCP mode the BIP-39 seed is
  supplied via the `KEEPSAKE_MNEMONIC` environment variable, so it lives in that
  process's environment — treat the machine and its processes as trusted. The
  **shared daemon** mode reduces this: the daemon holds the unlocked key, and each
  client (Claude / Cursor / Codex) connects with a **scoped capability token
  instead of the seed**.
- **No external audit yet.** The `keepsake-crypto` / `keepsake-firewall` crates
  have not been audited by a third party. This is tracked for a future release.
  Until then the trust substitute is **small, readable Rust you can audit and
  build yourself** (below).
- **Not Apple-notarized.** Notarization requires a paid Apple identity that would
  deanonymize the project; the app is ad-hoc signed and you open it manually once.

## Verify the build

You do not have to trust our binary. The whole thing builds from source (Rust +
Node), and the release is produced by a public GitHub Actions workflow
(`.github/workflows/release.yml`) with **no secret inputs**. Build it yourself and
compare, or simply run your own build. Every push and release also runs the full
test suite plus `clippy -D warnings` (`.github/workflows/ci.yml`), so a release
cannot ship on red tests.
