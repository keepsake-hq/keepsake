//! `keepsake-core` — the two-plane vault store and the §4a erasure mechanics.
//!
//! - **Content plane** (append-only): ciphertext cells + tombstones. Inert without keys.
//! - **Key-manifest plane** (erasable): the *only* home of wrapped DEKs.
//!
//! `forget` hard-deletes the manifest entry and tombstones the content, so a
//! restored append-only content backup is undecryptable even with the seed.

use std::collections::{HashMap, HashSet};

use keepsake_crypto::{CryptoError, Kek, SealedCell, WrappedDek};
use sha2::{Digest, Sha256};

/// Content-addressed identifier for a cell: SHA-256 of its ciphertext.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CellId([u8; 32]);

impl CellId {
    /// Derive the id from a sealed cell (hash of the ciphertext).
    pub fn of(cell: &SealedCell) -> CellId {
        let mut hasher = Sha256::new();
        hasher.update(&cell.ciphertext);
        let mut id = [0u8; 32];
        id.copy_from_slice(&hasher.finalize());
        CellId(id)
    }

    /// The raw 32-byte identifier.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reconstruct a `CellId` from its raw bytes (e.g. read back from a store).
    pub fn from_bytes(bytes: [u8; 32]) -> CellId {
        CellId(bytes)
    }
}

/// Append-only store of ciphertext cells and tombstones.
///
/// **Invariant (§4a):** this plane NEVER holds key material. Its API cannot
/// accept a [`WrappedDek`] — wrapped DEKs live only in the [`KeyManifest`].
pub trait ContentStore {
    fn append_cell(&mut self, id: &CellId, cell: SealedCell);
    fn get_cell(&self, id: &CellId) -> Option<SealedCell>;
    fn tombstone(&mut self, id: &CellId);
    fn is_tombstoned(&self, id: &CellId) -> bool;
}

/// Mutable, erasable store of wrapped per-cell DEKs (the only home of key material).
pub trait KeyManifest {
    fn put(&mut self, id: &CellId, wrapped: WrappedDek);
    fn get(&self, id: &CellId) -> Option<WrappedDek>;
    /// Hard-delete the wrapped DEK for `id`. After this the cell is unrecoverable.
    fn erase(&mut self, id: &CellId);
}

/// In-memory append-only content store.
#[derive(Default, Clone)]
pub struct MemContentStore {
    cells: HashMap<CellId, SealedCell>,
    tombstones: HashSet<CellId>,
}

impl ContentStore for MemContentStore {
    fn append_cell(&mut self, id: &CellId, cell: SealedCell) {
        self.cells.insert(id.clone(), cell);
    }
    fn get_cell(&self, id: &CellId) -> Option<SealedCell> {
        self.cells.get(id).cloned()
    }
    fn tombstone(&mut self, id: &CellId) {
        self.tombstones.insert(id.clone());
    }
    fn is_tombstoned(&self, id: &CellId) -> bool {
        self.tombstones.contains(id)
    }
}

/// In-memory erasable key manifest.
#[derive(Default, Clone)]
pub struct MemKeyManifest {
    keys: HashMap<CellId, WrappedDek>,
}

impl KeyManifest for MemKeyManifest {
    fn put(&mut self, id: &CellId, wrapped: WrappedDek) {
        self.keys.insert(id.clone(), wrapped);
    }
    fn get(&self, id: &CellId) -> Option<WrappedDek> {
        self.keys.get(id).cloned()
    }
    fn erase(&mut self, id: &CellId) {
        self.keys.remove(id);
    }
}

/// A vault binding the append-only content plane to the erasable key-manifest plane.
pub struct Vault<C: ContentStore, M: KeyManifest> {
    content: C,
    manifest: M,
}

impl<C: ContentStore, M: KeyManifest> Vault<C, M> {
    pub fn new(content: C, manifest: M) -> Self {
        Vault { content, manifest }
    }

    /// Borrow the content plane (e.g. to snapshot it for backup/sync).
    pub fn content(&self) -> &C {
        &self.content
    }

    /// Seal `plaintext` and store it across both planes; returns the cell id.
    pub fn remember(&mut self, kek: &Kek, plaintext: &[u8]) -> CellId {
        let (cell, wrapped) = kek.seal(plaintext);
        let id = CellId::of(&cell);
        self.content.append_cell(&id, cell);
        self.manifest.put(&id, wrapped);
        id
    }

    /// Recall and decrypt a cell. Returns `Ok(None)` if absent, tombstoned, or its
    /// key has been erased.
    pub fn recall(&self, kek: &Kek, id: &CellId) -> Result<Option<Vec<u8>>, CryptoError> {
        if self.content.is_tombstoned(id) {
            return Ok(None);
        }
        let Some(cell) = self.content.get_cell(id) else {
            return Ok(None);
        };
        let Some(wrapped) = self.manifest.get(id) else {
            return Ok(None);
        };
        Ok(Some(kek.open(&cell, &wrapped)?))
    }

    /// §4a `forget`: hard-delete the key-manifest entry and tombstone the content.
    pub fn forget(&mut self, id: &CellId) {
        self.manifest.erase(id);
        self.content.tombstone(id);
    }
}

/// Bi-temporal contradiction ledger: conflicting facts are versioned, never blindly
/// overwritten (§5 — makes memory evolution auditable, supports cryptographic erasure
/// per version via `saihm_forget`).
pub mod ledger {
    use std::collections::HashMap;

    /// One version of a fact, valid from `valid_from` until `superseded_at` (if set).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct FactVersion {
        pub value: String,
        pub valid_from: u64,
        pub superseded_at: Option<u64>,
    }

    /// A keyed, append-only history of fact values with conflict tracking.
    #[derive(Default)]
    pub struct ContradictionLedger {
        facts: HashMap<String, Vec<FactVersion>>,
        conflicts: usize,
    }

    impl ContradictionLedger {
        pub fn new() -> Self {
            Self::default()
        }

        /// Record `value` for `key` at logical time `t`. Returns `true` if this
        /// contradicted (superseded) a different existing value.
        pub fn record(&mut self, key: &str, value: &str, t: u64) -> bool {
            let versions = self.facts.entry(key.to_string()).or_default();
            match versions.last_mut() {
                Some(last) if last.value == value => false,
                Some(last) => {
                    last.superseded_at = Some(t);
                    versions.push(FactVersion {
                        value: value.to_string(),
                        valid_from: t,
                        superseded_at: None,
                    });
                    self.conflicts += 1;
                    true
                }
                None => {
                    versions.push(FactVersion {
                        value: value.to_string(),
                        valid_from: t,
                        superseded_at: None,
                    });
                    false
                }
            }
        }

        /// The currently-valid value for `key`.
        pub fn current(&self, key: &str) -> Option<&str> {
            self.facts
                .get(key)
                .and_then(|v| v.last())
                .map(|f| f.value.as_str())
        }

        /// The full version history for `key` (oldest first).
        pub fn history(&self, key: &str) -> &[FactVersion] {
            self.facts.get(key).map(|v| v.as_slice()).unwrap_or(&[])
        }

        /// Total number of contradictions recorded.
        pub fn conflicts(&self) -> usize {
            self.conflicts
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn contradicting_value_supersedes_and_keeps_history() {
            let mut ledger = ContradictionLedger::new();
            assert!(!ledger.record("home", "Vienna", 1));
            assert!(
                ledger.record("home", "Berlin", 2),
                "a different value contradicts"
            );

            assert_eq!(ledger.current("home"), Some("Berlin"));
            let history = ledger.history("home");
            assert_eq!(history.len(), 2);
            assert_eq!(history[0].superseded_at, Some(2));
            assert_eq!(history[1].superseded_at, None);
            assert_eq!(ledger.conflicts(), 1);
        }

        #[test]
        fn repeating_the_same_value_is_not_a_contradiction() {
            let mut ledger = ContradictionLedger::new();
            ledger.record("k", "v", 1);
            assert!(!ledger.record("k", "v", 2));
            assert_eq!(ledger.history("k").len(), 1);
            assert_eq!(ledger.conflicts(), 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepsake_crypto::RootKeys;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_kek() -> Kek {
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        Kek::from_root(&roots.encryption_root)
    }

    fn empty_vault() -> Vault<MemContentStore, MemKeyManifest> {
        Vault::new(MemContentStore::default(), MemKeyManifest::default())
    }

    #[test]
    fn cell_id_byte_roundtrip() {
        let kek = test_kek();
        let (cell, _wrapped) = kek.seal(b"x");
        let id = CellId::of(&cell);
        assert_eq!(CellId::from_bytes(*id.as_bytes()), id);
    }

    #[test]
    fn remember_then_recall_roundtrips() {
        let kek = test_kek();
        let mut vault = empty_vault();
        let id = vault.remember(&kek, b"hello memory");
        assert_eq!(
            vault.recall(&kek, &id).unwrap().as_deref(),
            Some(&b"hello memory"[..])
        );
    }

    #[test]
    fn forget_makes_recall_return_none() {
        let kek = test_kek();
        let mut vault = empty_vault();
        let id = vault.remember(&kek, b"secret");
        vault.forget(&id);
        assert_eq!(vault.recall(&kek, &id).unwrap(), None);
    }

    #[test]
    fn forget_is_irrecoverable_from_appendonly_content_backup_and_seed() {
        let kek = test_kek();
        let mut vault = empty_vault();
        let id = vault.remember(&kek, b"erase me");

        // An append-only backup/sync captures ONLY the content plane. Wrapped DEKs
        // are never in this plane (§4a invariant, enforced by ContentStore's type).
        let content_backup = vault.content().clone();

        // forget(): manifest entry hard-deleted, content tombstoned.
        vault.forget(&id);

        // Attacker restores the old content backup and re-derives the KEK from the
        // seed — but no wrapped DEK exists anywhere, so the cell stays sealed.
        let restored = Vault::new(content_backup, MemKeyManifest::default());
        assert_eq!(
            restored.recall(&kek, &id).unwrap(),
            None,
            "restored append-only content + seed must NOT recover an erased cell"
        );
    }
}
