//! `keepsake-vault` — the integration layer: durable two-plane store + local
//! embeddings = a vault that actually *remembers*.
//!
//! `remember` stores the encrypted cell and indexes its embedding; `recall` embeds
//! the query, runs semantic search, and decrypts the hits; `forget` erases content
//! and drops the embedding. The in-RAM index is rebuilt from persisted content on
//! open (embeddings are derived from content, the single erasable source of truth).

use keepsake_core::CellId;
use keepsake_crypto::Kek;
use keepsake_retrieval::{Embedder, VectorIndex};
use keepsake_store_sqlite::{SqliteVault, StoreError};

/// SAIHM sharing-contract kinds: TEMPORARY (≤24h), PERMANENT, SYNDICATE (multi-party).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContractKind {
    Temporary { expires_at: u64 },
    Permanent,
    Syndicate,
}

/// The maximum lifetime of a TEMPORARY contract (SAIHM: ≤ 24h).
pub const TEMPORARY_MAX_SECS: u64 = 24 * 60 * 60;

/// A shared cell under a contract: the content sealed to each grantee's public key.
pub struct ShareContract {
    pub kind: ContractKind,
    pub issued_at: u64,
    /// `(grantee_public_key, sealed_blob)` for each grantee.
    pub portions: Vec<([u8; 32], Vec<u8>)>,
}

impl ShareContract {
    /// Whether the contract is valid at `now` (TEMPORARY honours its expiry).
    pub fn is_valid(&self, now: u64) -> bool {
        match self.kind {
            ContractKind::Temporary { expires_at } => now <= expires_at,
            ContractKind::Permanent | ContractKind::Syndicate => true,
        }
    }
}

/// A grantee opens their portion of a contract, if it is valid and addressed to them.
pub fn open_contract_portion(
    contract: &ShareContract,
    grantee: &keepsake_crypto::ShareKeypair,
    now: u64,
) -> Option<Vec<u8>> {
    if !contract.is_valid(now) {
        return None;
    }
    let pubkey = grantee.public();
    contract
        .portions
        .iter()
        .find(|(g, _)| *g == pubkey)
        .and_then(|(_, sealed)| keepsake_crypto::open_sealed(grantee, sealed).ok())
}

/// A semantic memory vault over a [`SqliteVault`] and a local [`Embedder`].
pub struct MemoryVault<E: Embedder> {
    store: SqliteVault,
    index: VectorIndex,
    embedder: E,
}

impl<E: Embedder> MemoryVault<E> {
    /// Wrap a store and embedder. The in-RAM index starts empty; call
    /// [`MemoryVault::rebuild_index`] to populate it from persisted content.
    pub fn new(store: SqliteVault, embedder: E) -> Self {
        MemoryVault {
            store,
            index: VectorIndex::new(),
            embedder,
        }
    }

    /// Store `text` as an encrypted cell and index its embedding. Returns the id.
    pub fn remember(&mut self, kek: &Kek, text: &str) -> Result<CellId, StoreError> {
        let id = self.store.remember(kek, text.as_bytes())?;
        let vector = self
            .embedder
            .embed(text)
            .map_err(|e| StoreError::Embed(e.to_string()))?;
        self.index.add(id.clone(), &vector);
        Ok(id)
    }

    /// Semantic recall: embed `query`, search the index, decrypt up to `k` hits.
    /// Returns `(cell_id, plaintext)` pairs, most relevant first.
    pub fn recall(
        &self,
        kek: &Kek,
        query: &str,
        k: usize,
    ) -> Result<Vec<(CellId, String)>, StoreError> {
        let query_vec = self
            .embedder
            .embed(query)
            .map_err(|e| StoreError::Embed(e.to_string()))?;
        let mut out = Vec::new();
        for (id, _score) in self.index.search(&query_vec, k) {
            if let Some(bytes) = self.store.recall(kek, &id)? {
                if let Ok(text) = String::from_utf8(bytes) {
                    out.push((id, text));
                }
            }
        }
        Ok(out)
    }

    /// Erase a memory: forget the content (cryptographic erasure) and drop its
    /// embedding from the index.
    pub fn forget(&mut self, id: &CellId) -> Result<(), StoreError> {
        self.store.forget(id)?;
        self.index.remove(id);
        Ok(())
    }

    /// Share a cell's content with a grantee by sealing it to their X25519 public key.
    /// The grantee opens it with `keepsake_crypto::open_sealed`; nobody else can, and the
    /// proxy never hands out plaintext.
    pub fn share(
        &self,
        kek: &Kek,
        id: &CellId,
        grantee_public: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        match self.store.recall(kek, id)? {
            Some(plaintext) => Ok(keepsake_crypto::seal_to(grantee_public, &plaintext)),
            None => Ok(None),
        }
    }

    /// Number of live (non-forgotten) memories.
    pub fn count(&self) -> Result<usize, StoreError> {
        Ok(self.store.live_cell_ids()?.len())
    }

    /// Share a cell under a SAIHM contract: atomically seal the content to each grantee's
    /// public key. A TEMPORARY contract is rejected if its window is empty or exceeds 24h.
    pub fn share_with_contract(
        &self,
        kek: &Kek,
        id: &CellId,
        kind: ContractKind,
        grantees: &[[u8; 32]],
        now: u64,
    ) -> Result<Option<ShareContract>, StoreError> {
        if let ContractKind::Temporary { expires_at } = kind {
            if expires_at <= now || expires_at - now > TEMPORARY_MAX_SECS {
                return Ok(None);
            }
        }
        let Some(plaintext) = self.store.recall(kek, id)? else {
            return Ok(None);
        };
        // Atomic: if sealing to any grantee fails (e.g. a low-order / invalid key), reject
        // the whole contract rather than issuing a partial one.
        let Some(portions) = grantees
            .iter()
            .map(|g| keepsake_crypto::seal_to(g, &plaintext).map(|s| (*g, s)))
            .collect::<Option<Vec<_>>>()
        else {
            return Ok(None);
        };
        Ok(Some(ShareContract {
            kind,
            issued_at: now,
            portions,
        }))
    }

    /// The most recent live memories, newest first, as `(cell_id, plaintext,
    /// created_at)`. Chronological (no embedding/search) — backs the dashboard timeline.
    pub fn recent(
        &self,
        kek: &Kek,
        limit: usize,
    ) -> Result<Vec<(CellId, String, i64)>, StoreError> {
        let mut out = Vec::new();
        for (id, created_at) in self.store.recent(limit)? {
            if let Some(bytes) = self.store.recall(kek, &id)? {
                if let Ok(text) = String::from_utf8(bytes) {
                    out.push((id, text, created_at));
                }
            }
        }
        Ok(out)
    }

    /// Rebuild the in-RAM index from persisted content by re-embedding each live cell.
    pub fn rebuild_index(&mut self, kek: &Kek) -> Result<(), StoreError> {
        let mut index = VectorIndex::new();
        for id in self.store.live_cell_ids()? {
            if let Some(bytes) = self.store.recall(kek, &id)? {
                if let Ok(text) = String::from_utf8(bytes) {
                    let vector = self
                        .embedder
                        .embed(&text)
                        .map_err(|e| StoreError::Embed(e.to_string()))?;
                    index.add(id, &vector);
                }
            }
        }
        self.index = index;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepsake_crypto::RootKeys;
    use keepsake_retrieval::MockEmbedder;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_kek() -> Kek {
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        Kek::from_root(&roots.encryption_root)
    }

    fn memory_vault() -> MemoryVault<MockEmbedder> {
        MemoryVault::new(
            SqliteVault::open_in_memory().unwrap(),
            MockEmbedder::new(64),
        )
    }

    #[test]
    fn semantic_recall_returns_the_matching_memory() {
        let kek = test_kek();
        let mut vault = memory_vault();
        vault.remember(&kek, "alpha alpha alpha").unwrap();
        vault.remember(&kek, "bravo bravo bravo").unwrap();
        vault.remember(&kek, "charlie charlie charlie").unwrap();

        let hits = vault.recall(&kek, "bravo bravo bravo", 1).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "bravo bravo bravo");
    }

    #[test]
    fn recent_returns_decrypted_memories_with_timestamps() {
        let kek = test_kek();
        let mut vault = memory_vault();
        vault.remember(&kek, "first thing").unwrap();
        vault.remember(&kek, "second thing").unwrap();

        let recent = vault.recent(&kek, 10).unwrap();
        assert_eq!(recent.len(), 2);
        let texts: Vec<&str> = recent.iter().map(|(_, t, _)| t.as_str()).collect();
        assert!(texts.contains(&"first thing") && texts.contains(&"second thing"));
        assert!(
            recent.iter().all(|(_, _, ts)| *ts > 0),
            "carries a real timestamp"
        );
        assert_eq!(vault.recent(&kek, 1).unwrap().len(), 1, "limit respected");
    }

    #[test]
    fn forget_removes_from_semantic_recall() {
        let kek = test_kek();
        let mut vault = memory_vault();
        let id = vault.remember(&kek, "secret note").unwrap();
        vault.forget(&id).unwrap();

        let hits = vault.recall(&kek, "secret note", 5).unwrap();
        assert!(
            hits.iter().all(|(hid, _)| hid != &id),
            "forgotten memory must not surface"
        );
    }

    #[test]
    fn count_tracks_live_memories() {
        let kek = test_kek();
        let mut vault = memory_vault();
        let a = vault.remember(&kek, "one").unwrap();
        vault.remember(&kek, "two").unwrap();
        assert_eq!(vault.count().unwrap(), 2);
        vault.forget(&a).unwrap();
        assert_eq!(vault.count().unwrap(), 1);
    }

    #[test]
    fn share_seals_content_to_grantee_only() {
        use keepsake_crypto::{open_sealed, ShareKeypair};
        let kek = test_kek();
        let mut vault = memory_vault();
        let id = vault.remember(&kek, "shared secret note").unwrap();

        let grantee = ShareKeypair::from_seed(&[5u8; 32]);
        let other = ShareKeypair::from_seed(&[6u8; 32]);

        let sealed = vault.share(&kek, &id, &grantee.public()).unwrap().unwrap();
        let opened = open_sealed(&grantee, &sealed).unwrap();
        assert_eq!(String::from_utf8(opened).unwrap(), "shared secret note");
        assert!(
            open_sealed(&other, &sealed).is_err(),
            "only the grantee can open the shared cell"
        );
    }

    #[test]
    fn syndicate_contract_seals_to_all_grantees_only() {
        use keepsake_crypto::ShareKeypair;
        let kek = test_kek();
        let mut vault = memory_vault();
        let id = vault.remember(&kek, "syndicate secret").unwrap();

        let g1 = ShareKeypair::from_seed(&[1u8; 32]);
        let g2 = ShareKeypair::from_seed(&[2u8; 32]);
        let outsider = ShareKeypair::from_seed(&[9u8; 32]);

        let contract = vault
            .share_with_contract(
                &kek,
                &id,
                ContractKind::Syndicate,
                &[g1.public(), g2.public()],
                0,
            )
            .unwrap()
            .unwrap();
        assert_eq!(contract.portions.len(), 2);
        assert_eq!(
            String::from_utf8(open_contract_portion(&contract, &g1, 0).unwrap()).unwrap(),
            "syndicate secret"
        );
        assert_eq!(
            String::from_utf8(open_contract_portion(&contract, &g2, 0).unwrap()).unwrap(),
            "syndicate secret"
        );
        assert!(open_contract_portion(&contract, &outsider, 0).is_none());
    }

    #[test]
    fn temporary_contract_expires_and_rejects_over_24h() {
        use keepsake_crypto::ShareKeypair;
        let kek = test_kek();
        let mut vault = memory_vault();
        let id = vault.remember(&kek, "temp secret").unwrap();
        let g = ShareKeypair::from_seed(&[1u8; 32]);

        let contract = vault
            .share_with_contract(
                &kek,
                &id,
                ContractKind::Temporary { expires_at: 100 },
                &[g.public()],
                0,
            )
            .unwrap()
            .unwrap();
        assert!(
            open_contract_portion(&contract, &g, 50).is_some(),
            "valid before expiry"
        );
        assert!(
            open_contract_portion(&contract, &g, 200).is_none(),
            "expired afterwards"
        );

        // A window longer than 24h is rejected at issue.
        assert!(vault
            .share_with_contract(
                &kek,
                &id,
                ContractKind::Temporary {
                    expires_at: TEMPORARY_MAX_SECS + 1
                },
                &[g.public()],
                0,
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn rebuild_index_restores_recall_from_persisted_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let kek = test_kek();

        {
            let mut vault = MemoryVault::new(
                SqliteVault::open(&path, &[0x33u8; 32]).unwrap(),
                MockEmbedder::new(64),
            );
            vault.remember(&kek, "alpha alpha alpha").unwrap();
            vault.remember(&kek, "bravo bravo bravo").unwrap();
        }

        let mut reopened = MemoryVault::new(
            SqliteVault::open(&path, &[0x33u8; 32]).unwrap(),
            MockEmbedder::new(64),
        );
        // Fresh index is empty until rebuilt.
        assert!(reopened
            .recall(&kek, "alpha alpha alpha", 1)
            .unwrap()
            .is_empty());

        reopened.rebuild_index(&kek).unwrap();
        let hits = reopened.recall(&kek, "alpha alpha alpha", 1).unwrap();
        assert_eq!(hits[0].1, "alpha alpha alpha");
    }
}
