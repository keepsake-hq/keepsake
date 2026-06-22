//! `keepsake-desktop-core` — the desktop app's command logic, as plain, testable
//! functions over a held vault. The Tauri shell is a thin wrapper around these; keeping
//! them tauri-free makes the surface unit-testable and quick to compile.

use keepsake_core::CellId;
use keepsake_crypto::Kek;
use keepsake_retrieval::Embedder;
use keepsake_store_sqlite::StoreError;
use keepsake_vault::MemoryVault;
use serde::Serialize;

/// One recalled memory, ready to send to the frontend.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct MemoryHit {
    pub id: String,
    pub text: String,
}

/// Vault status for the frontend.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct VaultStatus {
    pub memories: usize,
    pub profile: String,
}

/// One memory on the dashboard timeline (chronological, with its creation time).
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct RecentMemory {
    pub id: String,
    pub text: String,
    pub created_at: i64,
}

/// An unlocked vault plus its KEK — the desktop app's session state.
pub struct Vaulted<E: Embedder> {
    vault: MemoryVault<E>,
    kek: Kek,
}

impl<E: Embedder> Vaulted<E> {
    pub fn new(vault: MemoryVault<E>, kek: Kek) -> Self {
        Vaulted { vault, kek }
    }

    /// Store a memory; returns the cell id (hex).
    pub fn remember(&mut self, text: &str) -> Result<String, String> {
        self.vault
            .remember(&self.kek, text)
            .map(|id| hex::encode(id.as_bytes()))
            .map_err(store_err)
    }

    /// Semantic recall of up to `k` memories.
    pub fn recall(&self, query: &str, k: usize) -> Result<Vec<MemoryHit>, String> {
        self.vault
            .recall(&self.kek, query, k)
            .map(|hits| {
                hits.into_iter()
                    .map(|(id, text)| MemoryHit {
                        id: hex::encode(id.as_bytes()),
                        text,
                    })
                    .collect()
            })
            .map_err(store_err)
    }

    /// Cryptographically erase a memory by its cell id (hex).
    pub fn forget(&mut self, cell_id_hex: &str) -> Result<(), String> {
        let bytes =
            hex::decode(cell_id_hex).map_err(|_| "invalid cell id (not hex)".to_string())?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "cell id must be 32 bytes".to_string())?;
        self.vault
            .forget(&CellId::from_bytes(arr))
            .map_err(store_err)
    }

    /// The most recent memories, newest first — backs the dashboard timeline.
    pub fn recent(&self, limit: usize) -> Result<Vec<RecentMemory>, String> {
        self.vault
            .recent(&self.kek, limit)
            .map(|rows| {
                rows.into_iter()
                    .map(|(id, text, created_at)| RecentMemory {
                        id: hex::encode(id.as_bytes()),
                        text,
                        created_at,
                    })
                    .collect()
            })
            .map_err(store_err)
    }

    /// Current vault status.
    pub fn status(&self) -> Result<VaultStatus, String> {
        Ok(VaultStatus {
            memories: self.vault.count().map_err(store_err)?,
            profile: "SAIHM Cell-/Tool-compatible, local receipt profile".to_string(),
        })
    }
}

fn store_err(e: StoreError) -> String {
    format!("vault error: {e:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepsake_crypto::RootKeys;
    use keepsake_retrieval::MockEmbedder;
    use keepsake_store_sqlite::SqliteVault;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn vaulted() -> Vaulted<MockEmbedder> {
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let kek = Kek::from_root(&roots.encryption_root);
        Vaulted::new(
            MemoryVault::new(
                SqliteVault::open_in_memory().unwrap(),
                MockEmbedder::new(64),
            ),
            kek,
        )
    }

    #[test]
    fn remember_recall_status_forget_cycle() {
        let mut v = vaulted();

        let id = v.remember("alpha alpha alpha").unwrap();
        assert_eq!(id.len(), 64, "cell id is 32 bytes hex");

        let hits = v.recall("alpha alpha alpha", 1).unwrap();
        assert_eq!(hits[0].text, "alpha alpha alpha");
        assert_eq!(hits[0].id, id);

        assert_eq!(v.status().unwrap().memories, 1);

        v.forget(&id).unwrap();
        assert_eq!(v.status().unwrap().memories, 0);
        assert!(v.recall("alpha alpha alpha", 5).unwrap().is_empty());
    }

    #[test]
    fn recent_returns_timeline_entries() {
        let mut v = vaulted();
        v.remember("a memory").unwrap();
        v.remember("another memory").unwrap();

        let recent = v.recent(10).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].id.len(), 64, "hex cell id");
        assert!(recent.iter().all(|m| m.created_at > 0));
        let texts: Vec<&str> = recent.iter().map(|m| m.text.as_str()).collect();
        assert!(texts.contains(&"a memory") && texts.contains(&"another memory"));
    }

    #[test]
    fn forget_rejects_bad_cell_id() {
        let mut v = vaulted();
        assert!(v.forget("not-hex").is_err());
        assert!(v.forget("abcd").is_err(), "too short");
    }
}
