//! `keepsake-desktop-core` — the desktop app's command logic, as plain, testable
//! functions over a held vault. The Tauri shell is a thin wrapper around these; keeping
//! them tauri-free makes the surface unit-testable and quick to compile.

use keepsake_core::CellId;
use keepsake_crypto::Kek;
use keepsake_retrieval::Embedder;
use keepsake_store_sqlite::StoreError;
use keepsake_vault::{MemoryVault, RecencyParams};
use serde::{Deserialize, Serialize};

/// Where the vault auto-syncs. Local-first by default (`Off`); sync is opt-in.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum SyncConfig {
    /// No sync — the vault stays only on this device.
    #[default]
    Off,
    /// The anonymous, blind hosted relay (sees only ciphertext).
    Hosted,
    /// A relay the user runs themselves.
    Own { url: String },
}

/// The hosted relay endpoint (anonymous, Cloudflare-fronted; the origin server stays hidden).
pub const HOSTED_RELAY_URL: &str = "https://sync.keepsakehq.app";

impl SyncConfig {
    /// The relay URL to sync with, or `None` if syncing is off or the custom URL is blank.
    pub fn resolve_url(&self) -> Option<String> {
        match self {
            SyncConfig::Off => None,
            SyncConfig::Hosted => Some(HOSTED_RELAY_URL.to_string()),
            SyncConfig::Own { url } if !url.trim().is_empty() => Some(url.trim().to_string()),
            SyncConfig::Own { .. } => None,
        }
    }

    /// Load from a JSON file; missing, unreadable or corrupt → the default (`Off`).
    pub fn load(path: &std::path::Path) -> SyncConfig {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Persist as JSON, creating parent directories as needed.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }
}

/// Set the vault files in `dir` aside with a timestamp suffix (e.g. `vault.db` →
/// `vault-old-1700000000.db`) so the user can start fresh **without destroying** the old, still-
/// encrypted memories. Returns the archived names created. NEVER deletes — if the user later finds
/// their 24 words, the archived files can still be opened. Sidecars (`-wal`, `-shm`) and the sync
/// setting move alongside so the fresh vault starts clean; absent files are simply skipped.
pub fn archive_vault_files(dir: &std::path::Path, ts: i64) -> std::io::Result<Vec<String>> {
    let moves = [
        ("vault.db", format!("vault-old-{ts}.db")),
        ("vault.db-wal", format!("vault-old-{ts}.db-wal")),
        ("vault.db-shm", format!("vault-old-{ts}.db-shm")),
        ("sync.json", format!("sync-old-{ts}.json")),
        ("recovery.json", format!("recovery-old-{ts}.json")),
    ];
    let mut moved = Vec::new();
    for (from, to) in moves {
        let src = dir.join(from);
        if src.exists() {
            std::fs::rename(&src, dir.join(&to))?;
            moved.push(to);
        }
    }
    Ok(moved)
}

/// Split the 24 words into `shares` secret pieces, any `threshold` of which bring the words back —
/// the engine of social recovery ("give a piece to people you trust"). Each piece is a short
/// `index-hex` string to save/print and hand to one trusted person. A single piece reveals nothing.
pub fn recovery_split(mnemonic: &str, threshold: u8, shares: u8) -> Result<Vec<String>, String> {
    let entropy = bip39::Mnemonic::parse(mnemonic.trim())
        .map_err(|_| "not a valid set of 24 words".to_string())?
        .to_entropy();
    Ok(keepsake_crypto::recovery::split(&entropy, threshold, shares)
        .into_iter()
        .map(|p| format!("{}-{}", p.index, hex::encode(&p.bytes)))
        .collect())
}

/// Rebuild the 24 words from collected pieces (each `index-hex`). Returns the mnemonic to unlock
/// with. Needs at least two pieces from two different people; mismatched pieces are rejected kindly.
pub fn recovery_combine(shares: &[String]) -> Result<String, String> {
    let parts: Vec<keepsake_crypto::recovery::Share> = shares
        .iter()
        .filter_map(|s| {
            let (idx, hx) = s.trim().split_once('-')?;
            Some(keepsake_crypto::recovery::Share {
                index: idx.trim().parse().ok()?,
                bytes: hex::decode(hx.trim()).ok()?,
            })
        })
        .collect();
    if parts.len() < 2 {
        return Err("please add at least two pieces, from two different people".to_string());
    }
    let entropy = keepsake_crypto::recovery::combine(&parts).ok_or_else(|| {
        "these pieces don't fit together — check they're from two different people".to_string()
    })?;
    Ok(bip39::Mnemonic::from_entropy(&entropy)
        .map_err(|_| "could not rebuild your words from these pieces".to_string())?
        .to_string())
}

/// A local, non-secret record of a social-recovery setup: how many pieces bring the words back, and
/// friendly names of who holds one (so the app can remind the user whom to ask). The pieces
/// themselves are never stored — only the names. Lives next to the vault, never synced.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct RecoveryMeta {
    pub threshold: u8,
    pub names: Vec<String>,
}

impl RecoveryMeta {
    pub fn load(path: &std::path::Path) -> Option<RecoveryMeta> {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            path,
            serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?,
        )
    }
}

#[cfg(test)]
mod sync_config_tests {
    use super::{SyncConfig, HOSTED_RELAY_URL};

    #[test]
    fn resolves_each_mode_and_roundtrips_on_disk() {
        assert_eq!(SyncConfig::Off.resolve_url(), None);
        assert_eq!(
            SyncConfig::Hosted.resolve_url().as_deref(),
            Some(HOSTED_RELAY_URL)
        );
        assert_eq!(
            SyncConfig::Own {
                url: "https://r.example".into()
            }
            .resolve_url()
            .as_deref(),
            Some("https://r.example")
        );
        assert_eq!(SyncConfig::Own { url: "   ".into() }.resolve_url(), None);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.json");
        assert_eq!(SyncConfig::load(&path), SyncConfig::Off); // missing → default
        let cfg = SyncConfig::Own {
            url: "https://r.example".into(),
        };
        cfg.save(&path).unwrap();
        assert_eq!(SyncConfig::load(&path), cfg);
    }
}

/// One recalled memory, ready to send to the frontend.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct MemoryHit {
    pub id: String,
    pub text: String,
    /// Where the memory came from (e.g. `desktop`, `proxy:openai:gpt-4`, `mcp:claude`), if known.
    pub source: Option<String>,
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
    /// Where the memory came from, if known.
    pub source: Option<String>,
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

    /// Store a memory (tagged with `desktop` provenance); returns the cell id (hex).
    pub fn remember(&mut self, text: &str) -> Result<String, String> {
        self.vault
            .remember_with_source(&self.kek, text, now_unix(), Some("desktop"))
            .map(|id| hex::encode(id.as_bytes()))
            .map_err(store_err)
    }

    /// Quality recall of up to `k` memories: recency-weighted, superseded facts hidden, and
    /// enriched with knowledge-graph–connected memories, each carrying its provenance.
    pub fn recall(&self, query: &str, k: usize) -> Result<Vec<MemoryHit>, String> {
        let hits = self
            .vault
            .recall_with_graph(&self.kek, query, k, now_unix(), RecencyParams::default())
            .map_err(store_err)?;
        Ok(hits
            .into_iter()
            .map(|(id, text)| MemoryHit {
                source: self.vault.source(&id).ok().flatten(),
                id: hex::encode(id.as_bytes()),
                text,
            })
            .collect())
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

    /// The most recent memories, newest first — backs the dashboard timeline (with provenance).
    pub fn recent(&self, limit: usize) -> Result<Vec<RecentMemory>, String> {
        let rows = self.vault.recent(&self.kek, limit).map_err(store_err)?;
        Ok(rows
            .into_iter()
            .map(|(id, text, created_at)| RecentMemory {
                source: self.vault.source(&id).ok().flatten(),
                id: hex::encode(id.as_bytes()),
                text,
                created_at,
            })
            .collect())
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

/// Current wall-clock time in Unix seconds (0 if the clock predates the epoch).
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
        assert_eq!(
            hits[0].source.as_deref(),
            Some("desktop"),
            "desktop memories carry their provenance"
        );

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

    #[test]
    fn archive_vault_files_renames_aside_and_never_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        std::fs::write(p.join("vault.db"), b"db").unwrap();
        std::fs::write(p.join("vault.db-wal"), b"wal").unwrap();
        std::fs::write(p.join("sync.json"), b"{}").unwrap();
        // (no -shm sidecar on purpose)

        let moved = super::archive_vault_files(p, 1234).unwrap();

        // The live names are gone...
        assert!(!p.join("vault.db").exists());
        assert!(!p.join("sync.json").exists());
        // ...but NOTHING was destroyed — the bytes live on under the archived names.
        assert_eq!(std::fs::read(p.join("vault-old-1234.db")).unwrap(), b"db");
        assert!(p.join("vault-old-1234.db-wal").exists());
        assert!(p.join("sync-old-1234.json").exists());
        // The absent sidecar was simply skipped, not invented.
        assert!(!p.join("vault-old-1234.db-shm").exists());
        assert_eq!(moved.len(), 3);
    }

    #[test]
    fn recovery_split_then_any_two_pieces_rebuild_the_words() {
        let shares = super::recovery_split(TEST_MNEMONIC, 2, 3).unwrap();
        assert_eq!(shares.len(), 3, "three pieces for three trusted people");
        // Any two of the three reconstruct the original 24 words.
        for (a, b) in [(0, 1), (0, 2), (1, 2)] {
            let back =
                super::recovery_combine(&[shares[a].clone(), shares[b].clone()]).unwrap();
            assert_eq!(back, TEST_MNEMONIC, "pieces {a}+{b} bring the words back");
        }
        // A single piece reveals nothing and is refused.
        assert!(super::recovery_combine(&[shares[0].clone()]).is_err());
        // Garbage pieces are rejected kindly, not with a panic.
        assert!(super::recovery_combine(&["nonsense".into(), "1-zz".into()]).is_err());
    }
}
