//! `keepsake-sync` — state-based, erasure-safe multi-device sync over a dumb relay.
//!
//! A [`SyncState`] is a *current-state* snapshot (encrypted [`CellRecord`]s + tombstone
//! ids) — never append-only history (§4a). The relay stores only the latest opaque
//! snapshot per device and sees no plaintext and no unwrapped keys; a forgotten cell
//! simply drops out of the next snapshot, so its wrapped key stops being relayed.

use std::collections::HashMap;

use keepsake_store_sqlite::{CellRecord, SqliteVault, StoreError};
use serde::{Deserialize, Serialize};

/// A current-state sync snapshot of a vault.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncState {
    pub records: Vec<CellRecord>,
    pub tombstones: Vec<[u8; 32]>,
}

impl SyncState {
    /// Snapshot the live records + tombstones of a vault.
    pub fn from_vault(vault: &SqliteVault) -> Result<SyncState, StoreError> {
        Ok(SyncState {
            records: vault.export_live_records()?,
            tombstones: vault.tombstone_ids()?,
        })
    }

    /// Merge this snapshot into `vault`: apply tombstones first (erasure wins), then
    /// import records (which themselves skip any locally-tombstoned cell).
    pub fn apply_to(&self, vault: &SqliteVault) -> Result<(), StoreError> {
        for tombstone in &self.tombstones {
            vault.apply_tombstone(tombstone)?;
        }
        for record in &self.records {
            vault.import_record(record)?;
        }
        Ok(())
    }

    /// Serialize for transport.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("SyncState serializes")
    }

    /// Deserialize a transported snapshot.
    pub fn from_bytes(bytes: &[u8]) -> Option<SyncState> {
        serde_json::from_slice(bytes).ok()
    }
}

/// A dumb in-memory relay: stores only the latest opaque snapshot per device id. It
/// never sees plaintext or unwrapped keys. A network relay has the same interface.
#[derive(Default)]
pub struct MemRelay {
    blobs: HashMap<String, Vec<u8>>,
}

impl MemRelay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Push (replace) a device's latest snapshot.
    pub fn push(&mut self, device: &str, blob: Vec<u8>) {
        self.blobs.insert(device.to_string(), blob);
    }

    /// Pull a device's latest snapshot.
    pub fn pull(&self, device: &str) -> Option<Vec<u8>> {
        self.blobs.get(device).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepsake_crypto::{Kek, RootKeys};

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_kek() -> Kek {
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        Kek::from_root(&roots.encryption_root)
    }

    #[test]
    fn two_devices_converge_through_the_relay() {
        let kek = test_kek();
        let a = SqliteVault::open_in_memory().unwrap();
        let b = SqliteVault::open_in_memory().unwrap();
        let mut relay = MemRelay::new();

        let id = a.remember(&kek, b"shared across devices").unwrap();
        relay.push("alice", SyncState::from_vault(&a).unwrap().to_bytes());

        let blob = relay.pull("alice").unwrap();
        SyncState::from_bytes(&blob).unwrap().apply_to(&b).unwrap();
        assert_eq!(
            b.recall(&kek, &id).unwrap().as_deref(),
            Some(&b"shared across devices"[..])
        );
    }

    #[test]
    fn forget_propagates_and_drops_the_key_from_the_relay() {
        let kek = test_kek();
        let a = SqliteVault::open_in_memory().unwrap();
        let b = SqliteVault::open_in_memory().unwrap();
        let mut relay = MemRelay::new();

        let id = a.remember(&kek, b"temporary").unwrap();
        relay.push("alice", SyncState::from_vault(&a).unwrap().to_bytes());
        SyncState::from_bytes(&relay.pull("alice").unwrap())
            .unwrap()
            .apply_to(&b)
            .unwrap();
        assert!(b.recall(&kek, &id).unwrap().is_some());

        // Forget on A: the new snapshot no longer carries the wrapped key (state-based).
        a.forget(&id).unwrap();
        let snapshot = SyncState::from_vault(&a).unwrap();
        assert!(
            snapshot.records.is_empty(),
            "a forgotten cell's wrapped key must not appear in the next snapshot"
        );
        relay.push("alice", snapshot.to_bytes());
        SyncState::from_bytes(&relay.pull("alice").unwrap())
            .unwrap()
            .apply_to(&b)
            .unwrap();
        assert_eq!(b.recall(&kek, &id).unwrap(), None);
    }
}
