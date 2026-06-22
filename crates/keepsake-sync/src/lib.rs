//! `keepsake-sync` — state-based, erasure-safe multi-device sync over a dumb relay.
//!
//! A [`SyncState`] is a *current-state* snapshot (encrypted [`CellRecord`]s + tombstone
//! ids) — never append-only history (§4a). The relay stores only the latest opaque
//! snapshot per device and sees no plaintext and no unwrapped keys; a forgotten cell
//! simply drops out of the next snapshot, so its wrapped key stops being relayed.

use std::collections::HashMap;

use keepsake_crypto::{sync_mac, sync_mac_verify};
use keepsake_store_sqlite::{CellRecord, SqliteVault, StoreError};
use serde::{Deserialize, Serialize};

/// Maximum size of a serialized + authenticated snapshot. A larger blob is rejected before
/// any verification, bounding a malicious relay's ability to exhaust memory (KS-013).
pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 1_000_000;
const MAX_TOMBSTONES: usize = 1_000_000;
const MAC_LEN: usize = 32;

/// A current-state sync snapshot of a vault.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncState {
    /// Monotonic per-sender epoch; receivers reject snapshots that do not move it forward.
    pub epoch: u64,
    pub records: Vec<CellRecord>,
    pub tombstones: Vec<[u8; 32]>,
}

impl SyncState {
    /// Snapshot the live records + tombstones of a vault, stamped with the vault's next
    /// monotonic send-epoch.
    pub fn from_vault(vault: &SqliteVault) -> Result<SyncState, StoreError> {
        Ok(SyncState {
            epoch: vault.next_send_epoch()?,
            records: vault.export_live_records()?,
            tombstones: vault.tombstone_ids()?,
        })
    }

    /// Merge an authenticated snapshot into `vault` for sync `stream`. Returns `Ok(false)`
    /// and changes nothing if the snapshot is stale/replayed (its epoch does not exceed the
    /// highest already applied from this stream). Tombstones apply first (erasure wins);
    /// records have their `cell_id` bound to their ciphertext inside `import_record`.
    pub fn apply_to(&self, vault: &SqliteVault, stream: &str) -> Result<bool, StoreError> {
        if self.epoch <= vault.seen_epoch(stream)? {
            return Ok(false);
        }
        for tombstone in &self.tombstones {
            vault.apply_tombstone(tombstone)?;
        }
        for record in &self.records {
            vault.import_record(record)?;
        }
        vault.set_seen_epoch(stream, self.epoch)?;
        Ok(true)
    }

    /// Serialize and authenticate for transport: `payload(JSON) || HMAC-SHA256`. Only a
    /// holder of the seed-derived `sync_key` (one of the user's own devices) can produce a
    /// valid tag, so a relay can neither forge nor tamper with a snapshot.
    pub fn seal(&self, sync_key: &[u8; 32]) -> Vec<u8> {
        let mut out = serde_json::to_vec(self).expect("SyncState serializes");
        let tag = sync_mac(sync_key, &out);
        out.extend_from_slice(&tag);
        out
    }

    /// Verify and deserialize a transported snapshot. `None` if it is oversized, the MAC does
    /// not verify (forged/tampered), or it exceeds the record/tombstone bounds.
    pub fn open(bytes: &[u8], sync_key: &[u8; 32]) -> Option<SyncState> {
        if bytes.len() < MAC_LEN || bytes.len() > MAX_SNAPSHOT_BYTES {
            return None;
        }
        let (payload, tag) = bytes.split_at(bytes.len() - MAC_LEN);
        if !sync_mac_verify(sync_key, payload, tag) {
            return None;
        }
        let state: SyncState = serde_json::from_slice(payload).ok()?;
        if state.records.len() > MAX_RECORDS || state.tombstones.len() > MAX_TOMBSTONES {
            return None;
        }
        Some(state)
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

    fn roots() -> RootKeys {
        RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap()
    }
    fn test_kek() -> Kek {
        Kek::from_root(&roots().encryption_root)
    }
    fn sync_key() -> [u8; 32] {
        roots().sync_mac_key()
    }

    #[test]
    fn two_devices_converge_through_the_relay() {
        let kek = test_kek();
        let key = sync_key();
        let a = SqliteVault::open_in_memory().unwrap();
        let b = SqliteVault::open_in_memory().unwrap();
        let mut relay = MemRelay::new();

        let id = a.remember(&kek, b"shared across devices").unwrap();
        relay.push("alice", SyncState::from_vault(&a).unwrap().seal(&key));

        let blob = relay.pull("alice").unwrap();
        assert!(SyncState::open(&blob, &key)
            .unwrap()
            .apply_to(&b, "alice")
            .unwrap());
        assert_eq!(
            b.recall(&kek, &id).unwrap().as_deref(),
            Some(&b"shared across devices"[..])
        );
    }

    #[test]
    fn forget_propagates_and_drops_the_key_from_the_relay() {
        let kek = test_kek();
        let key = sync_key();
        let a = SqliteVault::open_in_memory().unwrap();
        let b = SqliteVault::open_in_memory().unwrap();
        let mut relay = MemRelay::new();

        let id = a.remember(&kek, b"temporary").unwrap();
        relay.push("alice", SyncState::from_vault(&a).unwrap().seal(&key));
        SyncState::open(&relay.pull("alice").unwrap(), &key)
            .unwrap()
            .apply_to(&b, "alice")
            .unwrap();
        assert!(b.recall(&kek, &id).unwrap().is_some());

        // Forget on A: the new snapshot no longer carries the wrapped key (state-based).
        a.forget(&id).unwrap();
        let snapshot = SyncState::from_vault(&a).unwrap();
        assert!(
            snapshot.records.is_empty(),
            "a forgotten cell's wrapped key must not appear in the next snapshot"
        );
        relay.push("alice", snapshot.seal(&key));
        SyncState::open(&relay.pull("alice").unwrap(), &key)
            .unwrap()
            .apply_to(&b, "alice")
            .unwrap();
        assert_eq!(b.recall(&kek, &id).unwrap(), None);
    }

    #[test]
    fn a_snapshot_sealed_with_the_wrong_key_is_rejected() {
        // A relay (no seed) cannot forge a valid MAC, so a snapshot that would tombstone a
        // cell does not verify and is never applied.
        let kek = test_kek();
        let a = SqliteVault::open_in_memory().unwrap();
        let id = a.remember(&kek, b"keep me").unwrap();
        let forged = SyncState {
            epoch: 99,
            records: vec![],
            tombstones: vec![*id.as_bytes()],
        };
        let blob = forged.seal(&[0x99u8; 32]); // attacker's key, not the vault's
        assert!(
            SyncState::open(&blob, &sync_key()).is_none(),
            "a snapshot sealed with the wrong key must not verify"
        );
        assert!(
            a.recall(&kek, &id).unwrap().is_some(),
            "the cell survives a forged snapshot"
        );
    }

    #[test]
    fn a_replayed_older_snapshot_is_rejected() {
        let kek = test_kek();
        let key = sync_key();
        let a = SqliteVault::open_in_memory().unwrap();
        let b = SqliteVault::open_in_memory().unwrap();
        let id = a.remember(&kek, b"v1").unwrap();

        let stale = SyncState::from_vault(&a).unwrap().seal(&key); // epoch 1, carries the cell
        assert!(SyncState::open(&stale, &key)
            .unwrap()
            .apply_to(&b, "chan")
            .unwrap());

        a.forget(&id).unwrap();
        let fresh = SyncState::from_vault(&a).unwrap().seal(&key); // epoch 2, carries tombstone
        assert!(SyncState::open(&fresh, &key)
            .unwrap()
            .apply_to(&b, "chan")
            .unwrap());
        assert_eq!(b.recall(&kek, &id).unwrap(), None);

        // The relay replays the OLD (epoch 1) snapshot: rejected by the epoch gate.
        let applied = SyncState::open(&stale, &key)
            .unwrap()
            .apply_to(&b, "chan")
            .unwrap();
        assert!(!applied, "a replayed older snapshot must be rejected");
        assert_eq!(
            b.recall(&kek, &id).unwrap(),
            None,
            "an erased cell stays erased after a replay attempt"
        );
    }

    #[test]
    fn an_oversize_blob_is_rejected_before_verification() {
        let huge = vec![0u8; MAX_SNAPSHOT_BYTES + 1];
        assert!(
            SyncState::open(&huge, &sync_key()).is_none(),
            "an oversize blob must be rejected"
        );
    }
}
