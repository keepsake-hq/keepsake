//! `keepsake-store-sqlite` — durable two-plane vault store on SQLite.
//!
//! Implements the §4a erasure mechanics physically: `forget` hard-deletes the
//! wrapped DEK row, and with `secure_delete=ON` + `wal_checkpoint(TRUNCATE)` the
//! wrapped key bytes are removed from the database file *and* the WAL — so no
//! stale page image of the key survives on disk.

use keepsake_core::CellId;
use keepsake_crypto::{CryptoError, Kek, SealedCell, WrappedDek};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Errors from the SQLite-backed vault.
#[derive(Debug)]
pub enum StoreError {
    /// Underlying SQLite error.
    Db(rusqlite::Error),
    /// Crypto failure (e.g. AEAD authentication).
    Crypto(CryptoError),
    /// A stored field had an unexpected length (corruption).
    Corrupt,
    /// A local embedding model failure.
    Embed(String),
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Db(e)
    }
}

impl From<CryptoError> for StoreError {
    fn from(e: CryptoError) -> Self {
        StoreError::Crypto(e)
    }
}

/// A self-contained encrypted record for state-based sync: a ciphertext cell plus its
/// wrapped DEK. Inert without the holder's KEK (which devices derive from the same seed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellRecord {
    pub cell_id: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub wrap_nonce: [u8; 12],
    pub wrapped: Vec<u8>,
}

/// A durable vault: append-only `cells` + `tombstones` (content plane) and an
/// erasable `key_manifest` (key plane), all in one SQLite database.
pub struct SqliteVault {
    conn: Connection,
}

impl SqliteVault {
    /// Open (or create) a **SQLCipher-encrypted** vault at `path`, keyed by `db_key`.
    pub fn open(path: &std::path::Path, db_key: &[u8; 32]) -> Result<Self, StoreError> {
        Self::keyed(Connection::open(path)?, db_key)
    }

    /// Open an ephemeral in-memory vault (tests / scratch).
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::keyed(Connection::open_in_memory()?, &[0u8; 32])
    }

    fn keyed(conn: Connection, db_key: &[u8; 32]) -> Result<Self, StoreError> {
        // SQLCipher: install the raw 256-bit key BEFORE any other access. A 64-hex
        // `x'..'` value is used directly as the key (no KDF); the salt is per-db.
        conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(db_key)))?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, StoreError> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA secure_delete = ON;
             CREATE TABLE IF NOT EXISTS cells (
                 cell_id    BLOB PRIMARY KEY,
                 nonce      BLOB NOT NULL,
                 ciphertext BLOB NOT NULL,
                 created_at INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS tombstones (cell_id BLOB PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS key_manifest (
                 cell_id    BLOB PRIMARY KEY,
                 wrap_nonce BLOB NOT NULL,
                 wrapped    BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sync_meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS superseded (cell_id BLOB PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS fact_subjects (subject TEXT PRIMARY KEY, cell_id BLOB NOT NULL);",
        )?;
        // Back-fill the column on vaults created before `created_at` existed; errors
        // (the column already exists) are expected and ignored.
        let _ = conn.execute(
            "ALTER TABLE cells ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
            [],
        );
        // Provenance column for vaults created before `source` existed.
        let _ = conn.execute("ALTER TABLE cells ADD COLUMN source TEXT", []);
        Ok(SqliteVault { conn })
    }

    /// Seal `plaintext` and persist it across both planes; returns the cell id.
    pub fn remember(&self, kek: &Kek, plaintext: &[u8]) -> Result<CellId, StoreError> {
        self.remember_at(kek, plaintext, now_unix())
    }

    /// Like [`remember`](Self::remember) but with an explicit creation time
    /// (Unix seconds) — used for the recency timeline and deterministic tests.
    pub fn remember_at(
        &self,
        kek: &Kek,
        plaintext: &[u8],
        created_at: i64,
    ) -> Result<CellId, StoreError> {
        self.remember_with_source(kek, plaintext, created_at, None)
    }

    /// Like [`remember_at`](Self::remember_at) but records an optional provenance `source`
    /// string on the cell (e.g. `proxy:openai:gpt-4`, `mcp:claude`, `desktop`) — so a
    /// memory can later answer *where it came from*.
    pub fn remember_with_source(
        &self,
        kek: &Kek,
        plaintext: &[u8],
        created_at: i64,
        source: Option<&str>,
    ) -> Result<CellId, StoreError> {
        let (cell, wrapped) = kek.seal(plaintext);
        let id = CellId::of(&cell);
        let idb = id.as_bytes().as_slice();
        // Content plane: append-only (idempotent on the content-addressed id).
        self.conn.execute(
            "INSERT OR IGNORE INTO cells (cell_id, nonce, ciphertext, created_at, source) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![idb, cell.nonce.as_slice(), cell.ciphertext, created_at, source],
        )?;
        // Key plane: the only home of the wrapped DEK.
        self.conn.execute(
            "INSERT OR REPLACE INTO key_manifest (cell_id, wrap_nonce, wrapped) VALUES (?1, ?2, ?3)",
            params![idb, wrapped.nonce.as_slice(), wrapped.bytes],
        )?;
        Ok(id)
    }

    /// List up to `limit` live (non-tombstoned) cells, newest first, as
    /// `(cell_id, created_at)`. Backs the dashboard recency timeline.
    pub fn recent(&self, limit: usize) -> Result<Vec<(CellId, i64)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT cell_id, created_at FROM cells
             WHERE cell_id NOT IN (SELECT cell_id FROM tombstones)
             ORDER BY created_at DESC, rowid DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (cid, ts) = row?;
            let arr: [u8; 32] = cid.as_slice().try_into().map_err(|_| StoreError::Corrupt)?;
            out.push((CellId::from_bytes(arr), ts));
        }
        Ok(out)
    }

    /// The creation time (Unix seconds) of a cell, if it exists in the content plane.
    pub fn created_at(&self, id: &CellId) -> Result<Option<i64>, StoreError> {
        let ts: Option<i64> = self
            .conn
            .query_row(
                "SELECT created_at FROM cells WHERE cell_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(ts)
    }

    /// The provenance `source` of a cell (where it came from), if one was recorded.
    pub fn source(&self, id: &CellId) -> Result<Option<String>, StoreError> {
        let s: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT source FROM cells WHERE cell_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(s.flatten())
    }

    /// Recall and decrypt a cell. `Ok(None)` if absent, tombstoned, or key erased.
    pub fn recall(&self, kek: &Kek, id: &CellId) -> Result<Option<Vec<u8>>, StoreError> {
        let idb = id.as_bytes().as_slice();

        let tombstoned: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM tombstones WHERE cell_id = ?1",
                params![idb],
                |row| row.get(0),
            )
            .optional()?;
        if tombstoned.is_some() {
            return Ok(None);
        }

        let cell: Option<(Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT nonce, ciphertext FROM cells WHERE cell_id = ?1",
                params![idb],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((nonce, ciphertext)) = cell else {
            return Ok(None);
        };

        let wrapped: Option<(Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT wrap_nonce, wrapped FROM key_manifest WHERE cell_id = ?1",
                params![idb],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((wrap_nonce, wrapped_bytes)) = wrapped else {
            return Ok(None);
        };

        let sealed = SealedCell {
            nonce: to_nonce(&nonce)?,
            ciphertext,
        };
        let wdek = WrappedDek {
            nonce: to_nonce(&wrap_nonce)?,
            bytes: wrapped_bytes,
        };
        Ok(Some(kek.open(&sealed, &wdek)?))
    }

    /// §4a `forget`: hard-delete the key row, tombstone the content, and truncate
    /// the WAL so no stale image of the wrapped DEK survives on disk.
    pub fn forget(&self, id: &CellId) -> Result<(), StoreError> {
        let idb = id.as_bytes().as_slice();
        self.conn
            .execute("DELETE FROM key_manifest WHERE cell_id = ?1", params![idb])?;
        self.conn.execute(
            "INSERT OR IGNORE INTO tombstones (cell_id) VALUES (?1)",
            params![idb],
        )?;
        // Flush committed frames into the db and truncate the WAL to zero, so the
        // pre-delete page image of the wrapped DEK does not linger on disk.
        self.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    }

    /// Export all live cells with their wrapped keys (state-based sync snapshot).
    pub fn export_live_records(&self) -> Result<Vec<CellRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT c.cell_id, c.nonce, c.ciphertext, k.wrap_nonce, k.wrapped
             FROM cells c JOIN key_manifest k ON c.cell_id = k.cell_id
             WHERE c.cell_id NOT IN (SELECT cell_id FROM tombstones)",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (cid, nonce, ct, wn, wrapped) = row?;
            out.push(CellRecord {
                cell_id: cid.as_slice().try_into().map_err(|_| StoreError::Corrupt)?,
                nonce: nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupt)?,
                ciphertext: ct,
                wrap_nonce: wn.as_slice().try_into().map_err(|_| StoreError::Corrupt)?,
                wrapped,
            });
        }
        Ok(out)
    }

    /// Export the ids of all tombstoned (forgotten) cells.
    pub fn tombstone_ids(&self) -> Result<Vec<[u8; 32]>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT cell_id FROM tombstones")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(
                row?.as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupt)?,
            );
        }
        Ok(out)
    }

    /// Import a synced record. Skips the cell if it is locally tombstoned — **erasure
    /// always wins**, so a straggler record can never resurrect a forgotten cell.
    pub fn import_record(&self, rec: &CellRecord) -> Result<(), StoreError> {
        // Bind the claimed id to the ciphertext (content address). A synced record whose
        // cell_id does not match its own ciphertext is forged or corrupt — drop it, so it
        // cannot insert under an attacker-chosen id or overwrite another cell's key row.
        if CellId::of_ciphertext(&rec.ciphertext).as_bytes() != &rec.cell_id {
            return Ok(());
        }
        let id = &rec.cell_id[..];
        let tomb: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM tombstones WHERE cell_id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        if tomb.is_some() {
            return Ok(());
        }
        self.conn.execute(
            "INSERT OR IGNORE INTO cells (cell_id, nonce, ciphertext) VALUES (?1, ?2, ?3)",
            params![id, &rec.nonce[..], rec.ciphertext],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO key_manifest (cell_id, wrap_nonce, wrapped) VALUES (?1, ?2, ?3)",
            params![id, &rec.wrap_nonce[..], rec.wrapped],
        )?;
        Ok(())
    }

    /// Apply a synced tombstone: forget the cell id locally (erasure).
    pub fn apply_tombstone(&self, cell_id: &[u8; 32]) -> Result<(), StoreError> {
        self.forget(&CellId::from_bytes(*cell_id))
    }

    /// Atomically read-and-increment this vault's monotonic send-epoch counter. Each sync
    /// snapshot this vault produces carries a strictly greater epoch, so a relay cannot
    /// replay an older snapshot onto a device that has already applied a newer one.
    pub fn next_send_epoch(&self) -> Result<u64, StoreError> {
        let epoch: i64 = self.conn.query_row(
            "INSERT INTO sync_meta (k, v) VALUES ('send_epoch', 1)
             ON CONFLICT(k) DO UPDATE SET v = v + 1 RETURNING v",
            [],
            |row| row.get(0),
        )?;
        Ok(epoch as u64)
    }

    /// The highest snapshot epoch this vault has applied from `stream` (0 if none).
    pub fn seen_epoch(&self, stream: &str) -> Result<u64, StoreError> {
        let v: Option<i64> = self
            .conn
            .query_row(
                "SELECT v FROM sync_meta WHERE k = ?1",
                params![format!("seen:{stream}")],
                |row| row.get(0),
            )
            .optional()?;
        Ok(v.unwrap_or(0) as u64)
    }

    /// Record that this vault has applied snapshot `epoch` from `stream`.
    pub fn set_seen_epoch(&self, stream: &str, epoch: u64) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO sync_meta (k, v) VALUES (?1, ?2)
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![format!("seen:{stream}"), epoch as i64],
        )?;
        Ok(())
    }

    /// List the ids of all live (non-tombstoned) cells.
    pub fn live_cell_ids(&self) -> Result<Vec<CellId>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT cell_id FROM cells WHERE cell_id NOT IN (SELECT cell_id FROM tombstones)",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut ids = Vec::new();
        for row in rows {
            let bytes = row?;
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt)?;
            ids.push(CellId::from_bytes(arr));
        }
        Ok(ids)
    }

    /// Mark a cell as *superseded*: kept and still recallable by id (and still erasable),
    /// but hidden from quality recall because a newer version of its fact now exists.
    pub fn mark_superseded(&self, id: &CellId) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO superseded (cell_id) VALUES (?1)",
            params![id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// The ids of all superseded cells.
    pub fn superseded_ids(&self) -> Result<Vec<[u8; 32]>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT cell_id FROM superseded")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?.as_slice().try_into().map_err(|_| StoreError::Corrupt)?);
        }
        Ok(out)
    }

    /// The cell currently holding the value for fact `subject`, if any.
    pub fn subject_current(&self, subject: &str) -> Result<Option<CellId>, StoreError> {
        let v: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT cell_id FROM fact_subjects WHERE subject = ?1",
                params![subject],
                |row| row.get(0),
            )
            .optional()?;
        match v {
            Some(bytes) => {
                let arr: [u8; 32] =
                    bytes.as_slice().try_into().map_err(|_| StoreError::Corrupt)?;
                Ok(Some(CellId::from_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Point fact `subject` at the cell now holding its current value.
    pub fn set_subject_current(&self, subject: &str, id: &CellId) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO fact_subjects (subject, cell_id) VALUES (?1, ?2)
             ON CONFLICT(subject) DO UPDATE SET cell_id = excluded.cell_id",
            params![subject, id.as_bytes().as_slice()],
        )?;
        Ok(())
    }
}

/// Convert a stored blob into a 12-byte AES-GCM nonce.
fn to_nonce(bytes: &[u8]) -> Result<[u8; 12], StoreError> {
    bytes.try_into().map_err(|_| StoreError::Corrupt)
}

/// Current wall-clock time in Unix seconds (0 if the clock is before the epoch).
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

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_kek() -> Kek {
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        Kek::from_root(&roots.encryption_root)
    }

    #[test]
    fn remember_recall_roundtrips() {
        let vault = SqliteVault::open_in_memory().unwrap();
        let kek = test_kek();
        let id = vault.remember(&kek, b"persisted memory").unwrap();
        assert_eq!(
            vault.recall(&kek, &id).unwrap().as_deref(),
            Some(&b"persisted memory"[..])
        );
    }

    #[test]
    fn source_provenance_roundtrips_and_defaults_to_none() {
        let vault = SqliteVault::open_in_memory().unwrap();
        let kek = test_kek();
        let tagged = vault
            .remember_with_source(&kek, b"from claude", 100, Some("mcp:claude"))
            .unwrap();
        let plain = vault.remember(&kek, b"no source recorded").unwrap();
        assert_eq!(vault.source(&tagged).unwrap().as_deref(), Some("mcp:claude"));
        assert_eq!(
            vault.source(&plain).unwrap(),
            None,
            "a memory written without a source reads back as None"
        );
    }

    #[test]
    fn superseded_and_subject_index_track_fact_versions() {
        let vault = SqliteVault::open_in_memory().unwrap();
        let kek = test_kek();
        let old = vault.remember(&kek, b"Python").unwrap();
        let new = vault.remember(&kek, b"Rust").unwrap();
        vault.mark_superseded(&old).unwrap();
        vault.set_subject_current("language", &new).unwrap();

        assert_eq!(vault.superseded_ids().unwrap(), vec![*old.as_bytes()]);
        assert_eq!(vault.subject_current("language").unwrap(), Some(new));
        assert!(
            vault.recall(&kek, &old).unwrap().is_some(),
            "a superseded cell is hidden from recall but NOT erased"
        );
    }

    #[test]
    fn forget_removes_key_and_recall_returns_none() {
        let vault = SqliteVault::open_in_memory().unwrap();
        let kek = test_kek();
        let id = vault.remember(&kek, b"secret").unwrap();
        vault.forget(&id).unwrap();
        assert_eq!(vault.recall(&kek, &id).unwrap(), None);
    }

    #[test]
    fn db_is_encrypted_at_rest_and_wrong_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let kek = test_kek();
        let db_key = [0x11u8; 32];

        {
            let vault = SqliteVault::open(&path, &db_key).unwrap();
            vault.remember(&kek, b"top secret").unwrap();
        } // close -> flush to disk

        // SQLCipher: the file must NOT expose a plaintext SQLite header.
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.starts_with(b"SQLite format 3\0"),
            "an encrypted db must not carry a plaintext SQLite header"
        );

        // The wrong db key cannot open/read the vault; the right one can.
        assert!(
            SqliteVault::open(&path, &[0x99u8; 32]).is_err(),
            "wrong db key must be rejected"
        );
        assert!(SqliteVault::open(&path, &db_key).is_ok());
    }

    #[test]
    fn forget_removes_the_key_row_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let kek = test_kek();
        let db_key = [0x22u8; 32];

        let vault = SqliteVault::open(&path, &db_key).unwrap();
        let id = vault.remember(&kek, b"erase me").unwrap();
        assert!(vault.recall(&kek, &id).unwrap().is_some());

        // §4a: forget hard-deletes the key row (+ secure_delete + WAL truncate).
        vault.forget(&id).unwrap();
        assert_eq!(vault.recall(&kek, &id).unwrap(), None);

        // Still gone after a fresh reopen: the cell is unrecoverable.
        drop(vault);
        let reopened = SqliteVault::open(&path, &db_key).unwrap();
        assert_eq!(reopened.recall(&kek, &id).unwrap(), None);
    }

    #[test]
    fn recent_lists_newest_first_and_excludes_tombstoned() {
        let vault = SqliteVault::open_in_memory().unwrap();
        let kek = test_kek();
        let a = vault.remember_at(&kek, b"oldest", 100).unwrap();
        let b = vault.remember_at(&kek, b"middle", 200).unwrap();
        let c = vault.remember_at(&kek, b"newest", 300).unwrap();

        let recent = vault.recent(10).unwrap();
        assert_eq!(
            recent.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>(),
            vec![c.clone(), b.clone(), a.clone()],
            "newest first"
        );
        assert_eq!(recent[0].1, 300, "carries the creation time");

        vault.forget(&b).unwrap();
        assert_eq!(
            vault
                .recent(10)
                .unwrap()
                .iter()
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>(),
            vec![c, a],
            "tombstoned cells drop out"
        );

        assert_eq!(vault.recent(1).unwrap().len(), 1, "limit is respected");
    }

    #[test]
    fn live_cell_ids_excludes_tombstoned() {
        let vault = SqliteVault::open_in_memory().unwrap();
        let kek = test_kek();
        let a = vault.remember(&kek, b"one").unwrap();
        let b = vault.remember(&kek, b"two").unwrap();
        assert_eq!(vault.live_cell_ids().unwrap().len(), 2);

        vault.forget(&a).unwrap();
        assert_eq!(vault.live_cell_ids().unwrap(), vec![b]);
    }

    #[test]
    fn export_import_syncs_records_between_vaults() {
        let kek = test_kek();
        let a = SqliteVault::open_in_memory().unwrap();
        let b = SqliteVault::open_in_memory().unwrap();
        let id = a.remember(&kek, b"synced memory").unwrap();
        let id2 = a.remember(&kek, b"another fact").unwrap();

        for rec in a.export_live_records().unwrap() {
            b.import_record(&rec).unwrap();
        }
        assert_eq!(
            b.recall(&kek, &id).unwrap().as_deref(),
            Some(&b"synced memory"[..])
        );
        assert_eq!(
            b.recall(&kek, &id2).unwrap().as_deref(),
            Some(&b"another fact"[..])
        );

        // forget on A propagates as a tombstone; the other cell stays.
        a.forget(&id).unwrap();
        for t in a.tombstone_ids().unwrap() {
            b.apply_tombstone(&t).unwrap();
        }
        assert_eq!(b.recall(&kek, &id).unwrap(), None);
        assert!(b.recall(&kek, &id2).unwrap().is_some());
    }

    #[test]
    fn import_does_not_resurrect_a_tombstoned_cell() {
        let kek = test_kek();
        let a = SqliteVault::open_in_memory().unwrap();
        let id = a.remember(&kek, b"erase me").unwrap();
        let rec = a.export_live_records().unwrap().into_iter().next().unwrap();

        let b = SqliteVault::open_in_memory().unwrap();
        b.import_record(&rec).unwrap();
        assert!(b.recall(&kek, &id).unwrap().is_some());

        b.forget(&id).unwrap();
        b.import_record(&rec).unwrap(); // straggler re-import after erasure
        assert_eq!(
            b.recall(&kek, &id).unwrap(),
            None,
            "a tombstone must keep an erased cell erased"
        );
    }

    #[test]
    fn import_record_rejects_a_forged_cell_id() {
        let kek = test_kek();
        let a = SqliteVault::open_in_memory().unwrap();
        a.remember(&kek, b"genuine").unwrap();
        let mut rec = a.export_live_records().unwrap().into_iter().next().unwrap();
        // Forge the id to a value that does not match the ciphertext.
        rec.cell_id = [0xABu8; 32];

        let b = SqliteVault::open_in_memory().unwrap();
        b.import_record(&rec).unwrap();
        assert!(
            b.live_cell_ids().unwrap().is_empty(),
            "a record whose cell_id does not match its ciphertext must be dropped"
        );
    }

    #[test]
    fn send_epoch_is_strictly_monotonic_and_seen_epoch_persists() {
        let v = SqliteVault::open_in_memory().unwrap();
        assert_eq!(v.next_send_epoch().unwrap(), 1);
        assert_eq!(v.next_send_epoch().unwrap(), 2);
        assert_eq!(v.next_send_epoch().unwrap(), 3);
        assert_eq!(v.seen_epoch("chan").unwrap(), 0);
        v.set_seen_epoch("chan", 5).unwrap();
        assert_eq!(v.seen_epoch("chan").unwrap(), 5);
    }
}
