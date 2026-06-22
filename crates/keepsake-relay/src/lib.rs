//! `keepsake-relay` — a dumb, zero-knowledge sync relay over HTTP.
//!
//! It stores **opaque blobs** (encrypted [`keepsake_sync::SyncState`] snapshots) keyed by
//! an arbitrary slot string, behind a bearer token. It never sees plaintext or unwrapped
//! keys; pushing a post-`forget` snapshot simply replaces the slot, so the relay stops
//! carrying the erased cell's wrapped key.
//!
//! Storage is **file-backed (SQLite)** so slots survive a restart. The blobs are already
//! end-to-end encrypted, so the relay database holds nothing but ciphertext.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::{
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, put},
    Router,
};
use keepsake_store_sqlite::SqliteVault;
use keepsake_sync::SyncState;
use rusqlite::{params, Connection, OptionalExtension};

/// Errors from the relay client / sync helpers.
#[derive(Debug)]
pub enum RelayError {
    Http(reqwest::Error),
    Store(keepsake_store_sqlite::StoreError),
    Status(u16),
}

impl From<reqwest::Error> for RelayError {
    fn from(e: reqwest::Error) -> Self {
        RelayError::Http(e)
    }
}
impl From<keepsake_store_sqlite::StoreError> for RelayError {
    fn from(e: keepsake_store_sqlite::StoreError) -> Self {
        RelayError::Store(e)
    }
}

// ---- storage ----

/// A file-backed store of opaque blobs keyed by slot. Persists across restarts.
pub struct BlobStore {
    conn: Mutex<Connection>,
}

impl BlobStore {
    /// Open (or create) the store at `path` (e.g. `keepsake-relay.db`).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, rusqlite::Error> {
        Self::init(Connection::open(path)?)
    }

    /// Open an ephemeral in-memory store (tests / scratch).
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, rusqlite::Error> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS slots (
                 slot       TEXT PRIMARY KEY,
                 blob       BLOB NOT NULL,
                 updated_at INTEGER NOT NULL
             );",
        )?;
        Ok(BlobStore {
            conn: Mutex::new(conn),
        })
    }

    /// Store (or replace) the blob at `slot`.
    pub fn put(&self, slot: &str, blob: &[u8]) -> Result<(), rusqlite::Error> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO slots (slot, blob, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(slot) DO UPDATE SET blob = excluded.blob, updated_at = excluded.updated_at",
            params![slot, blob, now_unix()],
        )?;
        Ok(())
    }

    /// Fetch the blob at `slot` (`None` if absent).
    pub fn get(&self, slot: &str) -> Result<Option<Vec<u8>>, rusqlite::Error> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT blob FROM slots WHERE slot = ?1",
                params![slot],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---- server ----

struct RelayState {
    token: String,
    store: BlobStore,
}

/// Build the relay router with a bearer `token` over a (file-backed) [`BlobStore`].
pub fn app(token: String, store: BlobStore) -> Router {
    let state = Arc::new(RelayState { token, store });
    Router::new()
        .route("/v1/blob/{slot}", put(put_blob).get(get_blob))
        .route("/health", get(|| async { "ok" }))
        .layer(axum::extract::DefaultBodyLimit::max(
            keepsake_sync::MAX_SNAPSHOT_BYTES,
        ))
        .with_state(state)
}

/// Run the relay on `addr`, persisting slots to the SQLite file at `db_path`.
pub async fn serve(
    addr: SocketAddr,
    token: String,
    db_path: impl AsRef<Path>,
) -> std::io::Result<()> {
    let store = BlobStore::open(db_path).map_err(std::io::Error::other)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app(token, store)).await
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(bearer) => ct_eq(bearer.as_bytes(), format!("Bearer {token}").as_bytes()),
        None => false,
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn put_blob(
    State(state): State<Arc<RelayState>>,
    AxumPath(slot): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if !authorized(&headers, &state.token) {
        return StatusCode::UNAUTHORIZED;
    }
    match state.store.put(&slot, &body) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn get_blob(
    State(state): State<Arc<RelayState>>,
    AxumPath(slot): AxumPath<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !authorized(&headers, &state.token) {
        return (StatusCode::UNAUTHORIZED, Vec::new());
    }
    match state.store.get(&slot) {
        Ok(Some(blob)) => (StatusCode::OK, blob),
        Ok(None) => (StatusCode::NOT_FOUND, Vec::new()),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Vec::new()),
    }
}

// ---- client ----

/// HTTP client for the relay.
pub struct RelayClient {
    base: String,
    token: String,
    http: reqwest::Client,
}

impl RelayClient {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        RelayClient {
            base: base_url.into(),
            token: token.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Push (replace) the blob at `slot`.
    pub async fn push(&self, slot: &str, blob: Vec<u8>) -> Result<(), RelayError> {
        let resp = self
            .http
            .put(format!("{}/v1/blob/{slot}", self.base))
            .bearer_auth(&self.token)
            .body(blob)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(RelayError::Status(resp.status().as_u16()))
        }
    }

    /// Pull the blob at `slot` (`None` if absent).
    pub async fn pull(&self, slot: &str) -> Result<Option<Vec<u8>>, RelayError> {
        let resp = self
            .http
            .get(format!("{}/v1/blob/{slot}", self.base))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(RelayError::Status(resp.status().as_u16()));
        }
        // Guard against a malicious relay returning an enormous body (KS-013).
        if resp
            .content_length()
            .is_some_and(|len| len > keepsake_sync::MAX_SNAPSHOT_BYTES as u64)
        {
            return Err(RelayError::Status(413));
        }
        Ok(Some(resp.bytes().await?.to_vec()))
    }
}

/// Snapshot a vault and push it to `slot`.
pub async fn push_snapshot(
    client: &RelayClient,
    slot: &str,
    vault: &SqliteVault,
    sync_key: &[u8; 32],
) -> Result<(), RelayError> {
    client
        .push(slot, SyncState::from_vault(vault)?.seal(sync_key))
        .await
}

/// Pull `slot` and merge it into a vault. Returns `true` if a snapshot was applied.
pub async fn pull_and_apply(
    client: &RelayClient,
    slot: &str,
    vault: &SqliteVault,
    sync_key: &[u8; 32],
) -> Result<bool, RelayError> {
    match client.pull(slot).await? {
        Some(bytes) => match SyncState::open(&bytes, sync_key) {
            Some(state) => Ok(state.apply_to(vault, slot)?),
            None => Ok(false),
        },
        None => Ok(false),
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

    async fn spawn_relay(token: &str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = app(token.to_string(), BlobStore::open_in_memory().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{addr}")
    }

    #[test]
    fn blob_store_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        {
            let store = BlobStore::open(&path).unwrap();
            store.put("vault-channel", b"opaque snapshot").unwrap();
            store.put("vault-channel", b"newer snapshot").unwrap(); // replace
        } // drop -> closed

        // Reopened: the file-backed slot survived.
        let store = BlobStore::open(&path).unwrap();
        assert_eq!(
            store.get("vault-channel").unwrap().as_deref(),
            Some(&b"newer snapshot"[..])
        );
        assert_eq!(store.get("missing").unwrap(), None);
    }

    #[tokio::test]
    async fn blobs_round_trip_over_http_with_auth() {
        let base = spawn_relay("secret").await;
        let client = RelayClient::new(&base, "secret");

        client.push("slot", b"hello".to_vec()).await.unwrap();
        assert_eq!(client.pull("slot").await.unwrap(), Some(b"hello".to_vec()));
        assert_eq!(client.pull("missing").await.unwrap(), None);

        // Wrong token is rejected.
        let bad = RelayClient::new(&base, "wrong");
        assert!(matches!(
            bad.push("slot", b"x".to_vec()).await,
            Err(RelayError::Status(401))
        ));
    }

    #[tokio::test]
    async fn two_vaults_sync_over_the_http_relay() {
        let base = spawn_relay("t").await;
        let client = RelayClient::new(&base, "t");
        let kek = test_kek();

        let key = RootKeys::from_mnemonic(TEST_MNEMONIC, "")
            .unwrap()
            .sync_mac_key();
        let a = SqliteVault::open_in_memory().unwrap();
        let b = SqliteVault::open_in_memory().unwrap();
        let id = a.remember(&kek, b"network sync works").unwrap();

        push_snapshot(&client, "vault-channel", &a, &key)
            .await
            .unwrap();
        assert!(pull_and_apply(&client, "vault-channel", &b, &key)
            .await
            .unwrap());
        assert_eq!(
            b.recall(&kek, &id).unwrap().as_deref(),
            Some(&b"network sync works"[..])
        );

        // forget on A, re-push, re-apply: B loses it (erasure propagates over the wire).
        a.forget(&id).unwrap();
        push_snapshot(&client, "vault-channel", &a, &key)
            .await
            .unwrap();
        pull_and_apply(&client, "vault-channel", &b, &key)
            .await
            .unwrap();
        assert_eq!(b.recall(&kek, &id).unwrap(), None);
    }
}
