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
    routing::{get, post, put},
    Json, Router,
};
use std::collections::HashMap;
use keepsake_store_sqlite::SqliteVault;
use keepsake_sync::SyncState;
use rusqlite::{params, Connection, OptionalExtension};

/// Errors from the relay client / sync helpers.
#[derive(Debug)]
pub enum RelayError {
    Http(reqwest::Error),
    Store(keepsake_store_sqlite::StoreError),
    Status(u16),
    /// An OPAQUE backup step failed (e.g. wrong password) or a malformed server response.
    Backup,
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
impl From<keepsake_backup::BackupError> for RelayError {
    fn from(_: keepsake_backup::BackupError) -> Self {
        RelayError::Backup
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
    backup: BackupState,
}

/// Build the relay router with a bearer `token` over a (file-backed) [`BlobStore`].
pub fn app(token: String, store: BlobStore) -> Router {
    let backup = BackupState::new(&store);
    let state = Arc::new(RelayState {
        token,
        store,
        backup,
    });
    Router::new()
        .route("/v1/blob/{slot}", put(put_blob).get(get_blob))
        .route("/v1/backup/register/start", post(backup_register_start))
        .route("/v1/backup/register/finish", post(backup_register_finish))
        .route("/v1/backup/login/start", post(backup_login_start))
        .route("/v1/backup/login/finish", post(backup_login_finish))
        .route("/v1/backup/blob/{id}", put(backup_put).get(backup_get))
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

// ---- OPAQUE zero-knowledge backup (server endpoints + client) ----
//
// The relay validates the user's password (OPAQUE) and stores only a blind password file plus an
// opaque ciphertext — never the password, the seed, or the plaintext. After a successful login,
// the derived session key gates blob upload/download; the password-derived export key (which the
// relay never sees) locks the blob.

/// In-memory OPAQUE state for the backup endpoints: the server's long-term setup (persisted in the
/// blob store so password files survive a restart), pending logins (between the two round-trips),
/// and the session keys that gate blob access after a successful login.
struct BackupState {
    server_setup: Vec<u8>,
    pending: Mutex<HashMap<String, (String, Vec<u8>)>>,
    tokens: Mutex<HashMap<String, Vec<u8>>>,
}

impl BackupState {
    fn new(store: &BlobStore) -> Self {
        let server_setup = match store.get("backup:server-setup").ok().flatten() {
            Some(s) => s,
            None => {
                let s = keepsake_backup::server_setup_new();
                let _ = store.put("backup:server-setup", &s);
                s
            }
        };
        BackupState {
            server_setup,
            pending: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
        }
    }
}

#[derive(serde::Deserialize)]
struct RegStart {
    id: String,
    request: String,
}
#[derive(serde::Deserialize)]
struct RegFinish {
    id: String,
    upload: String,
}
#[derive(serde::Deserialize)]
struct LoginStart {
    id: String,
    request: String,
}
#[derive(serde::Deserialize)]
struct LoginFinish {
    session: String,
    finalization: String,
}

fn random_hex() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

async fn backup_register_start(
    State(state): State<Arc<RelayState>>,
    Json(b): Json<RegStart>,
) -> impl IntoResponse {
    let Ok(req) = hex::decode(&b.request) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({})));
    };
    match keepsake_backup::server_register(&state.backup.server_setup, &req, b.id.as_bytes()) {
        Ok(resp) => (
            StatusCode::OK,
            Json(serde_json::json!({ "response": hex::encode(resp) })),
        ),
        Err(_) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({}))),
    }
}

async fn backup_register_finish(
    State(state): State<Arc<RelayState>>,
    Json(b): Json<RegFinish>,
) -> impl IntoResponse {
    let Ok(upload) = hex::decode(&b.upload) else {
        return StatusCode::BAD_REQUEST;
    };
    match keepsake_backup::server_register_finish(&upload) {
        Ok(pwfile) => match state.store.put(&format!("bkpwf:{}", b.id), &pwfile) {
            Ok(()) => StatusCode::NO_CONTENT,
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        },
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

async fn backup_login_start(
    State(state): State<Arc<RelayState>>,
    Json(b): Json<LoginStart>,
) -> impl IntoResponse {
    let Ok(req) = hex::decode(&b.request) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({})));
    };
    let Some(pwfile) = state.store.get(&format!("bkpwf:{}", b.id)).ok().flatten() else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({})));
    };
    match keepsake_backup::server_login_start(
        &state.backup.server_setup,
        &pwfile,
        &req,
        b.id.as_bytes(),
    ) {
        Ok((sstate, resp)) => {
            let session = random_hex();
            state
                .backup
                .pending
                .lock()
                .unwrap()
                .insert(session.clone(), (b.id.clone(), sstate));
            (
                StatusCode::OK,
                Json(serde_json::json!({ "session": session, "response": hex::encode(resp) })),
            )
        }
        Err(_) => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({}))),
    }
}

async fn backup_login_finish(
    State(state): State<Arc<RelayState>>,
    Json(b): Json<LoginFinish>,
) -> impl IntoResponse {
    let pending = state.backup.pending.lock().unwrap().remove(&b.session);
    let Some((id, sstate)) = pending else {
        return StatusCode::UNAUTHORIZED;
    };
    let Ok(fin) = hex::decode(&b.finalization) else {
        return StatusCode::BAD_REQUEST;
    };
    match keepsake_backup::server_login_finish(&sstate, &fin) {
        Ok(session_key) => {
            state.backup.tokens.lock().unwrap().insert(id, session_key);
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::UNAUTHORIZED,
    }
}

fn backup_authorized(state: &RelayState, id: &str, headers: &HeaderMap) -> bool {
    let Some(bearer) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(token_hex) = bearer.strip_prefix("Bearer ") else {
        return false;
    };
    let Ok(token) = hex::decode(token_hex) else {
        return false;
    };
    match state.backup.tokens.lock().unwrap().get(id) {
        Some(expected) => ct_eq(&token, expected),
        None => false,
    }
}

async fn backup_put(
    State(state): State<Arc<RelayState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if !backup_authorized(&state, &id, &headers) {
        return StatusCode::UNAUTHORIZED;
    }
    match state.store.put(&format!("bkblob:{id}"), &body) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn backup_get(
    State(state): State<Arc<RelayState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !backup_authorized(&state, &id, &headers) {
        return (StatusCode::UNAUTHORIZED, Vec::new());
    }
    match state.store.get(&format!("bkblob:{id}")) {
        Ok(Some(b)) => (StatusCode::OK, b),
        Ok(None) => (StatusCode::NOT_FOUND, Vec::new()),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Vec::new()),
    }
}

/// Client for the OPAQUE backup endpoints: register a password, log in (deriving the bearer
/// session key + the server-blind export key), and upload/download the locked blob.
pub struct BackupRelayClient {
    base: String,
    http: reqwest::Client,
}

impl BackupRelayClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        BackupRelayClient {
            base: base_url.into(),
            http: reqwest::Client::new(),
        }
    }

    async fn post_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, RelayError> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base))
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(RelayError::Status(resp.status().as_u16()));
        }
        Ok(resp
            .json::<serde_json::Value>()
            .await
            .unwrap_or(serde_json::Value::Null))
    }

    async fn post_empty(&self, path: &str, body: serde_json::Value) -> Result<(), RelayError> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base))
            .json(&body)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(RelayError::Status(resp.status().as_u16()))
        }
    }

    /// Register a password for `id` (one-time). The relay stores only a blind password file.
    pub async fn register(&self, id: &str, password: &[u8]) -> Result<(), RelayError> {
        let (cstate, req) = keepsake_backup::client_register_start(password);
        let resp = self
            .post_json(
                "/v1/backup/register/start",
                serde_json::json!({ "id": id, "request": hex::encode(req) }),
            )
            .await?;
        let response = hex::decode(resp["response"].as_str().ok_or(RelayError::Backup)?)
            .map_err(|_| RelayError::Backup)?;
        let (upload, _export) = keepsake_backup::client_register_finish(cstate, password, &response)?;
        self.post_empty(
            "/v1/backup/register/finish",
            serde_json::json!({ "id": id, "upload": hex::encode(upload) }),
        )
        .await
    }

    /// Log in for `id`. Returns `(session_key, export_key)`: the session key is the bearer for blob
    /// upload/download; the export key locks/unlocks the blob (the relay never sees it).
    pub async fn login(&self, id: &str, password: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RelayError> {
        let (cstate, req) = keepsake_backup::client_login_start(password);
        let start = self
            .post_json(
                "/v1/backup/login/start",
                serde_json::json!({ "id": id, "request": hex::encode(req) }),
            )
            .await?;
        let session = start["session"]
            .as_str()
            .ok_or(RelayError::Backup)?
            .to_string();
        let response = hex::decode(start["response"].as_str().ok_or(RelayError::Backup)?)
            .map_err(|_| RelayError::Backup)?;
        let (finalization, session_key, export_key) =
            keepsake_backup::client_login_finish(cstate, password, &response)?;
        self.post_empty(
            "/v1/backup/login/finish",
            serde_json::json!({ "session": session, "finalization": hex::encode(finalization) }),
        )
        .await?;
        Ok((session_key, export_key))
    }

    /// Upload the locked blob for `id` (authenticated by the login `session_key`).
    pub async fn upload(
        &self,
        id: &str,
        session_key: &[u8],
        blob: Vec<u8>,
    ) -> Result<(), RelayError> {
        let resp = self
            .http
            .put(format!("{}/v1/backup/blob/{id}", self.base))
            .bearer_auth(hex::encode(session_key))
            .body(blob)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(RelayError::Status(resp.status().as_u16()))
        }
    }

    /// Download the locked blob for `id` (`None` if absent).
    pub async fn download(
        &self,
        id: &str,
        session_key: &[u8],
    ) -> Result<Option<Vec<u8>>, RelayError> {
        let resp = self
            .http
            .get(format!("{}/v1/backup/blob/{id}", self.base))
            .bearer_auth(hex::encode(session_key))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(RelayError::Status(resp.status().as_u16()));
        }
        Ok(Some(resp.bytes().await?.to_vec()))
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

    #[tokio::test]
    async fn opaque_backup_round_trips_zero_knowledge_over_http() {
        let base = spawn_relay("t").await;
        let client = BackupRelayClient::new(&base);
        let id = "vault-xyz";
        let password = b"correct horse battery staple";

        // Register the password once, then log in: the session key gates blob ops, the export key
        // (which the relay never sees) locks the blob.
        client.register(id, password).await.unwrap();
        let (session_key, export_key) = client.login(id, password).await.unwrap();

        let secret = b"the serialized memory passport bytes";
        let blob = keepsake_backup::lock_blob(&export_key, secret).unwrap();
        client.upload(id, &session_key, blob).await.unwrap();

        // A fresh login (another device, same password) recovers the same export key and the blob.
        let (session_key2, export_key2) = client.login(id, password).await.unwrap();
        let downloaded = client.download(id, &session_key2).await.unwrap().unwrap();
        assert_eq!(
            keepsake_backup::unlock_blob(&export_key2, &downloaded).unwrap(),
            secret,
            "the backup round-trips end-to-end, zero-knowledge"
        );

        // A wrong password cannot authenticate.
        assert!(client.login(id, b"wrong password").await.is_err());
    }
}
