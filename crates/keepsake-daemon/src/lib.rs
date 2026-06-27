//! `keepsake-daemon` — one local background service that holds the unlocked vault and a
//! single live index, so every client (MCP, proxy, desktop) shares the SAME memory in real
//! time and authenticates with a scoped capability token instead of carrying the raw seed.
//!
//! [`DaemonState::handle`] is the transport-agnostic JSON-RPC core (synchronous, easy to
//! test); a Unix-socket server wraps it so many clients share one vault and one live index.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use keepsake_core::CellId;
use keepsake_crypto::Kek;
use keepsake_firewall::capability::{Authorization, CapabilityToken};
use keepsake_retrieval::Embedder;
use keepsake_vault::{MemoryVault, RecallProfile};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// One unlocked vault (+ its live index) behind a mutex, the key-encryption-key, and the
/// capability root used to verify client tokens. Shared by every connected client.
pub struct DaemonState<E: Embedder> {
    vault: Arc<Mutex<MemoryVault<E>>>,
    kek: Kek,
    cap_root: [u8; 32],
}

impl<E: Embedder> DaemonState<E> {
    /// Wrap an already-unlocked vault. `cap_root` verifies clients' capability tokens.
    pub fn new(vault: MemoryVault<E>, kek: Kek, cap_root: [u8; 32]) -> Self {
        Self::from_shared(Arc::new(Mutex::new(vault)), kek, cap_root)
    }

    /// Share an already-wrapped vault — e.g. a desktop GUI that locks the SAME `Mutex` for its
    /// own reads/writes, so the GUI and every socket client see one live index.
    pub fn from_shared(vault: Arc<Mutex<MemoryVault<E>>>, kek: Kek, cap_root: [u8; 32]) -> Self {
        Self {
            vault,
            kek,
            cap_root,
        }
    }

    /// A handle to the shared vault, for an in-process owner (the desktop GUI) to read and write
    /// the same live index the socket clients use.
    pub fn vault(&self) -> Arc<Mutex<MemoryVault<E>>> {
        Arc::clone(&self.vault)
    }

    /// Handle one JSON-RPC request and return the JSON-RPC response. Synchronous: vault
    /// operations don't await, so the socket layer can call this from a blocking section.
    pub fn handle(&self, req: &Value) -> Value {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(Value::as_str).unwrap_or_default();
        let params = req.get("params").cloned().unwrap_or(Value::Null);

        // Resolve the caller's authority: a capability token narrows access; no token means
        // the local owner (the socket is user-private). Invalid/expired tokens are rejected.
        let caller = match params.get("capability").and_then(Value::as_str) {
            None => Caller::Owner,
            Some(tok) => match CapabilityToken::decode_hex(tok).and_then(|t| t.authorize(&self.cap_root)) {
                None => return rpc_error(id, -32001, "invalid or unauthorized capability token"),
                Some(auth) => {
                    if auth.is_expired(unix_now()) {
                        return rpc_error(id, -32001, "capability token expired");
                    }
                    Caller::Scoped(auth)
                }
            },
        };

        match method {
            "vault/remember" => self.remember(id, &params, &caller),
            "vault/remember_fact" => self.remember_fact(id, &params, &caller),
            "vault/recall" => self.recall(id, &params, &caller),
            "vault/forget" => self.forget(id, &params, &caller),
            "vault/status" => self.status(id, &caller),
            "vault/consolidate" => self.consolidate(id, &caller),
            "graph/add_triples" => self.graph_add_triples(id, &params, &caller),
            "graph/neighbors" => self.graph_neighbors(id, &params, &caller),
            "graph/map" => self.graph_map(id, &params, &caller),
            "vault/get" => self.vault_get(id, &params, &caller),
            "vault/profile_get" => self.profile_get(id, &caller),
            "vault/profile_set" => self.profile_set(id, &params, &caller),
            "vault/recent" => self.recent(id, &params, &caller),
            other => rpc_error(id, -32601, &format!("method not found: {other}")),
        }
    }

    fn remember(&self, id: Value, params: &Value, caller: &Caller) -> Value {
        if !caller.can_write() {
            return rpc_error(id, -32001, "capability does not permit write");
        }
        let Some(text) = params.get("text").and_then(Value::as_str) else {
            return rpc_error(id, -32602, "remember requires params.text (string)");
        };
        let source = params.get("source").and_then(Value::as_str);
        let mut vault = self.vault.lock().expect("vault mutex poisoned");
        match vault.remember_deduped_with_source(
            &self.kek,
            text,
            keepsake_vault::DEDUP_THRESHOLD,
            unix_now() as i64,
            source,
        ) {
            Ok((cell_id, stored)) => rpc_ok(
                id,
                json!({ "cell_id": hex::encode(cell_id.as_bytes()), "stored": stored }),
            ),
            Err(e) => rpc_error(id, -32010, &format!("remember failed: {e:?}")),
        }
    }

    /// Update a keyed fact: a changed value supersedes the prior one (hidden from recall,
    /// not erased). Write-scoped, like `remember`.
    fn remember_fact(&self, id: Value, params: &Value, caller: &Caller) -> Value {
        if !caller.can_write() {
            return rpc_error(id, -32001, "capability does not permit write");
        }
        let (Some(subject), Some(value)) = (
            params.get("subject").and_then(Value::as_str),
            params.get("value").and_then(Value::as_str),
        ) else {
            return rpc_error(
                id,
                -32602,
                "remember_fact requires params.subject and params.value (strings)",
            );
        };
        let mut vault = self.vault.lock().expect("vault mutex poisoned");
        match vault.remember_fact(&self.kek, subject, value, unix_now() as i64) {
            Ok((cell_id, changed)) => rpc_ok(
                id,
                json!({ "cell_id": hex::encode(cell_id.as_bytes()), "changed": changed }),
            ),
            Err(e) => rpc_error(id, -32010, &format!("remember_fact failed: {e:?}")),
        }
    }

    fn recall(&self, id: Value, params: &Value, caller: &Caller) -> Value {
        if !caller.can_read() {
            return rpc_error(id, -32001, "capability does not permit read");
        }
        let Some(query) = params.get("query").and_then(Value::as_str) else {
            return rpc_error(id, -32602, "recall requires params.query (string)");
        };
        let k = params.get("k").and_then(Value::as_u64).unwrap_or(4) as usize;
        let k = caller.clamp_records(k);
        let vault = self.vault.lock().expect("vault mutex poisoned");
        let now = unix_now() as i64;
        // Named recall profile (`params.profile`: balanced|semantic|recent|graph_first). The legacy
        // `params.graph == true` still maps to the graph-enriched profile. Default stays Balanced.
        let profile = match params.get("profile").and_then(Value::as_str) {
            Some(p) => RecallProfile::parse(p),
            None if params.get("graph").and_then(Value::as_bool).unwrap_or(false) => {
                RecallProfile::GraphFirst
            }
            None => RecallProfile::Balanced,
        };
        let result = vault.recall_with_profile(&self.kek, query, k, now, profile);
        match result {
            Ok(hits) => {
                let mut hits: Vec<Value> = hits
                    .into_iter()
                    .filter(|(_, text)| caller.permits_topic(text))
                    .map(|(cid, text)| {
                        let mut hit =
                            json!({ "cell_id": hex::encode(cid.as_bytes()), "text": text });
                        if let Ok(Some(src)) = vault.source(&cid) {
                            hit["source"] = json!(src);
                        }
                        hit
                    })
                    .collect();
                // The distilled profile (high-level overview) leads every recall, so the model
                // reads the big picture first and drills into specifics after.
                if let Ok(Some(profile)) = vault.profile() {
                    let profile = profile.trim();
                    if !profile.is_empty() {
                        hits.insert(
                            0,
                            json!({
                                "cell_id": "profile",
                                "text": format!("User profile (high-level overview): {profile}")
                            }),
                        );
                    }
                }
                rpc_ok(id, json!({ "hits": hits }))
            }
            Err(e) => rpc_error(id, -32010, &format!("recall failed: {e:?}")),
        }
    }

    /// Read the distilled profile (the model-written high-level overview). Read-scoped.
    fn profile_get(&self, id: Value, caller: &Caller) -> Value {
        if !caller.can_read() {
            return rpc_error(id, -32001, "capability does not permit read");
        }
        let vault = self.vault.lock().expect("vault mutex poisoned");
        match vault.profile() {
            Ok(p) => rpc_ok(id, json!({ "profile": p })),
            Err(e) => rpc_error(id, -32010, &format!("profile_get failed: {e:?}")),
        }
    }

    /// Store the distilled profile (the caller's in-loop model wrote it). Write-scoped.
    fn profile_set(&self, id: Value, params: &Value, caller: &Caller) -> Value {
        if !caller.can_write() {
            return rpc_error(id, -32001, "capability does not permit write");
        }
        let Some(text) = params.get("text").and_then(Value::as_str) else {
            return rpc_error(id, -32602, "profile_set requires params.text (string)");
        };
        let vault = self.vault.lock().expect("vault mutex poisoned");
        match vault.set_profile(text) {
            Ok(()) => rpc_ok(id, json!({ "ok": true })),
            Err(e) => rpc_error(id, -32010, &format!("profile_set failed: {e:?}")),
        }
    }

    /// The most recent `limit` memories as plain text — distillation input. Read-scoped.
    fn recent(&self, id: Value, params: &Value, caller: &Caller) -> Value {
        if !caller.can_read() {
            return rpc_error(id, -32001, "capability does not permit read");
        }
        let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
        let vault = self.vault.lock().expect("vault mutex poisoned");
        match vault.recent_texts(&self.kek, limit) {
            Ok(texts) => rpc_ok(id, json!({ "texts": texts })),
            Err(e) => rpc_error(id, -32010, &format!("recent failed: {e:?}")),
        }
    }

    fn forget(&self, id: Value, params: &Value, caller: &Caller) -> Value {
        if !caller.can_admin() {
            return rpc_error(id, -32001, "capability does not permit forget");
        }
        let Some(cell_id) = params
            .get("cell_id")
            .and_then(Value::as_str)
            .and_then(decode_cell_id)
        else {
            return rpc_error(id, -32602, "forget requires params.cell_id (32-byte hex)");
        };
        let mut vault = self.vault.lock().expect("vault mutex poisoned");
        match vault.forget(&cell_id) {
            Ok(()) => rpc_ok(id, json!({ "forgotten": true })),
            Err(e) => rpc_error(id, -32010, &format!("forget failed: {e:?}")),
        }
    }

    fn status(&self, id: Value, caller: &Caller) -> Value {
        if !caller.can_read() {
            return rpc_error(id, -32001, "capability does not permit read");
        }
        let vault = self.vault.lock().expect("vault mutex poisoned");
        match vault.count() {
            Ok(n) => rpc_ok(id, json!({ "memories": n })),
            Err(e) => rpc_error(id, -32010, &format!("status failed: {e:?}")),
        }
    }

    fn consolidate(&self, id: Value, caller: &Caller) -> Value {
        if !caller.can_admin() {
            return rpc_error(id, -32001, "capability does not permit consolidate");
        }
        let mut vault = self.vault.lock().expect("vault mutex poisoned");
        match vault.consolidate(keepsake_vault::DEDUP_THRESHOLD) {
            Ok(merged) => rpc_ok(id, json!({ "merged": merged })),
            Err(e) => rpc_error(id, -32010, &format!("consolidate failed: {e:?}")),
        }
    }

    /// Add knowledge-graph triples distilled from a memory cell. Write-scoped. Malformed
    /// entries are skipped; returns how many edges were added.
    fn graph_add_triples(&self, id: Value, params: &Value, caller: &Caller) -> Value {
        if !caller.can_write() {
            return rpc_error(id, -32001, "capability does not permit write");
        }
        let Some(cell_id) = params
            .get("cell_id")
            .and_then(Value::as_str)
            .and_then(decode_cell_id)
        else {
            return rpc_error(id, -32602, "graph/add_triples requires params.cell_id (hex)");
        };
        let mut vault = self.vault.lock().expect("vault mutex poisoned");
        let mut added = 0usize;
        if let Some(arr) = params.get("triples").and_then(Value::as_array) {
            for t in arr {
                let (Some(s), Some(r), Some(o)) = (
                    t.get("subject").and_then(Value::as_str),
                    t.get("relation").and_then(Value::as_str),
                    t.get("object").and_then(Value::as_str),
                ) else {
                    continue;
                };
                if vault.add_triple(&cell_id, s, r, o, unix_now() as i64).is_ok() {
                    added += 1;
                }
            }
        }
        rpc_ok(id, json!({ "added": added }))
    }

    /// What an entity is connected to in the knowledge graph. Read-scoped.
    fn graph_neighbors(&self, id: Value, params: &Value, caller: &Caller) -> Value {
        if !caller.can_read() {
            return rpc_error(id, -32001, "capability does not permit read");
        }
        let Some(entity) = params.get("entity").and_then(Value::as_str) else {
            return rpc_error(id, -32602, "graph/neighbors requires params.entity (string)");
        };
        let vault = self.vault.lock().expect("vault mutex poisoned");
        let neighbors: Vec<Value> = vault
            .graph_neighbors(entity)
            .into_iter()
            .map(|(relation, entity)| json!({ "relation": relation, "entity": entity }))
            .collect();
        rpc_ok(id, json!({ "neighbors": neighbors }))
    }

    /// Compact symbol-graph recall: the query-relevant region of the graph as a terse map (triples
    /// + backing cell ids), instead of full memory texts. Read-scoped; record limits clamp `k`.
    fn graph_map(&self, id: Value, params: &Value, caller: &Caller) -> Value {
        if !caller.can_read() {
            return rpc_error(id, -32001, "capability does not permit read");
        }
        let Some(query) = params.get("query").and_then(Value::as_str) else {
            return rpc_error(id, -32602, "graph/map requires params.query (string)");
        };
        let k = params.get("k").and_then(Value::as_u64).unwrap_or(8) as usize;
        let k = caller.clamp_records(k);
        let vault = self.vault.lock().expect("vault mutex poisoned");
        match vault.recall_map(&self.kek, query, k) {
            Ok(map) => rpc_ok(id, json!({ "map": map })),
            Err(e) => rpc_error(id, -32010, &format!("graph/map failed: {e:?}")),
        }
    }

    /// The full plaintext of one memory by cell id — the on-demand fetch behind a map entry.
    /// Read-scoped. A forgotten or absent id returns `text: null`, so erasure stays honest.
    fn vault_get(&self, id: Value, params: &Value, caller: &Caller) -> Value {
        if !caller.can_read() {
            return rpc_error(id, -32001, "capability does not permit read");
        }
        let Some(cell_id) = params
            .get("cell_id")
            .and_then(Value::as_str)
            .and_then(decode_cell_id)
        else {
            return rpc_error(id, -32602, "vault/get requires params.cell_id (32-byte hex)");
        };
        let vault = self.vault.lock().expect("vault mutex poisoned");
        match vault.get_cell(&self.kek, &cell_id) {
            Ok(text) => rpc_ok(id, json!({ "text": text })),
            Err(e) => rpc_error(id, -32010, &format!("vault/get failed: {e:?}")),
        }
    }
}

/// Who is making a request: the local owner (full access) or a capability-scoped client.
enum Caller {
    Owner,
    Scoped(Authorization),
}

impl Caller {
    fn can_read(&self) -> bool {
        match self {
            Caller::Owner => true,
            Caller::Scoped(a) => a.allows_read(),
        }
    }
    fn can_write(&self) -> bool {
        match self {
            Caller::Owner => true,
            Caller::Scoped(a) => a.allows_write(),
        }
    }
    fn can_admin(&self) -> bool {
        match self {
            Caller::Owner => true,
            Caller::Scoped(a) => a.allows_admin(),
        }
    }
    fn clamp_records(&self, k: usize) -> usize {
        match self {
            Caller::Owner => k,
            Caller::Scoped(a) => a.max_records().map_or(k, |m| k.min(m)),
        }
    }
    fn permits_topic(&self, text: &str) -> bool {
        match self {
            Caller::Owner => true,
            Caller::Scoped(a) => a.permits_topic(text),
        }
    }
}

fn decode_cell_id(s: &str) -> Option<CellId> {
    let bytes: [u8; 32] = hex::decode(s).ok()?.try_into().ok()?;
    Some(CellId::from_bytes(bytes))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Serve the daemon over a Unix socket: one shared vault, many local clients, newline-delimited
/// JSON-RPC. Each connection runs concurrently and every request goes through
/// [`DaemonState::handle`], so all clients read and write the SAME live index. The Unix socket
/// is user-private, so an owner connection without a token is allowed. Unix-only transport.
#[cfg(unix)]
pub async fn serve<E>(state: Arc<DaemonState<E>>, socket_path: &Path) -> std::io::Result<()>
where
    E: Embedder + Send + Sync + 'static,
{
    let _ = std::fs::remove_file(socket_path); // clear a stale socket from a previous run
    let listener = UnixListener::bind(socket_path)?;
    loop {
        let (stream, _addr) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = serve_connection(state, stream, false).await;
        });
    }
}

/// Serve the daemon over TCP for remote / cloud agents (e.g. Hermes on a VPS). A capability
/// token is REQUIRED on every request — the network is not user-private like the Unix socket —
/// so bind to localhost by default and only expose it deliberately (e.g. over Tailscale/VPN).
pub async fn serve_tcp<E>(
    state: Arc<DaemonState<E>>,
    addr: std::net::SocketAddr,
) -> std::io::Result<()>
where
    E: Embedder + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind(addr).await?;
    loop {
        let (stream, _peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = serve_connection(state, stream, true).await;
        });
    }
}

/// Handle one client connection (Unix or TCP). When `require_token` is set, a request without a
/// capability token is rejected — a network transport must always be authenticated.
async fn serve_connection<E, S>(
    state: Arc<DaemonState<E>>,
    stream: S,
    require_token: bool,
) -> std::io::Result<()>
where
    E: Embedder + Send + Sync + 'static,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut lines = tokio::io::BufReader::new(read_half).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(req) => {
                if require_token
                    && req
                        .get("params")
                        .and_then(|p| p.get("capability"))
                        .is_none()
                {
                    rpc_error(
                        req.get("id").cloned().unwrap_or(Value::Null),
                        -32001,
                        "a capability token is required over the network",
                    )
                } else {
                    state.handle(&req)
                }
            }
            Err(e) => rpc_error(Value::Null, -32700, &format!("parse error: {e}")),
        };
        let mut bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
        bytes.push(b'\n');
        write_half.write_all(&bytes).await?;
    }
    Ok(())
}

/// Spawn a background task that consolidates the vault every `period`, merging near-duplicate
/// memories so the store stays lean over time. Returns the task handle.
pub fn spawn_consolidation<E>(
    state: Arc<DaemonState<E>>,
    period: std::time::Duration,
) -> tokio::task::JoinHandle<()>
where
    E: Embedder + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        loop {
            tick.tick().await;
            if let Ok(mut vault) = state.vault.lock() {
                let _ = vault.consolidate(keepsake_vault::DEDUP_THRESHOLD);
            }
        }
    })
}

/// What can go wrong during one auto-sync round.
#[derive(Debug)]
pub enum SyncError {
    /// The vault mutex was poisoned by a panicking thread.
    Lock,
    /// A durable-store error while snapshotting or merging.
    Store(keepsake_store_sqlite::StoreError),
    /// A relay/network error while pushing or pulling.
    Relay(keepsake_relay::RelayError),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::Lock => write!(f, "vault lock poisoned"),
            SyncError::Store(e) => write!(f, "store error: {e:?}"),
            SyncError::Relay(e) => write!(f, "relay error: {e:?}"),
        }
    }
}

impl std::error::Error for SyncError {}

/// One auto-sync round against the vault's slot: **pull + merge first**, then push the merged
/// snapshot back. The brief vault lock is never held across the network, so a slow relay can't
/// block live clients. The relay only ever sees the sealed (encrypted) snapshot.
pub async fn sync_once<E>(
    state: &Arc<DaemonState<E>>,
    client: &keepsake_relay::RelayClient,
    slot: &str,
    write_token: &[u8; 32],
    sync_key: &[u8; 32],
) -> Result<(), SyncError>
where
    E: Embedder + Send + Sync + 'static,
{
    // 1. Pull the remote snapshot first (no lock held during the network call).
    let remote = client.pull_owned(slot).await.map_err(SyncError::Relay)?;

    // 2. Merge it in (if any) and snapshot the merged state — under one brief lock, no `.await`.
    let snapshot = {
        let mut vault = state.vault.lock().map_err(|_| SyncError::Lock)?;
        if let Some(bytes) = remote {
            if let Some(incoming) = keepsake_sync::SyncState::open(&bytes, sync_key) {
                if incoming
                    .apply_to(vault.store(), slot)
                    .map_err(SyncError::Store)?
                {
                    vault.rebuild_index(&state.kek).map_err(SyncError::Store)?;
                }
            }
        }
        keepsake_sync::SyncState::from_vault(vault.store())
            .map_err(SyncError::Store)?
            .seal(sync_key)
    };

    // 3. Push the merged snapshot back (no lock held during the network call).
    client
        .push_owned(slot, write_token, snapshot)
        .await
        .map_err(SyncError::Relay)?;
    Ok(())
}

/// The auto-sync loop as a plain future: build a relay client and run [`sync_once`] every
/// `period`, forever (transient errors are logged). Wrap this in your runtime's spawn —
/// `tokio::spawn` (see [`spawn_sync`]) or `tauri::async_runtime::spawn` in the desktop app.
pub async fn run_sync_loop<E>(
    state: Arc<DaemonState<E>>,
    relay_url: String,
    slot: String,
    write_token: [u8; 32],
    sync_key: [u8; 32],
    period: std::time::Duration,
) where
    E: Embedder + Send + Sync + 'static,
{
    let client = keepsake_relay::RelayClient::new(&relay_url, "");
    let mut tick = tokio::time::interval(period);
    loop {
        tick.tick().await;
        if let Err(e) = sync_once(&state, &client, &slot, &write_token, &sync_key).await {
            eprintln!("keepsake auto-sync: {e}");
        }
    }
}

/// Spawn [`run_sync_loop`] on the ambient Tokio runtime. Returns the task handle (abort to stop).
pub fn spawn_sync<E>(
    state: Arc<DaemonState<E>>,
    relay_url: String,
    slot: String,
    write_token: [u8; 32],
    sync_key: [u8; 32],
    period: std::time::Duration,
) -> tokio::task::JoinHandle<()>
where
    E: Embedder + Send + Sync + 'static,
{
    tokio::spawn(run_sync_loop(
        state, relay_url, slot, write_token, sync_key, period,
    ))
}

/// A thin client to a running daemon over its Unix socket. MCP, proxy and desktop use this
/// to read and write the shared vault with a scoped capability token — never the raw seed.
/// Each call is one request/response on a fresh connection (cheap over a local socket).
#[cfg(unix)]
#[derive(Clone)]
pub struct DaemonClient {
    socket_path: PathBuf,
    capability: Option<String>,
}

#[cfg(unix)]
impl DaemonClient {
    /// Connect (per call) to the daemon at `socket_path`, as the local owner.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            capability: None,
        }
    }

    /// Authenticate every call with this capability token (hex) instead of owner access.
    pub fn with_capability(mut self, token_hex: impl Into<String>) -> Self {
        self.capability = Some(token_hex.into());
        self
    }

    pub async fn remember(&self, text: &str) -> std::io::Result<Value> {
        self.call("vault/remember", json!({ "text": text })).await
    }

    /// Remember `text` tagged with a provenance `source` (e.g. `proxy:openai:gpt-4`).
    pub async fn remember_with_source(&self, text: &str, source: &str) -> std::io::Result<Value> {
        self.call("vault/remember", json!({ "text": text, "source": source }))
            .await
    }

    /// Read the distilled profile from the shared hub (`None` if not built yet).
    pub async fn profile(&self) -> std::io::Result<Option<String>> {
        let resp = self.call("vault/profile_get", json!({})).await?;
        Ok(resp["result"]["profile"].as_str().map(str::to_string))
    }

    /// Store the distilled profile on the shared hub.
    pub async fn set_profile(&self, text: &str) -> std::io::Result<Value> {
        self.call("vault/profile_set", json!({ "text": text })).await
    }

    /// The most recent `limit` memories as plain text — distillation input.
    pub async fn recent(&self, limit: usize) -> std::io::Result<Vec<String>> {
        let resp = self.call("vault/recent", json!({ "limit": limit })).await?;
        Ok(resp["result"]["texts"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|t| t.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Update a keyed fact; a changed value supersedes the prior one over the shared hub.
    pub async fn remember_fact(&self, subject: &str, value: &str) -> std::io::Result<Value> {
        self.call("vault/remember_fact", json!({ "subject": subject, "value": value }))
            .await
    }

    /// Recall with knowledge-graph enrichment: vector hits plus graph-connected memories.
    pub async fn recall_graph(&self, query: &str, k: usize) -> std::io::Result<Value> {
        self.call("vault/recall", json!({ "query": query, "k": k, "graph": true }))
            .await
    }

    /// Add knowledge-graph triples (`[{subject,relation,object}, …]`) distilled from a memory.
    pub async fn add_triples(&self, cell_id_hex: &str, triples: Value) -> std::io::Result<Value> {
        self.call(
            "graph/add_triples",
            json!({ "cell_id": cell_id_hex, "triples": triples }),
        )
        .await
    }

    /// What `entity` is connected to in the knowledge graph.
    pub async fn graph_neighbors(&self, entity: &str) -> std::io::Result<Value> {
        self.call("graph/neighbors", json!({ "entity": entity })).await
    }

    /// Compact symbol-graph recall: a terse map of the query-relevant region (structure, not texts).
    pub async fn recall_map(&self, query: &str, k: usize) -> std::io::Result<String> {
        let resp = self.call("graph/map", json!({ "query": query, "k": k })).await?;
        Ok(resp["result"]["map"]
            .as_str()
            .unwrap_or_default()
            .to_string())
    }

    /// The full text of one memory by cell id — the on-demand fetch behind a map entry.
    pub async fn get_cell(&self, cell_id_hex: &str) -> std::io::Result<Option<String>> {
        let resp = self.call("vault/get", json!({ "cell_id": cell_id_hex })).await?;
        Ok(resp["result"]["text"].as_str().map(str::to_string))
    }

    pub async fn recall(&self, query: &str, k: usize) -> std::io::Result<Value> {
        self.call("vault/recall", json!({ "query": query, "k": k })).await
    }

    pub async fn forget(&self, cell_id_hex: &str) -> std::io::Result<Value> {
        self.call("vault/forget", json!({ "cell_id": cell_id_hex })).await
    }

    pub async fn status(&self) -> std::io::Result<Value> {
        self.call("vault/status", json!({})).await
    }

    async fn call(&self, method: &str, mut params: Value) -> std::io::Result<Value> {
        if let Some(cap) = &self.capability {
            params["capability"] = json!(cap);
        }
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let stream = UnixStream::connect(&self.socket_path).await?;
        let (read_half, mut write_half) = stream.into_split();
        let mut bytes = serde_json::to_vec(&req).unwrap_or_default();
        bytes.push(b'\n');
        write_half.write_all(&bytes).await?;
        let mut lines = tokio::io::BufReader::new(read_half).lines();
        let line = lines.next_line().await?.unwrap_or_default();
        Ok(serde_json::from_str(&line).unwrap_or(Value::Null))
    }
}

fn rpc_ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepsake_crypto::RootKeys;
    use keepsake_firewall::capability::{CapabilityToken, Caveat};
    use keepsake_retrieval::MockEmbedder;
    use keepsake_store_sqlite::SqliteVault;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_state() -> (DaemonState<MockEmbedder>, [u8; 32]) {
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let kek = Kek::from_root(&roots.encryption_root);
        let vault = MemoryVault::new(SqliteVault::open_in_memory().unwrap(), MockEmbedder::new(64));
        let cap_root = roots.capability_root();
        (DaemonState::new(vault, kek, cap_root), cap_root)
    }

    #[test]
    fn distilled_profile_leads_recall_over_the_hub() {
        let (state, _) = test_state();
        let _ = state.handle(&remember_req("the sky is blue today", None));
        let _ = state.handle(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "vault/profile_set",
            "params": { "text": "Enjoys clear skies." }
        }));
        let resp = state.handle(&recall_req("the sky is blue today", 3, None));
        let hits = resp["result"]["hits"].as_array().expect("hits array");
        assert_eq!(hits[0]["cell_id"], "profile", "profile leads recall: {resp}");
        assert!(hits[0]["text"]
            .as_str()
            .unwrap()
            .contains("User profile"));
    }

    #[test]
    fn graph_map_compresses_and_vault_get_fetches_over_the_hub() {
        let (state, _) = test_state();
        let text = "Apollo is the secret flagship launching March 14";
        let r = state.handle(&remember_req(text, None));
        let cell = r["result"]["cell_id"].as_str().expect("cell_id").to_string();
        let _ = state.handle(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "graph/add_triples",
            "params": { "cell_id": cell, "triples": [
                {"subject": "Apollo", "relation": "launches_on", "object": "March 14"}
            ] }
        }));

        // graph/map → a compact map with the relation + the backing cell id, but NOT the full text.
        let m = state.handle(&json!({
            "jsonrpc": "2.0", "id": 2, "method": "graph/map",
            "params": { "query": text, "k": 5 }
        }));
        let map = m["result"]["map"].as_str().expect("map string");
        assert!(map.contains("launches_on"), "map carries the relation: {m}");
        assert!(map.contains(&cell), "map tags the edge with its cell id");
        assert!(!map.contains("secret flagship"), "map omits the full memory text");

        // vault/get → the full text by id; a forgotten id returns null.
        let g = state.handle(&json!({
            "jsonrpc": "2.0", "id": 3, "method": "vault/get", "params": { "cell_id": cell }
        }));
        assert_eq!(g["result"]["text"].as_str(), Some(text));
    }

    #[tokio::test]
    async fn auto_sync_converges_two_vaults_through_a_relay() {
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let slot = hex::encode(roots.sync_slot());
        let write_token = roots.sync_write_token();
        let sync_key = roots.sync_mac_key();
        let kek = Kek::from_root(&roots.encryption_root);
        let cap = roots.capability_root();

        let base = keepsake_relay::serve_ephemeral("t").await.unwrap();
        let client = keepsake_relay::RelayClient::new(&base, "");

        // Device A holds a memory; device B is empty. Same seed → same slot + keys.
        let mut va = MemoryVault::new(SqliteVault::open_in_memory().unwrap(), MockEmbedder::new(64));
        va.remember(&kek, "the blue whale is the largest animal").unwrap();
        let a = Arc::new(DaemonState::new(va, Kek::from_root(&roots.encryption_root), cap));
        let b = Arc::new(DaemonState::new(
            MemoryVault::new(SqliteVault::open_in_memory().unwrap(), MockEmbedder::new(64)),
            Kek::from_root(&roots.encryption_root),
            cap,
        ));

        // A publishes its merged snapshot; then B pulls + merges it.
        sync_once(&a, &client, &slot, &write_token, &sync_key)
            .await
            .unwrap();
        sync_once(&b, &client, &slot, &write_token, &sync_key)
            .await
            .unwrap();

        // B can now recall what only A had remembered — proves merge + index rebuild.
        let hits = {
            let v = b.vault.lock().unwrap();
            v.recall(&kek, "the blue whale is the largest animal", 1)
                .unwrap()
        };
        assert_eq!(hits.len(), 1, "B should recall A's memory after auto-sync");
    }

    /// Live end-to-end: two vaults converge through a REAL relay URL. Ignored by default + only
    /// runs when KEEPSAKE_E2E_RELAY is set, so it never touches CI.
    ///   KEEPSAKE_E2E_RELAY=https://sync.keepsakehq.app cargo test -p keepsake-daemon --ignored e2e
    #[tokio::test]
    #[ignore]
    async fn e2e_two_vaults_converge_through_a_live_relay() {
        let Ok(url) = std::env::var("KEEPSAKE_E2E_RELAY") else {
            return;
        };
        // A distinct passphrase → a distinct, unguessable slot (won't collide with real users).
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "e2e").unwrap();
        let slot = hex::encode(roots.sync_slot());
        let write_token = roots.sync_write_token();
        let sync_key = roots.sync_mac_key();
        let kek = Kek::from_root(&roots.encryption_root);
        let cap = roots.capability_root();
        let client = keepsake_relay::RelayClient::new(&url, "");

        let mut va = MemoryVault::new(SqliteVault::open_in_memory().unwrap(), MockEmbedder::new(64));
        va.remember(&kek, "the eiffel tower is in paris").unwrap();
        let a = Arc::new(DaemonState::new(va, Kek::from_root(&roots.encryption_root), cap));
        let b = Arc::new(DaemonState::new(
            MemoryVault::new(SqliteVault::open_in_memory().unwrap(), MockEmbedder::new(64)),
            Kek::from_root(&roots.encryption_root),
            cap,
        ));

        sync_once(&a, &client, &slot, &write_token, &sync_key)
            .await
            .unwrap();
        sync_once(&b, &client, &slot, &write_token, &sync_key)
            .await
            .unwrap();

        let hits = {
            let v = b.vault.lock().unwrap();
            v.recall(&kek, "the eiffel tower is in paris", 1).unwrap()
        };
        assert_eq!(hits.len(), 1, "device B recalls A's memory after syncing through {url}");
    }

    fn remember_req(text: &str, cap: Option<&str>) -> Value {
        let mut params = json!({ "text": text });
        if let Some(c) = cap {
            params["capability"] = json!(c);
        }
        json!({ "jsonrpc": "2.0", "id": 1, "method": "vault/remember", "params": params })
    }

    fn recall_req(query: &str, k: u64, cap: Option<&str>) -> Value {
        let mut params = json!({ "query": query, "k": k });
        if let Some(c) = cap {
            params["capability"] = json!(c);
        }
        json!({ "jsonrpc": "2.0", "id": 2, "method": "vault/recall", "params": params })
    }

    #[test]
    fn remember_then_recall_roundtrips_for_the_owner() {
        let (state, _) = test_state();

        let resp = state.handle(&remember_req("bravo bravo bravo", None));
        assert!(
            resp["result"]["cell_id"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "remember should return a cell_id, got: {resp}"
        );

        let resp = state.handle(&recall_req("bravo bravo bravo", 1, None));
        let hits = resp["result"]["hits"].as_array().expect("hits array");
        assert_eq!(hits.len(), 1, "one hit expected, got: {resp}");
        assert_eq!(hits[0]["text"], "bravo bravo bravo");
    }

    #[test]
    fn capability_tokens_scope_read_and_write_separately() {
        let (state, cap_root) = test_state();
        state.handle(&remember_req("delta delta delta", None));

        let read_tok = CapabilityToken::issue(&cap_root, vec![Caveat::new("capability", "memory:read")])
            .encode_hex();
        let write_tok =
            CapabilityToken::issue(&cap_root, vec![Caveat::new("capability", "memory:write")])
                .encode_hex();

        // A read token may recall…
        let r = state.handle(&recall_req("delta delta delta", 1, Some(&read_tok)));
        assert_eq!(
            r["result"]["hits"].as_array().map(Vec::len),
            Some(1),
            "read token recalls: {r}"
        );
        // …but not write.
        let r = state.handle(&remember_req("nope", Some(&read_tok)));
        assert!(r["error"].is_object(), "read token must not write: {r}");

        // A write token may remember…
        let r = state.handle(&remember_req("echo echo echo", Some(&write_tok)));
        assert!(r["result"]["cell_id"].is_string(), "write token writes: {r}");
        // …but not recall (write does NOT imply read).
        let r = state.handle(&recall_req("echo echo echo", 1, Some(&write_tok)));
        assert!(r["error"].is_object(), "write token must not read: {r}");

        // A garbage / tampered token is rejected outright.
        let r = state.handle(&recall_req("delta", 1, Some("deadbeef")));
        assert!(r["error"].is_object(), "garbage token rejected: {r}");
    }

    #[test]
    fn from_shared_lets_the_in_process_owner_see_daemon_writes() {
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let shared = std::sync::Arc::new(std::sync::Mutex::new(MemoryVault::new(
            SqliteVault::open_in_memory().unwrap(),
            MockEmbedder::new(64),
        )));
        let state = DaemonState::from_shared(
            std::sync::Arc::clone(&shared),
            Kek::from_root(&roots.encryption_root),
            roots.capability_root(),
        );

        // A write through the daemon's request handler…
        let r = state.handle(&remember_req("mike mike mike", None));
        assert!(r["result"]["cell_id"].is_string(), "daemon remembers: {r}");

        // …is visible to the in-process owner locking the SAME vault directly (the desktop GUI).
        let kek = Kek::from_root(&roots.encryption_root);
        let hits = shared
            .lock()
            .unwrap()
            .recall(&kek, "mike mike mike", 1)
            .unwrap();
        assert_eq!(hits[0].1, "mike mike mike");
    }

    #[test]
    fn daemon_recall_carries_provenance_source() {
        let (state, _) = test_state();
        state.handle(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "vault/remember",
            "params": { "text": "sierra sierra sierra", "source": "mcp:claude" }
        }));
        let r = state.handle(&recall_req("sierra sierra sierra", 1, None));
        let hits = r["result"]["hits"].as_array().expect("hits array");
        assert_eq!(
            hits[0]["source"], "mcp:claude",
            "recall over the hub carries provenance: {r}"
        );
    }

    #[test]
    fn daemon_remember_fact_supersedes_over_the_hub() {
        let (state, _) = test_state();
        state.handle(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "vault/remember_fact",
            "params": { "subject": "language", "value": "I code in Python" }
        }));
        let r = state.handle(&json!({
            "jsonrpc": "2.0", "id": 2, "method": "vault/remember_fact",
            "params": { "subject": "language", "value": "I switched to Rust" }
        }));
        assert_eq!(r["result"]["changed"], true, "a changed value supersedes: {r}");

        let r = state.handle(&recall_req("I code in Python switched Rust language", 5, None));
        let texts: Vec<String> = r["result"]["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["text"].as_str().unwrap_or_default().to_string())
            .collect();
        assert!(
            texts.iter().any(|t| t.contains("Rust")),
            "the current fact surfaces: {r}"
        );
        assert!(
            !texts.iter().any(|t| t.contains("Python")),
            "the superseded fact is hidden over the hub: {r}"
        );
    }

    #[test]
    fn daemon_graph_enriches_recall_and_exposes_neighbors() {
        let (state, _) = test_state();
        let x = state.handle(&remember_req("Apollo launches on March 14", None));
        let w = state.handle(&remember_req("the keynote slot is confirmed", None));
        let xid = x["result"]["cell_id"].as_str().unwrap().to_string();
        let wid = w["result"]["cell_id"].as_str().unwrap().to_string();

        // W's text never names Apollo, but a triple links it to Apollo.
        state.handle(&json!({"jsonrpc":"2.0","id":1,"method":"graph/add_triples","params":{
            "cell_id": xid, "triples":[{"subject":"Apollo","relation":"launches_on","object":"March 14"}]
        }}));
        let added = state.handle(&json!({"jsonrpc":"2.0","id":2,"method":"graph/add_triples","params":{
            "cell_id": wid, "triples":[{"subject":"Apollo","relation":"has_event","object":"keynote"}]
        }}));
        assert_eq!(added["result"]["added"], 1, "edge added: {added}");

        // Plain recall (k=1) → only the directly-matching memory.
        let r = state.handle(&recall_req("Apollo", 1, None));
        let texts: Vec<String> = r["result"]["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["text"].as_str().unwrap_or_default().to_string())
            .collect();
        assert!(
            texts.iter().any(|t| t.contains("launches")) && !texts.iter().any(|t| t.contains("keynote")),
            "plain recall misses the graph-only memory: {r}"
        );

        // Graph-enriched recall → also the connected memory the vector search missed.
        let r = state.handle(&json!({
            "jsonrpc":"2.0","id":3,"method":"vault/recall","params":{"query":"Apollo","k":1,"graph":true}
        }));
        let texts: Vec<String> = r["result"]["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["text"].as_str().unwrap_or_default().to_string())
            .collect();
        assert!(
            texts.iter().any(|t| t.contains("keynote")),
            "graph enrichment surfaces the connected memory: {r}"
        );

        // Neighbors of Apollo: March 14 and keynote.
        let r = state.handle(&json!({
            "jsonrpc":"2.0","id":4,"method":"graph/neighbors","params":{"entity":"Apollo"}
        }));
        assert_eq!(
            r["result"]["neighbors"].as_array().map(Vec::len),
            Some(2),
            "Apollo connects to two entities: {r}"
        );
    }

    #[test]
    fn daemon_dedups_identical_writes() {
        let (state, _) = test_state();
        state.handle(&remember_req("november november november", None));
        state.handle(&remember_req("november november november", None));
        let r = state.handle(&json!({
            "jsonrpc": "2.0", "id": 9, "method": "vault/status", "params": {}
        }));
        assert_eq!(
            r["result"]["memories"], 1,
            "two identical writes dedup to one memory: {r}"
        );
    }

    #[test]
    fn daemon_consolidate_merges_duplicates() {
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let shared = std::sync::Arc::new(std::sync::Mutex::new(MemoryVault::new(
            SqliteVault::open_in_memory().unwrap(),
            MockEmbedder::new(64),
        )));
        {
            // Inject two identical memories via raw remember (bypassing the write-time guard).
            let kek = Kek::from_root(&roots.encryption_root);
            let mut v = shared.lock().unwrap();
            v.remember(&kek, "oscar oscar oscar").unwrap();
            v.remember(&kek, "oscar oscar oscar").unwrap();
        }
        let state = DaemonState::from_shared(
            std::sync::Arc::clone(&shared),
            Kek::from_root(&roots.encryption_root),
            roots.capability_root(),
        );
        let r = state.handle(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "vault/consolidate", "params": {}
        }));
        assert_eq!(
            r["result"]["merged"], 1,
            "consolidate merges the duplicate: {r}"
        );
    }

    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;

    async fn connect(sock: &std::path::Path) -> UnixStream {
        for _ in 0..40 {
            if let Ok(s) = UnixStream::connect(sock).await {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("daemon did not start accepting connections");
    }

    async fn send_recv(stream: &mut UnixStream, req: &Value) -> Value {
        let mut bytes = serde_json::to_vec(req).unwrap();
        bytes.push(b'\n');
        stream.write_all(&bytes).await.unwrap();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte).await.unwrap();
            if n == 0 || byte[0] == b'\n' {
                break;
            }
            buf.push(byte[0]);
        }
        serde_json::from_slice(&buf).unwrap()
    }

    #[tokio::test]
    async fn two_clients_share_one_live_vault_over_the_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("daemon.sock");
        let state = Arc::new(test_state().0);
        {
            let state = Arc::clone(&state);
            let sock = sock.clone();
            tokio::spawn(async move { serve(state, &sock).await.unwrap() });
        }

        // Client A writes a memory…
        let mut a = connect(&sock).await;
        let r = send_recv(&mut a, &remember_req("golf golf golf", None)).await;
        assert!(r["result"]["cell_id"].is_string(), "client A remembers: {r}");

        // …and a SEPARATE client B recalls it live, without any restart.
        let mut b = connect(&sock).await;
        let r = send_recv(&mut b, &recall_req("golf golf golf", 1, None)).await;
        assert_eq!(
            r["result"]["hits"].as_array().map(Vec::len),
            Some(1),
            "client B sees A's memory live over a separate connection: {r}"
        );
    }

    #[tokio::test]
    async fn daemon_client_roundtrips_and_respects_token_scope() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("daemon.sock");
        let (state, cap_root) = test_state();
        {
            let state = Arc::new(state);
            let sock = sock.clone();
            tokio::spawn(async move { serve(state, &sock).await.unwrap() });
        }

        // Wait until the daemon is accepting connections (owner status succeeds).
        let owner = DaemonClient::new(&sock);
        for _ in 0..40 {
            if owner
                .status()
                .await
                .map(|r| r["result"].is_object())
                .unwrap_or(false)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        // The owner client writes and reads through the connector.
        let r = owner.remember("hotel hotel hotel").await.unwrap();
        assert!(r["result"]["cell_id"].is_string(), "owner remembers: {r}");
        let r = owner.recall("hotel hotel hotel", 1).await.unwrap();
        assert_eq!(
            r["result"]["hits"].as_array().map(Vec::len),
            Some(1),
            "owner recalls: {r}"
        );

        // A read-only-token client may recall the same vault but must not write to it.
        let read_tok =
            CapabilityToken::issue(&cap_root, vec![Caveat::new("capability", "memory:read")])
                .encode_hex();
        let reader = DaemonClient::new(&sock).with_capability(read_tok);
        let r = reader.recall("hotel hotel hotel", 1).await.unwrap();
        assert_eq!(
            r["result"]["hits"].as_array().map(Vec::len),
            Some(1),
            "read token recalls the shared vault: {r}"
        );
        let r = reader.remember("nope").await.unwrap();
        assert!(r["error"].is_object(), "read token must not write: {r}");
    }

    #[tokio::test]
    async fn tcp_network_mode_requires_a_token() {
        use keepsake_firewall::capability::{CapabilityToken, Caveat};
        use tokio::net::{TcpListener, TcpStream};

        let (state, cap_root) = test_state();
        let state = Arc::new(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let st = Arc::clone(&state);
                    tokio::spawn(async move {
                        let _ = serve_connection(st, stream, true).await;
                    });
                }
            });
        }

        async fn rt(addr: std::net::SocketAddr, req: &Value) -> Value {
            let mut s = TcpStream::connect(addr).await.unwrap();
            let mut bytes = serde_json::to_vec(req).unwrap();
            bytes.push(b'\n');
            s.write_all(&bytes).await.unwrap();
            let mut buf = Vec::new();
            let mut b = [0u8; 1];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 || b[0] == b'\n' {
                    break;
                }
                buf.push(b[0]);
            }
            serde_json::from_slice(&buf).unwrap()
        }

        // No token over the network → rejected.
        let r = rt(
            addr,
            &json!({"jsonrpc":"2.0","id":1,"method":"vault/status","params":{}}),
        )
        .await;
        assert!(r["error"].is_object(), "network mode requires a token: {r}");

        // A valid token → works.
        let tok = CapabilityToken::issue(&cap_root, vec![Caveat::new("capability", "memory:admin")])
            .encode_hex();
        let r = rt(
            addr,
            &json!({"jsonrpc":"2.0","id":2,"method":"vault/remember","params":{"text":"papa papa papa","capability":tok}}),
        )
        .await;
        assert!(
            r["result"]["cell_id"].is_string(),
            "a valid token works over the network: {r}"
        );
    }
}
