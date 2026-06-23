//! `keepsake-daemon` — one local background service that holds the unlocked vault and a
//! single live index, so every client (MCP, proxy, desktop) shares the SAME memory in real
//! time and authenticates with a scoped capability token instead of carrying the raw seed.
//!
//! [`DaemonState::handle`] is the transport-agnostic JSON-RPC core (synchronous, easy to
//! test); a Unix-socket server wraps it so many clients share one vault and one live index.

use std::path::Path;
use std::sync::{Arc, Mutex};

use keepsake_core::CellId;
use keepsake_crypto::Kek;
use keepsake_firewall::capability::{Authorization, CapabilityToken};
use keepsake_retrieval::Embedder;
use keepsake_vault::MemoryVault;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// One unlocked vault (+ its live index) behind a mutex, the key-encryption-key, and the
/// capability root used to verify client tokens. Shared by every connected client.
pub struct DaemonState<E: Embedder> {
    vault: Mutex<MemoryVault<E>>,
    kek: Kek,
    cap_root: [u8; 32],
}

impl<E: Embedder> DaemonState<E> {
    /// Wrap an already-unlocked vault. `cap_root` verifies clients' capability tokens.
    pub fn new(vault: MemoryVault<E>, kek: Kek, cap_root: [u8; 32]) -> Self {
        Self {
            vault: Mutex::new(vault),
            kek,
            cap_root,
        }
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
            "vault/recall" => self.recall(id, &params, &caller),
            "vault/forget" => self.forget(id, &params, &caller),
            "vault/status" => self.status(id, &caller),
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
        let mut vault = self.vault.lock().expect("vault mutex poisoned");
        match vault.remember(&self.kek, text) {
            Ok(cell_id) => rpc_ok(id, json!({ "cell_id": hex::encode(cell_id.as_bytes()) })),
            Err(e) => rpc_error(id, -32010, &format!("remember failed: {e:?}")),
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
        match vault.recall(&self.kek, query, k) {
            Ok(hits) => {
                let hits: Vec<Value> = hits
                    .into_iter()
                    .filter(|(_, text)| caller.permits_topic(text))
                    .map(|(cid, text)| json!({ "cell_id": hex::encode(cid.as_bytes()), "text": text }))
                    .collect();
                rpc_ok(id, json!({ "hits": hits }))
            }
            Err(e) => rpc_error(id, -32010, &format!("recall failed: {e:?}")),
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

/// Serve the daemon over a Unix socket: one shared vault, many clients, newline-delimited
/// JSON-RPC. Each connection runs concurrently and every request goes through
/// [`DaemonState::handle`], so all clients read and write the SAME live index — a memory
/// written by one client is immediately visible to another, with no restart.
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
            let _ = serve_connection(state, stream).await;
        });
    }
}

async fn serve_connection<E>(state: Arc<DaemonState<E>>, stream: UnixStream) -> std::io::Result<()>
where
    E: Embedder + Send + Sync + 'static,
{
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = tokio::io::BufReader::new(read_half).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(req) => state.handle(&req),
            Err(e) => rpc_error(Value::Null, -32700, &format!("parse error: {e}")),
        };
        let mut bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
        bytes.push(b'\n');
        write_half.write_all(&bytes).await?;
    }
    Ok(())
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
}
