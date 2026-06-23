//! `keepsake-mcp` — the SAIHM tool surface.
//!
//! A [`ToolRouter`] maps the eight `saihm_*` tool calls (JSON in / JSON out) onto a
//! sovereign [`MemoryVault`]. An MCP stdio transport is a thin shell over this router;
//! keeping the dispatch pure makes the whole surface unit-testable without a transport.

use keepsake_core::CellId;
use keepsake_crypto::Kek;
use keepsake_daemon::DaemonClient;
use keepsake_firewall::capability::{Authorization, CapabilityToken};
use keepsake_retrieval::Embedder;
use keepsake_vault::MemoryVault;
use serde_json::{json, Value};

/// The eight SAIHM tools. Governance tools are present for spec compatibility but
/// disabled in the chain-free local profile.
pub const SAIHM_TOOLS: [&str; 8] = [
    "saihm_remember",
    "saihm_recall",
    "saihm_forget",
    "saihm_status",
    "saihm_share",
    "saihm_revoke_share",
    "saihm_governance_propose",
    "saihm_governance_vote",
];

/// Routes SAIHM tool calls to a [`MemoryVault`].
pub struct ToolRouter<E: Embedder> {
    vault: MemoryVault<E>,
    kek: Kek,
    cap_root: [u8; 32],
    owner_session: bool,
}

impl<E: Embedder> ToolRouter<E> {
    /// A router for the owner's own local client: unauthenticated `tools/call` is allowed
    /// (the owner launched this process). Use [`ToolRouter::delegated`] to require a
    /// capability token on every call when exposing the vault to an untrusted agent.
    pub fn new(vault: MemoryVault<E>, kek: Kek, cap_root: [u8; 32]) -> Self {
        ToolRouter {
            vault,
            kek,
            cap_root,
            owner_session: true,
        }
    }

    /// A router for an untrusted client: every `tools/call` must carry a valid capability
    /// token, enforced via [`ToolRouter::dispatch_authorized`].
    pub fn delegated(vault: MemoryVault<E>, kek: Kek, cap_root: [u8; 32]) -> Self {
        ToolRouter {
            vault,
            kek,
            cap_root,
            owner_session: false,
        }
    }

    /// Whether unauthenticated `tools/call` is permitted (owner session).
    pub fn owner_session(&self) -> bool {
        self.owner_session
    }

    /// The list of exposed tool names.
    pub fn tools() -> &'static [&'static str] {
        &SAIHM_TOOLS
    }

    /// Dispatch a tool call. Always returns a JSON value (errors as `{"error": ...}`).
    pub fn dispatch(&mut self, tool: &str, args: &Value) -> Value {
        match tool {
            "saihm_remember" => {
                let Some(text) = args["text"].as_str() else {
                    return json!({"error": "missing 'text'"});
                };
                match self.vault.remember(&self.kek, text) {
                    Ok(id) => json!({"cell_id": cell_id_hex(&id)}),
                    Err(_) => json!({"error": "store failure"}),
                }
            }
            "saihm_recall" => {
                let query = args["query"].as_str().unwrap_or("");
                let k = args["k"].as_u64().unwrap_or(4) as usize;
                match self.vault.recall(&self.kek, query, k) {
                    Ok(hits) => json!({
                        "hits": hits
                            .iter()
                            .map(|(id, text)| json!({"cell_id": cell_id_hex(id), "text": text}))
                            .collect::<Vec<_>>()
                    }),
                    Err(_) => json!({"error": "store failure"}),
                }
            }
            "saihm_forget" => {
                let Some(s) = args["cell_id"].as_str() else {
                    return json!({"error": "missing 'cell_id'"});
                };
                let Some(id) = parse_cell_id(s) else {
                    return json!({"error": "invalid 'cell_id'"});
                };
                match self.vault.forget(&id) {
                    Ok(()) => json!({"forgotten": true}),
                    Err(_) => json!({"error": "store failure"}),
                }
            }
            "saihm_share" => {
                let (Some(cid), Some(gp)) =
                    (args["cell_id"].as_str(), args["grantee_public"].as_str())
                else {
                    return json!({"error": "need 'cell_id' and 'grantee_public'"});
                };
                let Some(id) = parse_cell_id(cid) else {
                    return json!({"error": "invalid 'cell_id'"});
                };
                let Some(pk) = hex::decode(gp)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                else {
                    return json!({"error": "invalid 'grantee_public'"});
                };
                match self.vault.share(&self.kek, &id, &pk) {
                    Ok(Some(sealed)) => json!({"sealed": hex::encode(sealed)}),
                    Ok(None) => json!({"error": "cell not found"}),
                    Err(_) => json!({"error": "store failure"}),
                }
            }
            "saihm_status" => json!({
                "profile": "SAIHM Cell-/Tool-compatible, local receipt profile",
                "tools": SAIHM_TOOLS.to_vec(),
            }),
            "saihm_revoke_share" => {
                json!({"error": "revoke is managed via capability tokens (roadmap)"})
            }
            "saihm_governance_propose" | "saihm_governance_vote" => {
                json!({"disabled": "governance is off in the chain-free local profile"})
            }
            other => json!({"error": format!("unknown tool: {other}")}),
        }
    }

    /// Dispatch under a capability token: verify it, collapse its caveats to an
    /// [`Authorization`] (meet semantics), enforce the per-tool permission, and — for recall —
    /// clamp to `max_records` and filter to the token's `scope_topic`. `now` is unix time.
    pub fn dispatch_authorized(
        &mut self,
        token: &CapabilityToken,
        now: u64,
        tool: &str,
        args: &Value,
    ) -> Value {
        let Some(auth) = token.authorize(&self.cap_root) else {
            return json!({"error": "invalid capability token"});
        };
        if auth.is_expired(now) {
            return json!({"error": "capability token expired"});
        }
        if !auth_allows_tool(&auth, tool) {
            return json!({"error": "capability not granted for this tool"});
        }
        if tool == "saihm_recall" {
            return self.authorized_recall(&auth, args);
        }
        self.dispatch(tool, args)
    }

    /// Recall under a scoped token: fetch at most `max_records`, then drop any hit that does
    /// not satisfy the token's `scope_topic` caveats.
    fn authorized_recall(&self, auth: &Authorization, args: &Value) -> Value {
        let query = args["query"].as_str().unwrap_or("");
        let requested = args["k"].as_u64().unwrap_or(4) as usize;
        let k = auth.max_records().map_or(requested, |m| requested.min(m));
        match self.vault.recall(&self.kek, query, k) {
            Ok(hits) => json!({
                "hits": hits
                    .iter()
                    .filter(|(_, text)| auth.permits_topic(text))
                    .map(|(id, text)| json!({"cell_id": cell_id_hex(id), "text": text}))
                    .collect::<Vec<_>>()
            }),
            Err(_) => json!({"error": "store failure"}),
        }
    }
}

/// The tool surface behind the MCP transport: a local [`ToolRouter`] (its own vault) or a
/// [`DaemonBackend`] (a thin client of the shared daemon). Making the transport generic over
/// this lets the same `serve_stdio`/`handle_message` drive either — so the MCP server can run
/// against a private vault OR connect to one shared daemon with a capability token.
pub trait ToolBackend {
    /// Whether unauthenticated `tools/call` is permitted (the owner launched this process).
    fn owner_session(&self) -> bool;
    /// Dispatch a tool call with owner authority. Returns JSON (`{"error": ...}` on failure).
    fn dispatch(&mut self, tool: &str, args: &Value) -> Value;
    /// Dispatch a tool call under a capability token at unix time `now`.
    fn dispatch_authorized(
        &mut self,
        token: &CapabilityToken,
        now: u64,
        tool: &str,
        args: &Value,
    ) -> Value;
}

impl<E: Embedder> ToolBackend for ToolRouter<E> {
    fn owner_session(&self) -> bool {
        ToolRouter::owner_session(self)
    }
    fn dispatch(&mut self, tool: &str, args: &Value) -> Value {
        ToolRouter::dispatch(self, tool, args)
    }
    fn dispatch_authorized(
        &mut self,
        token: &CapabilityToken,
        now: u64,
        tool: &str,
        args: &Value,
    ) -> Value {
        ToolRouter::dispatch_authorized(self, token, now, tool, args)
    }
}

/// Whether `auth` grants the permission a tool needs. Read, write, and admin are distinct —
/// write does not imply read.
fn auth_allows_tool(auth: &Authorization, tool: &str) -> bool {
    match tool {
        "saihm_recall" | "saihm_status" => auth.allows_read(),
        "saihm_remember" => auth.allows_write(),
        _ => auth.allows_admin(),
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cell_id_hex(id: &CellId) -> String {
    hex::encode(id.as_bytes())
}

fn parse_cell_id(s: &str) -> Option<CellId> {
    let bytes = hex::decode(s).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(CellId::from_bytes(arr))
}

// ---------------------------------------------------------------------------
// MCP stdio transport (JSON-RPC 2.0, newline-delimited) — so Claude/Cursor can
// talk to the vault directly. The owner's own client connects unauthenticated;
// capability tokens are for third-party agents (`dispatch_authorized`).
// ---------------------------------------------------------------------------

fn tool_definitions() -> Vec<Value> {
    vec![
        json!({"name":"saihm_remember","description":"Store a memory.","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}),
        json!({"name":"saihm_recall","description":"Semantic recall of stored memories.","inputSchema":{"type":"object","properties":{"query":{"type":"string"},"k":{"type":"integer"}},"required":["query"]}}),
        json!({"name":"saihm_forget","description":"Cryptographically erase a memory by cell id.","inputSchema":{"type":"object","properties":{"cell_id":{"type":"string"}},"required":["cell_id"]}}),
        json!({"name":"saihm_status","description":"Vault and protocol status.","inputSchema":{"type":"object"}}),
    ]
}

/// Handle one JSON-RPC message; returns the response (or `None` for notifications).
pub fn handle_message<B: ToolBackend>(backend: &mut B, msg: &Value) -> Option<Value> {
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let method = msg.get("method").and_then(|m| m.as_str())?;
    match method {
        "initialize" => Some(json!({
            "jsonrpc": "2.0", "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "keepsake", "version": env!("CARGO_PKG_VERSION")}
            }
        })),
        "notifications/initialized" => None,
        "tools/list" => Some(json!({
            "jsonrpc": "2.0", "id": id,
            "result": {"tools": tool_definitions()}
        })),
        "tools/call" => {
            let params = msg.get("params");
            let name = params
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let args = params
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            // Only the advertised tool surface is callable.
            if !tool_definitions().iter().any(|t| t["name"] == name) {
                return Some(json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": {"code": -32601, "message": format!("unknown tool: {name}")}
                }));
            }
            // A capability token in params is always enforced. Without one, only an owner
            // session may call — otherwise every connected model would hold owner privileges.
            let result = match params
                .and_then(|p| p.get("capability"))
                .and_then(|c| c.as_str())
            {
                Some(tok_hex) => match CapabilityToken::decode_hex(tok_hex) {
                    Some(token) => backend.dispatch_authorized(&token, now_unix(), name, &args),
                    None => json!({"error": "malformed capability token"}),
                },
                None if backend.owner_session() => backend.dispatch(name, &args),
                None => json!({"error": "capability token required"}),
            };
            Some(json!({
                "jsonrpc": "2.0", "id": id,
                "result": {"content": [{"type": "text", "text": result.to_string()}]}
            }))
        }
        _ => Some(json!({
            "jsonrpc": "2.0", "id": id,
            "error": {"code": -32601, "message": "method not found"}
        })),
    }
}

/// Serve the MCP protocol over stdio until stdin closes.
pub fn serve_stdio<B: ToolBackend>(backend: &mut B) -> std::io::Result<()> {
    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if let Some(response) = handle_message(backend, &msg) {
            let mut out = stdout.lock();
            writeln!(out, "{response}")?;
            out.flush()?;
        }
    }
    Ok(())
}

/// A [`ToolBackend`] that forwards every tool call to a running keepsake daemon over its Unix
/// socket, authenticating with a capability token instead of holding the seed. This is what
/// Claude Desktop / Cursor / Codex spawn, so they all share one live vault.
pub struct DaemonBackend {
    client: DaemonClient,
    runtime: tokio::runtime::Runtime,
}

impl DaemonBackend {
    /// Connect to the daemon at `socket_path`. With `capability` (hex) every call carries that
    /// scoped token; without it, the connection acts as the local owner.
    pub fn connect(
        socket_path: impl Into<std::path::PathBuf>,
        capability: Option<String>,
    ) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut client = DaemonClient::new(socket_path);
        if let Some(cap) = capability {
            client = client.with_capability(cap);
        }
        Ok(Self { client, runtime })
    }

    fn run(&self, tool: &str, args: &Value, token: Option<String>) -> Value {
        let client = match token {
            Some(t) => self.client.clone().with_capability(t),
            None => self.client.clone(),
        };
        match self.runtime.block_on(daemon_call(&client, tool, args)) {
            Ok(resp) => unwrap_rpc(resp),
            Err(e) => json!({ "error": format!("daemon unreachable: {e}") }),
        }
    }
}

impl ToolBackend for DaemonBackend {
    fn owner_session(&self) -> bool {
        true
    }
    fn dispatch(&mut self, tool: &str, args: &Value) -> Value {
        self.run(tool, args, None)
    }
    fn dispatch_authorized(
        &mut self,
        token: &CapabilityToken,
        _now: u64,
        tool: &str,
        args: &Value,
    ) -> Value {
        // The daemon verifies the token (and its expiry) against its own capability root.
        self.run(tool, args, Some(token.encode_hex()))
    }
}

async fn daemon_call(client: &DaemonClient, tool: &str, args: &Value) -> std::io::Result<Value> {
    match tool {
        "saihm_remember" => client.remember(args["text"].as_str().unwrap_or("")).await,
        "saihm_recall" => {
            client
                .recall(
                    args["query"].as_str().unwrap_or(""),
                    args["k"].as_u64().unwrap_or(4) as usize,
                )
                .await
        }
        "saihm_forget" => client.forget(args["cell_id"].as_str().unwrap_or("")).await,
        "saihm_status" => client.status().await,
        other => Ok(json!({ "error": { "message": format!("unknown tool: {other}") } })),
    }
}

/// Collapse a daemon JSON-RPC reply into the MCP dispatch shape: the inner `result` on
/// success, or `{"error": <message>}`.
fn unwrap_rpc(resp: Value) -> Value {
    if let Some(result) = resp.get("result") {
        result.clone()
    } else if let Some(message) = resp.get("error").and_then(|e| e.get("message")) {
        json!({ "error": message })
    } else {
        json!({ "error": "daemon returned an empty response" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepsake_crypto::RootKeys;
    use keepsake_retrieval::MockEmbedder;
    use keepsake_store_sqlite::SqliteVault;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_router() -> ToolRouter<MockEmbedder> {
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let kek = Kek::from_root(&roots.encryption_root);
        let vault = MemoryVault::new(
            SqliteVault::open_in_memory().unwrap(),
            MockEmbedder::new(64),
        );
        ToolRouter::new(vault, kek, roots.capability_root())
    }

    fn test_cap_root() -> [u8; 32] {
        RootKeys::from_mnemonic(TEST_MNEMONIC, "")
            .unwrap()
            .capability_root()
    }

    #[test]
    fn remember_then_recall_via_tools() {
        let mut router = test_router();
        let r = router.dispatch("saihm_remember", &json!({"text": "alpha alpha alpha"}));
        assert!(r["cell_id"].is_string(), "remember returns a cell_id");

        let rec = router.dispatch(
            "saihm_recall",
            &json!({"query": "alpha alpha alpha", "k": 1}),
        );
        assert_eq!(rec["hits"][0]["text"], "alpha alpha alpha");
    }

    #[test]
    fn forget_via_tools_removes_the_memory() {
        let mut router = test_router();
        let id = router.dispatch("saihm_remember", &json!({"text": "secret"}))["cell_id"]
            .as_str()
            .unwrap()
            .to_string();

        let f = router.dispatch("saihm_forget", &json!({"cell_id": id}));
        assert_eq!(f["forgotten"], true);

        let rec = router.dispatch("saihm_recall", &json!({"query": "secret", "k": 5}));
        assert_eq!(rec["hits"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn status_reports_local_profile_and_unknown_tool_errors() {
        let mut router = test_router();
        let s = router.dispatch("saihm_status", &json!({}));
        assert!(s["profile"].as_str().unwrap().contains("local"));
        let e = router.dispatch("not_a_tool", &json!({}));
        assert!(e["error"].is_string());
    }

    #[test]
    fn governance_tools_are_disabled_in_local_profile() {
        let mut router = test_router();
        let g = router.dispatch("saihm_governance_vote", &json!({}));
        assert!(g["disabled"].is_string());
    }

    fn tools_call(name: &str, args: Value) -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}})
    }

    fn wait_backend(sock: &std::path::Path, cap: Option<String>) -> DaemonBackend {
        let mut b = DaemonBackend::connect(sock.to_str().unwrap().to_string(), cap).unwrap();
        for _ in 0..60 {
            if b.dispatch("saihm_status", &json!({})).get("error").is_none() {
                return b;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!("daemon-backed MCP could not reach the daemon");
    }

    #[test]
    fn daemon_backed_mcp_roundtrips_and_enforces_token() {
        use keepsake_firewall::capability::{CapabilityToken, Caveat};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("daemon.sock");
        let cap_root = test_cap_root();

        // Run the daemon on its own thread + runtime; it holds the one shared vault.
        let sock_srv = sock.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
                let kek = Kek::from_root(&roots.encryption_root);
                let vault =
                    MemoryVault::new(SqliteVault::open_in_memory().unwrap(), MockEmbedder::new(64));
                let state = Arc::new(keepsake_daemon::DaemonState::new(
                    vault,
                    kek,
                    roots.capability_root(),
                ));
                keepsake_daemon::serve(state, &sock_srv).await.unwrap();
            });
        });

        // Owner-mode MCP backend drives tools/call straight through to the daemon.
        let mut owner = wait_backend(&sock, None);
        let r = handle_message(
            &mut owner,
            &tools_call("saihm_remember", json!({"text": "india india india"})),
        )
        .unwrap();
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("cell_id"), "remember via daemon-backed MCP: {text}");

        let r = handle_message(
            &mut owner,
            &tools_call("saihm_recall", json!({"query":"india india india","k":1})),
        )
        .unwrap();
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("india india india"),
            "recall via daemon-backed MCP: {text}"
        );

        // A read-only-token backend is refused a write by the daemon itself.
        let read_tok =
            CapabilityToken::issue(&cap_root, vec![Caveat::new("capability", "memory:read")])
                .encode_hex();
        let mut reader =
            DaemonBackend::connect(sock.to_str().unwrap().to_string(), Some(read_tok)).unwrap();
        let r = handle_message(
            &mut reader,
            &tools_call("saihm_remember", json!({"text":"nope"})),
        )
        .unwrap();
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("error"),
            "read-only token must not write via daemon: {text}"
        );
    }

    #[test]
    fn capability_token_scopes_tool_access() {
        use keepsake_firewall::capability::{CapabilityToken, Caveat};
        let cap_root = test_cap_root();
        let mut router = test_router();

        let read =
            CapabilityToken::issue(&cap_root, vec![Caveat::new("capability", "memory:read")]);
        assert!(
            router.dispatch_authorized(&read, 0, "saihm_remember", &json!({"text": "x"}))["error"]
                .is_string(),
            "a read token cannot write"
        );

        let write =
            CapabilityToken::issue(&cap_root, vec![Caveat::new("capability", "memory:write")]);
        assert!(
            router.dispatch_authorized(&write, 0, "saihm_remember", &json!({"text": "alpha"}))
                ["cell_id"]
                .is_string(),
            "a write token can remember"
        );

        let forged =
            CapabilityToken::issue(&[0u8; 32], vec![Caveat::new("capability", "memory:admin")]);
        assert!(
            router.dispatch_authorized(&forged, 0, "saihm_status", &json!({}))["error"].is_string(),
            "a token under the wrong root is rejected"
        );

        let expiring = CapabilityToken::issue(
            &cap_root,
            vec![
                Caveat::new("capability", "memory:read"),
                Caveat::new("expires", "100"),
            ],
        );
        assert!(
            router.dispatch_authorized(&expiring, 200, "saihm_status", &json!({}))["error"]
                .is_string(),
            "an expired token is rejected"
        );
    }

    #[test]
    fn max_records_caveat_clamps_recall() {
        use keepsake_firewall::capability::{CapabilityToken, Caveat};
        let cap_root = test_cap_root();
        let mut router = test_router();
        let admin =
            CapabilityToken::issue(&cap_root, vec![Caveat::new("capability", "memory:admin")]);
        for text in ["alpha one", "alpha two", "alpha three"] {
            router.dispatch_authorized(&admin, 0, "saihm_remember", &json!({ "text": text }));
        }
        let scoped = CapabilityToken::issue(
            &cap_root,
            vec![
                Caveat::new("capability", "memory:read"),
                Caveat::new("max_records", "1"),
            ],
        );
        let r = router.dispatch_authorized(
            &scoped,
            0,
            "saihm_recall",
            &json!({"query":"alpha","k":10}),
        );
        assert_eq!(
            r["hits"].as_array().unwrap().len(),
            1,
            "max_records caps the recall"
        );
    }

    #[test]
    fn write_token_cannot_recall_and_read_token_cannot_write() {
        use keepsake_firewall::capability::{CapabilityToken, Caveat};
        let cap_root = test_cap_root();
        let mut router = test_router();

        let write =
            CapabilityToken::issue(&cap_root, vec![Caveat::new("capability", "memory:write")]);
        assert!(
            router.dispatch_authorized(&write, 0, "saihm_recall", &json!({"query": "x"}))["error"]
                .is_string(),
            "a write token must not recall (write does not imply read)"
        );

        let read =
            CapabilityToken::issue(&cap_root, vec![Caveat::new("capability", "memory:read")]);
        assert!(
            router.dispatch_authorized(&read, 0, "saihm_remember", &json!({"text": "x"}))["error"]
                .is_string(),
            "a read token must not write"
        );
    }

    #[test]
    fn scope_topic_filters_recall_results() {
        use keepsake_firewall::capability::{CapabilityToken, Caveat};
        let cap_root = test_cap_root();
        let mut router = test_router();
        router.dispatch(
            "saihm_remember",
            &json!({"text": "my health appointment is monday"}),
        );
        router.dispatch(
            "saihm_remember",
            &json!({"text": "my finance budget for april"}),
        );

        let scoped = CapabilityToken::issue(
            &cap_root,
            vec![
                Caveat::new("capability", "memory:read"),
                Caveat::new("scope_topic", "health"),
            ],
        );
        let r =
            router.dispatch_authorized(&scoped, 0, "saihm_recall", &json!({"query":"my","k":10}));
        let hits = r["hits"].as_array().unwrap();
        assert!(
            hits.iter()
                .all(|h| h["text"].as_str().unwrap().contains("health")),
            "a topic-scoped token must only see memories about that topic"
        );
        assert!(!hits.is_empty(), "the on-topic memory is still retrievable");
    }

    #[test]
    fn tools_call_requires_a_token_in_delegated_mode_and_restricts_surface() {
        use keepsake_firewall::capability::{CapabilityToken, Caveat};
        let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let kek = Kek::from_root(&roots.encryption_root);
        let vault =
            MemoryVault::new(SqliteVault::open_in_memory().unwrap(), MockEmbedder::new(64));
        let mut router = ToolRouter::delegated(vault, kek, roots.capability_root());

        // No token on a delegated router => refused.
        let no_tok = handle_message(
            &mut router,
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"saihm_recall","arguments":{"query":"x"}}}),
        )
        .unwrap();
        assert!(no_tok["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("capability token required"));

        // A valid read token => allowed.
        let read = CapabilityToken::issue(
            &roots.capability_root(),
            vec![Caveat::new("capability", "memory:read")],
        );
        let ok = handle_message(
            &mut router,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"saihm_recall","arguments":{"query":"x"},"capability": read.encode_hex()}}),
        )
        .unwrap();
        assert!(ok["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("hits"));

        // An un-advertised tool is rejected regardless of session.
        let bad = handle_message(
            &mut router,
            &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"saihm_share","arguments":{}}}),
        )
        .unwrap();
        assert!(bad["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown tool"));
    }

    #[test]
    fn mcp_initialize_list_and_call() {
        let mut router = test_router();

        let init = handle_message(
            &mut router,
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
        )
        .unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "keepsake");

        let list = handle_message(
            &mut router,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .unwrap();
        assert!(list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "saihm_remember"));

        handle_message(
            &mut router,
            &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"saihm_remember","arguments":{"text":"alpha alpha"}}}),
        );
        let call = handle_message(
            &mut router,
            &json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"saihm_recall","arguments":{"query":"alpha alpha","k":1}}}),
        )
        .unwrap();
        assert!(call["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("alpha alpha"));

        // A notification yields no response.
        assert!(handle_message(
            &mut router,
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .is_none());
    }
}
