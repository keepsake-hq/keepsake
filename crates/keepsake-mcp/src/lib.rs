//! `keepsake-mcp` — the SAIHM tool surface.
//!
//! A [`ToolRouter`] maps the eight `saihm_*` tool calls (JSON in / JSON out) onto a
//! sovereign [`MemoryVault`]. An MCP stdio transport is a thin shell over this router;
//! keeping the dispatch pure makes the whole surface unit-testable without a transport.

use keepsake_core::CellId;
use keepsake_crypto::Kek;
use keepsake_firewall::capability::CapabilityToken;
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
}

impl<E: Embedder> ToolRouter<E> {
    pub fn new(vault: MemoryVault<E>, kek: Kek, cap_root: [u8; 32]) -> Self {
        ToolRouter {
            vault,
            kek,
            cap_root,
        }
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

    /// Dispatch under a capability token: verify it, enforce its caveats, then dispatch.
    /// `now` is the current unix time (for `expires` checks).
    pub fn dispatch_authorized(
        &mut self,
        token: &CapabilityToken,
        now: u64,
        tool: &str,
        args: &Value,
    ) -> Value {
        if !token.verify(&self.cap_root) {
            return json!({"error": "invalid capability token"});
        }
        if let Some(exp) = token.caveat("expires").and_then(|s| s.parse::<u64>().ok()) {
            if now > exp {
                return json!({"error": "capability token expired"});
            }
        }
        if !capability_allows(
            token.caveat("capability").unwrap_or(""),
            required_capability(tool),
        ) {
            return json!({"error": "capability not granted for this tool"});
        }

        // Clamp a scoped recall to the token's max_records.
        let mut args = args.clone();
        if tool == "saihm_recall" {
            if let Some(max) = token
                .caveat("max_records")
                .and_then(|s| s.parse::<u64>().ok())
            {
                if let Some(obj) = args.as_object_mut() {
                    let k = obj.get("k").and_then(|v| v.as_u64()).unwrap_or(4).min(max);
                    obj.insert("k".to_string(), json!(k));
                }
            }
        }
        self.dispatch(tool, &args)
    }
}

/// The capability level a tool requires.
fn required_capability(tool: &str) -> &'static str {
    match tool {
        "saihm_recall" | "saihm_status" => "read",
        "saihm_remember" => "write",
        _ => "admin",
    }
}

/// Whether a granted capability (`memory:read|write|admin`) covers `needed`.
fn capability_allows(granted: &str, needed: &str) -> bool {
    let level = |c: &str| match c {
        "memory:read" => 1u8,
        "memory:write" => 2,
        "memory:admin" => 3,
        _ => 0,
    };
    let need = match needed {
        "read" => 1u8,
        "write" => 2,
        _ => 3,
    };
    level(granted) >= need
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
pub fn handle_message<E: Embedder>(router: &mut ToolRouter<E>, msg: &Value) -> Option<Value> {
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
            let result = router.dispatch(name, &args);
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
pub fn serve_stdio<E: Embedder>(router: &mut ToolRouter<E>) -> std::io::Result<()> {
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
        if let Some(response) = handle_message(router, &msg) {
            let mut out = stdout.lock();
            writeln!(out, "{response}")?;
            out.flush()?;
        }
    }
    Ok(())
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
