//! `keepsake-proxy` binary — a local OpenAI-compatible gateway that injects your sovereign
//! memory and forwards to a local LLM (Ollama).
//!
//! Memory source via env: set `KEEPSAKE_SOCKET` (+ optional `KEEPSAKE_CAPABILITY`) to share
//! one running `keepsake-daemon` vault with every other agent; otherwise a private local vault
//! from `KEEPSAKE_MNEMONIC` (+ `KEEPSAKE_DB`). Also: `KEEPSAKE_TOKEN` (required bearer),
//! `OLLAMA_URL` (default `http://localhost:11434`). Binds `127.0.0.1:8787`.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use keepsake_crypto::{Kek, RootKeys};
use keepsake_daemon::DaemonClient;
use keepsake_firewall::ReceiptLog;
use keepsake_proxy::{serve, AppState, CloudProvider, MemorySource, ProviderKind, ProxyAuth};
use keepsake_retrieval::FastEmbedder;
use keepsake_store_sqlite::SqliteVault;
use keepsake_vault::MemoryVault;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    let token = std::env::var("KEEPSAKE_TOKEN").expect("set KEEPSAKE_TOKEN");
    let mnemonic = std::env::var("KEEPSAKE_MNEMONIC").expect("set KEEPSAKE_MNEMONIC");
    let ollama =
        std::env::var("OLLAMA_URL").unwrap_or_else(|_| "http://localhost:11434".to_string());

    // Cloud providers from the operator's env: KEEPSAKE_PROVIDER_<NAME>_URL (+ optional _KEY).
    // Keys stay in the environment — never logged, never written to receipts. Select one per
    // request with the `X-Keepsake-Provider: <name>` header; omit it to use the local model.
    let mut providers = std::collections::HashMap::new();
    for (k, v) in std::env::vars() {
        if let Some(name) = k
            .strip_prefix("KEEPSAKE_PROVIDER_")
            .and_then(|r| r.strip_suffix("_URL"))
        {
            let api_key = std::env::var(format!("KEEPSAKE_PROVIDER_{name}_KEY")).ok();
            // KEEPSAKE_PROVIDER_<NAME>_KIND=anthropic selects the native Messages API; default is
            // OpenAI-compatible (covers OpenAI, Groq, Together, OpenRouter, local models…).
            let kind = match std::env::var(format!("KEEPSAKE_PROVIDER_{name}_KIND")).as_deref() {
                Ok("anthropic") => ProviderKind::Anthropic,
                _ => ProviderKind::OpenAiCompatible,
            };
            providers.insert(
                name.to_lowercase(),
                CloudProvider { base_url: v, api_key, kind },
            );
        }
    }
    if !providers.is_empty() {
        let mut names: Vec<&str> = providers.keys().map(String::as_str).collect();
        names.sort_unstable();
        println!("keepsake-proxy: cloud providers configured: {}", names.join(", "));
    }

    let roots = RootKeys::from_mnemonic(&mnemonic, "").expect("valid BIP-39 mnemonic");
    let receipts_path = std::env::var("KEEPSAKE_RECEIPTS")
        .unwrap_or_else(|_| "keepsake-receipts.log".to_string());
    let receipts =
        ReceiptLog::open(&roots.receipt_root, &receipts_path).expect("open receipt log");

    // Memory source: a shared daemon (KEEPSAKE_SOCKET) so the gateway's turns land in the SAME
    // live vault every other agent uses — or a private local vault otherwise.
    let memory = if let Ok(socket) = std::env::var("KEEPSAKE_SOCKET") {
        let mut client = DaemonClient::new(socket);
        if let Ok(cap) = std::env::var("KEEPSAKE_CAPABILITY") {
            client = client.with_capability(cap);
        }
        println!("keepsake-proxy: sharing the keepsake-daemon vault");
        MemorySource::Daemon(client)
    } else {
        let db = std::env::var("KEEPSAKE_DB").unwrap_or_else(|_| "keepsake.db".to_string());
        let kek = Kek::from_root(&roots.encryption_root);
        let store = SqliteVault::open(Path::new(&db), &roots.db_key()).expect("open vault");
        let embedder = match std::env::var("KEEPSAKE_EMBED").as_deref() {
            Ok("bge") => FastEmbedder::bge_small(),
            _ => FastEmbedder::nomic(),
        }
        .expect("load local embedding model");
        let mut vault = MemoryVault::new(store, embedder);
        vault
            .rebuild_index(&kek)
            .expect("rebuild index from persisted content");
        MemorySource::Local {
            vault: Box::new(Mutex::new(vault)),
            kek,
        }
    };

    let state = Arc::new(AppState {
        memory,
        auth: ProxyAuth::new(token),
        ollama_url: ollama,
        providers,
        http: reqwest::Client::new(),
        receipts: Mutex::new(receipts),
        cap_root: roots.capability_root(),
    });

    let addr: SocketAddr = "127.0.0.1:8787".parse().unwrap();
    println!("keepsake-proxy listening on http://{addr}  (point any OpenAI client here)");
    serve(addr, state).await.expect("server error");
}
