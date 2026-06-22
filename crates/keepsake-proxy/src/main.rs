//! `keepsake-proxy` binary — a local OpenAI-compatible gateway that injects your
//! sovereign memory and forwards to a local LLM (Ollama).
//!
//! Config via env: `KEEPSAKE_DB` (default `keepsake.db`), `KEEPSAKE_TOKEN` (required
//! bearer), `KEEPSAKE_MNEMONIC` (required BIP-39 seed), `OLLAMA_URL`
//! (default `http://localhost:11434`). Binds `127.0.0.1:8787`.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use keepsake_crypto::{Kek, RootKeys};
use keepsake_firewall::ReceiptLog;
use keepsake_proxy::{serve, AppState, ProxyAuth};
use keepsake_retrieval::FastEmbedder;
use keepsake_store_sqlite::SqliteVault;
use keepsake_vault::MemoryVault;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    let db = std::env::var("KEEPSAKE_DB").unwrap_or_else(|_| "keepsake.db".to_string());
    let token = std::env::var("KEEPSAKE_TOKEN").expect("set KEEPSAKE_TOKEN");
    let mnemonic = std::env::var("KEEPSAKE_MNEMONIC").expect("set KEEPSAKE_MNEMONIC");
    let ollama =
        std::env::var("OLLAMA_URL").unwrap_or_else(|_| "http://localhost:11434".to_string());

    let roots = RootKeys::from_mnemonic(&mnemonic, "").expect("valid BIP-39 mnemonic");
    let kek = Kek::from_root(&roots.encryption_root);
    let receipts_path = std::env::var("KEEPSAKE_RECEIPTS")
        .unwrap_or_else(|_| "keepsake-receipts.log".to_string());
    let receipts =
        ReceiptLog::open(&roots.receipt_root, &receipts_path).expect("open receipt log");

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

    let state = Arc::new(AppState {
        vault: Mutex::new(vault),
        kek,
        auth: ProxyAuth::new(token),
        ollama_url: ollama,
        http: reqwest::Client::new(),
        receipts: Mutex::new(receipts),
        cap_root: roots.capability_root(),
    });

    let addr: SocketAddr = "127.0.0.1:8787".parse().unwrap();
    println!("keepsake-proxy listening on http://{addr}  (point any OpenAI client here)");
    serve(addr, state).await.expect("server error");
}
