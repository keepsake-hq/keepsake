//! `keepsake-daemon` binary: unlock the vault once, hold one live index, and serve every
//! local client over a Unix socket. Clients authenticate with a scoped capability token
//! instead of carrying the seed themselves.
//!
//! Config via env: `KEEPSAKE_MNEMONIC` (required seed), `KEEPSAKE_DB` (default
//! `keepsake.db`), `KEEPSAKE_SOCKET` (default `~/.keepsake/daemon.sock`).

use std::path::PathBuf;
use std::sync::Arc;

use keepsake_crypto::{Kek, RootKeys};
use keepsake_daemon::{serve, DaemonState};
use keepsake_retrieval::FastEmbedder;
use keepsake_store_sqlite::SqliteVault;
use keepsake_vault::MemoryVault;

#[tokio::main]
async fn main() {
    let mnemonic = std::env::var("KEEPSAKE_MNEMONIC").expect("set KEEPSAKE_MNEMONIC");
    let db = std::env::var("KEEPSAKE_DB").unwrap_or_else(|_| "keepsake.db".to_string());

    let roots = RootKeys::from_mnemonic(&mnemonic, "").expect("valid BIP-39 mnemonic");
    let kek = Kek::from_root(&roots.encryption_root);
    let store = SqliteVault::open(std::path::Path::new(&db), &roots.db_key()).expect("open vault");
    let embedder = FastEmbedder::nomic().expect("load local embedding model");
    let mut vault = MemoryVault::new(store, embedder);
    vault
        .rebuild_index(&kek)
        .expect("rebuild index from persisted content");

    let state = Arc::new(DaemonState::new(vault, kek, roots.capability_root()));

    let socket_path = socket_path();
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).expect("create socket directory");
    }
    println!("keepsake-daemon listening on {}", socket_path.display());
    serve(state, &socket_path).await.expect("daemon server error");
}

fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("KEEPSAKE_SOCKET") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".keepsake").join("daemon.sock")
}
