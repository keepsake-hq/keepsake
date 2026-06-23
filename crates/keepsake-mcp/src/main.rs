//! `keepsake-mcp` — the SAIHM tool surface as an MCP stdio server.
//!
//! Two modes, chosen by env:
//!   • shared (recommended): set `KEEPSAKE_SOCKET` (+ optional `KEEPSAKE_CAPABILITY` token) to
//!     connect to a running `keepsake-daemon`. No seed lives in this process.
//!   • local (legacy): set `KEEPSAKE_MNEMONIC` (+ optional `KEEPSAKE_DB`) to open a private
//!     vault inside this process.
//! Speaks JSON-RPC 2.0 over stdio either way. Register it in Claude Desktop / Cursor.

use std::path::Path;

use keepsake_crypto::{Kek, RootKeys};
use keepsake_mcp::{serve_stdio, DaemonBackend, ToolRouter};
use keepsake_retrieval::FastEmbedder;
use keepsake_store_sqlite::SqliteVault;
use keepsake_vault::MemoryVault;

fn main() {
    // Shared mode: a thin client of the daemon. No seed in this process.
    if let Ok(socket) = std::env::var("KEEPSAKE_SOCKET") {
        let capability = std::env::var("KEEPSAKE_CAPABILITY").ok();
        let mut backend =
            DaemonBackend::connect(socket, capability).expect("connect to keepsake-daemon");
        serve_stdio(&mut backend).expect("mcp stdio loop");
        return;
    }

    // Local mode: open a private vault from the seed.
    let mnemonic =
        std::env::var("KEEPSAKE_MNEMONIC").expect("set KEEPSAKE_SOCKET or KEEPSAKE_MNEMONIC");
    let db = std::env::var("KEEPSAKE_DB").unwrap_or_else(|_| "keepsake.db".to_string());

    let roots = RootKeys::from_mnemonic(&mnemonic, "").expect("valid BIP-39 mnemonic");
    let kek = Kek::from_root(&roots.encryption_root);
    let store = SqliteVault::open(Path::new(&db), &roots.db_key()).expect("open vault");
    let embedder = FastEmbedder::nomic().expect("load local embedding model");
    let mut vault = MemoryVault::new(store, embedder);
    vault.rebuild_index(&kek).expect("rebuild index");

    let mut router = ToolRouter::new(vault, kek, roots.capability_root());
    serve_stdio(&mut router).expect("mcp stdio loop");
}
