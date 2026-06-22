//! `keepsake-mcp` — the SAIHM tool surface as an MCP stdio server.
//!
//! Register this in Claude Desktop / Cursor. Config via env: `KEEPSAKE_MNEMONIC`
//! (required seed), `KEEPSAKE_DB` (default `keepsake.db`). Speaks JSON-RPC 2.0 over stdio.

use std::path::Path;

use keepsake_crypto::{Kek, RootKeys};
use keepsake_mcp::{serve_stdio, ToolRouter};
use keepsake_retrieval::FastEmbedder;
use keepsake_store_sqlite::SqliteVault;
use keepsake_vault::MemoryVault;

fn main() {
    let mnemonic = std::env::var("KEEPSAKE_MNEMONIC").expect("set KEEPSAKE_MNEMONIC");
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
