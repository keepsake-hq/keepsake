//! `keepsake-relay` — run the dumb zero-knowledge sync relay.
//!
//! Config via env: `KEEPSAKE_RELAY_TOKEN` (required bearer), `KEEPSAKE_RELAY_BIND`
//! (default `127.0.0.1:8788`), `KEEPSAKE_RELAY_DB` (default `keepsake-relay.db`).
//! Stores only opaque encrypted snapshots, persisted to a SQLite file.

use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let token = std::env::var("KEEPSAKE_RELAY_TOKEN").expect("set KEEPSAKE_RELAY_TOKEN");
    let bind =
        std::env::var("KEEPSAKE_RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8788".to_string());
    let db = std::env::var("KEEPSAKE_RELAY_DB").unwrap_or_else(|_| "keepsake-relay.db".to_string());
    let addr: SocketAddr = bind.parse().expect("valid bind address");
    println!("keepsake-relay (dumb, zero-knowledge) on http://{addr}, storing slots in {db}");
    keepsake_relay::serve(addr, token, db)
        .await
        .expect("relay server error");
}
