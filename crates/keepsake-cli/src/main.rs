//! `keepsake` — terminal interface to the sovereign memory vault.
//!
//! Config via env: `KEEPSAKE_DB` (default `keepsake.db`) and `KEEPSAKE_MNEMONIC`
//! (your BIP-39 seed; run `keepsake init` to create one).

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use keepsake_core::CellId;
use keepsake_crypto::{Kek, RootKeys};
use keepsake_firewall::capability::{CapabilityToken, Caveat};
use keepsake_retrieval::FastEmbedder;
use keepsake_store_sqlite::SqliteVault;
use keepsake_vault::MemoryVault;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(name = "keepsake", about = "Sovereign, local-first memory vault")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new 24-word seed phrase (back it up — losing it loses the vault).
    Init,
    /// Store a memory.
    Remember { text: String },
    /// Semantic recall of stored memories.
    Recall {
        query: String,
        #[arg(long, default_value_t = 5)]
        k: usize,
    },
    /// Cryptographically erase a memory by its cell id (hex).
    Forget { cell_id: String },
    /// Show vault status.
    Status,
    /// Run the shared memory hub (daemon) so every agent connects to ONE live vault.
    Serve,
    /// Mint a scoped capability token for an agent (a limited pass — never your seed).
    Token {
        /// Read-only (recall). Default (no flag) = full access.
        #[arg(long)]
        read: bool,
        /// Write-only (remember). Default (no flag) = full access.
        #[arg(long)]
        write: bool,
        /// Expiry as a unix timestamp (token stops working after it).
        #[arg(long)]
        expires: Option<u64>,
    },
    /// Print a ready-to-paste MCP config (hub socket + a fresh token) for Claude/Cursor/Codex.
    McpConfig,
    /// Export the whole vault to a portable, encrypted passport file (stays sealed to your seed).
    Export { file: String },
    /// Import a passport file into this vault (merges; your erasures always win).
    Import { file: String },
    /// Back up your vault to a self-hosted server, end-to-end encrypted. OPAQUE: the server checks
    /// your KEEPSAKE_BACKUP_PASSWORD without ever seeing it, your seed, or the plaintext.
    Backup { url: String },
    /// Restore your vault from such a backup (merges into the local vault).
    Restore { url: String },
    /// Social recovery: split or recombine the seed into Shamir shares.
    #[command(subcommand)]
    Recovery(RecoveryCmd),
    /// Device pairing: move the seed to a new device without copying it by hand.
    #[command(subcommand)]
    Pair(PairCmd),
}

#[derive(Subcommand)]
enum RecoveryCmd {
    /// Split the seed (KEEPSAKE_MNEMONIC) into `shares` shares; any `threshold` recover it.
    Split {
        #[arg(long)]
        threshold: u8,
        #[arg(long)]
        shares: u8,
    },
    /// Recombine `index-hex` shares back into the seed phrase.
    Combine { shares: Vec<String> },
}

#[derive(Subcommand)]
enum PairCmd {
    /// On the NEW device: create a one-time pairing code (saves a local secret).
    New,
    /// On an EXISTING device: seal the seed (KEEPSAKE_MNEMONIC) to a pairing code.
    Offer { code: String },
    /// On the NEW device: open an offer and reveal the seed phrase to import.
    Accept { offer: String },
}

fn pairing_file() -> PathBuf {
    std::env::var("KEEPSAKE_PAIRING_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("keepsake-pairing.seed"))
}

/// Write `data` to `path` with owner-only (0600) permissions on Unix, so a one-time pairing
/// secret cannot be read by other local users (KS-014).
fn write_owner_only(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

fn db_path() -> PathBuf {
    std::env::var("KEEPSAKE_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("keepsake.db"))
}

fn load() -> (MemoryVault<FastEmbedder>, Kek) {
    let mnemonic = std::env::var("KEEPSAKE_MNEMONIC")
        .expect("set KEEPSAKE_MNEMONIC (run `keepsake init` to create one)");
    let roots = RootKeys::from_mnemonic(&mnemonic, "").expect("valid BIP-39 mnemonic");
    let kek = Kek::from_root(&roots.encryption_root);
    let store = SqliteVault::open(&db_path(), &roots.db_key()).expect("open vault");
    let embedder = match std::env::var("KEEPSAKE_EMBED").as_deref() {
        Ok("bge") => FastEmbedder::bge_small(),
        _ => FastEmbedder::nomic(),
    }
    .expect("load local embedding model");
    let mut vault = MemoryVault::new(store, embedder);
    vault.rebuild_index(&kek).expect("rebuild index");
    (vault, kek)
}

fn main() {
    match Cli::parse().cmd {
        Cmd::Init => {
            let mnemonic = bip39::Mnemonic::generate(24).expect("generate mnemonic");
            println!("{mnemonic}");
            eprintln!();
            eprintln!("⚠  This is your vault seed. Write it down offline.");
            eprintln!("   If you lose it, the data is gone — there is no recovery by default.");
            eprintln!("   Then:  export KEEPSAKE_MNEMONIC=\"<the 24 words above>\"");
        }
        Cmd::Remember { text } => {
            let (mut vault, kek) = load();
            let id = vault.remember(&kek, &text).expect("remember");
            println!("{}", hex::encode(id.as_bytes()));
        }
        Cmd::Recall { query, k } => {
            let (vault, kek) = load();
            let hits = vault.recall(&kek, &query, k).expect("recall");
            if hits.is_empty() {
                eprintln!("(no memories matched)");
            }
            for (id, text) in hits {
                println!("{}  {}", hex::encode(id.as_bytes()), text);
            }
        }
        Cmd::Forget { cell_id } => {
            let (mut vault, _kek) = load();
            let bytes = hex::decode(&cell_id).expect("cell id must be hex");
            let arr: [u8; 32] = bytes.try_into().expect("cell id must be 32 bytes");
            vault.forget(&CellId::from_bytes(arr)).expect("forget");
            println!("forgotten {cell_id}");
        }
        Cmd::Status => {
            let (vault, _kek) = load();
            println!("vault:    {}", db_path().display());
            println!("profile:  SAIHM Cell-/Tool-compatible, local receipt profile");
            println!("memories: {}", vault.count().expect("count"));
        }
        Cmd::Serve => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime")
                .block_on(serve_daemon());
        }
        Cmd::Token {
            read,
            write,
            expires,
        } => {
            println!("{}", build_token(&cap_root(), read, write, expires));
            eprintln!(
                "\nGive this to an agent as KEEPSAKE_CAPABILITY — a scoped pass, never your seed."
            );
        }
        Cmd::McpConfig => {
            // A full-access token for your OWN agent on your OWN machine.
            let token = build_token(&cap_root(), false, false, None);
            println!(
                "{}",
                mcp_config_json(&socket_path().to_string_lossy(), &token)
            );
            eprintln!(
                "\nStart the hub first:  keepsake serve\nThen paste the JSON above into your MCP client's config (e.g. Claude Desktop)."
            );
        }
        Cmd::Export { file } => {
            let (vault, _kek) = load();
            let passport = vault.export_passport().expect("export passport");
            let json = serde_json::to_vec_pretty(&passport).expect("serialize passport");
            std::fs::write(&file, json).expect("write passport file");
            eprintln!("exported {} memories to {file}", passport.records.len());
        }
        Cmd::Import { file } => {
            let (mut vault, kek) = load();
            let bytes = std::fs::read(&file).expect("read passport file");
            let passport: keepsake_store_sqlite::Passport =
                serde_json::from_slice(&bytes).expect("parse passport file");
            let n = vault.import_passport(&kek, &passport).expect("import passport");
            println!("imported {n} records from {file}");
        }
        Cmd::Backup { url } => {
            let password = std::env::var("KEEPSAKE_BACKUP_PASSWORD")
                .expect("set KEEPSAKE_BACKUP_PASSWORD (the backup password — never your seed)");
            let (vault, _kek) = load();
            let passport = vault.export_passport().expect("export passport");
            let bytes = serde_json::to_vec(&passport).expect("serialize passport");
            let count = passport.records.len();
            let id = backup_id();
            run_async(async move {
                let client = keepsake_relay::BackupRelayClient::new(&url);
                // No account yet → register this password once, then log in.
                let (session_key, export_key) = match client.login(&id, password.as_bytes()).await {
                    Ok(v) => v,
                    Err(keepsake_relay::RelayError::Status(404)) => {
                        client.register(&id, password.as_bytes()).await.expect("register");
                        client.login(&id, password.as_bytes()).await.expect("login")
                    }
                    Err(_) => panic!("backup login failed (wrong password?)"),
                };
                let blob = keepsake_backup::lock_blob(&export_key, &bytes).expect("lock blob");
                client.upload(&id, &session_key, blob).await.expect("upload");
            });
            eprintln!("backed up {count} memories (encrypted; the server never sees them).");
        }
        Cmd::Restore { url } => {
            let password =
                std::env::var("KEEPSAKE_BACKUP_PASSWORD").expect("set KEEPSAKE_BACKUP_PASSWORD");
            let (mut vault, kek) = load();
            let id = backup_id();
            let n = run_async(async move {
                let client = keepsake_relay::BackupRelayClient::new(&url);
                let (session_key, export_key) = client
                    .login(&id, password.as_bytes())
                    .await
                    .expect("backup login (wrong password?)");
                let blob = client
                    .download(&id, &session_key)
                    .await
                    .expect("download")
                    .expect("no backup found on the server");
                let bytes = keepsake_backup::unlock_blob(&export_key, &blob).expect("unlock blob");
                let passport: keepsake_store_sqlite::Passport =
                    serde_json::from_slice(&bytes).expect("parse passport");
                vault.import_passport(&kek, &passport).expect("import passport")
            });
            println!("restored {n} records from backup.");
        }
        Cmd::Recovery(action) => match action {
            RecoveryCmd::Split { threshold, shares } => {
                let mnemonic = std::env::var("KEEPSAKE_MNEMONIC").expect("set KEEPSAKE_MNEMONIC");
                let entropy = bip39::Mnemonic::parse(&mnemonic)
                    .expect("valid BIP-39 mnemonic")
                    .to_entropy();
                for part in keepsake_crypto::recovery::split(&entropy, threshold, shares) {
                    println!("{}-{}", part.index, hex::encode(&part.bytes));
                }
                eprintln!(
                    "\n⚠  Give these {shares} shares to trusted guardians; any {threshold} recover the seed."
                );
            }
            RecoveryCmd::Combine { shares } => {
                let parts: Vec<_> = shares
                    .iter()
                    .map(|s| {
                        let (idx, hx) = s.split_once('-').expect("share format: index-hex");
                        keepsake_crypto::recovery::Share {
                            index: idx.parse().expect("share index"),
                            bytes: hex::decode(hx).expect("share hex"),
                        }
                    })
                    .collect();
                let entropy = keepsake_crypto::recovery::combine(&parts).expect("combine shares");
                let mnemonic = bip39::Mnemonic::from_entropy(&entropy).expect("valid entropy");
                println!("{mnemonic}");
            }
        },
        Cmd::Pair(action) => match action {
            PairCmd::New => {
                use rand::RngCore;
                let mut seed = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut seed);
                let device = keepsake_crypto::pairing::NewDevice::from_seed(&seed);
                write_owner_only(&pairing_file(), hex::encode(seed).as_bytes())
                    .expect("save pairing secret");
                seed.zeroize(); // wipe the in-memory copy after persisting
                println!("{}", hex::encode(device.pairing_code()));
                eprintln!(
                    "\nPairing code above. On your existing device:\n  keepsake pair offer <code>\nthen back here:\n  keepsake pair accept <offer>"
                );
            }
            PairCmd::Offer { code } => {
                let mnemonic = std::env::var("KEEPSAKE_MNEMONIC").expect("set KEEPSAKE_MNEMONIC");
                let code_bytes: [u8; 32] = hex::decode(&code)
                    .expect("hex pairing code")
                    .as_slice()
                    .try_into()
                    .expect("32-byte pairing code");
                let (offer, sas) = keepsake_crypto::pairing::make_offer(&code_bytes, &mnemonic)
                    .expect("pairing code must be a valid (non-low-order) X25519 key");
                println!("{}", hex::encode(offer));
                eprintln!(
                    "\n🔐 Verification code: {sas}\nConfirm this SAME 6-digit code appears on your new device before trusting the transfer.\nIf it differs, abort — someone may be intercepting the pairing."
                );
            }
            PairCmd::Accept { offer } => {
                let seed_hex = std::fs::read_to_string(pairing_file())
                    .expect("run `keepsake pair new` on this device first");
                let mut seed: [u8; 32] = hex::decode(seed_hex.trim())
                    .expect("hex")
                    .as_slice()
                    .try_into()
                    .expect("32-byte seed");
                let device = keepsake_crypto::pairing::NewDevice::from_seed(&seed);
                seed.zeroize();
                let offer_bytes = hex::decode(&offer).expect("hex offer");

                // Authenticated accept: the user must confirm the SAS matches the offering
                // device before the seed is revealed (KS-012).
                let sas = keepsake_crypto::pairing::pairing_sas(&device.pairing_code(), &offer_bytes)
                    .expect("offer is too short");
                use std::io::Write;
                eprint!(
                    "🔐 Verification code: {sas}\nType the code shown on your OTHER device to confirm: "
                );
                std::io::stderr().flush().ok();
                let mut typed = String::new();
                std::io::stdin()
                    .read_line(&mut typed)
                    .expect("read confirmation");
                if typed.trim() != sas {
                    let _ = std::fs::remove_file(pairing_file());
                    eprintln!("❌ Verification code mismatch — aborting. Do NOT trust this offer.");
                    std::process::exit(1);
                }

                let mnemonic = device.accept(&offer_bytes).expect("open pairing offer");
                println!("{mnemonic}");
                eprintln!("\n✅ Paired. Set this as your seed:\n  export KEEPSAKE_MNEMONIC=\"<the words above>\"");
                let _ = std::fs::remove_file(pairing_file());
            }
        },
    }
}

/// The hub's socket path: `KEEPSAKE_SOCKET` or `~/.keepsake/daemon.sock`.
fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("KEEPSAKE_SOCKET") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".keepsake").join("daemon.sock")
}

/// The capability root derived from the seed — used to mint/verify capability tokens.
fn cap_root() -> [u8; 32] {
    let mnemonic = std::env::var("KEEPSAKE_MNEMONIC").expect("set KEEPSAKE_MNEMONIC");
    RootKeys::from_mnemonic(&mnemonic, "")
        .expect("valid BIP-39 mnemonic")
        .capability_root()
}

/// A stable, non-secret backup account id derived from the seed via a one-way hash, so the relay
/// can key your blob without learning anything about the seed.
fn backup_id() -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"keepsake/v1/backup-id");
    h.update(cap_root());
    hex::encode(&h.finalize()[..16])
}

/// Run a future to completion on a small current-thread runtime (for the HTTP backup commands).
fn run_async<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(f)
}

/// Mint a capability token: `read` only → recall, `write` only → remember, neither → full
/// access (recall + remember + admin). `expires` adds a unix-timestamp expiry.
fn build_token(cap_root: &[u8; 32], read: bool, write: bool, expires: Option<u64>) -> String {
    let capability = if read && !write {
        "memory:read"
    } else if write && !read {
        "memory:write"
    } else {
        "memory:admin"
    };
    let mut caveats = vec![Caveat::new("capability", capability)];
    if let Some(e) = expires {
        caveats.push(Caveat::new("expires", &e.to_string()));
    }
    CapabilityToken::issue(cap_root, caveats).encode_hex()
}

/// A ready-to-paste MCP server config wiring the keepsake MCP shim to the hub `socket` with a
/// scoped `token` — so an agent connects to the shared vault without ever seeing the seed.
fn mcp_config_json(socket: &str, token: &str) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "mcpServers": {
            "keepsake": {
                "command": "keepsake-mcp",
                "env": {
                    "KEEPSAKE_SOCKET": socket,
                    "KEEPSAKE_CAPABILITY": token
                }
            }
        }
    }))
    .expect("serialize MCP config")
}

/// Unlock the vault from the seed and run the shared hub over its Unix socket.
async fn serve_daemon() {
    let mnemonic =
        std::env::var("KEEPSAKE_MNEMONIC").expect("set KEEPSAKE_MNEMONIC (run `keepsake init`)");
    let roots = RootKeys::from_mnemonic(&mnemonic, "").expect("valid BIP-39 mnemonic");
    let kek = Kek::from_root(&roots.encryption_root);
    let store = SqliteVault::open(&db_path(), &roots.db_key()).expect("open vault");
    let embedder = match std::env::var("KEEPSAKE_EMBED").as_deref() {
        Ok("bge") => FastEmbedder::bge_small(),
        _ => FastEmbedder::nomic(),
    }
    .expect("load local embedding model");
    let mut vault = MemoryVault::new(store, embedder);
    vault.rebuild_index(&kek).expect("rebuild index");

    let state =
        std::sync::Arc::new(keepsake_daemon::DaemonState::new(vault, kek, roots.capability_root()));
    let sock = socket_path();
    if let Some(parent) = sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    keepsake_daemon::spawn_consolidation(
        std::sync::Arc::clone(&state),
        std::time::Duration::from_secs(300),
    );
    eprintln!("keepsake hub listening on {}", sock.display());
    keepsake_daemon::serve(state, &sock)
        .await
        .expect("hub server error");
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn root() -> [u8; 32] {
        RootKeys::from_mnemonic(TEST_MNEMONIC, "")
            .unwrap()
            .capability_root()
    }

    fn authz(token: &str, r: &[u8; 32]) -> keepsake_firewall::capability::Authorization {
        CapabilityToken::decode_hex(token).unwrap().authorize(r).unwrap()
    }

    #[test]
    fn token_default_is_full_access() {
        let r = root();
        let a = authz(&build_token(&r, false, false, None), &r);
        assert!(a.allows_read() && a.allows_write() && a.allows_admin());
    }

    #[test]
    fn token_read_flag_is_read_only() {
        let r = root();
        let a = authz(&build_token(&r, true, false, None), &r);
        assert!(a.allows_read() && !a.allows_write());
    }

    #[test]
    fn token_write_flag_is_write_only() {
        let r = root();
        let a = authz(&build_token(&r, false, true, None), &r);
        assert!(!a.allows_read() && a.allows_write());
    }

    #[test]
    fn token_expiry_is_enforced() {
        let r = root();
        let a = authz(&build_token(&r, true, false, Some(100)), &r);
        assert!(!a.is_expired(50) && a.is_expired(200));
    }

    #[test]
    fn mcp_config_wires_socket_and_token() {
        let json = mcp_config_json("/home/x/.keepsake/daemon.sock", "deadbeef");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["mcpServers"]["keepsake"]["command"], "keepsake-mcp");
        assert_eq!(
            v["mcpServers"]["keepsake"]["env"]["KEEPSAKE_SOCKET"],
            "/home/x/.keepsake/daemon.sock"
        );
        assert_eq!(
            v["mcpServers"]["keepsake"]["env"]["KEEPSAKE_CAPABILITY"],
            "deadbeef"
        );
    }
}
