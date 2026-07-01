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
        /// Recall mode: balanced (default), semantic, recent, graph_first, or hybrid.
        #[arg(long, default_value = "balanced")]
        profile: String,
    },
    /// List memory sources Keepsake can import or connect.
    #[command(subcommand)]
    Connectors(ConnectorsCmd),
    /// Browse stored documents/memories by source.
    #[command(subcommand)]
    Docs(DocsCmd),
    /// Show or rebuild the local derived profile.
    #[command(subcommand)]
    Profile(ProfileCmd),
    /// Cryptographically erase a memory by its cell id (hex).
    Forget { cell_id: String },
    /// Compact symbol-graph recall: print a terse map (entities + relations, each with a cell id)
    /// of the query-relevant region — then expand a node's full text with `keepsake get <id>`.
    Map {
        query: String,
        #[arg(long, default_value_t = 8)]
        k: usize,
    },
    /// Print one memory's full text by its cell id (the on-demand expansion of a map entry).
    Get { cell_id: String },
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
    /// Print copyable setup steps for a local AI client.
    McpSetup {
        #[arg(default_value = "codex")]
        client: String,
    },
    /// Make connected agents use Keepsake as their PRIMARY memory: writes a high-priority
    /// "Keepsake is your memory" block atop CLAUDE.md + AGENTS.md and wires the MCP tool, so an
    /// agent always recalls from + writes to Keepsake instead of its own siloed memory.
    Connect {
        /// Directory to write into (default: current). Writes ./CLAUDE.md, ./AGENTS.md, ./.mcp.json.
        #[arg(long, default_value = ".")]
        dir: String,
    },
    /// (internal) Claude Code SessionStart hook — prints recalled memory as injected context.
    #[command(hide = true)]
    RecallHook,
    /// (internal) Claude Code Stop hook — stores the last user turn from the transcript.
    #[command(hide = true)]
    RememberHook,
    /// Export the whole vault to a portable, encrypted passport file (stays sealed to your seed).
    Export { file: String },
    /// Import a passport file into this vault (merges; your erasures always win).
    Import { file: String },
    /// Back up your vault to a self-hosted server, end-to-end encrypted. OPAQUE: the server checks
    /// your KEEPSAKE_BACKUP_PASSWORD without ever seeing it, your seed, or the plaintext.
    Backup { url: String },
    /// Restore your vault from such a backup (merges into the local vault).
    Restore { url: String },
    /// Sync this vault with a relay (your devices share one memory). Uses your seed-derived slot +
    /// write-token; the relay only ever sees encrypted snapshots. Run on a timer/cron, or manually.
    Sync { url: String },
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

#[derive(Subcommand)]
enum ConnectorsCmd {
    /// Show the connector catalog. Planned cloud entries are not auto-connected.
    List,
}

#[derive(Subcommand)]
enum DocsCmd {
    /// Show recent memories, optionally limited to one source tag.
    List {
        #[arg(long)]
        source: Option<String>,
        #[arg(long, default_value_t = 25)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Print the current local derived profile, if one exists.
    Show,
    /// Build a small local profile summary from recent memories.
    Redistill,
    /// Clear the derived profile without deleting memories.
    Clear,
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
        Cmd::Recall { query, k, profile } => {
            let (vault, kek) = load();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let hits = vault
                .recall_with_profile(
                    &kek,
                    &query,
                    k,
                    now,
                    keepsake_vault::RecallProfile::parse(&profile),
                )
                .expect("recall");
            if hits.is_empty() {
                eprintln!("(no memories matched)");
            }
            for (id, text) in hits {
                println!("{}  {}", hex::encode(id.as_bytes()), text);
            }
        }
        Cmd::Connectors(ConnectorsCmd::List) => {
            for c in keepsake_import::connector_catalog() {
                let status = match c.access {
                    keepsake_import::ConnectorAccess::CloudOAuthPlanned
                    | keepsake_import::ConnectorAccess::Planned => "planned",
                    _ => "available",
                };
                println!(
                    "{}\t{}\t{}\t{}",
                    c.id,
                    status,
                    if c.network {
                        "explicit network"
                    } else {
                        "local"
                    },
                    c.title
                );
            }
        }
        Cmd::Docs(DocsCmd::List { source, limit }) => {
            let (vault, kek) = load();
            let rows = vault.recent(&kek, limit).expect("recent memories");
            for (id, text, created_at) in rows {
                let src = vault.source(&id).ok().flatten();
                if source
                    .as_deref()
                    .is_some_and(|wanted| src.as_deref() != Some(wanted))
                {
                    continue;
                }
                let title = text
                    .lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty())
                    .unwrap_or("(untitled)");
                println!(
                    "{}\t{}\t{}\t{}",
                    hex::encode(id.as_bytes()),
                    created_at,
                    keepsake_import::source_label(src.as_deref()),
                    title
                );
            }
        }
        Cmd::Profile(ProfileCmd::Show) => {
            let (vault, _kek) = load();
            match vault.profile().expect("profile") {
                Some(profile) if !profile.trim().is_empty() => println!("{profile}"),
                _ => eprintln!("(no profile yet — run `keepsake profile redistill`)"),
            }
        }
        Cmd::Profile(ProfileCmd::Redistill) => {
            let (vault, kek) = load();
            let profile = build_local_profile_summary(&vault, &kek).expect("build profile");
            vault.set_profile(&profile).expect("save profile");
            println!("{profile}");
        }
        Cmd::Profile(ProfileCmd::Clear) => {
            let (vault, _kek) = load();
            vault.clear_profile().expect("clear profile");
            println!("profile cleared; memories kept");
        }
        Cmd::Forget { cell_id } => {
            let (mut vault, _kek) = load();
            let bytes = hex::decode(&cell_id).expect("cell id must be hex");
            let arr: [u8; 32] = bytes.try_into().expect("cell id must be 32 bytes");
            vault.forget(&CellId::from_bytes(arr)).expect("forget");
            println!("forgotten {cell_id}");
        }
        Cmd::Map { query, k } => {
            let (vault, kek) = load();
            let map = vault.recall_map(&kek, &query, k).expect("recall map");
            if map.is_empty() {
                eprintln!(
                    "(no graph edges for that query — populate the graph with KEEPSAKE_AUTO_GRAPH=1, or use `keepsake recall`)"
                );
            } else {
                print!("{map}");
            }
        }
        Cmd::Get { cell_id } => {
            let (vault, kek) = load();
            let bytes = hex::decode(&cell_id).expect("cell id must be hex");
            let arr: [u8; 32] = bytes.try_into().expect("cell id must be 32 bytes");
            match vault
                .get_cell(&kek, &CellId::from_bytes(arr))
                .expect("get cell")
            {
                Some(text) => println!("{text}"),
                None => eprintln!("(no such memory — it may have been forgotten)"),
            }
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
        Cmd::McpSetup { client } => {
            println!("{}", mcp_setup_text(&client));
        }
        Cmd::Connect { dir } => {
            let base = std::path::Path::new(&dir);
            let block = keepsake_instruction_block();
            // The instruction files every agent loads first — write the block at the top.
            for name in ["CLAUDE.md", "AGENTS.md"] {
                let path = base.join(name);
                let existing = std::fs::read_to_string(&path).unwrap_or_default();
                let updated = upsert_block(&existing, &block, KEEPSAKE_BEGIN, KEEPSAKE_END);
                std::fs::write(&path, updated)
                    .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
                println!("✓ Keepsake memory instructions → {}", path.display());
            }
            // Wire the MCP tool so the agent can actually call recall/remember (merge, don't clobber).
            let token = build_token(&cap_root(), false, false, None);
            let mcp_path = base.join(".mcp.json");
            let existing = std::fs::read_to_string(&mcp_path).unwrap_or_default();
            let merged = merge_mcp_json(&existing, &socket_path().to_string_lossy(), &token);
            std::fs::write(&mcp_path, merged)
                .unwrap_or_else(|e| panic!("write {}: {e}", mcp_path.display()));
            println!("✓ Keepsake MCP tool → {}", mcp_path.display());
            // Hard guarantee for Claude Code: harness-run hooks that auto-LOAD memory on session
            // start and auto-STORE the user's turn on stop — no model cooperation required. They
            // talk to the hub seedlessly with a scoped capability token.
            let socket = socket_path().to_string_lossy().to_string();
            let recall_cmd = format!(
                "KEEPSAKE_SOCKET=\"{socket}\" KEEPSAKE_CAPABILITY=\"{token}\" keepsake recall-hook"
            );
            let remember_cmd = format!(
                "KEEPSAKE_SOCKET=\"{socket}\" KEEPSAKE_CAPABILITY=\"{token}\" keepsake remember-hook"
            );
            let settings_path = base.join(".claude").join("settings.local.json");
            let settings_existing = std::fs::read_to_string(&settings_path).unwrap_or_default();
            let s1 = upsert_hook(
                &settings_existing,
                "SessionStart",
                Some("startup|resume"),
                &recall_cmd,
                "keepsake recall-hook",
                false,
            );
            let s2 = upsert_hook(
                &s1,
                "Stop",
                None,
                &remember_cmd,
                "keepsake remember-hook",
                true,
            );
            if let Some(parent) = settings_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&settings_path, s2)
                .unwrap_or_else(|e| panic!("write {}: {e}", settings_path.display()));
            println!(
                "✓ Keepsake auto-load + auto-store hooks → {} (personal; holds a local-only token — don't commit)",
                settings_path.display()
            );
            eprintln!(
                "\nNext:  keepsake serve   (start the hub)\nThen open Claude Code here — it now auto-loads from + auto-writes to Keepsake every session.\n(Codex/Cursor get the always-read instruction block; the deterministic hooks are Claude Code-specific.)"
            );
        }
        Cmd::RecallHook => {
            // SessionStart: ignore the stdin payload, pull memory from the hub, inject it as context.
            let _ = read_stdin();
            let socket = socket_path().to_string_lossy().to_string();
            let cap = std::env::var("KEEPSAKE_CAPABILITY").ok();
            let ctx = run_async(async move {
                let mut client = keepsake_daemon::DaemonClient::new(socket);
                if let Some(c) = cap {
                    client = client.with_capability(c);
                }
                let profile = client.profile().await.ok().flatten();
                let recent = client.recent(8).await.unwrap_or_default();
                session_start_context(profile.as_deref(), &recent)
            });
            let out = serde_json::json!({
                "hookSpecificOutput": { "hookEventName": "SessionStart", "additionalContext": ctx }
            });
            println!("{}", serde_json::to_string(&out).unwrap_or_default());
        }
        Cmd::RememberHook => {
            // Stop: read the transcript named on stdin, store the last substantive user turn.
            let input = read_stdin();
            let text = (|| {
                let v: serde_json::Value = serde_json::from_str(&input).ok()?;
                let path = v.get("transcript_path")?.as_str()?;
                let jsonl = std::fs::read_to_string(path).ok()?;
                last_user_text_from_transcript(&jsonl)
            })();
            // Skip trivial acknowledgements ("ok", "ja"); the hub dedups the rest.
            if let Some(text) = text.filter(|t| t.chars().count() >= 20) {
                let socket = socket_path().to_string_lossy().to_string();
                let cap = std::env::var("KEEPSAKE_CAPABILITY").ok();
                run_async(async move {
                    let mut client = keepsake_daemon::DaemonClient::new(socket);
                    if let Some(c) = cap {
                        client = client.with_capability(c);
                    }
                    let _ = client.remember_with_source(&text, "claude-code").await;
                });
            }
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
            let n = vault
                .import_passport(&kek, &passport)
                .expect("import passport");
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
                        client
                            .register(&id, password.as_bytes())
                            .await
                            .expect("register");
                        client.login(&id, password.as_bytes()).await.expect("login")
                    }
                    Err(_) => panic!("backup login failed (wrong password?)"),
                };
                let blob = keepsake_backup::lock_blob(&export_key, &bytes).expect("lock blob");
                client
                    .upload(&id, &session_key, blob)
                    .await
                    .expect("upload");
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
                vault
                    .import_passport(&kek, &passport)
                    .expect("import passport")
            });
            println!("restored {n} records from backup.");
        }
        Cmd::Sync { url } => {
            let mnemonic = std::env::var("KEEPSAKE_MNEMONIC").expect("set KEEPSAKE_MNEMONIC");
            let roots = RootKeys::from_mnemonic(&mnemonic, "").expect("valid BIP-39 mnemonic");
            let store = SqliteVault::open(&db_path(), &roots.db_key()).expect("open vault");
            let slot = hex::encode(roots.sync_slot());
            let write_token = roots.sync_write_token();
            let sync_key = roots.sync_mac_key();
            let pulled = run_async(async move {
                let client = keepsake_relay::RelayClient::new(&url, "");
                // Pull remote changes first (merge them in), then push our merged state back.
                let pulled =
                    keepsake_relay::pull_and_apply_owned(&client, &slot, &store, &sync_key)
                        .await
                        .expect("pull from relay");
                keepsake_relay::push_snapshot_owned(
                    &client,
                    &slot,
                    &write_token,
                    &store,
                    &sync_key,
                )
                .await
                .expect("push to relay");
                pulled
            });
            println!("synced (remote changes applied: {pulled}). The relay sees only ciphertext.");
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
                let sas =
                    keepsake_crypto::pairing::pairing_sas(&device.pairing_code(), &offer_bytes)
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
                if !keepsake_crypto::ct_eq(typed.trim().as_bytes(), sas.as_bytes()) {
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

/// Fence markers so `keepsake connect` can update its instruction block idempotently.
const KEEPSAKE_BEGIN: &str = "<!-- KEEPSAKE:BEGIN (managed by `keepsake connect`) -->";
const KEEPSAKE_END: &str = "<!-- KEEPSAKE:END -->";

/// The high-priority instruction block that makes an agent treat Keepsake as its primary memory.
/// Written atop CLAUDE.md / AGENTS.md, which every agent loads first.
fn keepsake_instruction_block() -> String {
    format!(
        "{KEEPSAKE_BEGIN}\n\
# Keepsake is your long-term memory\n\
\n\
**Keepsake is your single source of truth for durable memory** — use it instead of your own \
session memory or scratch notes. It is owned by the user and shared across every model and \
device they use.\n\
\n\
- **Before starting a task, RECALL from Keepsake**: call the `saihm_recall` tool (or run \
`keepsake recall \"<topic>\"`) to load what is already known about the user, the project, and \
prior decisions — before asking things you may already know.\n\
- **Whenever you learn something durable** (a decision, preference, fact, or outcome), \
**STORE it in Keepsake**: call `saihm_remember` (or run `keepsake remember \"<fact>\"`). Write \
as you go, not only at the end.\n\
- **Prefer Keepsake over your built-in memory** for anything that should survive across \
sessions, models, or machines. If they disagree, Keepsake wins.\n\
\n\
_Managed by `keepsake connect` — change Keepsake's settings, not these lines._\n\
{KEEPSAKE_END}"
    )
}

/// Idempotently place `block` (fenced by `begin`/`end`) at the TOP of `existing`: replace an
/// existing fenced block in place, else prepend it. Re-running never duplicates the block.
fn upsert_block(existing: &str, block: &str, begin: &str, end: &str) -> String {
    let body = match (existing.find(begin), existing.find(end)) {
        (Some(b), Some(e)) if e > b => {
            format!("{}{}", &existing[..b], &existing[e + end.len()..])
        }
        _ => existing.to_string(),
    };
    let body = body.trim();
    if body.is_empty() {
        format!("{block}\n")
    } else {
        format!("{block}\n\n{body}\n")
    }
}

/// Merge the keepsake MCP server into an existing `.mcp.json` (or start a fresh one), preserving
/// any other servers the user already configured.
fn merge_mcp_json(existing: &str, socket: &str, token: &str) -> String {
    let mut root: serde_json::Value =
        serde_json::from_str(existing).unwrap_or_else(|_| serde_json::json!({}));
    if !root.is_object() {
        root = serde_json::json!({});
    }
    let servers = root
        .as_object_mut()
        .unwrap()
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(map) = servers.as_object_mut() {
        map.insert(
            "keepsake".to_string(),
            serde_json::json!({
                "command": "keepsake-mcp",
                "env": { "KEEPSAKE_SOCKET": socket, "KEEPSAKE_CAPABILITY": token }
            }),
        );
    }
    serde_json::to_string_pretty(&root).unwrap_or_default()
}

/// Read all of stdin to a String (hooks receive their payload there).
fn read_stdin() -> String {
    use std::io::Read;
    let mut s = String::new();
    let _ = std::io::stdin().read_to_string(&mut s);
    s
}

/// The markdown the SessionStart hook injects so the model loads Keepsake memory before acting:
/// the distilled profile first (the pyramid's overview), then a few recent memories.
fn session_start_context(profile: Option<&str>, recent: &[String]) -> String {
    let has_profile = profile.map(|p| !p.trim().is_empty()).unwrap_or(false);
    if !has_profile && recent.is_empty() {
        return String::new();
    }
    let mut s = String::from("# Your Keepsake memory (consult this before acting)\n");
    if let Some(p) = profile {
        if !p.trim().is_empty() {
            s.push_str("\n## Profile\n");
            s.push_str(p.trim());
            s.push('\n');
        }
    }
    if !recent.is_empty() {
        s.push_str("\n## Recent memories\n");
        for m in recent {
            s.push_str("- ");
            s.push_str(m.trim());
            s.push('\n');
        }
    }
    s
}

/// Extract the last user-message text from a Claude Code transcript (JSONL: one object per line;
/// user lines are `{"type":"user","message":{"role":"user","content": <string|parts[]>}}`).
fn last_user_text_from_transcript(jsonl: &str) -> Option<String> {
    let mut last = None;
    for line in jsonl.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("type").and_then(|t| t.as_str()) != Some("user") {
            continue;
        }
        let Some(content) = v.get("message").and_then(|m| m.get("content")) else {
            continue;
        };
        let text = match content {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(parts) => parts
                .iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join(" "),
            _ => continue,
        };
        let text = text.trim().to_string();
        if !text.is_empty() {
            last = Some(text);
        }
    }
    last
}

/// Idempotently register a command hook for `event` in a Claude Code settings JSON: drop any prior
/// Keepsake hook (identified by `marker` in its command) and append the new one — re-running never
/// duplicates it, and the user's own hooks are preserved.
fn upsert_hook(
    settings_json: &str,
    event: &str,
    matcher: Option<&str>,
    command: &str,
    marker: &str,
    run_async: bool,
) -> String {
    let mut root: serde_json::Value =
        serde_json::from_str(settings_json).unwrap_or_else(|_| serde_json::json!({}));
    if !root.is_object() {
        root = serde_json::json!({});
    }
    let hooks = root
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    if !hooks.is_object() {
        *hooks = serde_json::json!({});
    }
    let arr = hooks
        .as_object_mut()
        .unwrap()
        .entry(event.to_string())
        .or_insert_with(|| serde_json::json!([]));
    let mut groups: Vec<serde_json::Value> = arr.as_array().cloned().unwrap_or_default();
    groups.retain(|g| {
        !g.get("hooks")
            .and_then(|h| h.as_array())
            .map(|hs| {
                hs.iter().any(|h| {
                    h.get("command")
                        .and_then(|c| c.as_str())
                        .map(|c| c.contains(marker))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    });
    let mut inner = serde_json::Map::new();
    inner.insert("type".into(), serde_json::json!("command"));
    inner.insert("command".into(), serde_json::json!(command));
    if run_async {
        inner.insert("async".into(), serde_json::json!(true));
    }
    inner.insert("timeout".into(), serde_json::json!(30));
    let mut group = serde_json::Map::new();
    if let Some(m) = matcher {
        group.insert("matcher".into(), serde_json::json!(m));
    }
    group.insert("hooks".into(), serde_json::json!([inner]));
    groups.push(serde_json::Value::Object(group));
    *arr = serde_json::json!(groups);
    serde_json::to_string_pretty(&root).unwrap_or_default()
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

fn mcp_setup_text(client: &str) -> String {
    let label = match client.trim().to_ascii_lowercase().as_str() {
        "claude" | "claude-code" | "claude code" => "Claude Code",
        "cursor" => "Cursor",
        "opencode" | "open-code" | "open code" => "OpenCode",
        "codex" => "Codex",
        _ => "Your AI client",
    };
    format!(
        "Keepsake MCP setup for {label}\n\n\
1. Start the local memory hub:\n\
   keepsake serve\n\n\
2. Print the MCP config with a scoped local token:\n\
   keepsake mcp-config\n\n\
3. In a project you want agents to remember, wire the instructions and MCP config:\n\
   keepsake connect --dir .\n\n\
Your 24 words are never copied into the client. The client gets a limited local pass."
    )
}

fn build_local_profile_summary(
    vault: &MemoryVault<FastEmbedder>,
    kek: &Kek,
) -> Result<String, keepsake_store_sqlite::StoreError> {
    let recent = vault.recent(kek, 200)?;
    let mut sources: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut examples = Vec::new();
    for (id, text, _) in &recent {
        let source = vault.source(id)?;
        *sources
            .entry(keepsake_import::source_label(source.as_deref()))
            .or_default() += 1;
        if examples.len() < 5 {
            let title = text
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .unwrap_or("(untitled)");
            examples.push(title.to_string());
        }
    }
    let mut out = String::from("# Keepsake profile\n\n");
    out.push_str(&format!("- Memories sampled: {}\n", recent.len()));
    if !sources.is_empty() {
        let source_line = sources
            .into_iter()
            .map(|(source, count)| format!("{source} ({count})"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("- Sources: {source_line}\n"));
    }
    if !examples.is_empty() {
        out.push_str("- Recent themes:\n");
        for ex in examples {
            out.push_str("  - ");
            out.push_str(&ex);
            out.push('\n');
        }
    }
    out.push_str("\nThis profile was built locally from recent memories.");
    Ok(out)
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

    let state = std::sync::Arc::new(keepsake_daemon::DaemonState::new(
        vault,
        kek,
        roots.capability_root(),
    ));
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
        CapabilityToken::decode_hex(token)
            .unwrap()
            .authorize(r)
            .unwrap()
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
    fn upsert_block_prepends_then_replaces_idempotently() {
        let block = format!("{KEEPSAKE_BEGIN}\nHELLO\n{KEEPSAKE_END}");
        // Into an empty file.
        let a = upsert_block("", &block, KEEPSAKE_BEGIN, KEEPSAKE_END);
        assert!(a.starts_with(KEEPSAKE_BEGIN));
        // Into existing content → block on top, the user's content kept below.
        let b = upsert_block("# My project\nnotes", &block, KEEPSAKE_BEGIN, KEEPSAKE_END);
        assert!(b.starts_with(KEEPSAKE_BEGIN));
        assert!(b.contains("# My project"));
        // Re-running is idempotent — exactly one block, identical output.
        let c = upsert_block(&b, &block, KEEPSAKE_BEGIN, KEEPSAKE_END);
        assert_eq!(b, c, "upsert must be idempotent");
        assert_eq!(c.matches(KEEPSAKE_BEGIN).count(), 1);
    }

    #[test]
    fn instruction_block_tells_the_agent_to_recall_and_store() {
        let b = keepsake_instruction_block();
        assert!(b.contains("saihm_recall"));
        assert!(b.contains("saihm_remember"));
        assert!(b.contains("single source of truth"));
        assert!(b.starts_with(KEEPSAKE_BEGIN) && b.ends_with(KEEPSAKE_END));
    }

    #[test]
    fn merge_mcp_json_adds_keepsake_and_keeps_other_servers() {
        let fresh = merge_mcp_json("", "/sock", "tok");
        assert!(fresh.contains("keepsake") && fresh.contains("/sock"));
        let existing = r#"{"mcpServers":{"other":{"command":"x"}}}"#;
        let merged = merge_mcp_json(existing, "/sock", "tok");
        assert!(
            merged.contains("\"other\""),
            "other server preserved: {merged}"
        );
        assert!(merged.contains("\"keepsake\""));
    }

    #[test]
    fn session_start_context_lists_profile_then_recent() {
        assert_eq!(session_start_context(None, &[]), "");
        let c = session_start_context(
            Some("User ships Rust crates."),
            &["prefers TDD".to_string()],
        );
        assert!(c.contains("Profile") && c.contains("User ships Rust crates."));
        assert!(c.contains("- prefers TDD"));
    }

    #[test]
    fn last_user_text_picks_the_final_user_message() {
        let jsonl = concat!(
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"first question\"}}\n",
            "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"answer\"}]}}\n",
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"second and final question\"}}\n",
        );
        assert_eq!(
            last_user_text_from_transcript(jsonl).as_deref(),
            Some("second and final question")
        );
        let arr = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"hi there friend\"}]}}";
        assert_eq!(
            last_user_text_from_transcript(arr).as_deref(),
            Some("hi there friend")
        );
        assert_eq!(last_user_text_from_transcript("garbage\n\n"), None);
    }

    #[test]
    fn upsert_hook_is_idempotent_and_preserves_others() {
        let pre =
            r#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo other"}]}]}}"#;
        let a = upsert_hook(
            pre,
            "SessionStart",
            Some("startup"),
            "keepsake recall-hook",
            "keepsake recall-hook",
            false,
        );
        assert!(a.contains("echo other"), "preserves the user's own hook");
        assert!(a.contains("keepsake recall-hook"));
        let b = upsert_hook(
            &a,
            "SessionStart",
            Some("startup"),
            "keepsake recall-hook",
            "keepsake recall-hook",
            false,
        );
        assert_eq!(
            b.matches("keepsake recall-hook").count(),
            1,
            "no duplicate keepsake hook on re-run"
        );
        assert!(b.contains("echo other"));
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

    #[test]
    fn mcp_setup_text_gives_copyable_steps_for_codex() {
        let text = mcp_setup_text("codex");
        assert!(text.contains("Codex"));
        assert!(text.contains("keepsake serve"));
        assert!(text.contains("keepsake mcp-config"));
        assert!(text.contains("keepsake connect"));
    }
}
