//! `keepsake` — terminal interface to the sovereign memory vault.
//!
//! Config via env: `KEEPSAKE_DB` (default `keepsake.db`) and `KEEPSAKE_MNEMONIC`
//! (your BIP-39 seed; run `keepsake init` to create one).

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use keepsake_core::CellId;
use keepsake_crypto::{Kek, RootKeys};
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
