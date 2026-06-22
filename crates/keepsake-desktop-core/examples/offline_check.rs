//! Proof that the whole backend works with NO network: load the Nomic model from local
//! files (no hf-hub), then run a full remember -> recall -> forget cycle. Build online,
//! then run with Wi-Fi off to prove offline operation.

use keepsake_crypto::{Kek, RootKeys};
use keepsake_desktop_core::Vaulted;
use keepsake_retrieval::FastEmbedder;
use keepsake_store_sqlite::SqliteVault;
use keepsake_vault::MemoryVault;

const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn snapshot_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").expect("HOME");
    let snaps = std::path::Path::new(&home)
        .join(".keepsake/models/models--nomic-ai--nomic-embed-text-v1.5/snapshots");
    std::fs::read_dir(&snaps)
        .expect("model snapshot dir")
        .flatten()
        .map(|e| e.path())
        .find(|p| p.join("tokenizer.json").exists())
        .expect("a Nomic snapshot with tokenizer.json")
}

fn main() {
    let dir = snapshot_dir();
    eprintln!(
        "loading Nomic from {} (local files, no network)...",
        dir.display()
    );
    let embedder = FastEmbedder::nomic_from_dir(&dir).expect("offline model load");

    let roots = RootKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let kek = Kek::from_root(&roots.encryption_root);
    let vault = MemoryVault::new(SqliteVault::open_in_memory().unwrap(), embedder);
    let mut v = Vaulted::new(vault, kek);

    let id = v
        .remember("The Bluefin tuna can swim up to 70 km/h")
        .unwrap();
    let hits = v.recall("how fast does the fish swim", 1).unwrap();
    assert!(!hits.is_empty(), "semantic recall returned nothing");
    println!(
        "OFFLINE OK: remembered {}…, recalled \"{}\"",
        &id[..8],
        hits[0].text
    );

    v.forget(&id).unwrap();
    assert_eq!(v.status().unwrap().memories, 0, "forget must erase");
    println!("OFFLINE OK: forget erased the memory; vault empty");
}
