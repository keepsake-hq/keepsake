//! Pre-download the Nomic model into the desktop app's stable cache
//! (`~/.keepsake/models`) so the first unlock is instant and works offline thereafter.
//! Run once with internet: `cargo run --release --example warm_model -p keepsake-retrieval`.

use keepsake_retrieval::{Embedder, FastEmbedder};

fn main() {
    let home = std::env::var("HOME").expect("HOME");
    let dir = std::path::Path::new(&home).join(".keepsake").join("models");
    std::fs::create_dir_all(&dir).expect("create model dir");
    eprintln!("warming Nomic into {} ...", dir.display());

    let embedder = FastEmbedder::nomic_cached(dir).expect("load Nomic");
    let v = embedder
        .embed("keepsake offline warm-up")
        .expect("embed warm-up text");
    println!("ok: nomic ready, embedding dim = {}", v.len());
}
