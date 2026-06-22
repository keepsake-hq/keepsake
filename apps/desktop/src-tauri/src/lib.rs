//! Keepsake desktop — the thin Tauri shell that exposes the vault to the frontend.
//!
//! All real logic lives in `keepsake-desktop-core` (testable, tauri-free). Here we only
//! hold the unlocked-vault session state and wire the `#[tauri::command]`s to it.

use std::sync::Mutex;

use keepsake_crypto::{Kek, RootKeys};
use keepsake_desktop_core::{MemoryHit, RecentMemory, VaultStatus, Vaulted};
use keepsake_retrieval::FastEmbedder;
use keepsake_store_sqlite::SqliteVault;
use keepsake_vault::MemoryVault;
use tauri::path::BaseDirectory;
use tauri::{Manager, State};

/// Session state: `None` while locked, `Some` once a seed has been entered.
struct AppState(Mutex<Option<Vaulted<FastEmbedder>>>);

/// The on-disk home for the vault + model cache (`~/.keepsake`).
fn keepsake_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let dir = std::path::Path::new(&home).join(".keepsake");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn vault_db_path() -> std::path::PathBuf {
    keepsake_dir().join("vault.db")
}

/// Find Nomic model files already present on disk (no network): a flat directory we
/// control, or the Hugging Face snapshot inside the download cache.
fn local_model_dir() -> Option<std::path::PathBuf> {
    let models = keepsake_dir().join("models");
    let flat = models.join("nomic-embed-text-v1.5");
    if flat.join("tokenizer.json").exists() {
        return Some(flat);
    }
    let snapshots = models
        .join("models--nomic-ai--nomic-embed-text-v1.5")
        .join("snapshots");
    if let Ok(entries) = std::fs::read_dir(&snapshots) {
        for entry in entries.flatten() {
            let dir = entry.path();
            if dir.join("tokenizer.json").exists() {
                return Some(dir);
            }
        }
    }
    None
}

/// Resolve the local embedding model, preferring fully-offline paths:
/// 1. a model **bundled inside the app** (offline on a fresh install, any machine),
/// 2. model files **already on disk** (loaded directly — no hf-hub network check),
/// 3. otherwise download once into the cache (the only path that needs internet).
fn load_embedder(app: &tauri::AppHandle) -> Result<FastEmbedder, String> {
    if let Ok(dir) = app
        .path()
        .resolve("models/nomic-embed-text-v1.5", BaseDirectory::Resource)
    {
        if dir.join("tokenizer.json").exists() {
            return FastEmbedder::nomic_from_dir(&dir)
                .map_err(|e| format!("load bundled model: {e}"));
        }
    }
    if let Some(dir) = local_model_dir() {
        return FastEmbedder::nomic_from_dir(&dir).map_err(|e| format!("load local model: {e}"));
    }
    FastEmbedder::nomic_cached(keepsake_dir().join("models"))
        .map_err(|e| format!("load embedding model: {e}"))
}

#[tauri::command]
fn locked(state: State<AppState>) -> bool {
    state.0.lock().unwrap().is_none()
}

/// Whether a vault already exists on disk (drives first-run onboarding vs. unlock).
#[tauri::command]
fn vault_exists() -> bool {
    vault_db_path().exists()
}

/// Mint a fresh 24-word seed for onboarding (shown once for the user to back up).
#[tauri::command]
fn generate_seed() -> String {
    keepsake_crypto::generate_mnemonic()
}

/// Whether the embedding model is already present locally (so unlock won't need to
/// download it). Lets the UI show "Downloading…" only on a true first run.
#[tauri::command]
fn model_ready(app: tauri::AppHandle) -> bool {
    if let Ok(dir) = app
        .path()
        .resolve("models/nomic-embed-text-v1.5", BaseDirectory::Resource)
    {
        if dir.join("tokenizer.json").exists() {
            return true;
        }
    }
    local_model_dir().is_some()
}

#[tauri::command]
fn unlock(
    app: tauri::AppHandle,
    state: State<AppState>,
    mnemonic: String,
) -> Result<VaultStatus, String> {
    let roots = RootKeys::from_mnemonic(mnemonic.trim(), "")
        .map_err(|_| "invalid seed phrase".to_string())?;
    let kek = Kek::from_root(&roots.encryption_root);
    let store =
        SqliteVault::open(&vault_db_path(), &roots.db_key()).map_err(|e| format!("{e:?}"))?;
    let embedder = load_embedder(&app)?;
    let mut vault = MemoryVault::new(store, embedder);
    vault.rebuild_index(&kek).map_err(|e| format!("{e:?}"))?;

    let vaulted = Vaulted::new(vault, kek);
    let status = vaulted.status()?;
    *state.0.lock().unwrap() = Some(vaulted);
    Ok(status)
}

#[tauri::command]
fn lock(state: State<AppState>) {
    *state.0.lock().unwrap() = None;
}

#[tauri::command]
fn remember(state: State<AppState>, text: String) -> Result<String, String> {
    let mut guard = state.0.lock().unwrap();
    guard
        .as_mut()
        .ok_or_else(|| "vault locked".to_string())?
        .remember(&text)
}

#[tauri::command]
fn recall(state: State<AppState>, query: String, k: usize) -> Result<Vec<MemoryHit>, String> {
    let guard = state.0.lock().unwrap();
    guard
        .as_ref()
        .ok_or_else(|| "vault locked".to_string())?
        .recall(&query, k)
}

#[tauri::command]
fn recent(state: State<AppState>, limit: usize) -> Result<Vec<RecentMemory>, String> {
    let guard = state.0.lock().unwrap();
    guard
        .as_ref()
        .ok_or_else(|| "vault locked".to_string())?
        .recent(limit)
}

#[tauri::command]
fn forget(state: State<AppState>, id: String) -> Result<(), String> {
    let mut guard = state.0.lock().unwrap();
    guard
        .as_mut()
        .ok_or_else(|| "vault locked".to_string())?
        .forget(&id)
}

#[tauri::command]
fn status(state: State<AppState>) -> Result<VaultStatus, String> {
    let guard = state.0.lock().unwrap();
    guard
        .as_ref()
        .ok_or_else(|| "vault locked".to_string())?
        .status()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState(Mutex::new(None)))
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            locked,
            vault_exists,
            generate_seed,
            model_ready,
            unlock,
            lock,
            remember,
            recall,
            recent,
            forget,
            status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
