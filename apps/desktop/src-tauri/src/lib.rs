//! Keepsake desktop — the thin Tauri shell.
//!
//! On unlock it opens the vault AND **hosts the shared memory hub**: a `keepsake-daemon`
//! serving the very same live vault over `~/.keepsake/daemon.sock`, so Claude / Cursor / Codex
//! and the proxy all read and write one shared memory. The GUI commands lock that same vault,
//! and `lock` stops the hub (re-locking the vault).

use std::sync::{Arc, Mutex};

use keepsake_core::CellId;
use keepsake_crypto::{Kek, RootKeys};
use keepsake_daemon::{run_sync_loop, DaemonState};
use keepsake_desktop_core::{MemoryHit, RecentMemory, VaultStatus};
use keepsake_retrieval::FastEmbedder;
use keepsake_store_sqlite::SqliteVault;
use keepsake_vault::MemoryVault;
use tauri::path::BaseDirectory;
use tauri::{Manager, State};
use tauri_plugin_updater::UpdaterExt;

const PROFILE: &str = "SAIHM Cell-/Tool-compatible, local receipt profile";

type SharedVault = Arc<Mutex<MemoryVault<FastEmbedder>>>;

/// The unlocked session: the shared vault (also served to agents by the hosted daemon), its
/// KEK, and the running daemon task (aborted on lock so the vault stops being served).
/// The seed-derived sync identity + daemon state, kept so the auto-sync task can be (re)started
/// when the sync setting changes, without re-entering the seed.
#[derive(Clone)]
struct SyncCtx {
    state: Arc<DaemonState<FastEmbedder>>,
    slot: String,
    write_token: [u8; 32],
    sync_key: [u8; 32],
}

struct Session {
    vault: SharedVault,
    kek: Kek,
    daemon: tauri::async_runtime::JoinHandle<()>,
    sync_ctx: SyncCtx,
    sync: Option<tauri::async_runtime::JoinHandle<()>>,
    /// The 24 words, held while unlocked so Settings can show them again (like a hardware wallet's
    /// "reveal recovery phrase"). Dropped on lock — never written to disk; wiped from memory on drop.
    mnemonic: zeroize::Zeroizing<String>,
    /// The safe-copy (backup) password, held after the user turns backup on, so fresh copies +
    /// restore don't re-ask. Dropped on lock — never written to disk; wiped from memory on drop.
    backup_password: Option<zeroize::Zeroizing<String>>,
}

/// Session state: `None` while locked, `Some` once a seed has been entered.
struct AppState(Mutex<Option<Session>>);

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

/// Where the hosted hub listens; agents point `KEEPSAKE_SOCKET` here.
fn socket_path() -> std::path::PathBuf {
    keepsake_dir().join("daemon.sock")
}

/// Where the sync-server choice is persisted.
fn sync_config_path() -> std::path::PathBuf {
    keepsake_dir().join("sync.json")
}

/// Where the (non-secret) social-recovery record lives: who holds a piece + the threshold.
fn recovery_meta_path() -> std::path::PathBuf {
    keepsake_dir().join("recovery.json")
}

/// Where the (non-secret) safe-copy state lives: on/off + when it last saved.
fn backup_meta_path() -> std::path::PathBuf {
    keepsake_dir().join("backup.json")
}

/// Friendly message for a relay/backup failure — never a raw error or HTTP code.
fn backup_err(e: keepsake_relay::RelayError) -> String {
    match e {
        keepsake_relay::RelayError::Backup | keepsake_relay::RelayError::Status(401) => {
            "that backup password didn't match".to_string()
        }
        _ => "couldn't reach the safe-copy server — check your internet and try again".to_string(),
    }
}

/// Pull the passport bytes + backup id out of the unlocked session (briefly held lock).
fn export_for_backup(state: &State<AppState>) -> Result<(Vec<u8>, String), String> {
    let guard = state.0.lock().unwrap();
    let session = guard.as_ref().ok_or_else(|| "vault locked".to_string())?;
    let passport = session
        .vault
        .lock()
        .map_err(|_| "vault poisoned".to_string())?
        .export_passport()
        .map_err(|e| format!("{e:?}"))?;
    let bytes = serde_json::to_vec(&passport).map_err(|e| e.to_string())?;
    let id = keepsake_desktop_core::backup_id(&session.mnemonic)?;
    Ok((bytes, id))
}

/// Register-if-needed + upload an encrypted blob of `bytes` under `id`, unlocked by `password`.
async fn upload_backup(id: &str, password: &str, bytes: Vec<u8>) -> Result<(), String> {
    let client = keepsake_relay::BackupRelayClient::new(keepsake_desktop_core::HOSTED_RELAY_URL);
    let (session_key, export_key) = match client.login(id, password.as_bytes()).await {
        Ok(v) => v,
        Err(keepsake_relay::RelayError::Status(404)) => {
            client.register(id, password.as_bytes()).await.map_err(backup_err)?;
            client.login(id, password.as_bytes()).await.map_err(backup_err)?
        }
        Err(e) => return Err(backup_err(e)),
    };
    let blob = keepsake_backup::lock_blob(&export_key, &bytes)
        .map_err(|_| "could not seal your safe copy".to_string())?;
    client.upload(id, &session_key, blob).await.map_err(backup_err)
}

/// Turn on the safe copy with `password` and upload now. The password is held in the session so
/// later copies + restore don't re-ask; it is never written to disk.
#[tauri::command]
async fn backup_enable(state: State<'_, AppState>, password: String) -> Result<(), String> {
    let (bytes, id) = export_for_backup(&state)?;
    upload_backup(&id, &password, bytes).await?;
    {
        let mut guard = state.0.lock().unwrap();
        if let Some(session) = guard.as_mut() {
            session.backup_password = Some(zeroize::Zeroizing::new(password));
        }
    }
    keepsake_desktop_core::BackupMeta {
        on: true,
        last_saved: now_unix(),
    }
    .save(&backup_meta_path())
    .map_err(|e| format!("{e}"))
}

/// Save a fresh safe copy using the password already held this session. No-op if off or no password
/// is held yet (e.g. right after typing the 24 words). Called automatically after changes.
#[tauri::command]
async fn backup_now(state: State<'_, AppState>) -> Result<(), String> {
    if !keepsake_desktop_core::BackupMeta::load(&backup_meta_path()).on {
        return Ok(());
    }
    let (bytes, id, password) = {
        let guard = state.0.lock().unwrap();
        let session = guard.as_ref().ok_or_else(|| "vault locked".to_string())?;
        let Some(password) = session.backup_password.clone() else {
            return Ok(());
        };
        let passport = session
            .vault
            .lock()
            .map_err(|_| "vault poisoned".to_string())?
            .export_passport()
            .map_err(|e| format!("{e:?}"))?;
        let bytes = serde_json::to_vec(&passport).map_err(|e| e.to_string())?;
        let id = keepsake_desktop_core::backup_id(&session.mnemonic)?;
        (bytes, id, password)
    };
    upload_backup(&id, &password, bytes).await?;
    keepsake_desktop_core::BackupMeta {
        on: true,
        last_saved: now_unix(),
    }
    .save(&backup_meta_path())
    .ok();
    Ok(())
}

/// Bring memories back from the safe copy into the (unlocked) vault, using `password`.
#[tauri::command]
async fn backup_restore(state: State<'_, AppState>, password: String) -> Result<usize, String> {
    let id = {
        let guard = state.0.lock().unwrap();
        let session = guard.as_ref().ok_or_else(|| "vault locked".to_string())?;
        keepsake_desktop_core::backup_id(&session.mnemonic)?
    };
    let client = keepsake_relay::BackupRelayClient::new(keepsake_desktop_core::HOSTED_RELAY_URL);
    let (session_key, export_key) = client
        .login(&id, password.as_bytes())
        .await
        .map_err(backup_err)?;
    let blob = client
        .download(&id, &session_key)
        .await
        .map_err(backup_err)?
        .ok_or_else(|| "no safe copy was found for these 24 words".to_string())?;
    let bytes = keepsake_backup::unlock_blob(&export_key, &blob)
        .map_err(|_| "that backup password didn't match".to_string())?;
    let passport: keepsake_store_sqlite::Passport =
        serde_json::from_slice(&bytes).map_err(|_| "the safe copy was unreadable".to_string())?;
    let guard = state.0.lock().unwrap();
    let session = guard.as_ref().ok_or_else(|| "vault locked".to_string())?;
    let mut vault = session.vault.lock().map_err(|_| "vault poisoned".to_string())?;
    vault
        .import_passport(&session.kek, &passport)
        .map_err(|e| format!("{e:?}"))
}

/// The safe-copy state (on/off + when it last saved) for Settings.
#[tauri::command]
fn backup_status() -> keepsake_desktop_core::BackupMeta {
    keepsake_desktop_core::BackupMeta::load(&backup_meta_path())
}

/// How often the background task reconciles the vault with the relay.
const SYNC_PERIOD: std::time::Duration = std::time::Duration::from_secs(30);

/// (Re)start the auto-sync task for `ctx` per `cfg`. Returns the task handle, or `None` if off.
fn start_sync(
    ctx: &SyncCtx,
    cfg: &keepsake_desktop_core::SyncConfig,
) -> Option<tauri::async_runtime::JoinHandle<()>> {
    let url = cfg.resolve_url()?;
    Some(tauri::async_runtime::spawn(run_sync_loop(
        Arc::clone(&ctx.state),
        url,
        ctx.slot.clone(),
        ctx.write_token,
        ctx.sync_key,
        SYNC_PERIOD,
    )))
}

/// Current wall-clock time in Unix seconds (0 if the clock predates the epoch).
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Find Nomic model files already present on disk (no network): a flat directory we control,
/// or the Hugging Face snapshot inside the download cache.
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
/// 1. a model **bundled inside the app**, 2. model files **already on disk**, 3. otherwise
/// download once into the cache (the only path that needs internet).
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

/// Run `f` against the unlocked vault (locking the shared vault); errors if locked.
fn with_vault<T>(
    state: &State<AppState>,
    f: impl FnOnce(&mut MemoryVault<FastEmbedder>, &Kek) -> Result<T, String>,
) -> Result<T, String> {
    let guard = state.0.lock().unwrap();
    let session = guard.as_ref().ok_or_else(|| "vault locked".to_string())?;
    let mut vault = session.vault.lock().map_err(|_| "vault poisoned".to_string())?;
    f(&mut vault, &session.kek)
}

fn vault_status(vault: &MemoryVault<FastEmbedder>) -> Result<VaultStatus, String> {
    Ok(VaultStatus {
        memories: vault.count().map_err(|e| format!("{e:?}"))?,
        profile: PROFILE.to_string(),
    })
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

/// Whether the embedding model is already present locally (so unlock won't need to download it).
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

    let shared: SharedVault = Arc::new(Mutex::new(vault));

    // Host the shared hub on the same live vault, so every agent shares this memory.
    let socket = socket_path();
    let _ = std::fs::remove_file(&socket);
    let daemon_state = Arc::new(DaemonState::from_shared(
        Arc::clone(&shared),
        Kek::from_root(&roots.encryption_root),
        roots.capability_root(),
    ));
    // Keep the seed-derived sync identity + daemon state so auto-sync can (re)start on demand.
    let sync_ctx = SyncCtx {
        state: Arc::clone(&daemon_state),
        slot: hex::encode(roots.sync_slot()),
        write_token: roots.sync_write_token(),
        sync_key: roots.sync_mac_key(),
    };
    // Host the shared hub over a Unix socket (macOS/Linux). On Windows the app + sync work the
    // same; only local multi-agent hub hosting (Unix-socket) is unavailable for now.
    #[cfg(unix)]
    let daemon = {
        let serve_socket = socket.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(e) = keepsake_daemon::serve(daemon_state, &serve_socket).await {
                log::error!("keepsake-daemon stopped: {e}");
            }
        })
    };
    #[cfg(not(unix))]
    let daemon = tauri::async_runtime::spawn(async move {
        drop(daemon_state);
    });

    // Start always-on auto-sync per the saved setting (off / local-first by default).
    let sync = start_sync(
        &sync_ctx,
        &keepsake_desktop_core::SyncConfig::load(&sync_config_path()),
    );

    let status = {
        let v = shared.lock().map_err(|_| "vault poisoned".to_string())?;
        vault_status(&v)?
    };
    *state.0.lock().unwrap() = Some(Session {
        vault: shared,
        kek,
        daemon,
        sync_ctx,
        sync,
        mnemonic: zeroize::Zeroizing::new(mnemonic.trim().to_string()),
        backup_password: None,
    });
    Ok(status)
}

#[tauri::command]
fn lock(state: State<AppState>) {
    if let Some(session) = state.0.lock().unwrap().take() {
        // Stop serving the now-relocked vault; dropping the session drops the vault.
        session.daemon.abort();
        if let Some(sync) = session.sync {
            sync.abort();
        }
    }
    let _ = std::fs::remove_file(socket_path());
}

/// Start over: lock the vault, then set the old vault files **aside** (renamed, never deleted) so a
/// fresh, empty Keepsake can be set up. Reversible — if the user later finds their 24 words, the
/// archived files are still on disk. The only "destructive" command, and even it destroys nothing.
#[tauri::command]
fn reset_vault(state: State<AppState>) -> Result<(), String> {
    lock(state); // stop serving + drop the open vault handle so the files aren't held
    keepsake_desktop_core::archive_vault_files(&keepsake_dir(), now_unix())
        .map(|_| ())
        .map_err(|e| format!("could not set your old memories aside: {e}"))
}

/// Return the 24 words so Settings can show them again (gated in the UI by a "make sure no one is
/// looking" step). Works only while unlocked; the words live in the session, never on disk.
#[tauri::command]
fn reveal_seed(state: State<AppState>) -> Result<String, String> {
    let guard = state.0.lock().unwrap();
    let session = guard.as_ref().ok_or_else(|| "vault locked".to_string())?;
    Ok(session.mnemonic.to_string())
}

/// Social recovery — split the 24 words into pieces for trusted people. Needs the vault unlocked.
#[tauri::command]
fn recovery_split(
    state: State<AppState>,
    threshold: u8,
    shares: u8,
) -> Result<Vec<String>, String> {
    let guard = state.0.lock().unwrap();
    let session = guard.as_ref().ok_or_else(|| "vault locked".to_string())?;
    keepsake_desktop_core::recovery_split(&session.mnemonic, threshold, shares)
}

/// Rebuild the 24 words from collected pieces (runs on the locked unlock screen). Returns the words.
#[tauri::command]
fn recovery_combine(shares: Vec<String>) -> Result<String, String> {
    keepsake_desktop_core::recovery_combine(&shares)
}

/// Remember locally (non-secret) who holds a recovery piece, so the app can remind the user.
#[tauri::command]
fn save_recovery_meta(threshold: u8, names: Vec<String>) -> Result<(), String> {
    keepsake_desktop_core::RecoveryMeta { threshold, names }
        .save(&recovery_meta_path())
        .map_err(|e| format!("could not save your safety net: {e}"))
}

#[tauri::command]
fn get_recovery_meta() -> Option<keepsake_desktop_core::RecoveryMeta> {
    keepsake_desktop_core::RecoveryMeta::load(&recovery_meta_path())
}

#[tauri::command]
fn get_sync_config() -> keepsake_desktop_core::SyncConfig {
    keepsake_desktop_core::SyncConfig::load(&sync_config_path())
}

#[tauri::command]
fn set_sync_config(
    state: State<AppState>,
    config: keepsake_desktop_core::SyncConfig,
) -> Result<(), String> {
    config
        .save(&sync_config_path())
        .map_err(|e| format!("could not save sync setting: {e}"))?;
    // Apply live: if unlocked, restart the auto-sync task with the new setting.
    if let Some(session) = state.0.lock().unwrap().as_mut() {
        if let Some(old) = session.sync.take() {
            old.abort();
        }
        session.sync = start_sync(&session.sync_ctx, &config);
    }
    Ok(())
}

#[tauri::command]
fn remember(state: State<AppState>, text: String) -> Result<String, String> {
    with_vault(&state, |vault, kek| {
        vault
            .remember_with_source(kek, &text, now_unix(), Some("desktop"))
            .map(|id| hex::encode(id.as_bytes()))
            .map_err(|e| format!("{e:?}"))
    })
}

#[tauri::command]
fn recall(state: State<AppState>, query: String, k: usize) -> Result<Vec<MemoryHit>, String> {
    with_vault(&state, |vault, kek| {
        Ok(vault
            .recall_with_graph(
                kek,
                &query,
                k,
                now_unix(),
                keepsake_vault::RecencyParams::default(),
            )
            .map_err(|e| format!("{e:?}"))?
            .into_iter()
            .map(|(id, text)| MemoryHit {
                source: vault.source(&id).ok().flatten(),
                id: hex::encode(id.as_bytes()),
                text,
            })
            .collect())
    })
}

#[tauri::command]
fn recent(state: State<AppState>, limit: usize) -> Result<Vec<RecentMemory>, String> {
    with_vault(&state, |vault, kek| {
        Ok(vault
            .recent(kek, limit)
            .map_err(|e| format!("{e:?}"))?
            .into_iter()
            .map(|(id, text, created_at)| RecentMemory {
                source: vault.source(&id).ok().flatten(),
                id: hex::encode(id.as_bytes()),
                text,
                created_at,
            })
            .collect())
    })
}

#[tauri::command]
fn forget(state: State<AppState>, id: String) -> Result<(), String> {
    with_vault(&state, |vault, _kek| {
        let bytes = hex::decode(&id).map_err(|_| "invalid cell id (not hex)".to_string())?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "cell id must be 32 bytes".to_string())?;
        vault
            .forget(&CellId::from_bytes(arr))
            .map_err(|e| format!("{e:?}"))
    })
}

#[tauri::command]
fn status(state: State<AppState>) -> Result<VaultStatus, String> {
    with_vault(&state, |vault, _kek| vault_status(vault))
}

/// Check the signed update feed; returns the new version string if one is available.
#[tauri::command]
async fn check_update(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    match updater.check().await {
        Ok(Some(update)) => Ok(Some(update.version)),
        Ok(None) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Download + install the available update (signature-verified by the plugin), then restart.
#[tauri::command]
async fn install_update(app: tauri::AppHandle) -> Result<(), String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    let Some(update) = updater.check().await.map_err(|e| e.to_string())? else {
        return Ok(());
    };
    update
        .download_and_install(|_chunk_len, _content_len| {}, || {})
        .await
        .map_err(|e| e.to_string())?;
    app.restart();
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
            #[cfg(desktop)]
            app.handle()
                .plugin(tauri_plugin_updater::Builder::new().build())?;
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
            status,
            check_update,
            install_update,
            get_sync_config,
            set_sync_config,
            reset_vault,
            reveal_seed,
            recovery_split,
            recovery_combine,
            save_recovery_meta,
            get_recovery_meta,
            backup_enable,
            backup_now,
            backup_restore,
            backup_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
