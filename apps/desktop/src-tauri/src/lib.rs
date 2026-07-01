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
use keepsake_desktop_core::{DocumentRow, MemoryHit, RecentMemory, VaultStatus};
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
            client
                .register(id, password.as_bytes())
                .await
                .map_err(backup_err)?;
            client
                .login(id, password.as_bytes())
                .await
                .map_err(backup_err)?
        }
        Err(e) => return Err(backup_err(e)),
    };
    let blob = keepsake_backup::lock_blob(&export_key, &bytes)
        .map_err(|_| "could not seal your safe copy".to_string())?;
    client
        .upload(id, &session_key, blob)
        .await
        .map_err(backup_err)
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
    let mut vault = session
        .vault
        .lock()
        .map_err(|_| "vault poisoned".to_string())?;
    vault
        .import_passport(&session.kek, &passport)
        .map_err(|e| format!("{e:?}"))
}

/// The safe-copy state (on/off + when it last saved) for Settings.
#[tauri::command]
fn backup_status() -> keepsake_desktop_core::BackupMeta {
    keepsake_desktop_core::BackupMeta::load(&backup_meta_path())
}

/// A dry-run preview of what would be imported from a source: the parsed items + counts. Reads only
/// local files — writes nothing to the vault.
#[derive(serde::Serialize)]
struct ImportPreview {
    items: Vec<keepsake_import::MemoryItem>,
    total: usize,
    by_role: Vec<(String, usize)>,
}

/// The result of committing an import.
#[derive(serde::Serialize)]
struct ImportResult {
    added: usize,
    skipped: usize,
    merged: usize,
    total: usize,
}

#[derive(serde::Serialize)]
struct ConnectorActionResult {
    connector_id: String,
    message: String,
    added: usize,
    skipped: usize,
    merged: usize,
    total: usize,
}

/// Build a preview (counts by role) from a parsed item list.
fn preview_of(items: Vec<keepsake_import::MemoryItem>) -> ImportPreview {
    let mut roles: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for it in &items {
        *roles.entry(it.role.clone()).or_default() += 1;
    }
    ImportPreview {
        total: items.len(),
        by_role: roles.into_iter().collect(),
        items,
    }
}

fn read_connector_items(connector_id: &str) -> Result<Vec<keepsake_import::MemoryItem>, String> {
    let spec = keepsake_import::connector_by_id(connector_id)
        .ok_or_else(|| format!("unknown connector: {connector_id}"))?;
    if spec.network {
        return Err(format!(
            "{} is planned and will not make a network call until an explicit setup flow exists",
            spec.title
        ));
    }
    let home = std::path::PathBuf::from(std::env::var("HOME").map_err(|_| "no HOME".to_string())?);
    match connector_id {
        "claude-code" => Ok(keepsake_import::read_claude_code(&home, &[])),
        "coding-agents" => Ok(keepsake_import::read_coding_agents(&home)),
        "obsidian" => Ok(keepsake_import::read_obsidian(&home)),
        "local-folder" | "chatgpt-export" | "chromadb" => Err(format!(
            "{} needs a user-picked file or folder; use import_path",
            spec.title
        )),
        "paste" => Err("Paste memories needs user-provided text; use import_paste".to_string()),
        "mcp-agents" => Err("Agent setup has no documents to import".to_string()),
        _ => Err(format!("{} is not importable yet", spec.title)),
    }
}

fn commit_import_items(
    vault: &mut MemoryVault<FastEmbedder>,
    kek: &Kek,
    items: &[keepsake_import::MemoryItem],
) -> ImportResult {
    let mut added = 0usize;
    let mut skipped = 0usize;
    for it in items {
        match vault.remember_deduped_with_source(
            kek,
            &it.text,
            keepsake_vault::DEDUP_THRESHOLD,
            it.created_at,
            Some(&it.source),
        ) {
            Ok((_, true)) => added += 1,
            Ok((_, false)) => skipped += 1,
            Err(_) => {}
        }
    }
    let merged = vault
        .consolidate(keepsake_vault::DEDUP_THRESHOLD)
        .unwrap_or(0);
    ImportResult {
        added,
        skipped,
        merged,
        total: items.len(),
    }
}

/// Scan a known source for memory and return a preview (no writes). v1 source: "claude-code".
#[tauri::command]
fn import_preview(source: String) -> Result<ImportPreview, String> {
    Ok(preview_of(read_connector_items(&source)?))
}

/// Universal: preview any folder/file/ZIP the user picked (no writes).
#[tauri::command]
fn import_path(path: String) -> Result<ImportPreview, String> {
    Ok(preview_of(keepsake_import::read_path(
        std::path::Path::new(&path),
        "import:folder",
    )))
}

/// Universal: preview pasted memory text (e.g. a ChatGPT/Gemini saved-memory list).
#[tauri::command]
fn import_paste(text: String) -> Result<ImportPreview, String> {
    Ok(preview_of(keepsake_import::read_pasted_text(
        &text,
        "import:paste",
    )))
}

/// Write previewed items into the unlocked vault through the existing dedup engine, then a
/// consolidation pass. Returns how many were added vs skipped as duplicates vs merged.
#[tauri::command]
fn import_commit(
    state: State<AppState>,
    items: Vec<keepsake_import::MemoryItem>,
) -> Result<ImportResult, String> {
    with_vault(&state, |vault, kek| {
        Ok(commit_import_items(vault, kek, &items))
    })
}

#[derive(serde::Serialize)]
struct GraphNodeDto {
    id: String,
    title: String,
    text: String,
    created_at: i64,
    source: Option<String>,
}

#[derive(serde::Serialize)]
struct GraphEdgeDto {
    a: usize,
    b: usize,
    weight: f32,
}

#[derive(serde::Serialize)]
struct GraphDto {
    nodes: Vec<GraphNodeDto>,
    edges: Vec<GraphEdgeDto>,
}

/// The similarity map of the unlocked vault's memories (nodes + weighted edges) for the visual
/// "Map" view. Computed locally from the on-device embeddings — no model, nothing leaves the device.
#[tauri::command]
fn memory_graph(state: State<AppState>) -> Result<GraphDto, String> {
    with_vault(&state, |vault, kek| {
        let g = vault
            .memory_graph(kek, 0.58, 8, 3000)
            .map_err(|e| format!("{e:?}"))?;
        Ok(GraphDto {
            nodes: g
                .nodes
                .into_iter()
                .map(|n| GraphNodeDto {
                    id: hex::encode(n.id.as_bytes()),
                    title: n.title,
                    text: n.text,
                    created_at: n.created_at,
                    source: n.source,
                })
                .collect(),
            edges: g
                .edges
                .into_iter()
                .map(|e| GraphEdgeDto {
                    a: e.a,
                    b: e.b,
                    weight: e.weight,
                })
                .collect(),
        })
    })
}

#[tauri::command]
fn connector_catalog(
    state: State<AppState>,
) -> Result<Vec<keepsake_desktop_core::ConnectorView>, String> {
    with_vault(&state, |vault, kek| {
        let memories = recent_memories(vault, kek, 5000)?;
        Ok(keepsake_desktop_core::connector_views(&memories))
    })
}

#[tauri::command]
fn connector_status(
    state: State<AppState>,
    connector_id: String,
) -> Result<keepsake_desktop_core::ConnectorView, String> {
    with_vault(&state, |vault, kek| {
        let memories = recent_memories(vault, kek, 5000)?;
        keepsake_desktop_core::connector_views(&memories)
            .into_iter()
            .find(|c| c.id == connector_id)
            .ok_or_else(|| format!("unknown connector: {connector_id}"))
    })
}

#[tauri::command]
fn connector_preview(connector_id: String) -> Result<ImportPreview, String> {
    Ok(preview_of(read_connector_items(&connector_id)?))
}

#[tauri::command]
fn connector_sync_now(
    state: State<AppState>,
    connector_id: String,
) -> Result<ConnectorActionResult, String> {
    let items = read_connector_items(&connector_id)?;
    with_vault(&state, |vault, kek| {
        let result = commit_import_items(vault, kek, &items);
        Ok(ConnectorActionResult {
            connector_id,
            message: "local sync complete".to_string(),
            added: result.added,
            skipped: result.skipped,
            merged: result.merged,
            total: result.total,
        })
    })
}

#[tauri::command]
fn connector_disconnect(
    state: State<AppState>,
    connector_id: String,
) -> Result<ConnectorActionResult, String> {
    let spec = keepsake_import::connector_by_id(&connector_id)
        .ok_or_else(|| format!("unknown connector: {connector_id}"))?;
    let source_tag = spec
        .source_tag
        .ok_or_else(|| format!("{} has no stored documents to disconnect", spec.title))?;
    with_vault(&state, |vault, kek| {
        let memories = recent_memories(vault, kek, 5000)?;
        let mut removed = 0usize;
        for memory in memories {
            if keepsake_desktop_core::source_matches(Some(source_tag), memory.source.as_deref()) {
                let bytes =
                    hex::decode(&memory.id).map_err(|_| "invalid cell id (not hex)".to_string())?;
                let arr: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "cell id must be 32 bytes".to_string())?;
                vault
                    .forget(&CellId::from_bytes(arr))
                    .map_err(|e| format!("{e:?}"))?;
                removed += 1;
            }
        }
        Ok(ConnectorActionResult {
            connector_id,
            message: "source disconnected locally".to_string(),
            added: 0,
            skipped: 0,
            merged: 0,
            total: removed,
        })
    })
}

#[tauri::command]
fn documents_list(
    state: State<AppState>,
    source: Option<String>,
    limit: Option<usize>,
) -> Result<Vec<DocumentRow>, String> {
    with_vault(&state, |vault, kek| {
        let memories = recent_memories(vault, kek, limit.unwrap_or(200).min(5000))?;
        Ok(keepsake_desktop_core::document_rows(
            &memories,
            source.as_deref(),
        ))
    })
}

#[tauri::command]
fn document_retry(state: State<AppState>, source: String) -> Result<ConnectorActionResult, String> {
    let connector_id = keepsake_import::connector_catalog()
        .into_iter()
        .find(|c| c.source_tag == Some(source.as_str()))
        .map(|c| c.id.to_string())
        .ok_or_else(|| format!("no connector for source: {source}"))?;
    connector_sync_now(state, connector_id)
}

#[tauri::command]
fn document_delete(state: State<AppState>, id: String) -> Result<(), String> {
    forget(state, id)
}

#[tauri::command]
fn documents_delete_source(
    state: State<AppState>,
    source: String,
) -> Result<ConnectorActionResult, String> {
    let connector_id = keepsake_import::connector_catalog()
        .into_iter()
        .find(|c| c.source_tag == Some(source.as_str()))
        .map(|c| c.id.to_string())
        .unwrap_or_else(|| source.clone());
    connector_disconnect(state, connector_id)
}

#[derive(serde::Serialize)]
struct ProfileDto {
    text: Option<String>,
    memory_count: usize,
    sources: Vec<(String, usize)>,
}

#[tauri::command]
fn profile_get(state: State<AppState>) -> Result<ProfileDto, String> {
    with_vault(&state, |vault, kek| {
        let memories = recent_memories(vault, kek, 5000)?;
        Ok(ProfileDto {
            text: vault.profile().map_err(|e| format!("{e:?}"))?,
            memory_count: vault.count().map_err(|e| format!("{e:?}"))?,
            sources: source_breakdown(&memories),
        })
    })
}

#[tauri::command]
fn profile_redistill(state: State<AppState>) -> Result<ProfileDto, String> {
    with_vault(&state, |vault, kek| {
        let memories = recent_memories(vault, kek, 5000)?;
        let text = local_profile_summary(&memories);
        vault.set_profile(&text).map_err(|e| format!("{e:?}"))?;
        Ok(ProfileDto {
            text: Some(text),
            memory_count: vault.count().map_err(|e| format!("{e:?}"))?,
            sources: source_breakdown(&memories),
        })
    })
}

#[tauri::command]
fn profile_clear(state: State<AppState>) -> Result<(), String> {
    with_vault(&state, |vault, _kek| {
        vault.clear_profile().map_err(|e| format!("{e:?}"))
    })
}

#[tauri::command]
fn mcp_setup_text(client: String) -> String {
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
3. In a project you want agents to remember, wire instructions and MCP config:\n\
   keepsake connect --dir .\n\n\
Your 24 words are never copied into the client. The client gets a limited local pass."
    )
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
    let mut vault = session
        .vault
        .lock()
        .map_err(|_| "vault poisoned".to_string())?;
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

/// Core unlock shared by the 24-word `unlock` command and the PIN-based `quick_unlock`: derive
/// keys from the mnemonic, open the vault, host the hub, start sync, and store the live Session.
fn unlock_with_mnemonic(
    app: &tauri::AppHandle,
    state: &State<AppState>,
    mnemonic: &str,
) -> Result<VaultStatus, String> {
    let roots = RootKeys::from_mnemonic(mnemonic.trim(), "")
        .map_err(|_| "invalid seed phrase".to_string())?;
    let kek = Kek::from_root(&roots.encryption_root);
    let store =
        SqliteVault::open(&vault_db_path(), &roots.db_key()).map_err(|e| format!("{e:?}"))?;
    let embedder = load_embedder(app)?;
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
fn unlock(
    app: tauri::AppHandle,
    state: State<AppState>,
    mnemonic: String,
) -> Result<VaultStatus, String> {
    unlock_with_mnemonic(&app, &state, &mnemonic)
}

/// Minimum PIN length. A short PIN is low-entropy; the Argon2id cost is what actually resists an
/// offline guess, but we still refuse trivially short PINs and offer a passphrase in the UI.
const QU_MIN_PIN: usize = 6;

/// True if quick-unlock is set up on this device (the sidecar exists). Drives the unlock-screen
/// PIN panel — checked separately from `vault_exists`, and reachable before the 24 words.
#[tauri::command]
fn quick_unlock_available() -> bool {
    keepsake_desktop_core::quickunlock::quickunlock_enabled(&keepsake_dir())
}

/// Turn quick-unlock on: wrap the live session's 24 words under `pin` and write the 0600 sidecar.
/// Requires an unlocked vault (we need the mnemonic to wrap).
#[tauri::command]
fn quick_unlock_enable(state: State<AppState>, pin: String) -> Result<(), String> {
    let pin = zeroize::Zeroizing::new(pin);
    if pin.chars().count() < QU_MIN_PIN {
        return Err(format!("Use at least {QU_MIN_PIN} characters."));
    }
    let guard = state.0.lock().unwrap();
    let session = guard.as_ref().ok_or_else(|| "vault locked".to_string())?;
    let wrapped = keepsake_crypto::quickunlock::wrap_mnemonic(&pin, &session.mnemonic);
    let file = keepsake_desktop_core::quickunlock::QuickUnlockFile::new(wrapped);
    file.save(&keepsake_desktop_core::quickunlock::quickunlock_path(
        &keepsake_dir(),
    ))
    .map_err(|e| format!("could not turn on quick unlock: {e}"))
}

/// Open the vault with the quick-unlock PIN. Wrong PINs are counted; after the cap the sidecar is
/// shredded and the user must use their 24 words again.
#[tauri::command]
fn quick_unlock(
    app: tauri::AppHandle,
    state: State<AppState>,
    pin: String,
) -> Result<VaultStatus, String> {
    let pin = zeroize::Zeroizing::new(pin);
    let path = keepsake_desktop_core::quickunlock::quickunlock_path(&keepsake_dir());
    let file = keepsake_desktop_core::quickunlock::load_quickunlock(&path)
        .ok_or_else(|| "quick unlock is not set up".to_string())?;
    match keepsake_crypto::quickunlock::unwrap_mnemonic(&pin, &file.wrapped) {
        Ok(mnemonic) => {
            let _ = keepsake_desktop_core::quickunlock::quickunlock_register_success(&path);
            unlock_with_mnemonic(&app, &state, &mnemonic)
        }
        Err(_) => {
            let remaining = keepsake_desktop_core::quickunlock::quickunlock_register_failure(&path)
                .unwrap_or(0);
            if remaining == 0 {
                Err("Too many wrong tries — please use your 24 words.".to_string())
            } else if remaining == 1 {
                Err("Wrong PIN. 1 try left before you'll need your 24 words.".to_string())
            } else {
                Err(format!("Wrong PIN. {remaining} tries left."))
            }
        }
    }
}

/// Turn quick-unlock off: shred the sidecar so no key is stored on the device again.
#[tauri::command]
fn quick_unlock_disable() -> Result<(), String> {
    keepsake_desktop_core::quickunlock::shred_quickunlock(
        &keepsake_desktop_core::quickunlock::quickunlock_path(&keepsake_dir()),
    )
    .map_err(|e| format!("could not turn off quick unlock: {e}"))
}

/// Change the quick-unlock PIN: verify the old one, re-wrap under a fresh salt with the new one.
#[tauri::command]
fn quick_unlock_change_pin(
    state: State<AppState>,
    current: String,
    fresh: String,
) -> Result<(), String> {
    {
        let guard = state.0.lock().unwrap();
        guard.as_ref().ok_or_else(|| "vault locked".to_string())?;
    }
    let current = zeroize::Zeroizing::new(current);
    let fresh = zeroize::Zeroizing::new(fresh);
    if fresh.chars().count() < QU_MIN_PIN {
        return Err(format!("Use at least {QU_MIN_PIN} characters."));
    }
    let path = keepsake_desktop_core::quickunlock::quickunlock_path(&keepsake_dir());
    let file = keepsake_desktop_core::quickunlock::load_quickunlock(&path)
        .ok_or_else(|| "quick unlock is not set up".to_string())?;
    let mnemonic = keepsake_crypto::quickunlock::unwrap_mnemonic(&current, &file.wrapped)
        .map_err(|_| "wrong current PIN".to_string())?;
    let wrapped = keepsake_crypto::quickunlock::wrap_mnemonic(&fresh, &mnemonic);
    let mut nf = keepsake_desktop_core::quickunlock::QuickUnlockFile::new(wrapped);
    nf.touchid = file.touchid;
    nf.save(&path)
        .map_err(|e| format!("could not change your PIN: {e}"))
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
fn recall_with_mode(
    state: State<AppState>,
    query: String,
    k: usize,
    mode: String,
) -> Result<Vec<MemoryHit>, String> {
    with_vault(&state, |vault, kek| {
        Ok(vault
            .recall_with_profile(
                kek,
                &query,
                k,
                now_unix(),
                keepsake_vault::RecallProfile::parse(&mode),
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
    with_vault(&state, |vault, kek| recent_memories(vault, kek, limit))
}

fn recent_memories(
    vault: &mut MemoryVault<FastEmbedder>,
    kek: &Kek,
    limit: usize,
) -> Result<Vec<RecentMemory>, String> {
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
}

fn source_breakdown(memories: &[RecentMemory]) -> Vec<(String, usize)> {
    let mut counts = std::collections::BTreeMap::new();
    for memory in memories {
        *counts
            .entry(keepsake_import::source_label(memory.source.as_deref()))
            .or_insert(0usize) += 1;
    }
    counts.into_iter().collect()
}

fn local_profile_summary(memories: &[RecentMemory]) -> String {
    let mut out = String::from("# Keepsake profile\n\n");
    out.push_str(&format!("- Memories sampled: {}\n", memories.len()));
    let sources = source_breakdown(memories);
    if !sources.is_empty() {
        out.push_str("- Sources: ");
        out.push_str(
            &sources
                .iter()
                .map(|(source, count)| format!("{source} ({count})"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push('\n');
    }
    let recent_titles: Vec<String> = memories
        .iter()
        .take(5)
        .filter_map(|m| {
            m.text
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .map(str::to_string)
        })
        .collect();
    if !recent_titles.is_empty() {
        out.push_str("- Recent themes:\n");
        for title in recent_titles {
            out.push_str("  - ");
            out.push_str(&title);
            out.push('\n');
        }
    }
    out.push_str("\nThis profile was built locally from recent memories.");
    out
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
        .plugin(tauri_plugin_dialog::init())
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
            recall_with_mode,
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
            backup_status,
            import_preview,
            import_path,
            import_paste,
            import_commit,
            memory_graph,
            connector_catalog,
            connector_status,
            connector_preview,
            connector_sync_now,
            connector_disconnect,
            documents_list,
            document_retry,
            document_delete,
            documents_delete_source,
            profile_get,
            profile_redistill,
            profile_clear,
            mcp_setup_text,
            quick_unlock_available,
            quick_unlock_enable,
            quick_unlock,
            quick_unlock_disable,
            quick_unlock_change_pin
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
