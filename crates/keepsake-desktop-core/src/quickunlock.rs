//! On-disk persistence for quick-unlock: the PIN-wrapped mnemonic sidecar
//! (`~/.keepsake/quickunlock.json`, owner-only 0600) plus the failed-attempt lockout.
//!
//! The crypto lives in [`keepsake_crypto::quickunlock`]; this layer only stores the wrapped
//! bytes + a failure counter, and shreds the file after too many wrong PINs so the user falls
//! back to their 24 words (the master backup — zero data loss). Strictly local: never synced,
//! never exported, never a Memory Receipt.

use keepsake_crypto::quickunlock::WrappedSeed;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// After this many consecutive wrong PINs the sidecar is shredded and the 24 words are required.
pub const DEFAULT_MAX_TRIES: u32 = 10;

/// The quick-unlock sidecar: the wrapped mnemonic + a failure counter + whether Touch ID was
/// opted on (Touch ID only gates the same PIN decrypt; the bytes are identical either way).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QuickUnlockFile {
    pub wrapped: WrappedSeed,
    pub try_count: u32,
    pub max_tries: u32,
    pub touchid: bool,
}

impl QuickUnlockFile {
    pub fn new(wrapped: WrappedSeed) -> Self {
        Self { wrapped, try_count: 0, max_tries: DEFAULT_MAX_TRIES, touchid: false }
    }

    /// Persist as JSON with owner-only (0600) permissions.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        write_owner_only(path, &data)
    }
}

/// The sidecar path next to the vault.
pub fn quickunlock_path(dir: &Path) -> PathBuf {
    dir.join("quickunlock.json")
}

/// True if quick-unlock is set up (the sidecar exists). Drives the return-screen panel.
pub fn quickunlock_enabled(dir: &Path) -> bool {
    quickunlock_path(dir).exists()
}

/// Load the sidecar, or `None` if absent/corrupt.
pub fn load_quickunlock(path: &Path) -> Option<QuickUnlockFile> {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok())
}

/// Overwrite-then-remove so the wrapped mnemonic does not linger in freed pages.
pub fn shred_quickunlock(path: &Path) -> std::io::Result<()> {
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = write_owner_only(path, &vec![0u8; meta.len() as usize]);
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Record a failed PIN attempt. Once `max_tries` consecutive failures are reached the sidecar is
/// shredded (forcing a fallback to the 24 words). Returns remaining tries — `0` means just shredded.
pub fn quickunlock_register_failure(path: &Path) -> std::io::Result<u32> {
    let Some(mut f) = load_quickunlock(path) else {
        return Ok(0);
    };
    f.try_count = f.try_count.saturating_add(1);
    if f.try_count >= f.max_tries {
        shred_quickunlock(path)?;
        return Ok(0);
    }
    let remaining = f.max_tries - f.try_count;
    f.save(path)?;
    Ok(remaining)
}

/// Record a successful unlock: reset the failure counter to zero.
pub fn quickunlock_register_success(path: &Path) -> std::io::Result<()> {
    if let Some(mut f) = load_quickunlock(path) {
        if f.try_count != 0 {
            f.try_count = 0;
            f.save(path)?;
        }
    }
    Ok(())
}

/// Write `data` to `path` with owner-only (0600) permissions on Unix so a secret-bearing file
/// cannot be read by other local users. Lifted from the CLI's pairing-seed writer (KS-014).
fn write_owner_only(path: &Path, data: &[u8]) -> std::io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> QuickUnlockFile {
        let w = keepsake_crypto::quickunlock::wrap_mnemonic("734512", "abandon art");
        QuickUnlockFile::new(w)
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ks-qu-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = quickunlock_path(&dir);
        let f = sample();
        f.save(&path).unwrap();
        assert!(quickunlock_enabled(&dir));
        let back = load_quickunlock(&path).unwrap();
        assert_eq!(back.max_tries, DEFAULT_MAX_TRIES);
        assert_eq!(back.try_count, 0);
        assert_eq!(back.wrapped.ct, f.wrapped.ct);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ks-qu-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = quickunlock_path(&dir);
        sample().save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "sidecar must be owner-only");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lockout_shreds_after_max_tries() {
        let dir = std::env::temp_dir().join(format!("ks-qu-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = quickunlock_path(&dir);
        let mut f = sample();
        f.max_tries = 3;
        f.save(&path).unwrap();

        assert_eq!(quickunlock_register_failure(&path).unwrap(), 2);
        assert_eq!(quickunlock_register_failure(&path).unwrap(), 1);
        assert_eq!(quickunlock_register_failure(&path).unwrap(), 0, "3rd failure shreds");
        assert!(!quickunlock_enabled(&dir), "sidecar gone after max tries");
        assert!(load_quickunlock(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn success_resets_counter() {
        let dir = std::env::temp_dir().join(format!("ks-qu-reset-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = quickunlock_path(&dir);
        let mut f = sample();
        f.try_count = 2;
        f.save(&path).unwrap();

        quickunlock_register_success(&path).unwrap();
        assert_eq!(load_quickunlock(&path).unwrap().try_count, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
