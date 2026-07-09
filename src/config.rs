//! Persistent identity: a single 32-byte seed on disk.

use crate::identity::Identity;
use std::path::PathBuf;

pub fn seed_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("meshguard")
        .join("seed")
}

/// Load the node identity, creating and persisting a new one on first run.
pub fn load_or_create_identity() -> anyhow::Result<Identity> {
    let path = seed_path();
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() >= 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes[..32]);
            return Ok(Identity::from_seed(seed));
        }
    }
    let id = Identity::generate();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, id.seed())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(id)
}
