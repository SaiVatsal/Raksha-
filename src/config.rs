//! Configuration and Runtime State Management for Raksha.
//! Manages ON/OFF shield state, user exclusions, and paths.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const STATE_FILE_NAME: &str = "raksha_state.cfg";
pub const DEFAULT_QUARANTINE_SUBDIR: &str = "raksha_quarantine";
pub const DEFAULT_CACHE_SUBDIR: &str = "raksha_cache";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RakshaConfig {
    pub enabled: bool,
    pub exclusions: Vec<String>,
    pub quarantine_dir: String,
    pub last_updated_secs: u64,
}

impl Default for RakshaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            exclusions: vec![
                r"C:\Windows".to_string(),
                r"C:\Program Files\Windows Defender".to_string(),
            ],
            quarantine_dir: DEFAULT_QUARANTINE_SUBDIR.to_string(),
            last_updated_secs: current_unix_timestamp(),
        }
    }
}

/// Resolves the base runtime directory for Raksha.
/// Priority:
/// 1. RAKSHA_HOME environment variable
/// 2. %LOCALAPPDATA%\Raksha on Windows
/// 3. Current working directory ./raksha_data fallback
pub fn get_base_dir() -> PathBuf {
    if let Ok(val) = std::env::var("RAKSHA_HOME") {
        let p = PathBuf::from(val);
        let _ = fs::create_dir_all(&p);
        return p;
    }

    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let p = PathBuf::from(local_app_data).join("Raksha");
        let _ = fs::create_dir_all(&p);
        return p;
    }

    let p = PathBuf::from("raksha_data");
    let _ = fs::create_dir_all(&p);
    p
}

/// Loads configuration from `<base_path>/raksha_state.cfg`.
/// If the file does not exist, writes the default configuration and returns it.
pub fn load_config(base_path: &Path) -> RakshaConfig {
    let cfg_path = base_path.join(STATE_FILE_NAME);
    if cfg_path.exists() {
        if let Ok(content) = fs::read_to_string(&cfg_path) {
            if let Ok(config) = serde_json::from_str::<RakshaConfig>(&content) {
                return config;
            }
        }
    }

    let default_cfg = RakshaConfig::default();
    let _ = save_config(base_path, &default_cfg);
    default_cfg
}

/// Atomically persists configuration to `<base_path>/raksha_state.cfg`.
pub fn save_config(base_path: &Path, config: &RakshaConfig) -> std::io::Result<()> {
    fs::create_dir_all(base_path)?;
    let cfg_path = base_path.join(STATE_FILE_NAME);
    let tmp_path = base_path.join(format!("{}.tmp", STATE_FILE_NAME));

    let json = serde_json::to_string_pretty(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    fs::write(&tmp_path, json.as_bytes())?;
    fs::rename(&tmp_path, &cfg_path)?;
    Ok(())
}

/// Sets real-time shield state (ON / OFF) in `<base_path>/raksha_state.cfg`.
pub fn set_protection_state(base_path: &Path, enabled: bool) -> std::io::Result<RakshaConfig> {
    let mut cfg = load_config(base_path);
    cfg.enabled = enabled;
    cfg.last_updated_secs = current_unix_timestamp();
    save_config(base_path, &cfg)?;
    Ok(cfg)
}

/// Appends a path to the exclusion list and persists the configuration.
pub fn add_exclusion(base_path: &Path, path_to_exclude: &str) -> std::io::Result<RakshaConfig> {
    let mut cfg = load_config(base_path);
    let normalized = path_to_exclude.trim().to_string();
    if !cfg
        .exclusions
        .iter()
        .any(|e| e.eq_ignore_ascii_case(&normalized))
    {
        cfg.exclusions.push(normalized);
        cfg.last_updated_secs = current_unix_timestamp();
        save_config(base_path, &cfg)?;
    }
    Ok(cfg)
}

/// Checks whether a given target path is excluded from scanning or quarantine.
/// Excludes:
/// - Windows OS core directories (C:\Windows)
/// - Raksha's own base directory, state, logs, and quarantine vault
/// - User configured exclusion list (case-insensitive substring/prefix)
pub fn is_path_excluded(target: &Path, config: &RakshaConfig, base_path: &Path) -> bool {
    let target_str = target.to_string_lossy();
    let target_lower = target_str.to_lowercase();

    // 1. Never scan C:\Windows or C:\Windows\*
    if target_lower.starts_with(r"c:\windows") || target_lower.starts_with("c:/windows") {
        return true;
    }

    // 2. Never scan Raksha's own base directory or vault
    let base_lower = base_path.to_string_lossy().to_lowercase();
    if !base_lower.is_empty() && target_lower.starts_with(&base_lower) {
        return true;
    }

    // 3. Never scan vault subdir by name
    if target_lower.contains(&config.quarantine_dir.to_lowercase()) {
        return true;
    }

    // 4. User-configured exclusions
    for exclusion in &config.exclusions {
        let ex_lower = exclusion.to_lowercase();
        if !ex_lower.is_empty() && target_lower.starts_with(&ex_lower) {
            return true;
        }
    }

    false
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_lifecycle() {
        let dir = tempdir().unwrap();
        let base = dir.path();

        let initial = load_config(base);
        assert!(initial.enabled);

        let toggled = set_protection_state(base, false).unwrap();
        assert!(!toggled.enabled);

        let reloaded = load_config(base);
        assert!(!reloaded.enabled);

        let with_ex = add_exclusion(base, "D:\\SafeTools").unwrap();
        assert!(with_ex.exclusions.contains(&"D:\\SafeTools".to_string()));

        // Path exclusion checks
        assert!(is_path_excluded(
            Path::new(r"C:\Windows\System32\cmd.exe"),
            &with_ex,
            base
        ));
        assert!(is_path_excluded(
            Path::new(r"D:\SafeTools\utility.exe"),
            &with_ex,
            base
        ));
        assert!(is_path_excluded(&base.join("anything"), &with_ex, base));
        assert!(!is_path_excluded(
            Path::new(r"C:\Users\Downloads\unknown.exe"),
            &with_ex,
            base
        ));
    }
}
