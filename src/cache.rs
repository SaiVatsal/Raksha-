//! Zero-CPU Smart Modification Cache for Raksha.
//! Tracks (file_size_bytes, last_modified_unix_secs) per path to skip unmodified clean files in O(1) time.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CACHE_FILE_NAME: &str = "raksha_mod_cache.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    pub file_size_bytes: u64,
    pub last_modified_unix_secs: u64,
    pub clean: bool,
    pub risk_score: u32,
    pub verified_at_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModificationCache {
    pub rules_version_hash: String,
    pub entries: HashMap<String, CacheEntry>,
    #[serde(skip)]
    pub dirty: bool,
    #[serde(skip)]
    pub cache_file_path: PathBuf,
}

impl ModificationCache {
    /// Loads the cache from `<base_path>/raksha_mod_cache.json`.
    /// If the rules version hash changed, the existing entries are invalidated.
    pub fn open_or_create(base_path: &Path, rules_version_hash: &str) -> Self {
        let cache_file_path = base_path.join(CACHE_FILE_NAME);

        if cache_file_path.exists() {
            if let Ok(content) = fs::read_to_string(&cache_file_path) {
                if let Ok(mut loaded) = serde_json::from_str::<ModificationCache>(&content) {
                    loaded.cache_file_path = cache_file_path.clone();
                    loaded.dirty = false;
                    if loaded.rules_version_hash == rules_version_hash {
                        return loaded;
                    } else {
                        // Rules changed: reset cache entries under new rules version
                        return Self {
                            rules_version_hash: rules_version_hash.to_string(),
                            entries: HashMap::new(),
                            dirty: true,
                            cache_file_path,
                        };
                    }
                }
            }
        }

        Self {
            rules_version_hash: rules_version_hash.to_string(),
            entries: HashMap::new(),
            dirty: false,
            cache_file_path,
        }
    }

    /// Fast O(1) check: Returns Some(clean_flag) if file size and mtime match precisely.
    /// Does not open or hash the file on a cache hit.
    pub fn check_clean(&self, file_path: &Path, size: u64, mtime: u64) -> Option<bool> {
        let key = normalize_path_key(file_path);
        if let Some(entry) = self.entries.get(&key) {
            if entry.file_size_bytes == size && entry.last_modified_unix_secs == mtime {
                return Some(entry.clean);
            }
        }
        None
    }

    /// Records or updates a scan verdict in the cache.
    pub fn record(
        &mut self,
        file_path: &Path,
        size: u64,
        mtime: u64,
        clean: bool,
        risk_score: u32,
    ) {
        let key = normalize_path_key(file_path);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = CacheEntry {
            file_size_bytes: size,
            last_modified_unix_secs: mtime,
            clean,
            risk_score,
            verified_at_unix_secs: now,
        };

        self.entries.insert(key, entry);
        self.dirty = true;
    }

    /// Persists changes to disk if dirty.
    pub fn flush(&mut self) -> std::io::Result<()> {
        if !self.dirty {
            return Ok(());
        }

        if let Some(parent) = self.cache_file_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let tmp = self.cache_file_path.with_extension("tmp");
        let serialized = serde_json::to_string(&self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        fs::write(&tmp, serialized.as_bytes())?;
        fs::rename(&tmp, &self.cache_file_path)?;
        self.dirty = false;
        Ok(())
    }
}

/// Helper to extract (file_size, mtime_unix_secs) from filesystem metadata.
pub fn get_file_mtime_and_size(path: &Path) -> std::io::Result<(u64, u64)> {
    let meta = fs::metadata(path)?;
    let size = meta.len();
    let mtime = meta
        .modified()?
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Ok((size, mtime))
}

fn normalize_path_key(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cache_hit_and_invalidation() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let test_file = base.join("clean_tool.exe");
        fs::write(&test_file, b"sample safe binary payload").unwrap();

        let (size, mtime) = get_file_mtime_and_size(&test_file).unwrap();

        let mut cache = ModificationCache::open_or_create(base, "v1.0.0");
        assert_eq!(cache.check_clean(&test_file, size, mtime), None);

        cache.record(&test_file, size, mtime, true, 0);
        assert_eq!(cache.check_clean(&test_file, size, mtime), Some(true));

        cache.flush().unwrap();

        // Reload
        let reloaded = ModificationCache::open_or_create(base, "v1.0.0");
        assert_eq!(reloaded.check_clean(&test_file, size, mtime), Some(true));

        // Invalidate by rule version change
        let invalidated = ModificationCache::open_or_create(base, "v2.0.0");
        assert_eq!(invalidated.check_clean(&test_file, size, mtime), None);
    }
}
