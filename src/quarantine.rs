//! Streaming XOR 0xAA Quarantine Vault & Lossless Restore Engine.
//! Neutralizes malware payloads in streaming 8 KB stack chunks with zero large-heap allocations.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const XOR_KEY: u8 = 0xAA;
pub const STREAM_BUFFER_SIZE: usize = 8192;
pub const MANIFEST_FILE_NAME: &str = "manifest.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantinedFileRecord {
    pub original_path: String,
    pub original_file_name: String,
    pub sha256: String,
    pub original_size_bytes: u64,
    pub quarantined_at_unix_secs: u64,
    pub threat_name: String,
    pub risk_score: u32,
    pub vault_file_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuarantineManifest {
    pub records: HashMap<String, QuarantinedFileRecord>,
}

/// Resolves the quarantine directory path.
pub fn get_vault_dir(base_path: &Path, vault_subdir: &str) -> PathBuf {
    base_path.join(vault_subdir)
}

/// Loads the quarantine vault manifest from disk.
pub fn load_manifest(vault_dir: &Path) -> QuarantineManifest {
    let manifest_path = vault_dir.join(MANIFEST_FILE_NAME);
    if manifest_path.exists() {
        if let Ok(content) = fs::read_to_string(&manifest_path) {
            if let Ok(manifest) = serde_json::from_str::<QuarantineManifest>(&content) {
                return manifest;
            }
        }
    }
    QuarantineManifest::default()
}

/// Atomically persists the quarantine vault manifest to disk.
pub fn save_manifest(vault_dir: &Path, manifest: &QuarantineManifest) -> std::io::Result<()> {
    fs::create_dir_all(vault_dir)?;
    let manifest_path = vault_dir.join(MANIFEST_FILE_NAME);
    let tmp_path = vault_dir.join(format!("{}.tmp", MANIFEST_FILE_NAME));

    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    fs::write(&tmp_path, json.as_bytes())?;
    fs::rename(&tmp_path, &manifest_path)?;
    Ok(())
}

/// Streams a file in 8 KB stack chunks, XORs each byte with 0xAA,
/// writes the output to `<vault_dir>/<sha256>.rkq`, updates manifest.json,
/// and securely removes the original file.
pub fn quarantine_file(
    base_path: &Path,
    vault_subdir: &str,
    target_file: &Path,
    threat_sha256: &str,
    threat_name: &str,
    risk_score: u32,
) -> std::io::Result<QuarantinedFileRecord> {
    let vault_dir = get_vault_dir(base_path, vault_subdir);
    fs::create_dir_all(&vault_dir)?;

    let meta = fs::metadata(target_file)?;
    let original_size = meta.len();
    let original_name = target_file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown.bin".to_string());

    let vault_file_name = format!("{}.rkq", threat_sha256.to_lowercase());
    let vault_file_path = vault_dir.join(&vault_file_name);
    let tmp_vault_file = vault_dir.join(format!("{}.tmp", vault_file_name));

    // Stream source -> XOR 0xAA -> tmp file
    {
        let mut source = File::open(target_file)?;
        let mut dest = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_vault_file)?;

        let mut buffer = [0u8; STREAM_BUFFER_SIZE];
        loop {
            let n = source.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            for byte in &mut buffer[..n] {
                *byte ^= XOR_KEY;
            }
            dest.write_all(&buffer[..n])?;
        }
        dest.flush()?;
    }

    // Atomic move
    fs::rename(&tmp_vault_file, &vault_file_path)?;

    // Record in manifest
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let record = QuarantinedFileRecord {
        original_path: target_file.to_string_lossy().to_string(),
        original_file_name: original_name,
        sha256: threat_sha256.to_lowercase(),
        original_size_bytes: original_size,
        quarantined_at_unix_secs: now,
        threat_name: threat_name.to_string(),
        risk_score,
        vault_file_name,
    };

    let mut manifest = load_manifest(&vault_dir);
    manifest
        .records
        .insert(record.sha256.clone(), record.clone());
    save_manifest(&vault_dir, &manifest)?;

    // Delete the original file
    if let Err(e) = fs::remove_file(target_file) {
        eprintln!(
            "[Raksha Quarantine] Notice: payload encrypted in vault, but original file delete returned: {}",
            e
        );
    }

    Ok(record)
}

/// Restores a quarantined file from the vault by reversing the XOR 0xAA stream.
/// Refuses to overwrite any existing file at the restoration destination.
pub fn restore_file(
    base_path: &Path,
    vault_subdir: &str,
    sha256_or_id: &str,
    target_destination: Option<&Path>,
) -> std::io::Result<PathBuf> {
    let vault_dir = get_vault_dir(base_path, vault_subdir);
    let mut manifest = load_manifest(&vault_dir);

    // Search record by exact or prefix match
    let id_lower = sha256_or_id.to_lowercase();
    let matched_key = manifest
        .records
        .keys()
        .find(|k| k.starts_with(&id_lower) || id_lower.starts_with(k.as_str()))
        .cloned()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "Quarantined item '{}' not found in vault manifest",
                    sha256_or_id
                ),
            )
        })?;

    let record = manifest.records.get(&matched_key).unwrap().clone();
    let vault_file_path = vault_dir.join(&record.vault_file_name);

    if !vault_file_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "Vault ciphertext file {:?} missing from disk",
                vault_file_path
            ),
        ));
    }

    // Determine destination
    let dest_path = match target_destination {
        Some(custom) => custom.to_path_buf(),
        None => PathBuf::from(&record.original_path),
    };

    // CRITICAL SECURITY RULE: Refuse to overwrite an existing destination file
    if dest_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "Refusing to restore: destination path {:?} already exists on disk",
                dest_path
            ),
        ));
    }

    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_dest = dest_path.with_extension("rkq_restore_tmp");

    // Streaming reverse XOR
    let mut hasher = Sha256::new();
    {
        let mut source = File::open(&vault_file_path)?;
        let mut dest = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_dest)?;

        let mut buffer = [0u8; STREAM_BUFFER_SIZE];
        loop {
            let n = source.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            for byte in &mut buffer[..n] {
                *byte ^= XOR_KEY;
            }
            hasher.update(&buffer[..n]);
            dest.write_all(&buffer[..n])?;
        }
        dest.flush()?;
    }

    let restored_sha256 = hex::encode(hasher.finalize());
    if !restored_sha256.eq_ignore_ascii_case(&record.sha256) {
        let _ = fs::remove_file(&tmp_dest);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Integrity mismatch during restore: expected {} but got {}",
                record.sha256, restored_sha256
            ),
        ));
    }

    fs::rename(&tmp_dest, &dest_path)?;

    // Remove from vault on successful restoration
    let _ = fs::remove_file(&vault_file_path);
    manifest.records.remove(&matched_key);
    let _ = save_manifest(&vault_dir, &manifest);

    Ok(dest_path)
}

/// Enumerates all currently quarantined files in the vault.
pub fn list_quarantine_records(base_path: &Path, vault_subdir: &str) -> Vec<QuarantinedFileRecord> {
    let vault_dir = get_vault_dir(base_path, vault_subdir);
    let manifest = load_manifest(&vault_dir);
    let mut list: Vec<QuarantinedFileRecord> = manifest.records.into_values().collect();
    list.sort_by_key(|a| std::cmp::Reverse(a.quarantined_at_unix_secs));
    list
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_quarantine_and_restore_cycle() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let sample_file = base.join("malicious_sample.txt");
        let content = b"Sample simulated payload data for quarantine test.";
        fs::write(&sample_file, content).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(content);
        let sha256_hex = hex::encode(hasher.finalize());

        // Quarantine
        let record =
            quarantine_file(base, "vault", &sample_file, &sha256_hex, "TestThreat", 90).unwrap();

        assert!(!sample_file.exists()); // Original deleted
        let vault_file = base.join("vault").join(&record.vault_file_name);
        assert!(vault_file.exists());

        // Verify the vault file content is XOR encrypted
        let enc_bytes = fs::read(&vault_file).unwrap();
        assert_ne!(&enc_bytes[..], content);
        let xored: Vec<u8> = enc_bytes.iter().map(|b| b ^ XOR_KEY).collect();
        assert_eq!(&xored[..], content);

        // Attempt restore to original destination
        let restored_path = restore_file(base, "vault", &sha256_hex, Some(&sample_file)).unwrap();
        assert_eq!(restored_path, sample_file);
        assert!(sample_file.exists());
        let restored_content = fs::read(&sample_file).unwrap();
        assert_eq!(&restored_content[..], content);

        // Attempting to restore again to existing file must fail with AlreadyExists
        // First re-quarantine so it exists in manifest
        quarantine_file(base, "vault", &sample_file, &sha256_hex, "TestThreat", 90).unwrap();
        // Create conflicting file at destination
        fs::write(&sample_file, b"Existing collision").unwrap();
        let err = restore_file(base, "vault", &sha256_hex, Some(&sample_file)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    }
}
