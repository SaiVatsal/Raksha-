//! Comprehensive Integration Test Suite for Raksha Anti-Malware Engine.
//! Tests signature engines, PE heuristics, XOR quarantine vault,
//! smart modification cache, configuration state, and tray icon generation.

use base64::Engine;
use raksha::cache::{get_file_mtime_and_size, ModificationCache};
use raksha::config::{add_exclusion, is_path_excluded, load_config, set_protection_state};
use raksha::ghidra_bridge::import_ghidra_triage;
use raksha::icons::generate_shield_icon_rgba;
use raksha::pe_xray::{audit_pe_bytes, create_synthetic_rwx_pe};
use raksha::quarantine::{quarantine_file, restore_file, XOR_KEY};
use raksha::signatures::{compute_file_sha256, SignatureEngine};
use sha2::{Digest, Sha256};
use std::fs;
use tempfile::tempdir;

/// 1. Verifies EICAR test pattern detection scores >= 100.
///    Constructed dynamically at runtime without literal source string.
#[test]
fn test_eicar_signature_detection() {
    // Reconstructed at runtime via base64 decoding
    let b64 = base64::engine::general_purpose::STANDARD;
    let pattern_bytes = b64
        .decode("RUlDQVItU1RBTkRBUkQtQU5USVZJUlVTLVRFU1QtRklMRQ==")
        .expect("Valid base64");

    // Construct mock payload in memory
    let mut file_data = Vec::new();
    file_data.extend_from_slice(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$");
    file_data.extend_from_slice(&pattern_bytes);
    file_data.extend_from_slice(b"!$H+H*\r\n");

    let engine = SignatureEngine::load_or_default(None);
    // Use in-memory buffer scan to prevent host OS Windows Defender interference (Error 225)
    let (_hash, score, hits) = engine.scan_bytes(&file_data).unwrap();

    assert!(
        score >= 100,
        "Expected EICAR score >= 100, obtained score: {}",
        score
    );
    assert!(
        hits.iter().any(|h| h.rule_name.contains("EICAR")),
        "Expected EICAR rule hit in detections list"
    );
}

/// 2. Builds a minimal 64-bit PE in memory with an RWX section (0xA0000000)
///    and 1,024 high-entropy bytes (> 7.5); asserts pe_xray flags both RWX and high entropy with score >= 90.
#[test]
fn test_synthetic_pe_rwx_and_high_entropy() {
    let pe_data = create_synthetic_rwx_pe();
    let audit = audit_pe_bytes(&pe_data);

    assert!(audit.is_pe, "Expected valid PE image structure");
    assert!(audit.is_64bit, "Expected 64-bit AMD64 binary architecture");
    assert!(
        audit.risk_score >= 90,
        "Expected combined risk score >= 90 (RWX + high entropy), got: {}",
        audit.risk_score
    );

    let has_rwx = audit.sections.iter().any(|s| s.is_rwx);
    assert!(has_rwx, "PE X-Ray failed to flag the RWX section");

    let has_high_entropy = audit.sections.iter().any(|s| s.entropy > 7.5);
    assert!(
        has_high_entropy,
        "PE X-Ray failed to flag the high-entropy (>7.5) section"
    );
}

/// 3. Asserts ransomware command sequence scores >= 90.
///    Constructed dynamically at runtime without literal source string.
#[test]
fn test_ransomware_command_detection() {
    let dir = tempdir().unwrap();
    let script_file = dir.path().join("ransomware_backup_kill.bat");

    // Build the ransomware shadow copy deletion command at runtime
    let cmd = format!("{} {} {} /all /quiet", "vssadmin", "delete", "shadows");
    fs::write(&script_file, cmd.as_bytes()).unwrap();

    let engine = SignatureEngine::load_or_default(None);
    let (_hash, score, hits) = engine.scan_file(&script_file).unwrap();

    assert!(
        score >= 90,
        "Expected ransomware deletion score >= 90, got: {}",
        score
    );
    assert!(
        hits.iter().any(|h| h.rule_name.contains("vssadmin")),
        "Expected vssadmin rule detection"
    );
}

/// 4. Quarantines a mock threat, verifies .rkq bytes are XOR-encrypted with 0xAA,
///    restores it, and verifies the restored SHA-256 matches 100%.
#[test]
fn test_xor_quarantine_and_lossless_restore() {
    let dir = tempdir().unwrap();
    let base_path = dir.path();
    let payload_file = base_path.join("threat_payload.exe");

    let original_payload = b"MOCK_MALWARE_BYTECODE_STREAM_FOR_QUARANTINE_VERIFICATION_1234567890";
    fs::write(&payload_file, original_payload).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(original_payload);
    let expected_sha256 = hex::encode(hasher.finalize());

    // 1. Execute quarantine
    let record = quarantine_file(
        base_path,
        "raksha_quarantine",
        &payload_file,
        &expected_sha256,
        "SimulatedThreat",
        95,
    )
    .expect("Quarantine operation should succeed");

    // Original file must be gone
    assert!(!payload_file.exists(), "Original file must be removed");

    // Vault ciphertext file must exist
    let vault_file = base_path
        .join("raksha_quarantine")
        .join(&record.vault_file_name);
    assert!(vault_file.exists(), "Vault ciphertext file must exist");

    // Read ciphertext and verify every byte was XORed with 0xAA
    let ciphertext = fs::read(&vault_file).unwrap();
    assert_ne!(
        &ciphertext[..],
        original_payload,
        "Ciphertext must not match plaintext"
    );

    let decrypted: Vec<u8> = ciphertext.iter().map(|b| b ^ XOR_KEY).collect();
    assert_eq!(
        &decrypted[..],
        original_payload,
        "Direct XOR decryption must match original plaintext"
    );

    // 2. Execute lossless restore
    let restored_path = restore_file(
        base_path,
        "raksha_quarantine",
        &expected_sha256,
        Some(&payload_file),
    )
    .expect("Restore operation should succeed");

    assert_eq!(restored_path, payload_file);
    assert!(payload_file.exists(), "Restored file must exist on disk");

    let restored_bytes = fs::read(&payload_file).unwrap();
    assert_eq!(&restored_bytes[..], original_payload);

    let restored_sha256 = compute_file_sha256(&payload_file).unwrap();
    assert_eq!(
        restored_sha256, expected_sha256,
        "Restored SHA-256 must match original 100%"
    );
}

/// 5. Verifies a second scan of an unmodified clean file hits the smart modification cache.
#[test]
fn test_smart_cache_zero_cpu_skip() {
    let dir = tempdir().unwrap();
    let base_path = dir.path();
    let clean_file = base_path.join("clean_document.pdf");
    fs::write(
        &clean_file,
        b"Safe PDF content without any malicious stubs.",
    )
    .unwrap();

    let (size, mtime) = get_file_mtime_and_size(&clean_file).unwrap();
    let mut cache = ModificationCache::open_or_create(base_path, "rules_v1");

    // First lookup: cache miss
    assert_eq!(
        cache.check_clean(&clean_file, size, mtime),
        None,
        "First lookup should be a cache miss"
    );

    // Record verified clean status
    cache.record(&clean_file, size, mtime, true, 0);
    cache.flush().unwrap();

    // Second lookup: cache hit
    assert_eq!(
        cache.check_clean(&clean_file, size, mtime),
        Some(true),
        "Second lookup should hit the cache in O(1) time"
    );

    // Modify file: mtime or size changes -> cache miss
    let (mod_size, mod_mtime) = (size + 10, mtime + 5);
    assert_eq!(
        cache.check_clean(&clean_file, mod_size, mod_mtime),
        None,
        "Modified file must trigger a cache miss"
    );
}

/// 6. Verifies state toggling and path exclusions.
#[test]
fn test_on_off_toggle_and_exclusions() {
    let dir = tempdir().unwrap();
    let base_path = dir.path();

    // Default configuration: enabled = true
    let mut config = load_config(base_path);
    assert!(config.enabled, "Default configuration should be enabled");

    // Toggle OFF
    config = set_protection_state(base_path, false).unwrap();
    assert!(!config.enabled, "Protection should now be disabled");

    // Toggle ON
    config = set_protection_state(base_path, true).unwrap();
    assert!(config.enabled, "Protection should now be re-enabled");

    // Add custom exclusion
    let safe_folder = r"D:\TrustedDevFolder";
    config = add_exclusion(base_path, safe_folder).unwrap();
    assert!(
        config.exclusions.iter().any(|e| e == safe_folder),
        "Exclusion path should be present in configuration"
    );

    // Verify exclusion logic
    assert!(
        is_path_excluded(
            std::path::Path::new(r"D:\TrustedDevFolder\app.exe"),
            &config,
            base_path
        ),
        "Excluded folder subpath must be excluded"
    );
    assert!(
        is_path_excluded(
            std::path::Path::new(r"C:\Windows\System32\kernel32.dll"),
            &config,
            base_path
        ),
        "C:\\Windows must always be excluded"
    );
    assert!(
        !is_path_excluded(
            std::path::Path::new(r"C:\Users\Target\Downloads\unknown.exe"),
            &config,
            base_path
        ),
        "Untrusted download path must not be excluded"
    );
}

/// 7. Verifies the 32x32 RGBA shield generator outputs a valid 4,096-byte buffer.
#[test]
fn test_tray_icon_rgba_generation() {
    let active_icon = generate_shield_icon_rgba(true);
    let inactive_icon = generate_shield_icon_rgba(false);

    // 32 x 32 x 4 bytes = 4,096 bytes
    assert_eq!(active_icon.len(), 4096, "Active icon must be 4,096 bytes");
    assert_eq!(
        inactive_icon.len(),
        4096,
        "Inactive icon must be 4,096 bytes"
    );

    // Active icon must contain Emerald Green (#10B981)
    let has_emerald = active_icon
        .as_chunks::<4>()
        .0
        .iter()
        .any(|px| px[0] == 0x10 && px[1] == 0xB9 && px[2] == 0x81);
    assert!(has_emerald, "Active icon must contain Emerald Green pixels");

    // Inactive icon must contain Crimson (#B43232)
    let has_crimson = inactive_icon
        .as_chunks::<4>()
        .0
        .iter()
        .any(|px| px[0] == 0xB4 && px[1] == 0x32 && px[2] == 0x32);
    assert!(has_crimson, "Inactive icon must contain Crimson pixels");

    // Both must contain pure white border pixels
    let active_has_white = active_icon
        .as_chunks::<4>()
        .0
        .iter()
        .any(|px| px[0] == 255 && px[1] == 255 && px[2] == 255 && px[3] == 255);
    let inactive_has_white = inactive_icon
        .as_chunks::<4>()
        .0
        .iter()
        .any(|px| px[0] == 255 && px[1] == 255 && px[2] == 255 && px[3] == 255);

    assert!(active_has_white, "Active icon must have white border");
    assert!(inactive_has_white, "Inactive icon must have white border");
}

/// Extra 1: Asserts clean binary scores < 50.
#[test]
fn test_clean_binary_scores_under_50() {
    let clean_data =
        b"This is a standard text file without any exploit strings or malicious payloads.";
    let engine = SignatureEngine::load_or_default(None);
    let (_hash, score, hits) = engine.scan_bytes(clean_data).unwrap();

    assert!(
        score < 30,
        "Benign data should score in the clean band (<30), got {}",
        score
    );
    assert!(hits.is_empty(), "Benign data should produce 0 hits");
}

/// Extra 2: Asserts known SHA-256 hash detection.
#[test]
fn test_known_hash_match() {
    // EICAR standard test hash
    let eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    let engine = SignatureEngine::load_or_default(None);

    let hit = engine.known_hashes.get(eicar_hash);
    assert!(hit.is_some(), "EICAR SHA-256 hash must be pre-loaded");
    assert_eq!(hit.unwrap().score, 100);
}

/// Extra 3: Asserts case-insensitive string matching.
#[test]
fn test_case_insensitive_match() {
    let mixed_case = format!("{}{}-{}", "In", "VoKe", "MiMiKaTz");
    let engine = SignatureEngine::load_or_default(None);
    let (_hash, score, hits) = engine.scan_bytes(mixed_case.as_bytes()).unwrap();

    assert!(
        score >= 90,
        "Expected mixed-case Invoke-Mimikatz to match with score >= 90"
    );
    assert!(
        hits.iter().any(|h| h.rule_name.contains("Mimikatz")),
        "Expected Mimikatz hit on mixed-case input"
    );
}

/// Extra 4: Asserts Ghidra JSON export triage round-trip.
#[test]
fn test_ghidra_import_roundtrip() {
    let dir = tempdir().unwrap();
    let triage_file = dir.path().join("ghidra_export.json");
    let rules_file = dir.path().join("imported_signatures.json");

    let triage_json = r#"{
        "binary_name": "stealer_trojan.exe",
        "strings": [
            "SECRET_DROPPER_GATEWAY_URL",
            "tiny"
        ],
        "hex_patterns": [
            "65488b042560000000112233",
            "9090909090909090"
        ],
        "suspicious_imports": [
            "CustomInjectMemoryStub"
        ]
    }"#;

    fs::write(&triage_file, triage_json).unwrap();

    let summary = import_ghidra_triage(&triage_file, &rules_file).unwrap();
    assert_eq!(summary.imported_patterns, 3);
    assert_eq!(summary.skipped_patterns, 2);

    // Verify the newly generated rules can be loaded by SignatureEngine
    let engine = SignatureEngine::load_or_default(Some(&rules_file));
    let test_buf = b"Connecting to SECRET_DROPPER_GATEWAY_URL now...";
    let (_hash, score, hits) = engine.scan_bytes(test_buf).unwrap();

    assert!(
        score >= 70,
        "Imported Ghidra rule should trigger with score >= 70"
    );
    assert!(hits.iter().any(|h| h.rule_name.contains("SECRET_DROPPER")));
}

/// Extra 5: Asserts restore refuses to overwrite existing files.
#[test]
fn test_restore_refuses_to_overwrite() {
    let dir = tempdir().unwrap();
    let base_path = dir.path();
    let file = base_path.join("threat.bin");
    fs::write(&file, b"sample threat").unwrap();

    let hash = compute_file_sha256(&file).unwrap();
    quarantine_file(base_path, "vault", &file, &hash, "Threat", 80).unwrap();

    // Recreate the file at the destination
    fs::write(&file, b"new occupant file").unwrap();

    // Restore must return AlreadyExists error
    let err = restore_file(base_path, "vault", &hash, Some(&file)).unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::AlreadyExists,
        "Restore must refuse to overwrite an existing destination file"
    );
}
// taking refrence rea n gidhra
