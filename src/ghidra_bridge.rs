//! Ghidra MCP & JSON Triage Rule Importer.
//! Ingests Ghidra decompilation/triage reports, deduplicates patterns,
//! filters common function prologues, and appends valid signatures.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::signatures::{BytePatternRule, RulesDocument};

pub const MIN_PATTERN_BYTES: usize = 8;

/// Ghidra Triage Report JSON Schema.
///
/// Example:
/// ```json
/// {
///   "binary_name": "trojan_stealer.exe",
///   "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
///   "strings": [
///     "COMMAND_AND_CONTROL_GATEWAY",
///     "PASSWORD_STEALER_PAYLOAD"
///   ],
///   "hex_patterns": [
///     "65488b042560000000488b4018",
///     "e8000000005883c010ffe000"
///   ],
///   "suspicious_imports": [
///     "NtCreateThreadEx",
///     "QueueUserAPC"
///   ]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraTriageReport {
    #[serde(default)]
    pub binary_name: String,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub strings: Vec<String>,
    #[serde(default)]
    pub hex_patterns: Vec<String>,
    #[serde(default)]
    pub suspicious_imports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GhidraImportSummary {
    pub imported_patterns: usize,
    pub skipped_patterns: usize,
    pub total_rules_after_import: usize,
}

/// Checks if a hex byte slice resembles standard non-malicious compiler function prologues or NOP/INT3 sleds.
pub fn is_common_prologue_or_padding(hex_str: &str) -> bool {
    let lower = hex_str.to_lowercase();

    // Sleds: all 0x90 (NOP) or 0xCC (INT3)
    if lower.chars().all(|c| c == '9' || c == '0') || lower.chars().all(|c| c == 'c') {
        return true;
    }

    // Standard x86/x64 prologues
    // 5589e5 (push ebp; mov ebp, esp)
    // 558bec (push ebp; mov ebp, esp)
    // 4883ec (sub rsp, imm)
    // 48895c24 (mov [rsp+..], rbx)
    let common_prologues = ["5589e5", "558bec", "4883ec", "48895c24"];
    for p in &common_prologues {
        if lower.starts_with(p) && lower.len() <= (p.len() + 8) {
            return true;
        }
    }

    false
}

/// Imports patterns from a Ghidra triage JSON file and appends them to target rules JSON.
pub fn import_ghidra_triage(
    ghidra_json_path: &Path,
    rules_json_path: &Path,
) -> Result<GhidraImportSummary, String> {
    let ghidra_content = fs::read_to_string(ghidra_json_path)
        .map_err(|e| format!("Failed to read Ghidra triage file: {}", e))?;

    let report: GhidraTriageReport = serde_json::from_str(&ghidra_content)
        .map_err(|e| format!("Invalid Ghidra triage JSON schema: {}", e))?;

    // Load existing rules document or create new
    let mut rules_doc: RulesDocument = if rules_json_path.exists() {
        let content = fs::read_to_string(rules_json_path)
            .map_err(|e| format!("Failed to read existing rules file: {}", e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse existing rules file: {}", e))?
    } else {
        RulesDocument {
            version: 1,
            known_hashes: Vec::new(),
            patterns: Vec::new(),
        }
    };

    let b64 = base64::engine::general_purpose::STANDARD;
    let mut existing_patterns: HashSet<String> = rules_doc
        .patterns
        .iter()
        .map(|p| p.pattern_b64.clone())
        .collect();

    let mut imported = 0;
    let mut skipped = 0;

    // 1. Process Strings
    for s in report.strings {
        let trimmed = s.trim();
        if trimmed.len() < MIN_PATTERN_BYTES {
            skipped += 1;
            continue;
        }

        let encoded = b64.encode(trimmed.as_bytes());
        if existing_patterns.contains(&encoded) {
            skipped += 1;
            continue;
        }

        existing_patterns.insert(encoded.clone());
        rules_doc.patterns.push(BytePatternRule {
            name: format!("GhidraImport_Str_{}", sanitize_rule_name(trimmed)),
            pattern_b64: encoded,
            weight: 70,
            is_ascii: true,
        });
        imported += 1;
    }

    // 2. Process Hex Patterns
    for h in report.hex_patterns {
        let cleaned: String = h.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if cleaned.len() < (MIN_PATTERN_BYTES * 2) {
            skipped += 1;
            continue;
        }

        if is_common_prologue_or_padding(&cleaned) {
            skipped += 1;
            continue;
        }

        if let Ok(raw_bytes) = hex::decode(&cleaned) {
            let encoded = b64.encode(&raw_bytes);
            if existing_patterns.contains(&encoded) {
                skipped += 1;
                continue;
            }

            existing_patterns.insert(encoded.clone());
            rules_doc.patterns.push(BytePatternRule {
                name: format!("GhidraImport_Hex_{}", &cleaned[..12.min(cleaned.len())]),
                pattern_b64: encoded,
                weight: 85,
                is_ascii: false,
            });
            imported += 1;
        } else {
            skipped += 1;
        }
    }

    // 3. Process Suspicious Imports
    for imp in report.suspicious_imports {
        let trimmed = imp.trim();
        if trimmed.len() < MIN_PATTERN_BYTES {
            skipped += 1;
            continue;
        }

        let encoded = b64.encode(trimmed.as_bytes());
        if existing_patterns.contains(&encoded) {
            skipped += 1;
            continue;
        }

        existing_patterns.insert(encoded.clone());
        rules_doc.patterns.push(BytePatternRule {
            name: format!("GhidraImport_Api_{}", sanitize_rule_name(trimmed)),
            pattern_b64: encoded,
            weight: 60,
            is_ascii: true,
        });
        imported += 1;
    }

    // Save updated rules document
    rules_doc.version += 1;
    let serialized = serde_json::to_string_pretty(&rules_doc)
        .map_err(|e| format!("Failed to serialize updated rules: {}", e))?;

    if let Some(parent) = rules_json_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(rules_json_path, serialized.as_bytes())
        .map_err(|e| format!("Failed to write updated rules file: {}", e))?;

    Ok(GhidraImportSummary {
        imported_patterns: imported,
        skipped_patterns: skipped,
        total_rules_after_import: rules_doc.patterns.len(),
    })
}

fn sanitize_rule_name(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(24)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ghidra_import_roundtrip() {
        let dir = tempdir().unwrap();
        let ghidra_file = dir.path().join("triage.json");
        let rules_file = dir.path().join("signatures.json");

        let triage_data = r#"{
            "binary_name": "stealer.exe",
            "strings": [
                "MALICIOUS_C2_CONNECTION_STRING",
                "short"
            ],
            "hex_patterns": [
                "65488b042560000000abcdef",
                "cccccccccccccccc"
            ],
            "suspicious_imports": [
                "CustomPayloadInjectorApi"
            ]
        }"#;

        fs::write(&ghidra_file, triage_data).unwrap();

        let summary = import_ghidra_triage(&ghidra_file, &rules_file).unwrap();
        // "short" skipped (< 8 bytes)
        // "cccccccccccccccc" skipped (all INT3 padding)
        // "MALICIOUS_C2_CONNECTION_STRING" imported
        // "65488b042560000000abcdef" imported
        // "CustomPayloadInjectorApi" imported
        assert_eq!(summary.imported_patterns, 3);
        assert_eq!(summary.skipped_patterns, 2);

        // Re-import must deduplicate all 3
        let summary2 = import_ghidra_triage(&ghidra_file, &rules_file).unwrap();
        assert_eq!(summary2.imported_patterns, 0);
        assert_eq!(summary2.skipped_patterns, 5);
    }
}
