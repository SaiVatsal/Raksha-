//! Layer 1: Streaming Cryptographic Hash & Aho-Corasick Multi-Pattern Byte Engine.
//! Scans files in streaming 8 KB stack chunks with zero large-heap allocations.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

pub const DEFAULT_RULES_JSON: &str = include_str!("../rules/default_signatures.json");
pub const STREAM_BUFFER_SIZE: usize = 8192;
pub const MAX_OVERLAP_SIZE: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownHashRule {
    pub sha256: String,
    pub description: String,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytePatternRule {
    pub name: String,
    pub pattern_b64: String,
    pub weight: u32,
    #[serde(default)]
    pub is_ascii: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesDocument {
    pub version: u32,
    pub known_hashes: Vec<KnownHashRule>,
    pub patterns: Vec<BytePatternRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHit {
    pub rule_name: String,
    pub weight: u32,
    pub description: String,
}

pub struct SignatureEngine {
    pub version: u32,
    pub version_hash: String,
    pub known_hashes: HashMap<String, KnownHashRule>,
    pub ascii_rules: Vec<BytePatternRule>,
    pub ascii_matcher: AhoCorasick,
    pub binary_rules: Vec<BytePatternRule>,
    pub binary_matcher: AhoCorasick,
}

impl SignatureEngine {
    /// Loads signature rules from a JSON string or falls back to embedded defaults.
    pub fn load_from_json(json_str: &str) -> Result<Self, String> {
        let doc: RulesDocument = serde_json::from_str(json_str)
            .map_err(|e| format!("Failed to parse signatures JSON: {}", e))?;

        // Calculate a version hash of the rules document
        let mut hasher = Sha256::new();
        hasher.update(json_str.as_bytes());
        let version_hash = hex::encode(hasher.finalize());

        let mut known_hashes = HashMap::new();
        for h in doc.known_hashes {
            known_hashes.insert(h.sha256.to_lowercase(), h);
        }

        let mut ascii_rules = Vec::new();
        let mut ascii_patterns = Vec::new();

        let mut binary_rules = Vec::new();
        let mut binary_patterns = Vec::new();

        let b64_engine = base64::engine::general_purpose::STANDARD;

        for p in doc.patterns {
            let decoded = b64_engine
                .decode(&p.pattern_b64)
                .map_err(|e| format!("Invalid base64 in pattern '{}': {}", p.name, e))?;

            if p.is_ascii {
                ascii_patterns.push(decoded);
                ascii_rules.push(p);
            } else {
                binary_patterns.push(decoded);
                binary_rules.push(p);
            }
        }

        let ascii_matcher = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(&ascii_patterns)
            .map_err(|e| format!("Failed to build ASCII Aho-Corasick matcher: {}", e))?;

        let binary_matcher = AhoCorasickBuilder::new()
            .ascii_case_insensitive(false)
            .build(&binary_patterns)
            .map_err(|e| format!("Failed to build Binary Aho-Corasick matcher: {}", e))?;

        Ok(Self {
            version: doc.version,
            version_hash,
            known_hashes,
            ascii_rules,
            ascii_matcher,
            binary_rules,
            binary_matcher,
        })
    }

    /// Loads signature database from a custom file path or embedded defaults if missing.
    pub fn load_or_default(rules_file: Option<&Path>) -> Self {
        if let Some(path) = rules_file {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(path) {
                    if let Ok(engine) = Self::load_from_json(&content) {
                        return engine;
                    }
                }
            }
        }

        Self::load_from_json(DEFAULT_RULES_JSON)
            .expect("Embedded default signatures must be valid JSON")
    }

    /// Performs streaming SHA-256 computation and multi-pattern byte scanning.
    /// Uses an 8 KB stack buffer with a 256-byte overlap to catch patterns across chunk boundaries.
    pub fn scan_reader<R: Read + Seek>(
        &self,
        mut reader: R,
    ) -> std::io::Result<(String, u32, Vec<SignatureHit>)> {
        let mut hasher = Sha256::new();
        let mut hits = Vec::new();
        let mut total_score: u32 = 0;

        // Bounded stack buffers
        let mut chunk_buf = [0u8; STREAM_BUFFER_SIZE];
        let mut overlap_buf = [0u8; MAX_OVERLAP_SIZE];
        let mut overlap_len = 0;

        // Combined inspection window: up to MAX_OVERLAP_SIZE + STREAM_BUFFER_SIZE (8,448 bytes)
        let mut window = [0u8; MAX_OVERLAP_SIZE + STREAM_BUFFER_SIZE];

        loop {
            let bytes_read = reader.read(&mut chunk_buf)?;
            if bytes_read == 0 {
                break;
            }

            // Stream into SHA-256
            hasher.update(&chunk_buf[..bytes_read]);

            // Construct overlapping window
            let window_len = overlap_len + bytes_read;
            window[..overlap_len].copy_from_slice(&overlap_buf[..overlap_len]);
            window[overlap_len..window_len].copy_from_slice(&chunk_buf[..bytes_read]);

            let active_slice = &window[..window_len];

            // 1. ASCII Aho-Corasick matching
            for m in self.ascii_matcher.find_iter(active_slice) {
                let rule = &self.ascii_rules[m.pattern().as_usize()];
                if !hits.iter().any(|h: &SignatureHit| h.rule_name == rule.name) {
                    hits.push(SignatureHit {
                        rule_name: rule.name.clone(),
                        weight: rule.weight,
                        description: format!("Signature pattern match: {}", rule.name),
                    });
                    total_score = total_score.saturating_add(rule.weight);
                }
            }

            // 2. Binary Aho-Corasick matching
            for m in self.binary_matcher.find_iter(active_slice) {
                let rule = &self.binary_rules[m.pattern().as_usize()];
                if !hits.iter().any(|h: &SignatureHit| h.rule_name == rule.name) {
                    hits.push(SignatureHit {
                        rule_name: rule.name.clone(),
                        weight: rule.weight,
                        description: format!("Binary bytecode match: {}", rule.name),
                    });
                    total_score = total_score.saturating_add(rule.weight);
                }
            }

            // Retain the tail of current chunk for the next window overlap
            overlap_len = bytes_read.min(MAX_OVERLAP_SIZE);
            let start = bytes_read - overlap_len;
            overlap_buf[..overlap_len].copy_from_slice(&chunk_buf[start..bytes_read]);
        }

        let sha256_hex = hex::encode(hasher.finalize());

        // Check known hashes
        if let Some(known) = self.known_hashes.get(&sha256_hex.to_lowercase()) {
            hits.push(SignatureHit {
                rule_name: "KnownMalwareHash".to_string(),
                weight: known.score,
                description: known.description.clone(),
            });
            total_score = total_score.max(known.score);
        }

        Ok((sha256_hex, total_score, hits))
    }

    /// Convenience scanner for file paths.
    pub fn scan_file(&self, path: &Path) -> std::io::Result<(String, u32, Vec<SignatureHit>)> {
        let file = File::open(path)?;
        self.scan_reader(file)
    }

    /// Convenience scanner for in-memory byte slices.
    pub fn scan_bytes(&self, data: &[u8]) -> std::io::Result<(String, u32, Vec<SignatureHit>)> {
        use std::io::Cursor;
        let cursor = Cursor::new(data);
        self.scan_reader(cursor)
    }
}

/// Standalone streaming SHA-256 calculator using an 8 KB buffer.
pub fn compute_file_sha256(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; STREAM_BUFFER_SIZE];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_engine_load() {
        let engine = SignatureEngine::load_or_default(None);
        assert!(!engine.known_hashes.is_empty());
        assert!(!engine.ascii_rules.is_empty());
        assert!(!engine.binary_rules.is_empty());
    }

    #[test]
    fn test_clean_buffer_score_zero() {
        let engine = SignatureEngine::load_or_default(None);
        let clean = b"This is a perfectly benign text document with no malicious patterns.";
        let (hash, score, hits) = engine.scan_bytes(clean).unwrap();
        assert_eq!(score, 0);
        assert!(hits.is_empty());
        assert!(!hash.is_empty());
    }
}
