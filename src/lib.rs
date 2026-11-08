//! Raksha: Ultra-Lightweight, High-Performance Windows Anti-Malware Engine & Real-Time Shield.
//! Written 100% in safe, idiomatic Rust.

pub mod behavioral;
pub mod cache;
pub mod config;
pub mod ghidra_bridge;
pub mod icons;
pub mod pe_xray;
pub mod quarantine;
pub mod shield;
pub mod signatures;

// Re-export common types
pub use config::{get_base_dir, load_config, set_protection_state, RakshaConfig};
pub use icons::generate_shield_icon_rgba;
pub use pe_xray::{audit_pe_bytes, calculate_shannon_entropy, PeAuditResult};
pub use quarantine::{list_quarantine_records, quarantine_file, restore_file};
pub use signatures::{compute_file_sha256, SignatureEngine, SignatureHit};
