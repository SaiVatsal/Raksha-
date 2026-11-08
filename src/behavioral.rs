//! Layer 3: Active Process & Windows Startup Registry Watchdog Engine.
//! Audits running processes in sensitive user directories and monitors Run/RunOnce persistence keys.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use sysinfo::System;

use crate::pe_xray::audit_pe_bytes;
use crate::signatures::SignatureEngine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessThreatHit {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub risk_score: u32,
    pub detections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryThreatHit {
    pub root_key: String,
    pub value_name: String,
    pub raw_command: String,
    pub resolved_exe: String,
    pub risk_score: u32,
    pub detections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GuardReport {
    pub total_processes_scanned: usize,
    pub suspicious_processes: Vec<ProcessThreatHit>,
    pub total_registry_entries_scanned: usize,
    pub suspicious_registry_entries: Vec<RegistryThreatHit>,
}

/// Scans active processes running from sensitive user directories:
/// %TEMP%, %APPDATA%, %LOCALAPPDATA%, and Downloads.
pub fn scan_active_processes(
    sig_engine: &SignatureEngine,
    base_path: &Path,
) -> (usize, Vec<ProcessThreatHit>) {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut sensitive_dirs = Vec::new();
    if let Ok(temp) = std::env::var("TEMP") {
        sensitive_dirs.push(temp.to_lowercase());
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        sensitive_dirs.push(appdata.to_lowercase());
    }
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        sensitive_dirs.push(local.to_lowercase());
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let downloads = PathBuf::from(profile).join("Downloads");
        sensitive_dirs.push(downloads.to_string_lossy().to_lowercase());
    }

    let mut scanned_count = 0;
    let mut suspicious = Vec::new();
    let base_lower = base_path.to_string_lossy().to_lowercase();

    for (pid, process) in sys.processes() {
        let exe_path = match process.exe() {
            Some(p) => p,
            None => continue,
        };

        if exe_path.as_os_str().is_empty() {
            continue;
        }

        let exe_str = exe_path.to_string_lossy();
        let exe_lower = exe_str.to_lowercase();

        // Never audit Raksha itself
        if exe_lower.contains("raksha")
            || (!base_lower.is_empty() && exe_lower.starts_with(&base_lower))
        {
            continue;
        }

        // Check if located in a sensitive path
        let in_sensitive = sensitive_dirs.iter().any(|d| exe_lower.starts_with(d));
        if !in_sensitive {
            continue;
        }

        scanned_count += 1;

        if let Ok(data) = std::fs::read(exe_path) {
            let mut detections = Vec::new();
            let mut score: u32 = 0;

            // Layer 1: Signatures
            if let Ok((_hash, sig_score, hits)) = sig_engine.scan_bytes(&data) {
                if sig_score > 0 {
                    score = score.saturating_add(sig_score);
                    for h in hits {
                        detections.push(format!("[Signature] {}", h.description));
                    }
                }
            }

            // Layer 2: PE X-Ray
            let pe_res = audit_pe_bytes(&data);
            if pe_res.is_pe && pe_res.risk_score > 0 {
                score = score.saturating_add(pe_res.risk_score);
                for d in pe_res.detections {
                    detections.push(format!("[PE Heuristic] {}", d));
                }
            }

            if score >= 30 {
                let pid_u32 = pid.as_u32();
                suspicious.push(ProcessThreatHit {
                    pid: pid_u32,
                    name: process.name().to_string(),
                    exe_path: exe_str.to_string(),
                    risk_score: score,
                    detections,
                });
            }
        }
    }

    (scanned_count, suspicious)
}

/// Audits Windows Startup persistence registry keys:
/// HKCU\Software\Microsoft\Windows\CurrentVersion\Run
/// HKLM\Software\Microsoft\Windows\CurrentVersion\Run
#[cfg(windows)]
pub fn scan_startup_registry(sig_engine: &SignatureEngine) -> (usize, Vec<RegistryThreatHit>) {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let targets = [
        (
            "HKCU",
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            "HKCU",
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        (
            "HKLM",
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            "HKLM",
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
    ];

    let mut scanned_count = 0;
    let mut hits = Vec::new();

    for (root_name, root_hkey, subkey_path) in targets {
        let root = RegKey::predef(root_hkey);
        if let Ok(key) = root.open_subkey_with_flags(subkey_path, KEY_READ) {
            for (name, value) in key.enum_values().flatten() {
                scanned_count += 1;
                let raw_cmd = value.to_string();
                let resolved_path = extract_exe_path_from_cmd(&raw_cmd);

                if let Some(target_file) = &resolved_path {
                    if target_file.exists() {
                        if let Ok(data) = std::fs::read(target_file) {
                            let mut detections = Vec::new();
                            let mut score: u32 = 0;

                            if let Ok((_, sig_score, sig_hits)) = sig_engine.scan_bytes(&data) {
                                if sig_score > 0 {
                                    score = score.saturating_add(sig_score);
                                    for sh in sig_hits {
                                        detections.push(format!("[Signature] {}", sh.description));
                                    }
                                }
                            }

                            let pe_res = audit_pe_bytes(&data);
                            if pe_res.is_pe && pe_res.risk_score > 0 {
                                score = score.saturating_add(pe_res.risk_score);
                                for d in pe_res.detections {
                                    detections.push(format!("[PE Heuristic] {}", d));
                                }
                            }

                            if score >= 30 {
                                hits.push(RegistryThreatHit {
                                    root_key: format!(r"{}\{}", root_name, subkey_path),
                                    value_name: name,
                                    raw_command: raw_cmd,
                                    resolved_exe: target_file.to_string_lossy().to_string(),
                                    risk_score: score,
                                    detections,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    (scanned_count, hits)
}

#[cfg(not(windows))]
pub fn scan_startup_registry(_sig_engine: &SignatureEngine) -> (usize, Vec<RegistryThreatHit>) {
    (0, Vec::new())
}

/// Parses an executable path from a Windows command line string.
/// Handles quoted paths like `"C:\Program Files\App\app.exe" -arg`
/// and unquoted paths like `C:\App\app.exe /run`.
pub fn extract_exe_path_from_cmd(cmd: &str) -> Option<PathBuf> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(stripped) = trimmed.strip_prefix('"') {
        if let Some(end) = stripped.find('"') {
            let extracted = &stripped[..end];
            return Some(PathBuf::from(extracted));
        }
    }

    // Split on first space
    let first_token = trimmed.split_whitespace().next().unwrap_or(trimmed);
    Some(PathBuf::from(first_token))
}

/// Runs a full behavioral audit of processes and startup registry entries.
pub fn run_guard_scan(sig_engine: &SignatureEngine, base_path: &Path) -> GuardReport {
    let (proc_count, proc_hits) = scan_active_processes(sig_engine, base_path);
    let (reg_count, reg_hits) = scan_startup_registry(sig_engine);

    GuardReport {
        total_processes_scanned: proc_count,
        suspicious_processes: proc_hits,
        total_registry_entries_scanned: reg_count,
        suspicious_registry_entries: reg_hits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_exe_path() {
        let quoted = r#""C:\Program Files\App\test.exe" --silent"#;
        assert_eq!(
            extract_exe_path_from_cmd(quoted),
            Some(PathBuf::from(r"C:\Program Files\App\test.exe"))
        );

        let unquoted = r"C:\Windows\System32\calc.exe";
        assert_eq!(
            extract_exe_path_from_cmd(unquoted),
            Some(PathBuf::from(r"C:\Windows\System32\calc.exe"))
        );
    }
}
