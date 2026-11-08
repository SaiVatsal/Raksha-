//! Real-time notify File System Watcher Daemon.
//! Monitors directories, debounces writes, retries sharing violations,
//! and neutralizes threats in real time.

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::cache::{get_file_mtime_and_size, ModificationCache};
use crate::config::{is_path_excluded, load_config, DEFAULT_QUARANTINE_SUBDIR};
use crate::pe_xray::audit_pe_bytes;
use crate::quarantine::quarantine_file;
use crate::signatures::SignatureEngine;

/// Waits for a file's size to stabilize (debouncing write streams)
/// and retries opening it to handle Windows sharing violations (ERROR_SHARING_VIOLATION).
pub fn wait_for_stable_size_and_open(path: &Path) -> std::io::Result<File> {
    let mut prev_size = u64::MAX;

    for _ in 0..5 {
        if let Ok(meta) = std::fs::metadata(path) {
            let current = meta.len();
            if current > 0 && current == prev_size {
                break;
            }
            prev_size = current;
        }
        thread::sleep(Duration::from_millis(120));
    }

    let mut last_error = None;
    for _ in 0..4 {
        match File::open(path) {
            Ok(file) => return Ok(file),
            Err(e) => {
                last_error = Some(e);
                thread::sleep(Duration::from_millis(150));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "File lock wait timeout",
        )
    }))
}

/// Evaluates a single file through Signatures, Heuristics, and Smart Cache.
/// Neutralizes to quarantine vault if risk_score >= 50 and auto_quarantine is enabled.
pub fn scan_and_handle_file(
    file_path: &Path,
    sig_engine: &SignatureEngine,
    cache: &mut ModificationCache,
    base_path: &Path,
    auto_quarantine: bool,
) -> (u32, Vec<String>) {
    let config = load_config(base_path);
    if is_path_excluded(file_path, &config, base_path) {
        return (0, vec!["Excluded path".to_string()]);
    }

    let (size, mtime) = match get_file_mtime_and_size(file_path) {
        Ok(res) => res,
        Err(_) => return (0, Vec::new()),
    };

    // Fast O(1) Smart Modification Cache check
    if let Some(clean) = cache.check_clean(file_path, size, mtime) {
        if clean {
            return (0, vec!["Smart cache clean hit".to_string()]);
        }
    }

    let file = match wait_for_stable_size_and_open(file_path) {
        Ok(f) => f,
        Err(_) => return (0, Vec::new()),
    };

    let mut detections = Vec::new();
    let mut risk_score: u32 = 0;

    // Layer 1: Signatures
    let (sha256_hex, sig_score, sig_hits) = match sig_engine.scan_reader(file) {
        Ok(res) => res,
        Err(_) => return (0, Vec::new()),
    };

    if sig_score > 0 {
        risk_score = risk_score.saturating_add(sig_score);
        for h in sig_hits {
            detections.push(format!("[Signature] {}", h.description));
        }
    }

    // Layer 2: PE Header & Heuristics X-Ray (if MZ header present)
    if let Ok(file_bytes) = std::fs::read(file_path) {
        let pe_audit = audit_pe_bytes(&file_bytes);
        if pe_audit.is_pe && pe_audit.risk_score > 0 {
            risk_score = risk_score.saturating_add(pe_audit.risk_score);
            for d in pe_audit.detections {
                detections.push(format!("[PE Heuristic] {}", d));
            }
        }
    }

    // Handle verdict
    let primary_threat_name = detections
        .first()
        .cloned()
        .unwrap_or_else(|| "GenericThreat".to_string());

    if risk_score >= 50 {
        if auto_quarantine {
            let _ = quarantine_file(
                base_path,
                DEFAULT_QUARANTINE_SUBDIR,
                file_path,
                &sha256_hex,
                &primary_threat_name,
                risk_score,
            );
        }
        cache.record(file_path, size, mtime, false, risk_score);
        let _ = cache.flush();
    } else if risk_score < 30 {
        // Safe: record in cache to skip re-scans
        cache.record(file_path, size, mtime, true, risk_score);
        let _ = cache.flush();
    }

    (risk_score, detections)
}

/// Spawns a background filesystem watcher on `watch_target`.
/// Periodically checks `running_flag` to allow instant on/off toggling.
pub fn run_watcher_loop(
    watch_target: &Path,
    base_path: &Path,
    running_flag: Arc<AtomicBool>,
    auto_quarantine: bool,
) {
    let (tx, rx) = channel();
    let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("[Raksha Shield] Failed to initialize watcher: {}", e);
            return;
        }
    };

    if let Err(e) = watcher.watch(watch_target, RecursiveMode::Recursive) {
        eprintln!("[Raksha Shield] Watch error on {:?}: {}", watch_target, e);
        return;
    }

    let sig_engine = SignatureEngine::load_or_default(None);
    let mut cache = ModificationCache::open_or_create(base_path, &sig_engine.version_hash);

    println!(
        "[Raksha Shield] Real-time folder watchdog active on: {:?}",
        watch_target
    );

    while running_flag.load(Ordering::SeqCst) {
        // Non-busy message pull with 200ms timeout
        if let Ok(Ok(event)) = rx.recv_timeout(Duration::from_millis(200)) {
            let is_target_event = matches!(
                event.kind,
                EventKind::Create(_) | EventKind::Modify(_) | EventKind::Any
            );

            if is_target_event {
                for path in event.paths {
                    if path.is_file() {
                        let (score, hits) = scan_and_handle_file(
                            &path,
                            &sig_engine,
                            &mut cache,
                            base_path,
                            auto_quarantine,
                        );

                        if score >= 50 {
                            println!(
                                "\n[THREAT NEUTRALIZED] File {:?} scored {}/100 -> Quarantined!",
                                path, score
                            );
                            for h in hits {
                                println!("  - {}", h);
                            }
                        } else if score >= 30 {
                            println!(
                                "\n[SUSPICIOUS FILE DETECTED] File {:?} scored {}/100",
                                path, score
                            );
                            for h in hits {
                                println!("  - {}", h);
                            }
                        }
                    }
                }
            }
        }
    }

    println!("[Raksha Shield] Watcher loop terminated cleanly.");
}
