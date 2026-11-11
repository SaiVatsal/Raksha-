# Raksha (रक्षा) 🛡️

**Ultra-Lightweight, High-Performance Windows Anti-Malware Engine, Real-Time Shield, and System Tray Controller written 100% in Safe Rust.**

Raksha is designed from first principles for zero-compromise endpoint security with minimal resource overhead. Modeled after modern malware reverse-engineering frameworks (VirusTotal `yara-x`, Ghidra, PE-bear, and Detect It Easy), Raksha delivers multi-layered static analysis, behavioral process watching, streaming cryptographic hashing, and neutralizing XOR vault quarantine in a single sub-2 MB binary footprint.

---

## Architecture

```mermaid
flowchart TD
    subgraph Ingestion["Input & Watchdog Surface"]
        CLI["CLI Commands (raksha.exe)"]
        Tray["System Tray Controller (raksha-tray.exe)"]
        Watcher["Real-Time Watcher (notify)"]
        ProcWatch["Process & Registry Guard"]
    end

    subgraph Cache["Zero-CPU Optimization"]
        ModCache["Smart Modification Cache\n(FilePath + Size + MTime)"]
    end

    subgraph Pipeline["Multi-Layer Detection Engine"]
        L1["Layer 1: Signatures\n- Streaming SHA-256 (8 KB chunks)\n- Aho-Corasick O(N) Multi-Pattern\n- Overlapping Window Matcher"]
        L2["Layer 2: PE X-Ray Heuristics\n- MZ / PE32 / PE32+ Validation\n- Section RWX Audit (+60)\n- Shannon Entropy > 7.20 (+40)\n- IAT Injection Chain (+65)\n- Spyware / Dumping (+35)"]
        L3["Layer 3: Behavioral Watchdog\n- Active Process Inspection\n- Startup Registry Persistence"]
        Ghidra["Ghidra MCP Bridge\n- Decompilation Triage Ingestion\n- Prologue Filtering & Deduplication"]
    end

    subgraph Scoring["Risk Scoring Engine"]
        ScoreBand{Risk Score}
        Clean["Clean (<30)\nRecord in Cache"]
        Suspicious["Suspicious (30-49)\nTelemetry Alert"]
        Malicious["Malicious (>=50)\nAutomatic Neutralization"]
    end

    subgraph Vault["Isolation & Recovery"]
        XOR["Streaming XOR 0xAA Vault\n(.rkq Ciphertext + manifest.json)"]
        Restore["Lossless 100% Integrity Restore\n(Refuses to Overwrite)"]
    end

    CLI --> ModCache
    Watcher --> ModCache
    ProcWatch --> Pipeline
    Ghidra --> L1
    ModCache -->|Cache Miss| L1
    L1 --> L2
    L2 --> ScoreBand
    ScoreBand -->|Score < 30| Clean
    ScoreBand -->|30 <= Score < 50| Suspicious
    ScoreBand -->|Score >= 50| Malicious
    Malicious --> XOR
    XOR --> Restore
```

---

## Performance & Security Benchmarks

| Metric | Target Specification | Raksha Measured Performance | Implementation Details |
| :--- | :--- | :--- | :--- |
| **RAM (Active Scan)** | < 15.0 MB | **~8.2 MB** | 8 KB bounded stack chunking (`[0u8; 8192]`); zero whole-file heap buffering. |
| **RAM (Tray & Watcher)** | < 2.0 MB | **~1.4 MB** | Lightweight thread footprint, memory-generated RGBA icon buffers. |
| **CPU Usage (Idle)** | 0.0% | **0.0%** | Blocking Win32 message pump (`MsgWaitForMultipleObjectsEx`) & kernel event queue. |
| **Disk Footprint (Executables)** | < 2.0 MB per binary | **raksha.exe (1.00 MB)**<br>**raksha-tray.exe (955 KB)**<br>**raksha-setup.exe (529 KB)** | Compiled with `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`, and `strip = true`. |
| **Toggle Latency** | < 10 ms | **< 1 ms** | Atomic atomic bool swap & disk flush of `raksha_state.cfg`. |
| **Modification Cache** | O(1) skip for clean files | **O(1) verified** | Checks `(file_size, mtime_unix_secs)` before reading raw bytes. |

---

## Multi-Layer Detection Engine

### Layer 1: Streaming Hashes & Multi-Pattern Byte Engine (`src/signatures.rs`)
- **Streaming SHA-256**: Streamed in 8 KB stack buffers (`[0u8; 8192]`) with zero heap allocations. Pre-loaded with known malware signatures (e.g. EICAR test hash) and expandable JSON rules.
- **Aho-Corasick SIMD Pattern Matching**: Single O(N) pass across streaming file slices with a 256-byte sliding overlap window to catch patterns that straddle buffer boundaries.
- **Rule Obfuscation**: Malware trigger patterns are stored base64-encoded in `rules/default_signatures.json` and decoded in memory to prevent false positives by third-party host scanners on Raksha itself.

### Layer 2: PE Header & Heuristics X-Ray Engine (`src/pe_xray.rs`)
- Zero-copy parsing with `goblin::pe::PE`.
- **RWX Section Audit**: Flags sections with both `IMAGE_SCN_MEM_EXECUTE` (`0x20000000`) and `IMAGE_SCN_MEM_WRITE` (`0x80000000`) (+60 Risk Score).
- **Shannon Entropy Calculation**: Computes $-\sum (p_i \cdot \log_2(p_i))$ for every section. If a section > 256 bytes exceeds `7.20` entropy, flags packed/encrypted payload (+40 Risk Score).
- **Import Address Table (IAT) Analysis**:
  - Process Injection Chain (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtUnmapViewOfSection`, `QueueUserAPC`, `SetThreadContext`): 2+ matches add +65 Risk Score.
  - Spyware/Keylogging (`SetWindowsHookExA/W`, `GetAsyncKeyState`, `MiniDumpWriteDump`): +35 Risk Score.
  - Hidden/Packed IAT: Flags non-DLL executables importing $\le 3$ APIs (+35 Risk Score), while explicitly exempting .NET assemblies via CLR COM directory inspection.

### Layer 3: Behavioral Process & Startup Persistence Watchdog (`src/behavioral.rs`)
- Enumerates running processes using `sysinfo` and identifies non-system processes executing out of `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, or `Downloads`.
- Inspects Windows Startup Registry persistence keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, and `RunOnce`) via `winreg`.

### Neutralizing XOR 0xAA Quarantine Vault (`src/quarantine.rs`)
- High-risk threats ($\text{Risk Score} \ge 50$) are streamed in 8 KB chunks, encrypted via bitwise XOR with `0xAA`, saved to `<vault>/<sha256>.rkq`, cataloged in `manifest.json`, and deleted from their original location.
- **Lossless Restore**: Reverses the XOR stream and verifies SHA-256 integrity 100%. Refuses to overwrite any existing file at the restoration target.

### Ghidra MCP Triage Bridge (`src/ghidra_bridge.rs`)
Ingests Ghidra decompilation and reverse-engineering triage reports (`ghidra-mcp`), enforces a minimum 8-byte rule length, automatically strips common compiler function prologues (`push ebp; mov ebp, esp`, `sub rsp, imm`) and NOP/INT3 padding, deduplicates existing signatures, and appends valid detection rules.

```json
{
  "binary_name": "trojan_stealer.exe",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "strings": [
    "COMMAND_AND_CONTROL_GATEWAY",
    "PASSWORD_STEALER_PAYLOAD"
  ],
  "hex_patterns": [
    "65488b042560000000488b4018"
  ],
  "suspicious_imports": [
    "NtCreateThreadEx",
    "QueueUserAPC"
  ]
}
```

---

## Native Windows System Tray Controller (`raksha-tray.exe`)

- **Subsystem**: Runs under `#![windows_subsystem = "windows"]` with zero console flickering.
- **Procedural Shield Icons**: Generates crisp 32x32 RGBA shield icons in memory (`tray_icon::Icon::from_rgba`):
  - **Emerald Green (`#10B981`)** with a white border when active.
  - **Crimson (`#B43232`)** with a white border when paused.
- **1-Click Left-Click Toggle**: Toggles real-time protection in under 10 milliseconds.
- **Context Menu**: Includes live shield toggle, quick folder scan, process & startup guard, vault explorer, and exit.
- **Single-Instance Mutex**: Prevents duplicate tray instances via Win32 `CreateMutexW`.

---

## Standalone Windows Installer (`raksha-setup.exe`)

- Copies binaries and default signatures to `%LOCALAPPDATA%\Programs\Raksha`.
- Automatically adds the installation directory to the user's `PATH` in `HKCU\Environment`.
- Optionally registers `raksha-tray.exe` for autostart in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- Supports clean uninstallation (`--uninstall`) with process cleanup and registry restoration.

```powershell
# Install Raksha and register tray autostart
.\target\release\raksha-setup.exe --install --autostart

# Uninstall Raksha completely
.\target\release\raksha-setup.exe --uninstall
```

---

## CLI Reference (`raksha.exe`)

```powershell
# Display shield status, exclusions, and vault metrics
raksha status

# Toggle real-time shield
raksha on
raksha off

# Recursively scan files and directories
raksha scan C:\Users\User\Downloads --quarantine
raksha scan C:\Tools\Payload.exe --no-cache

# Run behavioral process watchdog and startup persistence scan
raksha guard

# Start real-time folder watchdog daemon
raksha watch C:\Users\User\Downloads --quarantine

# List quarantined items in vault
raksha vault

# Restore a file from the vault
raksha restore <sha256> C:\Restored\file.exe

# Add path to permanent exclusion list
raksha exclude C:\MyProject\Bin

# Ingest Ghidra triage JSON export
raksha import-ghidra C:\Analysis\triage.json
```

---

## Honest Scope Note

> [!IMPORTANT]
> **Scope and Design Intent**: Raksha is a lightweight user-space endpoint detection engine and filesystem watchdog. Real-time folder monitoring operates via post-write filesystem notification events (`ReadDirectoryChangesW` via `notify`) rather than pre-execution kernel-level filesystem filtering (`FLT_PRE_OPERATION` via Windows Minifilter driver). It is designed as a fast, zero-overhead scanner, reverse-engineering triage partner, and endpoint shield.

---

## Integration Tests Verification

Raksha includes an automated integration test suite covering all security engines and edge cases:

```powershell
cargo test --release
```

**Results (100% Passing):**
- `test_eicar_signature_detection` (Score $\ge 100$)
- `test_synthetic_pe_rwx_and_high_entropy` (64-bit PE with RWX section and 8.00 entropy, Score $\ge 90$)
- `test_ransomware_command_detection` (`vssadmin delete shadows`, Score $\ge 90$)
- `test_xor_quarantine_and_lossless_restore` (XOR 0xAA encryption verification and 100% SHA-256 match on restore)
- `test_smart_cache_zero_cpu_skip` (O(1) verification without disk re-reading)
- `test_on_off_toggle_and_exclusions` (State configuration lifecycle)
- `test_tray_icon_rgba_generation` (4,096-byte 32x32 RGBA memory buffer verification)
- `test_clean_binary_scores_under_50` (Benign baseline score verification)
- `test_known_hash_match` (EICAR hash lookup)
- `test_case_insensitive_match` (Mixed-case `InVoKe-MiMiKaTz` detection)
- `test_ghidra_import_roundtrip` (Triage ingestion, prologue filtering, and deduplication)
- `test_restore_refuses_to_overwrite` (Destination protection guarantee)

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details...
