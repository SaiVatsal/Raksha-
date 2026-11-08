//! Layer 2: Pin-to-Pin Portable Executable (PE32 / PE32+) Heuristic X-Ray Engine.
//! Audits section RWX permissions, Shannon entropy, packer signatures, and IAT injection chains.

use goblin::pe::PE;
use serde::{Deserialize, Serialize};

pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
pub const IMAGE_FILE_DLL: u16 = 0x2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionAudit {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub entropy: f64,
    pub is_rwx: bool,
    pub is_packer_name: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeAuditResult {
    pub is_pe: bool,
    pub is_64bit: bool,
    pub entry_rva: u64,
    pub image_base: u64,
    pub total_imports: usize,
    pub risk_score: u32,
    pub detections: Vec<String>,
    pub sections: Vec<SectionAudit>,
}

impl PeAuditResult {
    pub fn not_a_pe() -> Self {
        Self {
            is_pe: false,
            is_64bit: false,
            entry_rva: 0,
            image_base: 0,
            total_imports: 0,
            risk_score: 0,
            detections: Vec::new(),
            sections: Vec::new(),
        }
    }
}

/// Computes the Shannon entropy of a byte slice, bounded between 0.0 and 8.0.
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Inspects and audits raw bytes for PE structure and heuristic anomalies.
pub fn audit_pe_bytes(bytes: &[u8]) -> PeAuditResult {
    // Fast check: PE files must start with "MZ" (0x4D, 0x5A) and be large enough for headers
    if bytes.len() < 0x40 || bytes[0] != 0x4D || bytes[1] != 0x5A {
        return PeAuditResult::not_a_pe();
    }

    let pe = match PE::parse(bytes) {
        Ok(parsed) => parsed,
        Err(_) => return PeAuditResult::not_a_pe(),
    };

    let is_64bit = pe.is_64;
    let entry_rva = pe.entry as u64;
    let image_base = pe.image_base;

    let mut risk_score: u32 = 0;
    let mut detections = Vec::new();
    let mut section_audits = Vec::new();

    let mut has_rwx_section = false;
    let mut has_high_entropy_section = false;
    let mut has_packer_section_name = false;

    // Known packer section names (case-insensitive)
    let packer_names = [
        ".upx0", ".upx1", ".vmp0", ".vmp1", ".themida", ".aspack", "upx0", "upx1",
    ];

    for section in &pe.sections {
        let name_raw = String::from_utf8_lossy(&section.name);
        let name = name_raw.trim_matches('\0').trim().to_string();
        let name_lower = name.to_lowercase();

        let is_rwx = (section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
            && (section.characteristics & IMAGE_SCN_MEM_WRITE != 0);

        let is_packer_name = packer_names.iter().any(|&p| name_lower.contains(p));

        // Calculate entropy on section raw bytes
        let raw_offset = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;

        let entropy = if raw_offset < bytes.len() && raw_size > 0 {
            let end = (raw_offset + raw_size).min(bytes.len());
            let slice = &bytes[raw_offset..end];
            calculate_shannon_entropy(slice)
        } else {
            0.0
        };

        if is_rwx {
            has_rwx_section = true;
        }

        if is_packer_name {
            has_packer_section_name = true;
        }

        // Section entropy > 7.20 on sections larger than 256 bytes
        if raw_size > 256 && entropy > 7.20 {
            has_high_entropy_section = true;
        }

        section_audits.push(SectionAudit {
            name,
            virtual_size: section.virtual_size,
            raw_size: section.size_of_raw_data,
            characteristics: section.characteristics,
            entropy,
            is_rwx,
            is_packer_name,
        });
    }

    // Apply section heuristics
    if has_rwx_section {
        risk_score = risk_score.saturating_add(60);
        detections.push("Dangerous RWX Section (Self-Modifying / Shellcode Injection)".to_string());
    }

    if has_packer_section_name {
        risk_score = risk_score.saturating_add(40);
        detections.push("Known Malware Packer Section Identified".to_string());
    }

    if has_high_entropy_section {
        risk_score = risk_score.saturating_add(40);
        detections.push("High-Entropy Section > 7.20 (Packed / Encrypted Payload)".to_string());
    }

    // Import Address Table (IAT) Audit
    let total_imports = pe.imports.len();
    let mut imported_names: Vec<String> = pe.imports.iter().map(|i| i.name.to_string()).collect();
    imported_names.sort();

    // 1. Process Injection Chain
    let injection_apis = [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "QueueUserAPC",
        "SetThreadContext",
    ];

    let mut injection_matches = 0;
    for api in &injection_apis {
        if imported_names
            .iter()
            .any(|imp| imp.eq_ignore_ascii_case(api))
        {
            injection_matches += 1;
        }
    }

    if injection_matches >= 2 {
        risk_score = risk_score.saturating_add(65);
        detections.push(format!(
            "Process Injection API Chain ({}/{} APIs present)",
            injection_matches,
            injection_apis.len()
        ));
    }

    // 2. Spyware / Credential Dumping
    let spyware_apis = [
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "GetAsyncKeyState",
        "MiniDumpWriteDump",
    ];

    let mut spyware_matches = 0;
    for api in &spyware_apis {
        if imported_names
            .iter()
            .any(|imp| imp.eq_ignore_ascii_case(api))
        {
            spyware_matches += 1;
        }
    }

    if spyware_matches >= 1 {
        risk_score = risk_score.saturating_add(35);
        detections.push("Spyware / Keystroke Logging / Credential Dumping Import".to_string());
    }

    // 3. Hidden / Packed IAT: non-DLL executable importing <= 3 functions
    let is_dll = (pe.header.coff_header.characteristics & IMAGE_FILE_DLL) != 0;

    // Check for .NET CLR directory presence
    let has_clr_header = match &pe.header.optional_header {
        Some(opt) => {
            if let Some(clr) = opt.data_directories.get_clr_runtime_header() {
                clr.virtual_address != 0 && clr.size != 0
            } else {
                false
            }
        }
        None => false,
    };

    if !is_dll && !has_clr_header && total_imports > 0 && total_imports <= 3 {
        risk_score = risk_score.saturating_add(35);
        detections.push(format!(
            "Hidden / Packed IAT: Suspiciously low import count ({})",
            total_imports
        ));
    }

    PeAuditResult {
        is_pe: true,
        is_64bit,
        entry_rva,
        image_base,
        total_imports,
        risk_score,
        detections,
        sections: section_audits,
    }
}

/// Generates a valid synthetic 64-bit PE image in memory containing:
/// - An executable section flagged RWX (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE = 0xA0000000)
/// - 1,024 high-entropy bytes (> 7.50 Shannon entropy) in the section's raw data
pub fn create_synthetic_rwx_pe() -> Vec<u8> {
    let mut pe = Vec::with_capacity(2048);

    // 1. DOS Header (64 bytes)
    pe.extend_from_slice(b"MZ"); // e_magic
    pe.resize(0x3C, 0); // pad to e_lfanew
    pe.extend_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 0x80
    pe.resize(0x80, 0); // pad to NT headers

    // 2. NT Signature ("PE\0\0")
    pe.extend_from_slice(b"PE\0\0");

    // 3. COFF File Header (20 bytes)
    pe.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
    pe.extend_from_slice(&1u16.to_le_bytes()); // NumberOfSections: 1
    pe.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    pe.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
    pe.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
    pe.extend_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader: 240 (0xF0)
    pe.extend_from_slice(&0x0022u16.to_le_bytes()); // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // 4. Optional Header PE32+ (240 bytes)
    pe.extend_from_slice(&0x020Bu16.to_le_bytes()); // Magic: PE32+ (64-bit)
    pe.push(1); // MajorLinkerVersion
    pe.push(0); // MinorLinkerVersion
    pe.extend_from_slice(&1024u32.to_le_bytes()); // SizeOfCode
    pe.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
    pe.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
    pe.extend_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    pe.extend_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    pe.extend_from_slice(&6u16.to_le_bytes()); // MajorOperatingSystemVersion
    pe.extend_from_slice(&0u16.to_le_bytes()); // MinorOperatingSystemVersion
    pe.extend_from_slice(&0u16.to_le_bytes()); // MajorImageVersion
    pe.extend_from_slice(&0u16.to_le_bytes()); // MinorImageVersion
    pe.extend_from_slice(&6u16.to_le_bytes()); // MajorSubsystemVersion
    pe.extend_from_slice(&0u16.to_le_bytes()); // MinorSubsystemVersion
    pe.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
    pe.extend_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    pe.extend_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
    pe.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
    pe.extend_from_slice(&3u16.to_le_bytes()); // Subsystem: Windows CUI
    pe.extend_from_slice(&0x8160u16.to_le_bytes()); // DllCharacteristics
    pe.extend_from_slice(&0x100000u64.to_le_bytes()); // SizeOfStackReserve
    pe.extend_from_slice(&0x1000u64.to_le_bytes()); // SizeOfStackCommit
    pe.extend_from_slice(&0x100000u64.to_le_bytes()); // SizeOfHeapReserve
    pe.extend_from_slice(&0x1000u64.to_le_bytes()); // SizeOfHeapCommit
    pe.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
    pe.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes: 16
    pe.extend_from_slice(&[0u8; 128]); // 16 Data Directories (16 * 8 = 128 bytes)

    // 5. Section Header (40 bytes)
    pe.extend_from_slice(b".text\0\0\0"); // Name (8 bytes)
    pe.extend_from_slice(&1024u32.to_le_bytes()); // VirtualSize
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    pe.extend_from_slice(&1024u32.to_le_bytes()); // SizeOfRawData
    pe.extend_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
    pe.extend_from_slice(&0u32.to_le_bytes()); // PointerToRelocations
    pe.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
    pe.extend_from_slice(&0u16.to_le_bytes()); // NumberOfRelocations
    pe.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
                                               // Characteristics: RWX (0x20000000 EXECUTE | 0x80000000 WRITE | 0x40000000 READ | 0x00000020 CODE = 0xE0000020)
    pe.extend_from_slice(&0xE0000020u32.to_le_bytes());

    // 6. Pad to PointerToRawData (0x400 = 1024 bytes)
    pe.resize(0x400, 0);

    // 7. Append 1,024 high-entropy bytes (4 of each 0..=255 -> entropy exactly 8.00)
    for _ in 0..4 {
        for b in 0..=255u8 {
            pe.push(b);
        }
    }

    pe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthetic_pe_rwx_and_entropy() {
        let pe_data = create_synthetic_rwx_pe();
        let audit = audit_pe_bytes(&pe_data);

        assert!(audit.is_pe, "Expected valid PE");
        assert!(audit.is_64bit, "Expected 64-bit PE");
        assert!(
            audit.risk_score >= 90,
            "Expected risk score >= 90 from RWX (+60) and high entropy (+40), got {}",
            audit.risk_score
        );

        let has_rwx = audit.sections.iter().any(|s| s.is_rwx);
        assert!(has_rwx, "Expected RWX section flagged");

        let has_high_ent = audit.sections.iter().any(|s| s.entropy > 7.5);
        assert!(has_high_ent, "Expected section entropy > 7.5");
    }

    #[test]
    fn test_non_pe_data() {
        let text = b"Not a portable executable file at all";
        let res = audit_pe_bytes(text);
        assert!(!res.is_pe);
        assert_eq!(res.risk_score, 0);
    }

    #[test]
    fn test_entropy_calculation() {
        // Uniform byte distribution has maximum entropy ~8.0
        let mut uniform = Vec::with_capacity(256 * 10);
        for _ in 0..10 {
            for b in 0..=255u8 {
                uniform.push(b);
            }
        }
        let ent = calculate_shannon_entropy(&uniform);
        assert!(ent > 7.95, "Uniform data entropy was {}", ent);

        // Constant byte sequence has entropy 0.0
        let zeroes = vec![0u8; 1024];
        let ent_zeroes = calculate_shannon_entropy(&zeroes);
        assert_eq!(ent_zeroes, 0.0);
    }
}
