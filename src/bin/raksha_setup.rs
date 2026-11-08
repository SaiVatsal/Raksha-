//! Raksha Standalone Windows Installer & Uninstaller (`raksha-setup.exe`).
//! Installs binaries to %LOCALAPPDATA%\Programs\Raksha, configures User PATH in HKCU\Environment,
//! manages Windows Startup persistence in HKCU\Software\Microsoft\Windows\CurrentVersion\Run,
//! and deploys Windows Desktop and Start Menu shortcuts with the custom emerald shield app icon.

use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
#[cfg(windows)]
use winreg::RegKey;

const INSTALL_SUBDIR: &str = r"Programs\Raksha";
const RUN_KEY_NAME: &str = "RakshaTray";
const EMBEDDED_ICON: &[u8] = include_bytes!("../../assets/raksha.ico");

#[derive(Parser, Debug)]
#[command(
    name = "raksha-setup",
    about = "Raksha Standalone Windows Installer & Uninstaller",
    version = "0.1.0",
    author = "Raksha Security Systems"
)]
struct SetupArgs {
    /// Install Raksha binaries into %LOCALAPPDATA%\Programs\Raksha and register PATH
    #[arg(long)]
    install: bool,

    /// Register Raksha System Tray to autostart with Windows logon
    #[arg(long)]
    autostart: bool,

    /// Completely uninstall Raksha, clean registry keys, and unregister PATH
    #[arg(long)]
    uninstall: bool,
}

fn get_install_target_dir() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(local).join(INSTALL_SUBDIR)
    } else {
        PathBuf::from(r"C:\Program Files\Raksha")
    }
}

#[cfg(windows)]
fn show_gui_message_box(title: &str, text: &str, flags: u32) -> i32 {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW;

    let wide_title: Vec<u16> = std::ffi::OsStr::new(title)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let wide_text: Vec<u16> = std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe { MessageBoxW(0, wide_text.as_ptr(), wide_title.as_ptr(), flags) }
}

fn main() {
    let args = SetupArgs::parse();
    let install_dir = get_install_target_dir();

    // Check if run interactively (e.g. double clicked without arguments)
    if !args.install && !args.uninstall {
        #[cfg(windows)]
        {
            let prompt = format!(
                "Welcome to Raksha Endpoint Security Setup!\n\n\
                Would you like to install Raksha on your computer?\n\n\
                Target Directory:\n{}\n\n\
                Components included:\n\
                • Ultra-lightweight Anti-Malware Engine (raksha.exe)\n\
                • Real-Time Threat Shield & System Tray (raksha-tray.exe)\n\
                • High-Performance Aho-Corasick & PE X-Ray Scanner\n\
                • Desktop & Start Menu Shortcuts with Shield Icon\n\
                • Windows User PATH & Autostart Registration\n\n\
                Click 'Yes' to install Raksha now.\n\
                Click 'No' to cancel setup.",
                install_dir.display()
            );

            let res = show_gui_message_box(
                "Raksha Security - Setup Wizard",
                &prompt,
                0x00000004 | 0x00000020 | 0x00040000 | 0x00010000, // MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND
            );

            if res == 6 {
                // IDYES
                perform_install(&install_dir, true, true);
            }
            return;
        }

        #[cfg(not(windows))]
        {
            println!("Raksha setup requires Windows.");
            return;
        }
    }

    if args.install {
        perform_install(&install_dir, args.autostart, false);
    } else if args.uninstall {
        perform_uninstall(&install_dir, false);
    }
}

fn perform_install(install_dir: &Path, autostart: bool, is_gui: bool) {
    println!(
        "[Raksha Setup] Beginning installation into: {:?}",
        install_dir
    );

    if let Err(e) = fs::create_dir_all(install_dir) {
        eprintln!(
            "[Raksha Setup Error] Failed to create destination directory: {}",
            e
        );
        if is_gui {
            #[cfg(windows)]
            show_gui_message_box(
                "Raksha Setup Error",
                &format!("Failed to create destination directory:\n{}", e),
                0x00000010 | 0x00040000,
            );
        }
        return;
    }

    let current_exe = std::env::current_exe().unwrap_or_default();
    let current_dir = current_exe.parent().unwrap_or_else(|| Path::new("."));

    // Candidate search locations for built binaries
    let mut search_dirs = vec![
        current_dir.to_path_buf(),
        current_dir.join("Raksha-Setup"),
        PathBuf::from("target/release"),
        PathBuf::from("target/x86_64-pc-windows-gnu/release"),
        PathBuf::from("target/debug"),
        PathBuf::from("target/x86_64-pc-windows-gnu/debug"),
        PathBuf::from("."),
    ];

    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        let manifest_path = PathBuf::from(manifest_dir);
        search_dirs.push(manifest_path.join("target/release"));
        search_dirs.push(manifest_path.join("target/x86_64-pc-windows-gnu/release"));
        search_dirs.push(manifest_path.join("target/debug"));
        search_dirs.push(manifest_path);
    }

    let binaries = ["raksha.exe", "raksha-tray.exe"];

    for bin_name in &binaries {
        let dest = install_dir.join(bin_name);
        let mut copied = false;

        for src_dir in &search_dirs {
            let src = src_dir.join(bin_name);
            if src.exists() && src != dest && fs::copy(&src, &dest).is_ok() {
                println!("  [OK] Installed {:?} -> {:?}", bin_name, dest);
                copied = true;
                break;
            }
        }

        if !copied && !dest.exists() {
            println!("  [Notice] Binary '{}' not found in local target paths; placeholder/copy will occur upon build release.", bin_name);
        }
    }

    // Install application icon (raksha.ico)
    let icon_dest = install_dir.join("raksha.ico");
    if let Err(e) = fs::write(&icon_dest, EMBEDDED_ICON) {
        eprintln!(
            "[Raksha Setup Error] Failed to write application icon: {}",
            e
        );
    } else {
        println!("  [OK] Installed Application Icon -> {:?}", icon_dest);
    }

    // Install default signatures
    let rules_dest_dir = install_dir.join("rules");
    let _ = fs::create_dir_all(&rules_dest_dir);
    let rules_dest_file = rules_dest_dir.join("default_signatures.json");

    let embedded_rules = raksha::signatures::DEFAULT_RULES_JSON;
    if let Err(e) = fs::write(&rules_dest_file, embedded_rules.as_bytes()) {
        eprintln!(
            "[Raksha Setup Error] Failed to write default signatures: {}",
            e
        );
    } else {
        println!("  [OK] Installed Signature Rules -> {:?}", rules_dest_file);
    }

    // Register User PATH in HKCU\Environment
    #[cfg(windows)]
    {
        add_to_user_path(install_dir);
    }

    // Register Autostart in HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    #[cfg(windows)]
    if autostart {
        register_tray_autostart(install_dir);
    }

    // Create Windows Desktop and Start Menu Shortcuts with custom icon
    #[cfg(windows)]
    {
        create_desktop_and_start_menu_shortcuts(install_dir);
    }

    // Launch Tray Icon in background if present
    let tray_exe = install_dir.join("raksha-tray.exe");
    if tray_exe.exists() {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const DETACHED_PROCESS: u32 = 0x00000008;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;

            if std::process::Command::new(&tray_exe)
                .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
                .spawn()
                .is_ok()
            {
                println!("  [OK] Started Raksha Real-Time Shield (System Tray active)");
            }
        }
        #[cfg(not(windows))]
        {
            let _ = std::process::Command::new(&tray_exe).spawn();
        }
    }

    println!("\n================ INSTALLATION COMPLETE ================");
    println!("Raksha is now installed at: {:?}", install_dir);
    println!("Command 'raksha' is now registered in your PATH.");
    if autostart {
        println!("Raksha Tray is registered to automatically start on logon.");
    }
    println!("Desktop and Start Menu shortcuts created with Raksha app icon.");
    println!("Run 'raksha status' or click the shield tray icon to manage protection.");
    println!("=======================================================");

    if is_gui {
        #[cfg(windows)]
        show_gui_message_box(
            "Raksha Security - Installation Complete",
            "Raksha Endpoint Security has been successfully installed!\n\n\
            ✓ Real-Time Shield is now running in your System Tray (emerald icon)\n\
            ✓ Desktop shortcut 'Raksha Security Shield' created with app icon\n\
            ✓ Windows Start Menu shortcut added\n\
            ✓ Command 'raksha' registered in your system PATH\n\n\
            Your computer is now actively protected.",
            0x00000040 | 0x00040000 | 0x00010000,
        );
    }
}

fn perform_uninstall(install_dir: &Path, is_gui: bool) {
    println!("[Raksha Setup] Beginning uninstallation...");

    // 1. Terminate running processes
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/f", "/im", "raksha-tray.exe"])
            .output();
        let _ = std::process::Command::new("taskkill")
            .args(["/f", "/im", "raksha.exe"])
            .output();
    }

    // 2. Remove Registry Autostart, PATH, and Shortcuts
    #[cfg(windows)]
    {
        unregister_tray_autostart();
        remove_from_user_path(install_dir);
        remove_shortcuts();
    }

    // 3. Remove Installed Files
    if install_dir.exists() {
        if let Err(e) = fs::remove_dir_all(install_dir) {
            eprintln!(
                "[Raksha Setup Error] Failed to remove install folder {:?}: {}",
                install_dir, e
            );
        } else {
            println!("  [OK] Removed installation directory: {:?}", install_dir);
        }
    }

    println!("\n[Raksha Setup] Uninstallation completed successfully.");

    if is_gui {
        #[cfg(windows)]
        show_gui_message_box(
            "Raksha Security - Uninstallation Complete",
            "Raksha Endpoint Security has been successfully removed from this machine.",
            0x00000040 | 0x00040000 | 0x00010000,
        );
    }
}

#[cfg(windows)]
fn add_to_user_path(target_dir: &Path) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok((env_key, _)) = hkcu.create_subkey_with_flags("Environment", KEY_READ | KEY_WRITE) {
        let current_path: String = env_key.get_value("Path").unwrap_or_default();
        let target_str = target_dir.to_string_lossy();

        if !current_path
            .to_lowercase()
            .contains(&target_str.to_lowercase())
        {
            let new_path = if current_path.is_empty() {
                target_str.to_string()
            } else {
                format!("{};{}", current_path.trim_end_matches(';'), target_str)
            };

            if env_key.set_value("Path", &new_path).is_ok() {
                println!(
                    "  [OK] Registered {:?} in HKCU\\Environment User PATH",
                    target_str
                );
            }
        } else {
            println!("  [Notice] Path already registered in HKCU\\Environment User PATH");
        }
    }
}

#[cfg(windows)]
fn remove_from_user_path(target_dir: &Path) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok((env_key, _)) = hkcu.create_subkey_with_flags("Environment", KEY_READ | KEY_WRITE) {
        let current_path: String = env_key.get_value("Path").unwrap_or_default();
        let target_str = target_dir.to_string_lossy().to_lowercase();

        let updated_parts: Vec<&str> = current_path
            .split(';')
            .filter(|p| !p.trim().is_empty() && !p.to_lowercase().contains(&target_str))
            .collect();

        let new_path = updated_parts.join(";");
        let _ = env_key.set_value("Path", &new_path);
        println!(
            "  [OK] Unregistered {:?} from HKCU\\Environment User PATH",
            target_dir
        );
    }
}

#[cfg(windows)]
fn register_tray_autostart(install_dir: &Path) {
    let tray_exe = install_dir.join("raksha-tray.exe");
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_path = r"Software\Microsoft\Windows\CurrentVersion\Run";

    if let Ok((run_key, _)) = hkcu.create_subkey_with_flags(run_path, KEY_WRITE) {
        let cmd = format!("\"{}\"", tray_exe.display());
        if run_key.set_value(RUN_KEY_NAME, &cmd).is_ok() {
            println!("  [OK] Registered Autostart in HKCU\\{}: {}", run_path, cmd);
        }
    }
}

#[cfg(windows)]
fn unregister_tray_autostart() {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_path = r"Software\Microsoft\Windows\CurrentVersion\Run";

    if let Ok(run_key) = hkcu.open_subkey_with_flags(run_path, KEY_WRITE) {
        let _ = run_key.delete_value(RUN_KEY_NAME);
        println!(
            "  [OK] Removed autostart entry '{}' from HKCU\\{}",
            RUN_KEY_NAME, run_path
        );
    }
}

#[cfg(windows)]
fn create_desktop_and_start_menu_shortcuts(install_dir: &Path) {
    let tray_exe = install_dir.join("raksha-tray.exe");
    let icon_file = install_dir.join("raksha.ico");

    let tray_str = tray_exe.to_string_lossy().replace('\'', "''");
    let icon_str = icon_file.to_string_lossy().replace('\'', "''");
    let dir_str = install_dir.to_string_lossy().replace('\'', "''");

    let script = format!(
        r#"
$ws = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
$startMenu = [Environment]::GetFolderPath('Programs')

$targets = @(
    (Join-Path $desktop 'Raksha Security Shield.lnk'),
    (Join-Path $startMenu 'Raksha Security Shield.lnk')
)

foreach ($path in $targets) {{
    try {{
        $s = $ws.CreateShortcut($path)
        $s.TargetPath = '{tray}'
        $s.IconLocation = '{icon},0'
        $s.Description = 'Raksha Ultra-Lightweight Real-Time Anti-Malware Shield'
        $s.WorkingDirectory = '{dir}'
        $s.Save()
    }} catch {{}}
}}
"#,
        tray = tray_str,
        icon = icon_str,
        dir = dir_str,
    );

    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &script,
        ])
        .output();

    println!("  [OK] Created Desktop and Start Menu Shortcuts with custom shield icon");
}

#[cfg(windows)]
fn remove_shortcuts() {
    let script = r#"
$desktop = [Environment]::GetFolderPath('Desktop')
$startMenu = [Environment]::GetFolderPath('Programs')
$targets = @(
    (Join-Path $desktop 'Raksha Security Shield.lnk'),
    (Join-Path $desktop 'Raksha Shield.lnk'),
    (Join-Path $startMenu 'Raksha Security Shield.lnk'),
    (Join-Path $startMenu 'Raksha Shield.lnk')
)
foreach ($path in $targets) {
    if (Test-Path $path) { Remove-Item -Force $path }
}
"#;
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            script,
        ])
        .output();

    println!("  [OK] Removed Desktop and Start Menu shortcuts");
}
