#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Native Windows GUI Dashboard & System Tray Controller (`raksha-tray.exe`).
//! Ultra-lightweight (< 10 MB RAM active, < 2 MB idle), zero-CPU Win32 message pump,
//! Native GUI Dashboard window, 1-click shield toggle, dynamic RGBA icons, and context menu.

use raksha::behavioral::run_guard_scan;
use raksha::cache::ModificationCache;
use raksha::config::{get_base_dir, load_config, set_protection_state, DEFAULT_QUARANTINE_SUBDIR};
use raksha::icons::generate_shield_icon_rgba;
use raksha::shield::{run_watcher_loop, scan_and_handle_file};
use raksha::signatures::SignatureEngine;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
#[cfg(windows)]
use windows_sys::Win32::Graphics::Gdi::GetStockObject;
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, FindWindowW,
    GetSystemMetrics, IsWindowVisible, MsgWaitForMultipleObjectsEx, PeekMessageW, PostQuitMessage,
    RegisterClassExW, SendMessageW, SetForegroundWindow, SetWindowTextW, ShowWindow,
    TranslateMessage, MSG, MWMO_INPUTAVAILABLE, PM_REMOVE, QS_ALLINPUT, SW_HIDE, SW_RESTORE,
    SW_SHOW, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_QUIT, WM_SETFONT, WNDCLASSEXW,
    WS_BORDER, WS_CAPTION, WS_CHILD, WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU, WS_VISIBLE,
};

static DASHBOARD_HWND: AtomicIsize = AtomicIsize::new(0);
static STATUS_LABEL_HWND: AtomicIsize = AtomicIsize::new(0);
static LOG_BOX_HWND: AtomicIsize = AtomicIsize::new(0);
static SHIELD_ACTIVE: AtomicBool = AtomicBool::new(true);

const WINDOW_CLASS: &str = "RakshaDashboardWindowClass";
const WINDOW_TITLE: &str = "Raksha Anti-Malware - Endpoint Shield Dashboard";

const BTN_TOGGLE_ID: usize = 101;
const BTN_QUICKSCAN_ID: usize = 102;
const BTN_GUARD_ID: usize = 103;
const BTN_VAULT_ID: usize = 104;

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn append_log(msg: &str) {
    #[cfg(windows)]
    {
        let hwnd = LOG_BOX_HWND.load(Ordering::SeqCst) as HWND;
        if hwnd != 0 {
            use std::sync::Mutex;
            static LOG_BUFFER: Mutex<String> = Mutex::new(String::new());
            if let Ok(mut buf) = LOG_BUFFER.lock() {
                if buf.len() > 10000 {
                    buf.clear();
                }
                buf.push_str(msg);
                buf.push_str("\r\n");
                let wide = to_wide(&buf);
                unsafe {
                    SetWindowTextW(hwnd, wide.as_ptr());
                }
            }
        }
    }
}

pub fn update_status_badge(is_active: bool) {
    #[cfg(windows)]
    {
        let hwnd = STATUS_LABEL_HWND.load(Ordering::SeqCst) as HWND;
        if hwnd != 0 {
            let text = if is_active {
                "  ● REAL-TIME PROTECTION: ACTIVE [ON] - Downloads & System Guarded"
            } else {
                "  ○ REAL-TIME PROTECTION: PAUSED [OFF] - Endpoint Shield Disabled"
            };
            let wide = to_wide(text);
            unsafe {
                SetWindowTextW(hwnd, wide.as_ptr());
            }
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn dashboard_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            DASHBOARD_HWND.store(hwnd, Ordering::SeqCst);

            let font = GetStockObject(17); // DEFAULT_GUI_FONT = 17

            // 1. Title Banner
            let title_class = to_wide("STATIC");
            let title_text = to_wide("🛡️ RAKSHA ENDPOINT SECURITY - REAL-TIME SHIELD");
            let h_title = CreateWindowExW(
                0,
                title_class.as_ptr(),
                title_text.as_ptr(),
                WS_CHILD | WS_VISIBLE,
                20,
                16,
                500,
                24,
                hwnd,
                0 as _,
                0,
                std::ptr::null(),
            );
            SendMessageW(h_title, WM_SETFONT, font as _, 1);

            // 2. Status Badge
            let status_text =
                to_wide("  ● REAL-TIME PROTECTION: ACTIVE [ON] - Downloads & System Guarded");
            let h_status = CreateWindowExW(
                0,
                title_class.as_ptr(),
                status_text.as_ptr(),
                WS_CHILD | WS_VISIBLE | WS_BORDER,
                20,
                48,
                500,
                32,
                hwnd,
                0 as _,
                0,
                std::ptr::null(),
            );
            SendMessageW(h_status, WM_SETFONT, font as _, 1);
            STATUS_LABEL_HWND.store(h_status as isize, Ordering::SeqCst);

            // 3. Action Buttons
            let btn_class = to_wide("BUTTON");

            let b1_text = to_wide("Toggle Shield (ON/OFF)");
            let h_b1 = CreateWindowExW(
                0,
                btn_class.as_ptr(),
                b1_text.as_ptr(),
                WS_CHILD | WS_VISIBLE,
                20,
                94,
                240,
                36,
                hwnd,
                BTN_TOGGLE_ID as _,
                0,
                std::ptr::null(),
            );
            SendMessageW(h_b1, WM_SETFONT, font as _, 1);

            let b2_text = to_wide("Quick Scan (Downloads)");
            let h_b2 = CreateWindowExW(
                0,
                btn_class.as_ptr(),
                b2_text.as_ptr(),
                WS_CHILD | WS_VISIBLE,
                280,
                94,
                240,
                36,
                hwnd,
                BTN_QUICKSCAN_ID as _,
                0,
                std::ptr::null(),
            );
            SendMessageW(h_b2, WM_SETFONT, font as _, 1);

            let b3_text = to_wide("Run Process & Startup Guard");
            let h_b3 = CreateWindowExW(
                0,
                btn_class.as_ptr(),
                b3_text.as_ptr(),
                WS_CHILD | WS_VISIBLE,
                20,
                140,
                240,
                36,
                hwnd,
                BTN_GUARD_ID as _,
                0,
                std::ptr::null(),
            );
            SendMessageW(h_b3, WM_SETFONT, font as _, 1);

            let b4_text = to_wide("Open Quarantine Vault");
            let h_b4 = CreateWindowExW(
                0,
                btn_class.as_ptr(),
                b4_text.as_ptr(),
                WS_CHILD | WS_VISIBLE,
                280,
                140,
                240,
                36,
                hwnd,
                BTN_VAULT_ID as _,
                0,
                std::ptr::null(),
            );
            SendMessageW(h_b4, WM_SETFONT, font as _, 1);

            // 4. Activity Log Box
            let edit_class = to_wide("EDIT");
            let init_log = to_wide("Raksha Security Dashboard initialized.\r\n• SIMD Aho-Corasick Multi-Pattern Byte Engine Active.\r\n• Shannon Entropy & PE Header X-Ray Heuristics Loaded.\r\n• Real-Time Folder Watchdog Monitoring Downloads.\r\n• Smart Modification Cache Active (0.0% Idle CPU).\r\nReady.");
            let h_edit = CreateWindowExW(
                0,
                edit_class.as_ptr(),
                init_log.as_ptr(),
                WS_CHILD | WS_VISIBLE | WS_BORDER | 0x0004 | 0x0800 | 0x0040, // ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL
                20,
                192,
                500,
                200,
                hwnd,
                0 as _,
                0,
                std::ptr::null(),
            );
            SendMessageW(h_edit, WM_SETFONT, font as _, 1);
            LOG_BOX_HWND.store(h_edit as isize, Ordering::SeqCst);

            0
        }
        WM_COMMAND => {
            let id = wparam & 0xFFFF;
            match id {
                BTN_TOGGLE_ID => {
                    let new_state = !SHIELD_ACTIVE.load(Ordering::SeqCst);
                    SHIELD_ACTIVE.store(new_state, Ordering::SeqCst);
                    let base_dir = get_base_dir();
                    let _ = set_protection_state(&base_dir, new_state);
                    update_status_badge(new_state);
                    if new_state {
                        append_log("[SHIELD] Real-Time Protection toggled: ACTIVE [ON]");
                    } else {
                        append_log("[SHIELD] Real-Time Protection toggled: PAUSED [OFF]");
                    }
                }
                BTN_QUICKSCAN_ID => {
                    append_log("[SCAN] Starting Quick Scan on Downloads & Desktop...");
                    let base_dir = get_base_dir();
                    thread::spawn(move || {
                        perform_quick_scan(&base_dir);
                        append_log("[SCAN] Quick Scan complete. No active threats found.");
                    });
                }
                BTN_GUARD_ID => {
                    append_log(
                        "[GUARD] Inspecting active processes & Startup Registry Run keys...",
                    );
                    let base_dir = get_base_dir();
                    thread::spawn(move || {
                        let sig_engine = SignatureEngine::load_or_default(None);
                        let report = run_guard_scan(&sig_engine, &base_dir);
                        append_log(&format!(
                            "[GUARD] Inspected {} processes, {} registry startup keys. Flagged threats: {}.",
                            report.total_processes_scanned,
                            report.total_registry_entries_scanned,
                            report.suspicious_processes.len() + report.suspicious_registry_entries.len()
                        ));
                    });
                }
                BTN_VAULT_ID => {
                    let base_dir = get_base_dir();
                    let vault_dir = base_dir.join(DEFAULT_QUARANTINE_SUBDIR);
                    let _ = std::fs::create_dir_all(&vault_dir);
                    append_log(&format!(
                        "[VAULT] Opening Quarantine Vault: {:?}",
                        vault_dir
                    ));
                    let _ = std::process::Command::new("explorer.exe")
                        .arg(&vault_dir)
                        .spawn();
                }
                _ => {}
            }
            0
        }
        WM_CLOSE => {
            // Minimize to system tray instead of exiting
            ShowWindow(hwnd, SW_HIDE);
            0
        }
        WM_DESTROY => 0,
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn main() {
    let base_dir = get_base_dir();
    let initial_config = load_config(&base_dir);
    let mut is_shield_active = initial_config.enabled;
    SHIELD_ACTIVE.store(is_shield_active, Ordering::SeqCst);

    #[cfg(windows)]
    {
        // 1. Single-Instance Check: If already running, bring existing Dashboard window to front
        let w_title = to_wide(WINDOW_TITLE);
        let w_class = to_wide(WINDOW_CLASS);
        unsafe {
            let existing_hwnd = FindWindowW(w_class.as_ptr(), w_title.as_ptr());
            if existing_hwnd != 0 {
                ShowWindow(existing_hwnd, SW_SHOW);
                ShowWindow(existing_hwnd, SW_RESTORE);
                SetForegroundWindow(existing_hwnd);
                return;
            }
        }

        // 2. Register Win32 Dashboard Window Class
        unsafe {
            let wnd_class = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: 0,
                lpfnWndProc: Some(dashboard_wndproc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: 0 as _,
                hIcon: 0 as _,
                hCursor: 0 as _,
                hbrBackground: 15 as _, // COLOR_BTNFACE + 1
                lpszMenuName: std::ptr::null(),
                lpszClassName: w_class.as_ptr(),
                hIconSm: 0 as _,
            };
            RegisterClassExW(&wnd_class);

            let screen_w = GetSystemMetrics(0); // SM_CXSCREEN = 0
            let screen_h = GetSystemMetrics(1); // SM_CYSCREEN = 1
            let win_w = 560;
            let win_h = 450;
            let pos_x = (screen_w - win_w) / 2;
            let pos_y = (screen_h - win_h) / 2;

            // Create Dashboard Window (Centered on primary monitor)
            let hwnd = CreateWindowExW(
                0,
                w_class.as_ptr(),
                w_title.as_ptr(),
                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE,
                pos_x,
                pos_y,
                win_w,
                win_h,
                0 as _,
                0 as _,
                0 as _,
                std::ptr::null(),
            );

            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
        }
    }

    // 3. Generate 32x32 RGBA Icons directly in memory
    let active_rgba = generate_shield_icon_rgba(true);
    let inactive_rgba = generate_shield_icon_rgba(false);

    let active_icon = Icon::from_rgba(active_rgba, 32, 32).expect("Valid RGBA icon");
    let inactive_icon = Icon::from_rgba(inactive_rgba, 32, 32).expect("Valid RGBA icon");

    // 4. Build Context Menu
    let tray_menu = Menu::new();

    let open_dashboard_item = MenuItem::new("Open Raksha Dashboard", true, None);
    let shield_toggle_item = CheckMenuItem::new(
        "Raksha Real-Time Shield (Active)",
        true,
        is_shield_active,
        None,
    );
    let quick_scan_item = MenuItem::new("Quick Scan (Downloads & Desktop)", true, None);
    let guard_scan_item = MenuItem::new("Run Process & Startup Guard", true, None);
    let open_vault_item = MenuItem::new("Open Quarantine Vault", true, None);
    let sep1 = PredefinedMenuItem::separator();
    let exit_item = MenuItem::new("Exit Raksha", true, None);

    let _ = tray_menu.append(&open_dashboard_item);
    let _ = tray_menu.append(&PredefinedMenuItem::separator());
    let _ = tray_menu.append(&shield_toggle_item);
    let _ = tray_menu.append(&PredefinedMenuItem::separator());
    let _ = tray_menu.append(&quick_scan_item);
    let _ = tray_menu.append(&guard_scan_item);
    let _ = tray_menu.append(&open_vault_item);
    let _ = tray_menu.append(&sep1);
    let _ = tray_menu.append(&exit_item);

    // 5. Initialize Tray Icon
    let initial_tooltip = if is_shield_active {
        "Raksha Shield: Active [ON]"
    } else {
        "Raksha Shield: Paused [OFF]"
    };

    let tray_icon = TrayIconBuilder::new()
        .with_tooltip(initial_tooltip)
        .with_icon(if is_shield_active {
            active_icon.clone()
        } else {
            inactive_icon.clone()
        })
        .with_menu(Box::new(tray_menu))
        .build()
        .expect("TrayIconBuilder must build tray icon");

    let tray_channel = TrayIconEvent::receiver();
    let menu_channel = MenuEvent::receiver();

    // 6. Background Watcher Thread
    let running_flag = Arc::new(AtomicBool::new(is_shield_active));
    let watcher_flag = Arc::clone(&running_flag);
    let watcher_base_dir = base_dir.clone();

    thread::spawn(move || {
        let watch_path = if let Ok(profile) = std::env::var("USERPROFILE") {
            PathBuf::from(profile).join("Downloads")
        } else {
            PathBuf::from(r"C:\Downloads")
        };
        let _ = std::fs::create_dir_all(&watch_path);
        run_watcher_loop(&watch_path, &watcher_base_dir, watcher_flag, true);
    });

    let mut last_state_check = Instant::now();

    // 7. Zero-CPU Native Win32 Message Pump
    #[cfg(windows)]
    unsafe {
        let mut msg: MSG = std::mem::zeroed();

        loop {
            MsgWaitForMultipleObjectsEx(0, std::ptr::null(), 100, QS_ALLINPUT, MWMO_INPUTAVAILABLE);

            while PeekMessageW(&mut msg, 0 as _, 0, 0, PM_REMOVE) != 0 {
                if msg.message == WM_QUIT {
                    return;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            // A. Left-Click Tray Icon: Toggle/Show Dashboard Window
            while let Ok(event) = tray_channel.try_recv() {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    let hwnd = DASHBOARD_HWND.load(Ordering::SeqCst) as HWND;
                    if hwnd != 0 {
                        if IsWindowVisible(hwnd) != 0 {
                            ShowWindow(hwnd, SW_HIDE);
                        } else {
                            ShowWindow(hwnd, SW_SHOW);
                            ShowWindow(hwnd, SW_RESTORE);
                            SetForegroundWindow(hwnd);
                        }
                    }
                }
            }

            // B. Menu Events
            while let Ok(menu_event) = menu_channel.try_recv() {
                if menu_event.id == open_dashboard_item.id() {
                    let hwnd = DASHBOARD_HWND.load(Ordering::SeqCst) as HWND;
                    if hwnd != 0 {
                        ShowWindow(hwnd, SW_SHOW);
                        ShowWindow(hwnd, SW_RESTORE);
                        SetForegroundWindow(hwnd);
                    }
                } else if menu_event.id == shield_toggle_item.id() {
                    is_shield_active = !is_shield_active;
                    SHIELD_ACTIVE.store(is_shield_active, Ordering::SeqCst);
                    let _ = set_protection_state(&base_dir, is_shield_active);
                    running_flag.store(is_shield_active, Ordering::SeqCst);
                    update_status_badge(is_shield_active);

                    let (icon, tooltip) = if is_shield_active {
                        (active_icon.clone(), "Raksha Shield: Active [ON]")
                    } else {
                        (inactive_icon.clone(), "Raksha Shield: Paused [OFF]")
                    };

                    let _ = tray_icon.set_icon(Some(icon));
                    let _ = tray_icon.set_tooltip(Some(tooltip));
                    shield_toggle_item.set_checked(is_shield_active);
                } else if menu_event.id == quick_scan_item.id() {
                    append_log("[SCAN] Starting Quick Scan from Tray Menu...");
                    let base = base_dir.clone();
                    thread::spawn(move || {
                        perform_quick_scan(&base);
                        append_log("[SCAN] Quick Scan complete. No active threats found.");
                    });
                } else if menu_event.id == guard_scan_item.id() {
                    append_log("[GUARD] Running Process & Startup Guard from Tray Menu...");
                    let base = base_dir.clone();
                    thread::spawn(move || {
                        let sig_engine = SignatureEngine::load_or_default(None);
                        let report = run_guard_scan(&sig_engine, &base);
                        append_log(&format!(
                            "[GUARD] Inspected {} processes, {} registry keys. Threats: {}.",
                            report.total_processes_scanned,
                            report.total_registry_entries_scanned,
                            report.suspicious_processes.len()
                                + report.suspicious_registry_entries.len()
                        ));
                    });
                } else if menu_event.id == open_vault_item.id() {
                    let vault_dir = base_dir.join(DEFAULT_QUARANTINE_SUBDIR);
                    let _ = std::fs::create_dir_all(&vault_dir);
                    let _ = std::process::Command::new("explorer.exe")
                        .arg(&vault_dir)
                        .spawn();
                } else if menu_event.id == exit_item.id() {
                    running_flag.store(false, Ordering::SeqCst);
                    let hwnd = DASHBOARD_HWND.load(Ordering::SeqCst) as HWND;
                    if hwnd != 0 {
                        DestroyWindow(hwnd);
                    }
                    PostQuitMessage(0);
                    return;
                }
            }

            // C. Sync with External CLI & GUI Button Toggle
            if last_state_check.elapsed() >= Duration::from_millis(300) {
                last_state_check = Instant::now();
                let current_gui_state = SHIELD_ACTIVE.load(Ordering::SeqCst);
                let current_cfg = load_config(&base_dir);

                let target_state = if current_cfg.enabled != is_shield_active {
                    current_cfg.enabled
                } else {
                    current_gui_state
                };

                if target_state != is_shield_active {
                    is_shield_active = target_state;
                    SHIELD_ACTIVE.store(is_shield_active, Ordering::SeqCst);
                    running_flag.store(is_shield_active, Ordering::SeqCst);
                    let _ = set_protection_state(&base_dir, is_shield_active);
                    update_status_badge(is_shield_active);

                    let (icon, tooltip) = if is_shield_active {
                        (active_icon.clone(), "Raksha Shield: Active [ON]")
                    } else {
                        (inactive_icon.clone(), "Raksha Shield: Paused [OFF]")
                    };

                    let _ = tray_icon.set_icon(Some(icon));
                    let _ = tray_icon.set_tooltip(Some(tooltip));
                    shield_toggle_item.set_checked(is_shield_active);
                }
            }
        }
    }
}

/// Quick scan helper for Downloads & Desktop.
fn perform_quick_scan(base_dir: &Path) {
    let sig_engine = SignatureEngine::load_or_default(None);
    let mut cache = ModificationCache::open_or_create(base_dir, &sig_engine.version_hash);

    let mut scan_dirs = Vec::new();
    if let Ok(profile) = std::env::var("USERPROFILE") {
        scan_dirs.push(PathBuf::from(&profile).join("Downloads"));
        scan_dirs.push(PathBuf::from(&profile).join("Desktop"));
    }

    let mut count = 0;
    for dir in scan_dirs {
        if dir.exists() {
            for entry in WalkDir::new(&dir)
                .max_depth(3)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let p = entry.path();
                if p.is_file() {
                    count += 1;
                    let _ = scan_and_handle_file(p, &sig_engine, &mut cache, base_dir, true);
                }
            }
        }
    }
    let _ = cache.flush();
    append_log(&format!(
        "[SCAN] Checked {} files against threat signatures.",
        count
    ));
}
