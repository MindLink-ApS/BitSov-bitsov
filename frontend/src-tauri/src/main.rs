//! BitSov v2 desktop client — Tauri shell.
//!
//! The desktop app is a thin native wrapper around the SolidJS web frontend.
//! All node communication goes through the REST API + WebSocket — the Tauri
//! process does not run a node itself.
//!
//! Tauri commands can be added here for operations that benefit from native
//! access (e.g., reading the mnemonic file from disk, system notifications).

// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
