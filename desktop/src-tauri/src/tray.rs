//! Menu-bar (macOS) / tray (Windows) quick access and the global-shortcut
//! quick-search window (spec: quick access and global shortcut).

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{App, Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

use crate::state::VaultState;

/// Build the tray/menu-bar icon with quick actions.
pub fn setup_tray(app: &App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open vault", true, None::<&str>)?;
    let quick = MenuItem::with_id(app, "quick", "Quick search", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock vault", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quick, &lock, &quit])?;

    TrayIconBuilder::new()
        .icon(app.default_window_icon().unwrap().clone())
        .tooltip("Vault")
        .menu(&menu)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main(app),
            "quick" => toggle_quick(app),
            "lock" => app.state::<VaultState>().lock_now(),
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

/// Register the configurable global shortcut that toggles the quick-search
/// window (default ⌘/Ctrl+Shift+Space).
pub fn register_quick_shortcut(app: &App) -> tauri::Result<()> {
    let shortcut = Shortcut::new(Some(Modifiers::SUPER | Modifiers::SHIFT), Code::Space);
    app.global_shortcut()
        .on_shortcut(shortcut, move |app, _shortcut, event| {
            if event.state() == ShortcutState::Pressed {
                toggle_quick(app);
            }
        })
        .map_err(|e| tauri::Error::Anyhow(e.into()))?;
    Ok(())
}

fn show_main<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

/// Show/focus the quick-search window, creating it on first use. It never
/// renders secrets while locked (the UI route guards on unlock state) and hides
/// on focus loss.
fn toggle_quick<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(win) = app.get_webview_window("quick") {
        if win.is_visible().unwrap_or(false) {
            let _ = win.hide();
        } else {
            let _ = win.show();
            let _ = win.set_focus();
        }
        return;
    }
    let win = WebviewWindowBuilder::new(app, "quick", WebviewUrl::App("quick".into()))
        .title("Quick search")
        .inner_size(620.0, 420.0)
        .decorations(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .build();
    if let Ok(win) = win {
        let handle = win.clone();
        // Dismiss on focus loss.
        win.on_window_event(move |event| {
            if let tauri::WindowEvent::Focused(false) = event {
                let _ = handle.hide();
            }
        });
        let _ = win.set_focus();
    }
}
