//! macOS autofill: synthesize keystrokes into the frontmost app.
//! `paste()` writes the concealed clipboard then posts ⌘V; `type_text()`
//! posts per-char Unicode keyboard events so the secret NEVER touches the
//! pasteboard. Either way the secret stays inside this process — no JS,
//! no AppleScript, no argv.
//!
//! Posting events requires "post event" (Accessibility) permission for the
//! responsible app — Raycast when driven by the extension, the terminal
//! when run by hand. `CGPreflightPostEventAccess` is the honest check;
//! `CGRequestPostEventAccess` triggers the system prompt once.

use std::ffi::c_void;

type CGEventRef = *mut c_void;
type CGEventSourceRef = *const c_void;

const K_CG_HID_EVENT_TAP: u32 = 0;
// events created without a real source get silently filtered on modern
// macOS — CGEventPost is void so the drop is invisible. Always source them.
const K_CG_EVENT_SOURCE_STATE_HID_SYSTEM: u32 = 1;
const K_VK_TAB: u16 = 0x30;

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGEventSourceCreate(state: u32) -> CGEventSourceRef;
    fn CGEventCreateKeyboardEvent(src: CGEventSourceRef, key: u16, down: bool) -> CGEventRef;
    fn CGEventKeyboardSetUnicodeString(ev: CGEventRef, len: usize, s: *const u16);
    fn CGEventPost(tap: u32, ev: CGEventRef);
    fn CGPreflightPostEventAccess() -> bool;
    fn CGRequestPostEventAccess() -> bool;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(cf: *const c_void);
}

/// Preflight + optional prompt — call BEFORE publishing a secret so a
/// denied permission never sees the clipboard populated pointlessly.
pub fn preflight() -> Result<(), String> {
    if unsafe { CGPreflightPostEventAccess() } {
        return Ok(());
    }
    // triggers the system consent dialog once; still false → tell the user
    // exactly which app to grant (the launcher, not mypassman itself)
    unsafe { CGRequestPostEventAccess() };
    if unsafe { CGPreflightPostEventAccess() } {
        return Ok(());
    }
    Err(
        "autofill needs Accessibility access for the app that launched \
mypassman (Raycast or your terminal): System Settings → Privacy & Security → \
Accessibility"
            .into(),
    )
}

/// Focus needs a beat to return to the target app after a launcher
/// (Raycast) closes its window. Tunable via MPM_FILL_DELAY_MS.
fn settle() {
    let ms = std::env::var("MPM_FILL_DELAY_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(350);
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

fn post_key(key: u16, utf16: &[u16]) -> Result<(), String> {
    unsafe {
        let src = CGEventSourceCreate(K_CG_EVENT_SOURCE_STATE_HID_SYSTEM);
        if src.is_null() {
            return Err("CGEventSourceCreate failed".into());
        }
        for down in [true, false] {
            let ev = CGEventCreateKeyboardEvent(src, key, down);
            if ev.is_null() {
                CFRelease(src);
                return Err("CGEventCreateKeyboardEvent failed".into());
            }
            if !utf16.is_empty() {
                CGEventKeyboardSetUnicodeString(ev, utf16.len(), utf16.as_ptr());
            }
            CGEventPost(K_CG_HID_EVENT_TAP, ev);
            CFRelease(ev);
        }
        CFRelease(src);
    }
    Ok(())
}

/// Simulate ⌘V via System Events — the concealed clipboard write already
/// happened. CGEvent-posted keys get silently dropped for spawned CLI
/// children on modern macOS; System Events is the TCC-trusted broker every
/// launcher script relies on. No secret crosses argv — just the keystroke.
pub fn paste() -> Result<(), String> {
    settle();
    let out = std::process::Command::new("osascript")
        .args([
            "-e",
            "tell application \"System Events\" to keystroke \"v\" using command down",
        ])
        // never forward credential env vars to a subprocess we don't own
        .env_remove("MPM_PASSWORD")
        .env_remove("MPM_EXPORT_PASSWORD")
        .output()
        .map_err(|e| format!("osascript spawn: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(format!(
        "System Events keystroke denied ({err}) — grant Automation access: \
System Settings → Privacy & Security → Automation"
    ))
}

/// Type each part in order, Tab between them — `user⇥pass` form fill.
/// Per-char events (not one big string) for compatibility with fields
/// that drop multi-char synthetic input.
pub fn type_seq(parts: &[&str]) -> Result<(), String> {
    // unbounded typing is a self-DoS: at ~9ms/char a pathological field
    // would type for hours into wherever focus wanders. Bound it.
    let cap: usize = std::env::var("MPM_TYPE_MAX_CHARS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4096);
    let total: usize = parts.iter().map(|p| p.chars().count()).sum();
    if total > cap {
        return Err(format!(
            "{total} chars to type exceeds {cap} cap — copy instead"
        ));
    }
    preflight()?;
    settle();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            post_key(K_VK_TAB, &[])?;
            // JS-heavy forms re-render on Tab — give the next field a beat
            // before its input starts arriving
            std::thread::sleep(std::time::Duration::from_millis(80));
        }
        type_chars(part)?;
    }
    Ok(())
}

fn type_chars(text: &str) -> Result<(), String> {
    for ch in text.chars() {
        let mut buf = [0u16; 2];
        let units = ch.encode_utf16(&mut buf);
        post_key(0, units)?;
        std::thread::sleep(std::time::Duration::from_millis(9));
    }
    Ok(())
}
