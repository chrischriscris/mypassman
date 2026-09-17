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
const K_CG_EVENT_FLAG_MASK_COMMAND: u64 = 0x0010_0000;
const K_VK_ANSI_V: u16 = 0x09;

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGEventCreateKeyboardEvent(src: CGEventSourceRef, key: u16, down: bool) -> CGEventRef;
    fn CGEventKeyboardSetUnicodeString(ev: CGEventRef, len: usize, s: *const u16);
    fn CGEventSetFlags(ev: CGEventRef, flags: u64);
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
        .unwrap_or(200);
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

fn post_key(key: u16, cmd: bool, utf16: &[u16]) -> Result<(), String> {
    unsafe {
        for down in [true, false] {
            let ev = CGEventCreateKeyboardEvent(std::ptr::null(), key, down);
            if ev.is_null() {
                return Err("CGEventCreateKeyboardEvent failed".into());
            }
            if cmd {
                CGEventSetFlags(ev, K_CG_EVENT_FLAG_MASK_COMMAND);
            }
            if !utf16.is_empty() {
                CGEventKeyboardSetUnicodeString(ev, utf16.len(), utf16.as_ptr());
            }
            CGEventPost(K_CG_HID_EVENT_TAP, ev);
            CFRelease(ev);
        }
    }
    Ok(())
}

/// Simulate ⌘V — the concealed clipboard write already happened.
pub fn paste() -> Result<(), String> {
    preflight()?;
    settle();
    post_key(K_VK_ANSI_V, true, &[])
}

/// Type `text` char-by-char as Unicode events — zero clipboard use.
/// Per-char events (not one big string) for compatibility with fields
/// that drop multi-char synthetic input.
pub fn type_text(text: &str) -> Result<(), String> {
    preflight()?;
    settle();
    for ch in text.chars() {
        let mut buf = [0u16; 2];
        let units = ch.encode_utf16(&mut buf);
        post_key(0, false, units)?;
        std::thread::sleep(std::time::Duration::from_millis(9));
    }
    Ok(())
}
