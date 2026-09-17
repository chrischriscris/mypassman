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

/// Verify-and-paste in ONE JXA eval: the expected pasteboard content
/// arrives on stdin (bytes — never argv/env/script text); the general
/// pasteboard is compared against it and System Events posts ⌘V only on
/// an exact match. Compare and keystroke are adjacent statements in one
/// process — no window for a concurrent clipboard write to swap contents
/// under us. On keystroke failure the payload is cleared iff it's still
/// ours. Exit codes: 3 = clipboard changed; 4 = keystroke denied; 5 = bad input.
pub fn paste(expected: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    settle();
    // JXA quirk: zero-arg ObjC methods auto-invoke on property access —
    // `pb.clearContents` IS the call; `clearContents()` throws "not a
    // function". Only methods with arguments take parens.
    const JXA: &str = r#"
ObjC.import('AppKit');
ObjC.import('stdlib');
var d = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
var s = $.NSString.alloc.initWithDataEncoding(d, $.NSUTF8StringEncoding);
if (s === null) { $.exit(5); }
s = s.js;
var pb = $.NSPasteboard.generalPasteboard;
var cur = pb.stringForType('public.utf8-plain-text');
if (cur === null || cur.js !== s) { $.exit(3); }
try {
    Application('System Events').keystroke('v', {using: 'command down'});
} catch (e) {
    if (pb.stringForType('public.utf8-plain-text').js === s) {
        pb.clearContents;
    }
    $.exit(4);
}
"#;
    let mut p = Command::new("osascript")
        .args(["-l", "JavaScript", "-e", JXA])
        .stdin(Stdio::piped())
        // never forward credential env vars to a subprocess we don't own
        .env_remove("MPM_PASSWORD")
        .env_remove("MPM_EXPORT_PASSWORD")
        .spawn()
        .map_err(|e| format!("osascript spawn: {e}"))?;
    p.stdin
        .take()
        .unwrap()
        .write_all(expected)
        .map_err(|e| e.to_string())?;
    match p.wait().map_err(|e| e.to_string())?.code() {
        Some(0) => Ok(()),
        Some(3) => Err("clipboard changed since the copy — refused to paste".into()),
        Some(4) => Err(
            "System Events keystroke denied — allow the launching app in \
System Settings → Privacy & Security → Automation"
                .into(),
        ),
        _ => Err("paste helper failed".into()),
    }
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
