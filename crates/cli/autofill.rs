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

/// Frontmost app's bundle id via NSWorkspace — no Accessibility or
/// Automation permission needed. `None` means the OS can't name the
/// frontmost app; a caller that asserted a target must treat that as a
/// failure, never as "check passed".
fn frontmost_bundle() -> Option<String> {
    use objc2::runtime::AnyObject;
    use objc2::{class, msg_send};
    unsafe {
        let ws: *mut AnyObject = msg_send![class!(NSWorkspace), sharedWorkspace];
        if ws.is_null() {
            return None;
        }
        let app: *mut AnyObject = msg_send![ws, frontmostApplication];
        if app.is_null() {
            return None;
        }
        let bid: *mut AnyObject = msg_send![app, bundleIdentifier];
        if bid.is_null() {
            return None;
        }
        let s: *const std::ffi::c_char = msg_send![bid, UTF8String];
        if s.is_null() {
            return None;
        }
        Some(std::ffi::CStr::from_ptr(s).to_string_lossy().into_owned())
    }
}

/// When a launcher asserts the intended destination, verify it is still
/// frontmost — as close to event delivery as we can get. An unidentifiable
/// frontmost app aborts rather than spraying a secret wherever focus is.
fn check_target(expected: Option<&str>) -> Result<(), String> {
    match expected {
        None => Ok(()),
        Some(want) => match frontmost_bundle().as_deref() {
            Some(b) if b == want => Ok(()),
            _ => Err("target app changed or is unverifiable — fill aborted".into()),
        },
    }
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

/// Verify-and-paste in ONE JXA eval: stdin carries
/// `<expected bundle id (may be empty)>\n<expected pasteboard bytes>` —
/// never argv/env/script text. The frontmost app's bundle id and the
/// general pasteboard are both compared, and System Events posts ⌘V only
/// on exact matches. The checks and keystroke are adjacent statements in
/// one process — no window for a focus jump or a concurrent clipboard
/// write to redirect the secret. On keystroke failure the payload is
/// cleared iff it's still ours. Exit codes: 3 = clipboard changed;
/// 4 = keystroke denied; 5 = bad input; 6 = wrong/unverifiable target.
pub fn paste(expected: &[u8], bundle: Option<&str>) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    settle();
    check_target(bundle)?;
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
var nl = s.indexOf('\n');
if (nl < 0) { $.exit(5); }
var wantBundle = s.slice(0, nl);
var payload = s.slice(nl + 1);
if (wantBundle.length > 0) {
    var fm = $.NSWorkspace.sharedWorkspace.frontmostApplication;
    var bid = fm !== null && fm.bundleIdentifier !== null ? fm.bundleIdentifier.js : null;
    if (bid !== wantBundle) { $.exit(6); }
}
var pb = $.NSPasteboard.generalPasteboard;
var cur = pb.stringForType('public.utf8-plain-text');
if (cur === null || cur.js !== payload) { $.exit(3); }
try {
    Application('System Events').keystroke('v', {using: 'command down'});
} catch (e) {
    if (pb.stringForType('public.utf8-plain-text').js === payload) {
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
    // first line: the bundle id the frontmost app must match ("" = no
    // assertion); the rest is the exact expected pasteboard payload —
    // bundle ids never contain newlines, so one \n is an unambiguous split
    let mut input = Vec::with_capacity(bundle.map_or(1, |b| b.len() + 1) + expected.len());
    input.extend_from_slice(bundle.unwrap_or("").as_bytes());
    input.push(b'\n');
    input.extend_from_slice(expected);
    p.stdin
        .take()
        .unwrap()
        .write_all(&input)
        .map_err(|e| e.to_string())?;
    match p.wait().map_err(|e| e.to_string())?.code() {
        Some(0) => Ok(()),
        Some(3) => Err("clipboard changed since the copy — refused to paste".into()),
        Some(4) => Err(
            "System Events keystroke denied — allow the launching app in \
System Settings → Privacy & Security → Automation"
                .into(),
        ),
        Some(6) => Err("target app changed or is unverifiable — fill aborted".into()),
        _ => Err("paste helper failed".into()),
    }
}

/// Type each part in order, Tab between them — `user⇥pass` form fill.
/// Per-char events (not one big string) for compatibility with fields
/// that drop multi-char synthetic input. With `expected` set, the
/// frontmost app's bundle id is re-verified before every field.
pub fn type_seq(parts: &[&str], expected: Option<&str>) -> Result<(), String> {
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
        check_target(expected).map_err(|e| {
            if i == 0 {
                e
            } else {
                format!("{e} (after {i} field(s))")
            }
        })?;
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
