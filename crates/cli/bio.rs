//! Biometric unlock (macOS): Touch ID via LAContext gating a KEK in the
//! login keychain.
//!
//! A random 32-byte KEK lives in a generic-password item; every unlock
//! first runs `LAContext.evaluatePolicy(.biometrics)` — the system shows
//! Touch ID, and on success we read the KEK and unwrap the KeyBundle in
//! the manifest's SLOT_BIOMETRIC slot (same wrap-slot model as password
//! and recovery).
//!
//! Security posture, honestly: on an UNSIGNED build the KEK item is
//! reachable by same-uid processes without the prompt — the fingerprint
//! is a user-presence gate, not a hardware boundary (same trust domain
//! as the daemon socket). A properly signed release can upgrade this to
//! a Secure-Enclave-wrapped KEK (SEP-enforced biometry) without any
//! format change — the slot already binds vault_id + key_epoch.
//!
//! `$MPM_NO_BIO=1` or `--recovery` bypass the prompt; password always works.

#![cfg(target_os = "macos")]

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::string::CFString;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use security_framework_sys::item::*;
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};
use std::ptr;
use zeroize::Zeroizing;

const SERVICE: &str = "mypassman-bio";
pub const BIO_KEY_LEN: usize = 32;

type Dict = CFMutableDictionary<CFString, CFType>;

fn cfs(r: core_foundation::string::CFStringRef) -> CFString {
    unsafe { CFString::wrap_under_get_rule(r) }
}

macro_rules! k {
    ($s:ident) => {
        unsafe { cfs($s) }
    };
}

/// (class, service, account, not-synchronizable) — the KEK item.
fn query(vault_id: &[u8; 16]) -> Dict {
    let mut d: Dict = CFMutableDictionary::new();
    d.set(k!(kSecClass), k!(kSecClassGenericPassword).as_CFType());
    d.set(k!(kSecAttrService), CFString::new(SERVICE).as_CFType());
    d.set(
        k!(kSecAttrAccount),
        CFString::new(&mpm_store::hex(vault_id)).as_CFType(),
    );
    d.set(
        k!(kSecAttrSynchronizable),
        CFBoolean::false_value().as_CFType(),
    );
    d
}

/// Is biometry (Touch ID) even available on this Mac?
pub fn available() -> bool {
    let ctx = unsafe { LAContext::new() };
    unsafe {
        ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
            .is_ok()
    }
}

/// Show the Touch ID prompt. The reply runs on a private queue — the
/// channel makes it synchronous for us. A strong ref to the context is
/// held for the whole wait (LAContext deallocation cancels evaluation).
fn authenticate() -> bool {
    let ctx = unsafe { LAContext::new() };
    let reason = NSString::from_str("unlock mypassman vault");
    let (tx, rx) = std::sync::mpsc::channel();
    let block = block2::RcBlock::new(move |ok: Bool, _err: *mut NSError| {
        let _ = tx.send(ok.as_bool());
    });
    unsafe {
        ctx.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
            &reason,
            &block,
        );
    }
    rx.recv().unwrap_or(false)
}

/// Store `key` (the KEK) as a plain keychain item.
pub fn enroll(vault_id: &[u8; 16], key: &[u8; BIO_KEY_LEN]) -> Result<(), String> {
    remove(vault_id); // idempotent re-enroll
    let mut d = query(vault_id);
    d.set(k!(kSecValueData), CFData::from_buffer(key).as_CFType());
    d.set(
        k!(kSecAttrLabel),
        CFString::new("mypassman vault key (Touch ID-gated)").as_CFType(),
    );
    let status = unsafe { SecItemAdd(d.as_concrete_TypeRef(), ptr::null_mut()) };
    if status == 0 {
        Ok(())
    } else {
        Err(format!("SecItemAdd: errSec {status}"))
    }
}

/// Touch ID prompt, then read the KEK. `None` on cancel/absent/error.
/// Order matters: existence check → biometric gate → data read, so the
/// KEK is never resident in our address space before the prompt passes.
pub fn load(vault_id: &[u8; 16]) -> Option<Zeroizing<[u8; BIO_KEY_LEN]>> {
    // does the item even exist? don't prompt Touch ID for nothing
    let status =
        unsafe { SecItemCopyMatching(query(vault_id).as_concrete_TypeRef(), ptr::null_mut()) };
    if status != 0 {
        return None;
    }
    if !authenticate() {
        return None;
    }
    let mut q = query(vault_id);
    q.set(k!(kSecReturnData), CFBoolean::true_value().as_CFType());
    let mut out: core_foundation::base::CFTypeRef = ptr::null();
    let status = unsafe { SecItemCopyMatching(q.as_concrete_TypeRef(), &mut out) };
    if status != 0 || out.is_null() {
        return None;
    }
    let data = unsafe { CFData::wrap_under_create_rule(out as _) };
    if data.bytes().len() != BIO_KEY_LEN {
        return None;
    }
    let mut key = Zeroizing::new([0u8; BIO_KEY_LEN]);
    key.copy_from_slice(data.bytes());
    Some(key)
}

/// Delete the KEK item.
pub fn remove(vault_id: &[u8; 16]) {
    let q = query(vault_id);
    unsafe {
        SecItemDelete(q.as_concrete_TypeRef());
    }
}
