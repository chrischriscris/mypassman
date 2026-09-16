//! Best-effort page locking. Deliberately NOT load-bearing (DESIGN.md §10):
//! RLIMIT_MEMLOCK is 64 KiB on stock Linux, unavailable on iOS, and covers
//! neither hibernation nor already-paged memory.

#[cfg(unix)]
pub fn lock_page(ptr: *const u8, len: usize) -> bool {
    unsafe { libc::mlock(ptr as *const _, len) == 0 }
}

#[cfg(unix)]
pub fn unlock_page(ptr: *const u8, len: usize) -> bool {
    unsafe { libc::munlock(ptr as *const _, len) == 0 }
}

#[cfg(not(unix))]
pub fn lock_page(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(not(unix))]
pub fn unlock_page(_ptr: *const u8, _len: usize) -> bool {
    false
}
