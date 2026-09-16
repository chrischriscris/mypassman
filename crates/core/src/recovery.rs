//! Recovery kit (DESIGN.md §11): a 128-bit code shown ONCE, which
//! Argon2id-derives an independent KEK wrapping the key bundle in its own
//! slot. Losing the master password without it = total loss.
//!
//! Encoding: base32 over an unambiguous alphabet (no 0/o/1/i/l), grouped
//! for print: `xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-x` (26 chars, 16 bytes).

use crate::error::{CoreError, Result};

// Crockford-ish: 0-9 plus letters minus i,l,o,u (avoids 0/o, 1/i/l and
// accidental profanity). Parser additionally maps o→0 and i,l→1.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
const CODE_BYTES: usize = 16; // 128 bits → 26 base32 chars
pub const CODE_LEN: usize = 26;

pub fn generate_code() -> [u8; CODE_BYTES] {
    let mut b = [0u8; CODE_BYTES];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    b
}

/// 16 bytes → 26-char code, dash-grouped by 4.
pub fn format_code(raw: &[u8; CODE_BYTES]) -> String {
    let mut chars = String::with_capacity(CODE_LEN + 8);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &byte in raw {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            chars.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        chars.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    // group by 4
    let mut out = String::with_capacity(chars.len() + 6);
    for (i, c) in chars.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

/// Parse a formatted code back to 16 bytes. Accepts dashes/spaces/case.
pub fn parse_code(s: &str) -> Result<[u8; CODE_BYTES]> {
    let mut vals = Vec::with_capacity(CODE_LEN);
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '-') {
        // typo tolerance: o→0, i/l→1 (Crockford convention)
        let c = match c.to_ascii_lowercase() {
            'o' => '0',
            'i' | 'l' => '1',
            c => c,
        };
        let v = ALPHABET.iter().position(|&a| a as char == c);
        match v {
            Some(v) => vals.push(v as u8),
            None => return Err(CoreError::Tlv("bad recovery char")),
        }
    }
    if vals.len() != CODE_LEN {
        return Err(CoreError::Tlv("bad recovery length"));
    }
    let mut raw = [0u8; CODE_BYTES];
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = 0usize;
    for v in vals {
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if out < CODE_BYTES {
                raw[out] = (acc >> bits) as u8;
                out += 1;
            }
        }
    }
    // 26 chars carry 130 bits for 128 of payload — the 2 trailing pad
    // bits must be zero, else non-canonical codes alias the same secret
    if bits > 0 && acc & ((1u32 << bits) - 1) != 0 {
        return Err(CoreError::Tlv("non-canonical recovery code"));
    }
    Ok(raw)
}
