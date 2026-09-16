//! Password/passphrase generation. Uniform sampling via rejection —
//! no modulo bias.
//!
//! Entropy: `-l 20` charset password ≈ 119 bits; 6-word passphrase ≈ 77 bits.
//! Wordlist: EFF large wordlist (vendored, public domain).

use zeroize::Zeroizing;

const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
// printable symbols minus shell/quoting hazards (', ", `, \, space, ;, |, &, <>, $)
const SYMBOLS: &[u8] = b"!@#%^*-_=+?/.,:[]{}()~";

const WORDLIST: &str = include_str!("../assets/eff_large_wordlist.txt");

fn wordlist() -> Vec<&'static str> {
    WORDLIST
        .lines()
        .filter_map(|l| l.split('\t').nth(1))
        .collect()
}

fn draw(max: usize) -> usize {
    // rejection sampling over u64: accept only values below the largest
    // multiple of `max`, so every index has identical probability
    let max = max as u64;
    let bound = u64::MAX / max * max;
    loop {
        let x = rand_core::RngCore::next_u64(&mut rand_core::OsRng);
        if x < bound {
            return (x % max) as usize;
        }
    }
}

/// Charset password. `symbols=false` → alnum only.
pub fn password(len: usize, symbols: bool) -> Zeroizing<String> {
    if !symbols {
        return password_from(ALNUM, len);
    }
    let mut s = [0u8; 62 + 22];
    s[..62].copy_from_slice(ALNUM);
    s[62..].copy_from_slice(SYMBOLS);
    password_from(&s, len)
}

fn password_from(set: &[u8], len: usize) -> Zeroizing<String> {
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        out.push(set[draw(set.len())] as char);
    }
    Zeroizing::new(out)
}

/// Diceware-style passphrase: `words` joined by '-'.
pub fn passphrase(words: usize) -> Zeroizing<String> {
    let wl = wordlist();
    let mut out = String::new();
    for i in 0..words {
        if i > 0 {
            out.push('-');
        }
        out.push_str(wl[draw(wl.len())]);
    }
    Zeroizing::new(out)
}
