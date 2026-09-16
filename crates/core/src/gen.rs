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
    assert!(max > 0, "draw from empty set");
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
    // concat at runtime so a SYMBOLS edit can't silently truncate/overrun
    let set: Vec<u8> = if symbols {
        [ALNUM, SYMBOLS].concat()
    } else {
        ALNUM.to_vec()
    };
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        out.push(set[draw(set.len())] as char);
    }
    Zeroizing::new(out)
}

/// Diceware-style passphrase: `words` joined by '-'.
pub fn passphrase(words: usize) -> Zeroizing<String> {
    let wl = wordlist();
    assert!(!wl.is_empty(), "wordlist asset is empty");
    // join() allocates the result once — no realloc'd partial passphrases
    // left scattered across freed heap
    let picked: Vec<&str> = (0..words).map(|_| wl[draw(wl.len())]).collect();
    Zeroizing::new(picked.join("-"))
}
