//! TOTP (RFC 6238) + base32 secret decode (RFC 4648) + `otpauth://` URIs.
//!
//! Secrets arrive base32 (that's what every QR/`otpauth://` URI uses).
//! The decoded secret is returned `Zeroizing` — it's a live credential.

use crate::error::{CoreError, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgo {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgo {
    pub fn from_name(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" | "" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(CoreError::Tlv("unknown totp algorithm")),
        }
    }
}

/// RFC 4648 base32 (no padding required, case-insensitive, spaces/`-`
/// ignored — people copy secrets sloppily).
pub fn base32_decode(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for ch in s.bytes() {
        if ch == b' ' || ch == b'-' || ch == b'=' {
            continue;
        }
        let v = A
            .iter()
            .position(|&c| c == ch.to_ascii_uppercase())
            .ok_or(CoreError::Tlv("bad base32 secret"))?;
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(Zeroizing::new(out))
}

/// HOTP: dynamic truncation of HMAC(secret, counter).
fn hotp(secret: &[u8], counter: u64, digits: u32, algo: TotpAlgo) -> u32 {
    let msg = counter.to_be_bytes();
    let mac: Vec<u8> = match algo {
        TotpAlgo::Sha1 => {
            let mut m = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("hmac any len");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        TotpAlgo::Sha256 => {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("hmac any len");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        TotpAlgo::Sha512 => {
            let mut m = <Hmac<Sha512> as Mac>::new_from_slice(secret).expect("hmac any len");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
    };
    let off = (mac[mac.len() - 1] & 0x0f) as usize;
    let code = (u32::from_be_bytes([mac[off] & 0x7f, mac[off + 1], mac[off + 2], mac[off + 3]]))
        % 10u32.pow(digits);
    // mac is a derived secret — zeroize before drop
    let mut mac = mac;
    zeroize::Zeroize::zeroize(&mut mac);
    code
}

/// Current TOTP code for `secret` at unix `time`. Returns (code string,
/// seconds until rollover).
pub fn totp(secret: &[u8], time: u64, period: u64, digits: u32, algo: TotpAlgo) -> (String, u64) {
    let period = if period == 0 { 30 } else { period };
    let digits = if digits == 0 { 6 } else { digits };
    let counter = time / period;
    let code = hotp(secret, counter, digits, algo);
    (
        format!("{:0width$}", code, width = digits as usize),
        period - time % period,
    )
}

/// Parse `otpauth://totp/LABEL?secret=…&issuer=…&digits=…&period=…&algorithm=…`
/// → (raw secret bytes, issuer, label, digits, period, algo).
pub struct OtpAuth {
    pub secret: Zeroizing<Vec<u8>>,
    pub issuer: String,
    pub label: String,
    pub digits: u32,
    pub period: u64,
    pub algo: TotpAlgo,
}

pub fn parse_otpauth(uri: &str) -> Result<OtpAuth> {
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .ok_or(CoreError::Tlv("not an otpauth://totp URI"))?;
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let mut secret = None;
    let mut issuer = String::new();
    let mut digits = 6u32;
    let mut period = 30u64;
    let mut algo = TotpAlgo::Sha1;
    for kv in query.split('&') {
        let Some((k, v)) = kv.split_once('=') else {
            continue;
        };
        match k {
            "secret" => secret = Some(base32_decode(&pct_decode(v))?),
            "issuer" => issuer = pct_decode(v),
            "digits" => digits = v.parse().unwrap_or(6),
            "period" => period = v.parse().unwrap_or(30),
            "algorithm" => algo = TotpAlgo::from_name(v)?,
            _ => {}
        }
    }
    Ok(OtpAuth {
        secret: secret.ok_or(CoreError::Tlv("otpauth missing secret"))?,
        issuer,
        label: pct_decode(label),
        digits,
        period,
        algo,
    })
}

fn pct_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 App B vectors — 8-digit codes; per-algo seed lengths.
    #[test]
    fn rfc6238_vectors() {
        let cases: &[(u64, &[u8], TotpAlgo, &str)] = &[
            (59, b"12345678901234567890", TotpAlgo::Sha1, "94287082"),
            (
                1111111109,
                b"12345678901234567890",
                TotpAlgo::Sha1,
                "07081804",
            ),
            (
                1111111111,
                b"12345678901234567890",
                TotpAlgo::Sha1,
                "14050471",
            ),
            (
                1234567890,
                b"12345678901234567890",
                TotpAlgo::Sha1,
                "89005924",
            ),
            (
                2000000000,
                b"12345678901234567890",
                TotpAlgo::Sha1,
                "69279037",
            ),
            (
                59,
                b"12345678901234567890123456789012",
                TotpAlgo::Sha256,
                "46119246",
            ),
            (
                1111111109,
                b"12345678901234567890123456789012",
                TotpAlgo::Sha256,
                "68084774",
            ),
            (
                59,
                b"1234567890123456789012345678901234567890123456789012345678901234",
                TotpAlgo::Sha512,
                "90693936",
            ),
            (
                1234567890,
                b"1234567890123456789012345678901234567890123456789012345678901234",
                TotpAlgo::Sha512,
                "93441116",
            ),
        ];
        for (t, key, algo, want) in cases {
            let (code, _) = totp(key, *t, 30, 8, *algo);
            assert_eq!(&code, want, "t={t} {algo:?}");
        }
    }

    #[test]
    fn base32_roundtrip_and_slop() {
        // "Hello!" → JBSWY3DPEE
        let enc = b"Hello!";
        let s = "JBSWY3DPEE";
        assert_eq!(&*base32_decode(s).unwrap(), enc);
        // case-insensitive, spaces/dashes ignored
        assert_eq!(&*base32_decode("jbsw-y3dp ee").unwrap(), enc);
        assert!(base32_decode("JBSW!!").is_err());
    }

    #[test]
    fn otpauth_parse() {
        let oa = parse_otpauth(
            "otpauth://totp/GitHub:chus?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8&period=45&algorithm=SHA256",
        )
        .unwrap();
        assert_eq!(oa.digits, 8);
        assert_eq!(oa.period, 45);
        assert_eq!(oa.algo, TotpAlgo::Sha256);
        assert_eq!(oa.issuer, "GitHub");
        assert_eq!(oa.label, "GitHub:chus");
        assert!(parse_otpauth("otpauth://hotp/x?secret=AA").is_err());
    }
}
