//! Item model (DESIGN.md §6). Field values are raw bytes (UTF-8 for text);
//! numeric tags are canonical-sorted inside the fields TLV.

use crate::error::{CoreError, Result};
use crate::tlv::{Reader, Writer};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ItemKind {
    Login = 1,
    Card = 2,
    ApiKey = 3,
    Totp = 4,
    Secret = 5,
    Identity = 6,
    SshKey = 7,
    // Attachment = 8 (post-1.0)
}

impl ItemKind {
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::Login,
            2 => Self::Card,
            3 => Self::ApiKey,
            4 => Self::Totp,
            5 => Self::Secret,
            6 => Self::Identity,
            7 => Self::SshKey,
            v => return Err(CoreError::BadKind(v)),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Card => "card",
            Self::ApiKey => "apikey",
            Self::Totp => "totp",
            Self::Secret => "secret",
            Self::Identity => "identity",
            Self::SshKey => "sshkey",
        }
    }

    pub fn from_name(s: &str) -> Result<Self> {
        Ok(match s {
            "login" => Self::Login,
            "card" => Self::Card,
            "apikey" | "api_key" | "api-key" => Self::ApiKey,
            "totp" | "otp" => Self::Totp,
            "secret" | "note" => Self::Secret,
            "identity" => Self::Identity,
            "sshkey" | "ssh" => Self::SshKey,
            _ => return Err(CoreError::BadKind(0)),
        })
    }
}

// ── field tags (per-kind semantics live in docs/FORMAT.md) ──────────
pub mod tag {
    pub const NAME: u8 = 0x01;
    pub const NOTES: u8 = 0x02;
    pub const TAGS: u8 = 0x03; // comma-separated
                               // login
    pub const USERNAME: u8 = 0x10;
    pub const PASSWORD: u8 = 0x11;
    pub const URL: u8 = 0x12; // repeatable
                              // card
    pub const CARD_NUMBER: u8 = 0x20;
    pub const CARD_EXP: u8 = 0x21; // "MM/YY"
    pub const CARD_CVV: u8 = 0x22;
    pub const CARD_HOLDER: u8 = 0x23;
    pub const CARD_PIN: u8 = 0x24;
    // apikey
    pub const KEY: u8 = 0x30;
    pub const KEY_SECRET: u8 = 0x31;
    pub const ENDPOINT: u8 = 0x32;
    pub const ENV: u8 = 0x33;
    pub const EXPIRES: u8 = 0x34;
    // totp
    pub const TOTP_SECRET: u8 = 0x40;
    pub const TOTP_ALGO: u8 = 0x41;
    pub const TOTP_DIGITS: u8 = 0x42;
    pub const TOTP_PERIOD: u8 = 0x43;
    pub const TOTP_ISSUER: u8 = 0x44;
    // secret
    pub const TEXT: u8 = 0x50;
    // identity
    pub const FULL_NAME: u8 = 0x60;
    pub const ADDRESS: u8 = 0x61;
    pub const PHONE: u8 = 0x62;
    pub const EMAIL: u8 = 0x63;
    // sshkey
    pub const SSH_PRIVATE: u8 = 0x70;
    pub const SSH_PUBLIC: u8 = 0x71;
}

/// An item's field set. Tags → values; repeatable tags become Vec entries.
#[derive(Debug, Clone, Default)]
pub struct Item {
    pub fields: BTreeMap<u8, Vec<Vec<u8>>>,
}

impl Item {
    pub fn set(&mut self, tag: u8, val: impl Into<Vec<u8>>) {
        self.fields.insert(tag, vec![val.into()]);
    }

    pub fn push(&mut self, tag: u8, val: impl Into<Vec<u8>>) {
        self.fields.entry(tag).or_default().push(val.into());
    }

    pub fn get(&self, tag: u8) -> Option<&[u8]> {
        self.fields
            .get(&tag)
            .and_then(|v| v.first())
            .map(|v| v.as_slice())
    }

    pub fn get_str(&self, tag: u8) -> Option<&str> {
        self.get(tag).and_then(|b| std::str::from_utf8(b).ok())
    }

    pub fn get_all(&self, tag: u8) -> &[Vec<u8>] {
        self.fields.get(&tag).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn name(&self) -> &str {
        self.get_str(tag::NAME).unwrap_or("")
    }

    /// Canonical TLV: ascending tag order (BTreeMap guarantees it);
    /// repeatable tags stay consecutive.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        for (t, vals) in &self.fields {
            for v in vals {
                w.field(*t, v);
            }
        }
        w.finish()
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut item = Item::default();
        let mut r = Reader::new(buf);
        let mut ord = crate::tlv::OrderGuard::default();
        while let Some((t, v)) = r.next_field()? {
            ord.check(t, &[tag::URL])?; // only URL may repeat
            item.push(t, v.to_vec());
        }
        Ok(item)
    }
}

/// An Item holds decrypted secret field bytes — scrub them on drop rather
/// than leaving them on freed heap. (Defense-in-depth; see mem.rs removal
/// note in DESIGN.md.)
impl Drop for Item {
    fn drop(&mut self) {
        for vals in self.fields.values_mut() {
            for v in vals.iter_mut() {
                zeroize::Zeroize::zeroize(v);
            }
        }
    }
}
