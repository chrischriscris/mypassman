//! Canonical TLV: tag(u8) || len(u32 LE) || value.
//! Canonical form = ascending tag order, minimal encoding. Fixed-size
//! fields are length-checked on read; reject duplicates and noncanonical
//! input (DESIGN.md §5 "canonical encoding is law").

use crate::error::{CoreError, Result};

#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Tags must be pushed in ascending order except for repeatable tags,
    /// which may repeat consecutively.
    pub fn field(&mut self, tag: u8, val: &[u8]) -> &mut Self {
        self.buf.push(tag);
        self.buf.extend_from_slice(&(val.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(val);
        self
    }

    pub fn u8f(&mut self, tag: u8, v: u8) -> &mut Self {
        self.field(tag, &[v])
    }

    pub fn u16f(&mut self, tag: u8, v: u16) -> &mut Self {
        self.field(tag, &v.to_le_bytes())
    }

    pub fn u32f(&mut self, tag: u8, v: u32) -> &mut Self {
        self.field(tag, &v.to_le_bytes())
    }

    pub fn u64f(&mut self, tag: u8, v: u64) -> &mut Self {
        self.field(tag, &v.to_le_bytes())
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Single-pass reader. Collect with `for (tag, val) in r` semantics via `next`.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns Ok(None) at clean end.
    pub fn next_field(&mut self) -> Result<Option<(u8, &'a [u8])>> {
        if self.pos == self.buf.len() {
            return Ok(None);
        }
        if self.buf.len() - self.pos < 5 {
            return Err(CoreError::Tlv("truncated header"));
        }
        let tag = self.buf[self.pos];
        let len = u32::from_le_bytes(self.buf[self.pos + 1..self.pos + 5].try_into().unwrap())
            as usize;
        let start = self.pos + 5;
        let end = start.checked_add(len).ok_or(CoreError::Tlv("len overflow"))?;
        if end > self.buf.len() {
            return Err(CoreError::Tlv("truncated value"));
        }
        self.pos = end;
        Ok(Some((tag, &self.buf[start..end])))
    }

    pub fn want_fixed(tag: u8, val: &[u8], len: usize) -> Result<()> {
        if val.len() != len {
            return Err(CoreError::BadLen(tag));
        }
        Ok(())
    }
}

pub fn u8v(tag: u8, val: &[u8]) -> Result<u8> {
    Reader::want_fixed(tag, val, 1)?;
    Ok(val[0])
}

pub fn u16v(tag: u8, val: &[u8]) -> Result<u16> {
    Reader::want_fixed(tag, val, 2)?;
    Ok(u16::from_le_bytes(val.try_into().unwrap()))
}

pub fn u32v(tag: u8, val: &[u8]) -> Result<u32> {
    Reader::want_fixed(tag, val, 4)?;
    Ok(u32::from_le_bytes(val.try_into().unwrap()))
}

pub fn u64v(tag: u8, val: &[u8]) -> Result<u64> {
    Reader::want_fixed(tag, val, 8)?;
    Ok(u64::from_le_bytes(val.try_into().unwrap()))
}
