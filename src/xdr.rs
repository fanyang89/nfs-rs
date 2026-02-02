//! Minimal XDR (RFC 4506) encode/decode helpers.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XdrError {
    UnexpectedEof,
    LengthOverflow,
    InvalidBool(u32),
    InvalidEnum(u32),
    InvalidUtf8,
}

impl fmt::Display for XdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XdrError::UnexpectedEof => write!(f, "unexpected end of XDR buffer"),
            XdrError::LengthOverflow => write!(f, "XDR length overflow"),
            XdrError::InvalidBool(v) => write!(f, "invalid XDR bool: {v}"),
            XdrError::InvalidEnum(v) => write!(f, "invalid XDR enum: {v}"),
            XdrError::InvalidUtf8 => write!(f, "invalid UTF-8 string"),
        }
    }
}

impl std::error::Error for XdrError {}

pub type Result<T> = core::result::Result<T, XdrError>;

#[derive(Debug, Clone, Default)]
pub struct XdrWriter {
    buf: Vec<u8>,
}

impl XdrWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn put_i32(&mut self, v: i32) {
        self.put_u32(v as u32);
    }

    pub fn put_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn put_i64(&mut self, v: i64) {
        self.put_u64(v as u64);
    }

    pub fn put_bool(&mut self, v: bool) {
        self.put_u32(if v { 1 } else { 0 });
    }

    pub fn put_opaque_fixed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        self.pad_to_4();
    }

    pub fn put_opaque(&mut self, bytes: &[u8]) {
        let len: u32 = bytes.len().try_into().expect("XDR opaque too large");
        self.put_u32(len);
        self.buf.extend_from_slice(bytes);
        self.pad_to_4();
    }

    pub fn put_string(&mut self, s: &str) {
        self.put_opaque(s.as_bytes());
    }

    pub fn put_vec<T>(&mut self, items: &[T], mut f: impl FnMut(&mut Self, &T)) {
        let len: u32 = items.len().try_into().expect("XDR array too large");
        self.put_u32(len);
        for it in items {
            f(self, it);
        }
    }

    fn pad_to_4(&mut self) {
        let pad = (4 - (self.buf.len() % 4)) % 4;
        self.buf.extend(core::iter::repeat_n(0u8, pad));
    }
}

#[derive(Debug, Clone)]
pub struct XdrReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> XdrReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn get_u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn get_i32(&mut self) -> Result<i32> {
        Ok(self.get_u32()? as i32)
    }

    pub fn get_u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn get_i64(&mut self) -> Result<i64> {
        Ok(self.get_u64()? as i64)
    }

    pub fn get_bool(&mut self) -> Result<bool> {
        match self.get_u32()? {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(XdrError::InvalidBool(v)),
        }
    }

    pub fn get_opaque_fixed(&mut self, len: usize) -> Result<Vec<u8>> {
        let b = self.take(len)?;
        let out = b.to_vec();
        self.skip_pad(len)?;
        Ok(out)
    }

    pub fn get_opaque(&mut self) -> Result<Vec<u8>> {
        let len = self.get_u32()? as usize;
        let b = self.take(len)?;
        let out = b.to_vec();
        self.skip_pad(len)?;
        Ok(out)
    }

    pub fn get_string(&mut self) -> Result<String> {
        let bytes = self.get_opaque()?;
        String::from_utf8(bytes).map_err(|_| XdrError::InvalidUtf8)
    }

    pub fn get_vec<T>(&mut self, mut f: impl FnMut(&mut Self) -> Result<T>) -> Result<Vec<T>> {
        let len = self.get_u32()? as usize;
        let mut out = Vec::with_capacity(len.min(1024));
        for _ in 0..len {
            out.push(f(self)?);
        }
        Ok(out)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.buf.len())
            .is_none()
        {
            return Err(XdrError::UnexpectedEof);
        }
        let start = self.pos;
        let end = start + n;
        self.pos = end;
        Ok(&self.buf[start..end])
    }

    fn skip_pad(&mut self, n: usize) -> Result<()> {
        let pad = (4 - (n % 4)) % 4;
        if pad == 0 {
            return Ok(());
        }
        self.take(pad).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdr_u32_roundtrip() {
        let mut w = XdrWriter::new();
        w.put_u32(0x11223344);
        w.put_u32(0);
        w.put_u32(u32::MAX);
        let bytes = w.into_bytes();

        let mut r = XdrReader::new(&bytes);
        assert_eq!(r.get_u32().unwrap(), 0x11223344);
        assert_eq!(r.get_u32().unwrap(), 0);
        assert_eq!(r.get_u32().unwrap(), u32::MAX);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn xdr_opaque_padding() {
        let mut w = XdrWriter::new();
        w.put_opaque(&[1, 2, 3]);
        let bytes = w.into_bytes();

        let mut r = XdrReader::new(&bytes);
        let v = r.get_opaque().unwrap();
        assert_eq!(v, vec![1, 2, 3]);
        assert_eq!(r.remaining(), 0);
    }
}
