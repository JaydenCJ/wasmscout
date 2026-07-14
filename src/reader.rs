//! Bounded byte reader for the wasm binary format: LEB128 integers,
//! length-prefixed names and raw slices, with absolute-offset errors.
//!
//! Every read is bounds-checked and every error carries the absolute file
//! offset where it happened, so a hostile or truncated file produces a
//! precise diagnostic instead of a panic.

use std::fmt;

/// A parse failure with the absolute file offset where it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub offset: usize,
    pub message: String,
}

impl ParseError {
    pub fn new(offset: usize, message: impl Into<String>) -> ParseError {
        ParseError {
            offset,
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "offset {:#06x}: {}", self.offset, self.message)
    }
}

pub type Result<T> = std::result::Result<T, ParseError>;

/// Byte cursor over a slice. `base` is the slice's absolute position in the
/// file, so sub-readers report file offsets, not slice-local offsets.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader {
            data,
            pos: 0,
            base: 0,
        }
    }

    /// Absolute file offset of the next unread byte.
    pub fn offset(&self) -> usize {
        self.base + self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn err<T>(&self, message: impl Into<String>) -> Result<T> {
        Err(ParseError::new(self.offset(), message))
    }

    pub fn byte(&mut self) -> Result<u8> {
        match self.data.get(self.pos) {
            Some(&b) => {
                self.pos += 1;
                Ok(b)
            }
            None => self.err("unexpected end of input"),
        }
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return self.err(format!(
                "need {n} byte(s), only {} remain",
                self.remaining()
            ));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.bytes(n).map(|_| ())
    }

    /// Sub-reader over the next `n` bytes; keeps absolute offsets intact.
    pub fn slice(&mut self, n: usize) -> Result<Reader<'a>> {
        let base = self.offset();
        let data = self.bytes(n)?;
        Ok(Reader { data, pos: 0, base })
    }

    /// Unsigned LEB128, at most 32 bits (5 encoded bytes).
    pub fn leb_u32(&mut self) -> Result<u32> {
        let start = self.offset();
        let mut value: u32 = 0;
        for i in 0..5u32 {
            let b = self.byte()?;
            let bits = u32::from(b & 0x7f);
            // The 5th byte may only contribute 4 bits (28 already consumed).
            if i == 4 && (b & 0x70) != 0 {
                return Err(ParseError::new(start, "LEB128 value overflows u32"));
            }
            value |= bits << (i * 7);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ParseError::new(
            start,
            "LEB128 u32 runs longer than 5 bytes",
        ))
    }

    /// Unsigned LEB128, at most 64 bits (10 encoded bytes).
    pub fn leb_u64(&mut self) -> Result<u64> {
        let start = self.offset();
        let mut value: u64 = 0;
        for i in 0..10u32 {
            let b = self.byte()?;
            let bits = u64::from(b & 0x7f);
            // The 10th byte may only contribute the lowest bit.
            if i == 9 && (b & 0x7e) != 0 {
                return Err(ParseError::new(start, "LEB128 value overflows u64"));
            }
            value |= bits << (i * 7);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ParseError::new(
            start,
            "LEB128 u64 runs longer than 10 bytes",
        ))
    }

    /// Signed LEB128 (up to 64 bits); used to walk constant-expression
    /// immediates where the value itself does not matter for the audit.
    pub fn leb_s64(&mut self) -> Result<i64> {
        let start = self.offset();
        let mut value: i64 = 0;
        let mut shift = 0u32;
        for _ in 0..10 {
            let b = self.byte()?;
            value |= i64::from(b & 0x7f) << shift.min(63);
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && (b & 0x40) != 0 {
                    value |= -1i64 << shift;
                }
                return Ok(value);
            }
        }
        Err(ParseError::new(
            start,
            "LEB128 s64 runs longer than 10 bytes",
        ))
    }

    /// Length-prefixed name. wasm names are UTF-8; hostile files may not be,
    /// so decoding is lossy — an audit should describe a file, not die on it.
    pub fn name(&mut self) -> Result<String> {
        let len = self.leb_u32()? as usize;
        if len > self.remaining() {
            return self.err(format!(
                "name claims {len} byte(s), only {} remain",
                self.remaining()
            ));
        }
        let raw = self.bytes(len)?;
        Ok(String::from_utf8_lossy(raw).into_owned())
    }

    /// Guard for `vec(...)` counts: every element occupies at least
    /// `min_bytes`, so a count larger than what fits in the remaining bytes
    /// is a lie (or an attempt to make the parser allocate gigabytes).
    pub fn check_count(&self, count: u32, min_bytes: usize, what: &str) -> Result<()> {
        let need = (count as usize).saturating_mul(min_bytes.max(1));
        if need > self.remaining() {
            return Err(ParseError::new(
                self.offset(),
                format!(
                    "{what} count {count} is impossible: needs at least {need} byte(s), only {} remain",
                    self.remaining()
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb_u32_decodes_valid_encodings() {
        let mut r = Reader::new(&[0x00, 0x3f, 0x7f]);
        assert_eq!(r.leb_u32().unwrap(), 0);
        assert_eq!(r.leb_u32().unwrap(), 63);
        assert_eq!(r.leb_u32().unwrap(), 127);
        // 624485 is the classic LEB128 example from the DWARF spec.
        let mut r = Reader::new(&[0xe5, 0x8e, 0x26]);
        assert_eq!(r.leb_u32().unwrap(), 624_485);
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
        assert_eq!(r.leb_u32().unwrap(), u32::MAX);
    }

    #[test]
    fn leb_u32_rejects_overflow_and_truncation() {
        // The 5th byte carries bits 28..34; anything above bit 31 must fail.
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff, 0x1f]);
        let err = r.leb_u32().unwrap_err();
        assert!(err.message.contains("overflows u32"), "{}", err.message);
        assert_eq!(err.offset, 0);
        // High bit set on the last available byte: the value never terminates.
        let mut r = Reader::new(&[0x80, 0x80]);
        let err = r.leb_u32().unwrap_err();
        assert!(err.message.contains("unexpected end"), "{}", err.message);
    }

    #[test]
    fn leb_u64_and_s64_decode_extremes() {
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        assert_eq!(r.leb_u64().unwrap(), u64::MAX);
        // -123456 encoded per the LEB128 signed algorithm.
        let mut r = Reader::new(&[0xc0, 0xbb, 0x78]);
        assert_eq!(r.leb_s64().unwrap(), -123_456);
    }

    #[test]
    fn name_decodes_utf8_and_survives_invalid_bytes() {
        // "hi" followed by a 2-byte name with an invalid UTF-8 byte: the
        // second must decode lossily instead of failing the whole audit.
        let mut r = Reader::new(&[0x02, b'h', b'i', 0x02, 0xff, b'x']);
        assert_eq!(r.name().unwrap(), "hi");
        assert_eq!(r.name().unwrap(), "\u{fffd}x");
    }

    #[test]
    fn name_rejects_length_past_end() {
        let mut r = Reader::new(&[0x0a, b'a']);
        let err = r.name().unwrap_err();
        assert!(err.message.contains("claims 10 byte(s)"), "{}", err.message);
    }

    #[test]
    fn sub_reader_errors_report_absolute_offsets() {
        let data = [0x00, 0x00, 0x00, 0x01, 0x02];
        let mut r = Reader::new(&data);
        r.skip(3).unwrap();
        let mut sub = r.slice(2).unwrap();
        sub.skip(2).unwrap();
        let err = sub.byte().unwrap_err();
        // The sub-reader starts at file offset 3 and is 2 bytes long.
        assert_eq!(err.offset, 5);
    }

    #[test]
    fn check_count_rejects_impossible_vector_counts() {
        let r = Reader::new(&[0u8; 8]);
        assert!(r.check_count(8, 1, "item").is_ok());
        let err = r.check_count(9, 1, "item").unwrap_err();
        assert!(err.message.contains("impossible"), "{}", err.message);
        // Saturating multiply: a count crafted to overflow usize still fails.
        assert!(r.check_count(u32::MAX, usize::MAX, "item").is_err());
    }
}
