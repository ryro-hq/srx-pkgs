//! Canonical regular-file Artifact framing shared by admission gates.
//! The engine validates the resulting bytes independently on admission.
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub struct Encoder {
    bytes: Vec<u8>,
    expected: usize,
    written: usize,
    maximum: usize,
    previous: String,
}
impl Encoder {
    pub fn new(count: usize, maximum: usize) -> Result<Self> {
        let mut bytes = b"syrox-artifact\n".to_vec();
        bytes.extend(u32::try_from(count)?.to_le_bytes());
        if bytes.len() > maximum {
            return Err("Artifact exceeds cap".into());
        }
        Ok(Self {
            bytes,
            expected: count,
            written: 0,
            maximum,
            previous: String::new(),
        })
    }
    pub fn push(&mut self, path: &str, executable: bool, bytes: &[u8]) -> Result<()> {
        let frame = 11_usize
            .checked_add(path.len())
            .and_then(|n| n.checked_add(bytes.len()));
        if self.written >= self.expected
            || path <= self.previous.as_str()
            || !frame
                .and_then(|n| self.bytes.len().checked_add(n))
                .is_some_and(|n| n <= self.maximum)
        {
            return Err("Artifact exceeds cap or file order/count mismatch".into());
        }
        self.bytes.extend(u16::try_from(path.len())?.to_le_bytes());
        self.bytes.extend(path.as_bytes());
        self.bytes.push(u8::from(executable));
        self.bytes.extend(u64::try_from(bytes.len())?.to_le_bytes());
        self.bytes.extend(bytes);
        self.previous = path.to_owned();
        self.written += 1;
        Ok(())
    }
    pub fn finish(self) -> Result<Vec<u8>> {
        if self.written != self.expected {
            return Err("Artifact file count mismatch".into());
        }
        Ok(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_consumes_the_same_budget_as_payload() {
        let maximum = b"syrox-artifact\n".len() + 4 + 11 + 1 + 3;
        let mut exact = Encoder::new(1, maximum).unwrap();
        exact.push("x", false, b"123").unwrap();
        assert_eq!(exact.finish().unwrap().len(), maximum);
        let mut overflow = Encoder::new(1, maximum).unwrap();
        assert!(overflow.push("x", false, b"1234").is_err());
        assert!(Encoder::new(1, maximum).unwrap().finish().is_err());
    }
}
