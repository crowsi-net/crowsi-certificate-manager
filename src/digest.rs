use sha2::{Digest, Sha256};

/// Length-prefixing prevents ambiguous concatenation in protocol digests.
pub(crate) struct DigestBuilder(Sha256);

impl DigestBuilder {
    pub(crate) fn new(domain: &str) -> Self {
        let mut value = Self(Sha256::new());
        value.text(domain);
        value
    }

    pub(crate) fn text(&mut self, value: &str) {
        self.0
            .update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        self.0.update(value.as_bytes());
    }

    pub(crate) fn optional(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.0.update([1]);
                self.text(value);
            }
            None => self.0.update([0]),
        }
    }

    pub(crate) fn number(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.0
            .update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        self.0.update(value);
    }

    pub(crate) fn finish(self) -> String {
        format!("{:x}", self.0.finalize())
    }
}

pub(crate) fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}
