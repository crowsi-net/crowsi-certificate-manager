use std::fmt;

use serde::{Deserialize, Serialize};

use crate::digest::DigestBuilder;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum KeyEnrollmentV2 {
    CsrDerBase64 {
        csr_der_base64: String,
    },
    PublicKeyDerBase64 {
        public_key_der_base64: String,
        proof_of_possession_base64: String,
    },
}

impl KeyEnrollmentV2 {
    pub(crate) fn add_to_digest(&self, digest: &mut DigestBuilder) {
        match self {
            Self::CsrDerBase64 { csr_der_base64 } => {
                digest.text("csr");
                digest.text(csr_der_base64);
            }
            Self::PublicKeyDerBase64 {
                public_key_der_base64,
                proof_of_possession_base64,
            } => {
                digest.text("public-key");
                digest.text(public_key_der_base64);
                digest.text(proof_of_possession_base64);
            }
        }
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::CsrDerBase64 { csr_der_base64 } => csr_der_base64.len(),
            Self::PublicKeyDerBase64 {
                public_key_der_base64,
                proof_of_possession_base64,
            } => public_key_der_base64.len() + proof_of_possession_base64.len(),
        }
    }
}

impl fmt::Debug for KeyEnrollmentV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyEnrollmentV2([REDACTED])")
    }
}
