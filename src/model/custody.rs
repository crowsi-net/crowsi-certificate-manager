use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyCustodyStateV2 {
    NonExportable,
    ExportableOrUnknown,
}

impl KeyCustodyStateV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NonExportable => "non-exportable",
            Self::ExportableOrUnknown => "exportable-or-unknown",
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedKeyCustodyAttestationV2 {
    schema: String,
    verifier_key_id: String,
    payload_base64: String,
    signature_base64: String,
}

impl SignedKeyCustodyAttestationV2 {
    #[must_use]
    pub fn new(
        verifier_key_id: impl Into<String>,
        payload_base64: impl Into<String>,
        signature_base64: impl Into<String>,
    ) -> Self {
        Self {
            schema: "crowsi://certificates/key-custody-attestation/v2".into(),
            verifier_key_id: verifier_key_id.into(),
            payload_base64: payload_base64.into(),
            signature_base64: signature_base64.into(),
        }
    }

    pub(crate) fn parts(&self) -> (&str, &str, &str, &str) {
        (
            &self.schema,
            &self.verifier_key_id,
            &self.payload_base64,
            &self.signature_base64,
        )
    }
}

impl fmt::Debug for SignedKeyCustodyAttestationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedKeyCustodyAttestationV2")
            .field("verifier_key_id", &self.verifier_key_id)
            .field("payload", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedKeyCustodyAttestationV2 {
    pub attestation_id: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub service_id: String,
    pub workload_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub profile: String,
    pub proof_key_ref: String,
    pub identity_revocation_epoch: u64,
    pub public_key_sha256: String,
    pub command_digest_sha256: String,
    pub provider_id: String,
    pub signature_key_id: String,
    pub signature_key_version: String,
    pub signature_public_key_spki_sha256: String,
    pub signature_algorithm: String,
    pub signature_key_purpose: String,
    pub trust_revision: u64,
    pub custody: KeyCustodyStateV2,
    pub attestation_digest_sha256: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub signature_verified: bool,
}
