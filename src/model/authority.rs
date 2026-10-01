use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessState {
    Ready,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestationState {
    Verified,
    Unverified,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorityAttestationLeaseV2 {
    pub lease_id: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub authority_id: String,
    pub key_id: String,
    pub authority_key_version: String,
    pub authority_public_key_spki_sha256: String,
    pub signature_algorithm: String,
    pub key_provider_signature_profile: String,
    pub key_purpose: String,
    pub authority_receipt_key_id: String,
    pub authority_receipt_key_version: String,
    pub authority_receipt_public_key_spki_sha256: String,
    pub authority_receipt_signature_algorithm: String,
    pub authority_receipt_key_purpose: String,
    pub verifier_key_id: String,
    pub verifier_key_version: String,
    pub verifier_public_key_spki_sha256: String,
    pub verifier_signature_algorithm: String,
    pub verifier_key_purpose: String,
    pub trust_revision: u64,
    pub attestation_digest_sha256: String,
    pub fence: u64,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorityReadinessAttestationV2 {
    schema: String,
    verifier_key_id: String,
    payload_base64: String,
    signature_base64: String,
}

impl SignedAuthorityReadinessAttestationV2 {
    #[must_use]
    pub fn new(
        verifier_key_id: impl Into<String>,
        payload_base64: impl Into<String>,
        signature_base64: impl Into<String>,
    ) -> Self {
        Self {
            schema: "crowsi://certificates/authority-readiness-attestation/v2".into(),
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

impl fmt::Debug for SignedAuthorityReadinessAttestationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedAuthorityReadinessAttestationV2")
            .field("verifier_key_id", &self.verifier_key_id)
            .field("payload", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorityReadinessV2 {
    pub authority_state: ReadinessState,
    pub key_provider_state: ReadinessState,
    pub attestation_state: AttestationState,
    pub lease: AuthorityAttestationLeaseV2,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateState {
    Active,
    Revoked,
    Expired,
    Unknown,
}

impl CertificateState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Unknown => "unknown",
        }
    }
}
