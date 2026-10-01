use std::fmt;

use serde::{Deserialize, Serialize};

use crate::digest::DigestBuilder;

use super::CertificateState;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateMetadataV2 {
    pub certificate_id: String,
    pub serial_number: String,
    pub fingerprint_sha256: String,
    pub public_key_sha256: String,
    pub public_key_algorithm: String,
    pub not_before_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub state: CertificateState,
}

impl CertificateMetadataV2 {
    #[must_use]
    pub fn digest_sha256(&self) -> String {
        let mut digest = DigestBuilder::new("crowsi-certificate-metadata-v2");
        for value in [
            &self.certificate_id,
            &self.serial_number,
            &self.fingerprint_sha256,
            &self.public_key_sha256,
            &self.public_key_algorithm,
        ] {
            digest.text(value);
        }
        digest.number(self.not_before_epoch_s);
        digest.number(self.expires_at_epoch_s);
        digest.text(self.state.as_str());
        digest.finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicCertificateV2 {
    pub metadata: CertificateMetadataV2,
    pub certificate_der_base64: String,
    pub chain_der_base64: Vec<String>,
}

impl fmt::Debug for PublicCertificateV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicCertificateV2")
            .field("certificate_id", &self.metadata.certificate_id)
            .field("certificate_der_base64", &"[REDACTED]")
            .field("chain_der_base64", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorityOutcomeReceiptV2 {
    pub schema: String,
    pub key_id: String,
    pub payload_base64: String,
    pub signature_base64: String,
}

impl fmt::Debug for SignedAuthorityOutcomeReceiptV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedAuthorityOutcomeReceiptV2")
            .field("key_id", &self.key_id)
            .field("payload", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityOutcomeV2 {
    pub metadata: CertificateMetadataV2,
    pub public_certificate: Option<PublicCertificateV2>,
    pub signed_receipt: SignedAuthorityOutcomeReceiptV2,
}

impl AuthorityOutcomeV2 {
    #[must_use]
    pub fn digest_sha256(&self) -> String {
        let mut digest = DigestBuilder::new("crowsi-authority-outcome-v2");
        digest.text(&self.metadata.digest_sha256());
        match &self.public_certificate {
            Some(value) => {
                digest.text("certificate");
                digest.text(&value.certificate_der_base64);
                digest.number(u64::try_from(value.chain_der_base64.len()).unwrap_or(u64::MAX));
                for item in &value.chain_der_base64 {
                    digest.text(item);
                }
            }
            None => digest.text("no-certificate"),
        }
        digest.finish()
    }
}

impl fmt::Debug for AuthorityOutcomeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityOutcomeV2")
            .field("certificate_id", &self.metadata.certificate_id)
            .field("public_certificate", &"[REDACTED]")
            .field("signed_receipt", &self.signed_receipt)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedAuthorityOutcomeReceiptV2 {
    pub completion_evidence: crowsi_control_contracts::CertificateAuthorityOutcomeEvidenceV2,
    pub request_id: String,
    pub management_command_digest_sha256: String,
    pub authority_command_digest_sha256: String,
    pub authority_outcome_digest_sha256: String,
    pub authority_id: String,
    pub authority_key_id: String,
    pub authority_key_version: String,
    pub authority_public_key_spki_sha256: String,
    pub signature_key_id: String,
    pub authority_receipt_key_version: String,
    pub authority_receipt_public_key_spki_sha256: String,
    pub signature_algorithm: String,
    pub key_purpose: String,
    pub authority_lease_id: String,
    pub authority_attestation_digest_sha256: String,
    pub authority_fence: u64,
    pub authority_trust_revision: u64,
    pub lifecycle_reservation_id: String,
    pub lifecycle_fence: u64,
    pub executed_at_epoch_s: u64,
    pub receipt_digest_sha256: String,
    pub signature_verified: bool,
}
