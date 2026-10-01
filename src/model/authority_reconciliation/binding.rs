use super::super::{AuthorityAttestationLeaseV2, AuthorityCommandV2};

#[derive(Clone, Eq, PartialEq)]
pub struct OriginalAuthorityExecutionBindingV2 {
    pub authority_id: String,
    pub certificate_signing_key_id: String,
    pub certificate_signing_key_version: String,
    pub certificate_signing_public_key_spki_sha256: String,
    pub receipt_signing_key_id: String,
    pub receipt_signing_key_version: String,
    pub receipt_signing_public_key_spki_sha256: String,
    pub trust_revision: u64,
    pub lease_id: String,
    pub attestation_digest_sha256: String,
    pub fence: u64,
}

impl OriginalAuthorityExecutionBindingV2 {
    #[must_use]
    pub fn from_command(value: &AuthorityCommandV2) -> Self {
        Self {
            authority_id: value.authority_id.clone(),
            certificate_signing_key_id: value.authority_key_id.clone(),
            certificate_signing_key_version: value.authority_key_version.clone(),
            certificate_signing_public_key_spki_sha256: value
                .authority_public_key_spki_sha256
                .clone(),
            receipt_signing_key_id: value.authority_receipt_key_id.clone(),
            receipt_signing_key_version: value.authority_receipt_key_version.clone(),
            receipt_signing_public_key_spki_sha256: value
                .authority_receipt_public_key_spki_sha256
                .clone(),
            trust_revision: value.authority_trust_revision,
            lease_id: value.authority_lease_id.clone(),
            attestation_digest_sha256: value.authority_attestation_digest_sha256.clone(),
            fence: value.authority_fence,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReconciliationAuthorityBindingV2 {
    pub authority_id: String,
    pub certificate_signing_key_id: String,
    pub certificate_signing_key_version: String,
    pub certificate_signing_public_key_spki_sha256: String,
    pub receipt_signing_key_id: String,
    pub receipt_signing_key_version: String,
    pub receipt_signing_public_key_spki_sha256: String,
    pub receipt_signature_algorithm: String,
    pub receipt_key_purpose: String,
    pub trust_revision: u64,
    pub lease_id: String,
    pub attestation_digest_sha256: String,
    pub fence: u64,
    pub expires_at_epoch_s: u64,
}

impl ReconciliationAuthorityBindingV2 {
    #[must_use]
    pub fn from_lease(value: &AuthorityAttestationLeaseV2) -> Self {
        Self {
            authority_id: value.authority_id.clone(),
            certificate_signing_key_id: value.key_id.clone(),
            certificate_signing_key_version: value.authority_key_version.clone(),
            certificate_signing_public_key_spki_sha256: value
                .authority_public_key_spki_sha256
                .clone(),
            receipt_signing_key_id: value.authority_receipt_key_id.clone(),
            receipt_signing_key_version: value.authority_receipt_key_version.clone(),
            receipt_signing_public_key_spki_sha256: value
                .authority_receipt_public_key_spki_sha256
                .clone(),
            receipt_signature_algorithm: value.authority_receipt_signature_algorithm.clone(),
            receipt_key_purpose: value.authority_receipt_key_purpose.clone(),
            trust_revision: value.trust_revision,
            lease_id: value.lease_id.clone(),
            attestation_digest_sha256: value.attestation_digest_sha256.clone(),
            fence: value.fence,
            expires_at_epoch_s: value.expires_at_epoch_s,
        }
    }
}
