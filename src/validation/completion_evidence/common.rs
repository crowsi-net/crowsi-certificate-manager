use crowsi_control_contracts::{
    CertificateAuthorityOutcomeEvidenceV2, CertificateReceiptSignatureAlgorithmV2,
};

use crate::{CertificateManagerConfig, ManagerError};

pub fn validate_completion_evidence_fresh(
    value: &CertificateAuthorityOutcomeEvidenceV2,
    execution_time_epoch_s: u64,
    observed_at_epoch_s: u64,
) -> Result<(), ManagerError> {
    (execution_time_epoch_s <= observed_at_epoch_s
        && value.issued_at_epoch_s <= observed_at_epoch_s
        && observed_at_epoch_s < value.expires_at_epoch_s)
        .then_some(())
        .ok_or(ManagerError::TrustedTimeRejected)
}

pub(crate) fn valid_completion_authority_trust(
    config: &CertificateManagerConfig,
    value: &CertificateAuthorityOutcomeEvidenceV2,
) -> bool {
    value.security_domain == config.security_domain
        && value.deployment_id == config.deployment_id
        && value.trust_revision == config.trust_revision
        && value.authority_id == config.authority_id
        && value.receipt_key_id == config.authority_receipt_verifier_key_id
        && value.receipt_key_version == config.authority_receipt_key_version
        && value.receipt_public_key_spki_sha256 == config.authority_receipt_public_key_spki_sha256
        && value.receipt_signature_algorithm
            == CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS
        && value.receipt_signature_algorithm.as_str()
            == config.authority_receipt_signature_algorithm
        && value.receipt_key_purpose == config.authority_receipt_key_purpose
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= config.max_completion_evidence_ttl_seconds
}

pub(crate) fn no_original_relation(value: &CertificateAuthorityOutcomeEvidenceV2) -> bool {
    value.original_authorization_jti.is_none()
        && value.original_operation_id.is_none()
        && value.original_lease_digest_sha256.is_none()
        && value.original_action.is_none()
        && value.original_authority_command_digest_sha256.is_none()
        && value.original_unknown_evidence_digest_sha256.is_none()
        && value.lifecycle_reservation_id.is_none()
        && value.original_previous_fence.is_none()
        && value.original_current_fence.is_none()
        && value.original_previous_lifecycle_revocation_epoch.is_none()
        && value.original_lifecycle_revocation_epoch.is_none()
}
