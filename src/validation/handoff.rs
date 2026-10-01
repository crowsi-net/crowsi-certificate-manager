use crowsi_control_contracts::{
    CertificateManagerHandoffDispositionV2, CertificatePayloadV2,
    CertificateReceiptSignatureAlgorithmV2, Validate,
};

use crate::{
    CertificateManagerConfig, ManagerError, ManagerHandoffReadbackV2, VerifiedManagerHandoffV2,
};

pub fn validate_manager_handoff(
    config: &CertificateManagerConfig,
    expected: &ManagerHandoffReadbackV2,
    value: &VerifiedManagerHandoffV2,
) -> Result<(), ManagerError> {
    let evidence = &value.evidence;
    let common = evidence.validate().is_ok()
        && evidence.receipt_id == expected.receipt_id
        && evidence.action == expected.action
        && evidence.authorization_jti == expected.authorization_jti
        && evidence.operation_id == expected.operation_id
        && evidence.lease_digest_sha256 == expected.lease_digest_sha256
        && evidence.authorization_command_digest_sha256
            == expected.authorization_command_digest_sha256
        && evidence.security_domain == expected.security_domain
        && evidence.deployment_id == expected.deployment_id
        && evidence.trust_revision == expected.trust_revision
        && evidence.target_resource_id == expected.target_resource_id
        && evidence.expected_resource_version == expected.expected_resource_version
        && evidence.previous_fence == expected.previous_fence
        && evidence.current_fence == expected.current_fence
        && evidence.previous_lifecycle_revocation_epoch
            == expected.previous_lifecycle_revocation_epoch
        && evidence.lifecycle_revocation_epoch == expected.lifecycle_revocation_epoch
        && evidence.issuer == config.manager_handoff_issuer
        && evidence.audience == config.manager_handoff_audience
        && evidence.manager_workload == config.manager_handoff_workload
        && evidence.receipt_key_id == config.manager_handoff_key_id
        && evidence.receipt_key_version == config.manager_handoff_key_version
        && evidence.receipt_public_key_spki_sha256 == config.manager_handoff_public_key_spki_sha256
        && evidence.receipt_signature_algorithm
            == CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS
        && evidence.receipt_signature_algorithm.as_str()
            == config.manager_handoff_signature_algorithm
        && evidence.receipt_key_purpose == config.manager_handoff_key_purpose
        && ack_binding(value);
    let disposition = match evidence.disposition {
        CertificateManagerHandoffDispositionV2::Accepted => {
            evidence.observed_at_epoch_s >= expected.reserved_at_epoch_s
                && evidence.observed_at_epoch_s < expected.expires_at_epoch_s
                && value.acknowledgement.recorded_at_epoch_s < expected.expires_at_epoch_s
                && value.acknowledgement.disposition == "accepted"
                && value.acknowledgement.resulting_state == "executing"
        }
        CertificateManagerHandoffDispositionV2::NotAccepted => {
            evidence.observed_at_epoch_s >= expected.expires_at_epoch_s
                && value.acknowledgement.disposition == "not-accepted"
                && value.acknowledgement.resulting_state == "abandoned"
        }
    };
    (common && disposition)
        .then_some(())
        .ok_or(ManagerError::HandoffResultUnknown)
}

fn ack_binding(value: &VerifiedManagerHandoffV2) -> bool {
    let evidence = &value.evidence;
    let ack = &value.acknowledgement;
    ack.authorization_jti == evidence.authorization_jti
        && ack.receipt_id == evidence.receipt_id
        && ack.evidence_digest_sha256 == evidence.certificate_digest_sha256()
        && ack.recorded_at_epoch_s >= evidence.observed_at_epoch_s
}
