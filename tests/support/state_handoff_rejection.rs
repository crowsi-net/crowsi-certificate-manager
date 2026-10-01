use crowsi_certificate_manager::{HandoffResumeContextV2, VerifiedManagerHandoffV2};
use crowsi_control_contracts::{CertificateManagerHandoffDispositionV2, CertificatePayloadV2};

pub fn exact(context: &HandoffResumeContextV2, rejected: &VerifiedManagerHandoffV2) -> bool {
    let expected = &context.pending.readback;
    let evidence = &rejected.evidence;
    let ack = &rejected.acknowledgement;
    evidence.disposition == CertificateManagerHandoffDispositionV2::NotAccepted
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
        && evidence.observed_at_epoch_s >= expected.expires_at_epoch_s
        && ack.authorization_jti == evidence.authorization_jti
        && ack.receipt_id == evidence.receipt_id
        && ack.evidence_digest_sha256 == evidence.certificate_digest_sha256()
        && ack.disposition == "not-accepted"
        && ack.resulting_state == "abandoned"
        && ack.recorded_at_epoch_s >= evidence.observed_at_epoch_s
}
