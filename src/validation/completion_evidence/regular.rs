use crowsi_control_contracts::{
    CertificateActionV2, CertificateExecutionDispositionV2, CertificatePayloadV2, Validate,
};

use crate::{
    AuthorityCommandV2, AuthorityOutcomeV2, CertificateManagerConfig, CertificateOperation,
    VerifiedAuthorityOutcomeReceiptV2,
};

use super::{no_original_relation, valid_completion_authority_trust};

pub fn valid_outcome_evidence(
    config: &CertificateManagerConfig,
    command: &AuthorityCommandV2,
    outcome: &AuthorityOutcomeV2,
    verified: &VerifiedAuthorityOutcomeReceiptV2,
) -> bool {
    let value = &verified.completion_evidence;
    value.validate().is_ok()
        && value.issuer == config.authority_outcome_issuer
        && value.audience == config.authority_outcome_audience
        && value.action == action(command.operation)
        && value.authorization_jti == command.authorization_jti
        && value.operation_id == command.authorization_operation_id
        && value.lease_digest_sha256 == command.authorization_lease_digest_sha256
        && value.authorization_command_digest_sha256 == command.management_command_digest_sha256
        && value.target_resource_id == command.resource_id
        && value.expected_resource_version == command.expected_resource_version
        && value.previous_fence == command.previous_fence
        && value.current_fence == command.current_fence
        && value.previous_lifecycle_revocation_epoch == command.previous_lifecycle_revocation_epoch
        && value.lifecycle_revocation_epoch == command.lifecycle_revocation_epoch
        && value.disposition == CertificateExecutionDispositionV2::Completed
        && value.authority_outcome_digest_sha256 == Some(outcome.digest_sha256())
        && no_original_relation(value)
        && valid_completion_authority_trust(config, value)
        && value.issued_at_epoch_s == verified.executed_at_epoch_s
        && verified.receipt_digest_sha256 == value.certificate_digest_sha256()
}

const fn action(value: CertificateOperation) -> CertificateActionV2 {
    match value {
        CertificateOperation::Issue => CertificateActionV2::Issue,
        CertificateOperation::Renew => CertificateActionV2::Renew,
        CertificateOperation::Revoke => CertificateActionV2::Revoke,
        CertificateOperation::Status => CertificateActionV2::CertificateStatus,
    }
}
