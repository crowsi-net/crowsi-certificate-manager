use crowsi_control_contracts::{
    CertificateActionV2, CertificateExecutionDispositionV2, CertificateLifecycleActionV2,
    CertificatePayloadV2, Validate,
};

use crate::{
    AuthorityReconciliationCommandV2, AuthorityReconciliationDispositionV2,
    AuthorityReconciliationOutcomeV2, CertificateManagerConfig, VerifiedAuthorityReconciliationV2,
};

use super::valid_completion_authority_trust;

pub fn valid_reconciliation_evidence(
    config: &CertificateManagerConfig,
    command: &AuthorityReconciliationCommandV2,
    outcome: &AuthorityReconciliationOutcomeV2,
    verified: &VerifiedAuthorityReconciliationV2,
) -> bool {
    let value = &verified.completion_evidence;
    value.validate().is_ok()
        && value.issuer == config.authority_outcome_issuer
        && value.audience == config.authority_outcome_audience
        && value.action == CertificateActionV2::ReconcileUnknown
        && value.authorization_jti == command.authorization_jti
        && value.operation_id == command.authorization_operation_id
        && value.lease_digest_sha256 == command.authorization_lease_digest_sha256
        && value.authorization_command_digest_sha256 == command.authorization_command_digest_sha256
        && value.target_resource_id == command.resource_id
        && value.expected_resource_version == command.expected_resource_version
        && value.previous_fence == command.authorization_previous_fence
        && value.current_fence == command.authorization_current_fence
        && value.previous_lifecycle_revocation_epoch
            == command.authorization_previous_lifecycle_revocation_epoch
        && value.lifecycle_revocation_epoch == command.authorization_lifecycle_revocation_epoch
        && value.disposition == disposition(outcome.disposition)
        && value.authority_outcome_digest_sha256
            == outcome
                .authority_outcome
                .as_ref()
                .map(crate::AuthorityOutcomeV2::digest_sha256)
        && original_relation(command, value)
        && valid_completion_authority_trust(config, value)
        && value.issued_at_epoch_s == verified.observed_at_epoch_s
        && verified.receipt_digest_sha256 == value.certificate_digest_sha256()
}

fn original_relation(
    command: &AuthorityReconciliationCommandV2,
    value: &crowsi_control_contracts::CertificateAuthorityOutcomeEvidenceV2,
) -> bool {
    value.original_authorization_jti.as_deref() == Some(&command.original_authorization_jti)
        && value.original_operation_id.as_deref()
            == Some(&command.original_authorization_operation_id)
        && value.original_lease_digest_sha256.as_deref()
            == Some(&command.original_authorization_lease_digest_sha256)
        && value.original_action == Some(lifecycle_action(command.original_action))
        && value.original_authority_command_digest_sha256.as_deref()
            == Some(&command.authority_command_digest_sha256)
        && value.original_unknown_evidence_digest_sha256.as_deref()
            == Some(&command.unknown_evidence_digest_sha256)
        && value.lifecycle_reservation_id.as_deref() == Some(&command.lifecycle_reservation_id)
        && value.original_previous_fence == Some(command.lifecycle_previous_fence)
        && value.original_current_fence == Some(command.lifecycle_fence)
        && value.original_previous_lifecycle_revocation_epoch
            == Some(command.previous_lifecycle_revocation_epoch)
        && value.original_lifecycle_revocation_epoch == Some(command.lifecycle_revocation_epoch)
}

const fn lifecycle_action(
    value: crate::CertificateLifecycleActionV2,
) -> CertificateLifecycleActionV2 {
    match value {
        crate::CertificateLifecycleActionV2::Issue => CertificateLifecycleActionV2::Issue,
        crate::CertificateLifecycleActionV2::Renew => CertificateLifecycleActionV2::Renew,
        crate::CertificateLifecycleActionV2::Revoke => CertificateLifecycleActionV2::Revoke,
    }
}

const fn disposition(
    value: AuthorityReconciliationDispositionV2,
) -> CertificateExecutionDispositionV2 {
    match value {
        AuthorityReconciliationDispositionV2::Completed => {
            CertificateExecutionDispositionV2::Completed
        }
        AuthorityReconciliationDispositionV2::NotExecuted => {
            CertificateExecutionDispositionV2::NotExecuted
        }
        AuthorityReconciliationDispositionV2::StillUnknown => {
            CertificateExecutionDispositionV2::StillUnknown
        }
    }
}
