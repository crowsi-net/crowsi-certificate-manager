use crate::{
    CertificateAuthorizationOperationBindingV2, CertificateAuthorizedActionV2,
    CertificateCommandV2, CertificateManagerConfig, ManagerError, OperationStatusQueryV2,
    ReconciliationQueryV2, VerifiedCertificateExecutionAuthorizationV2, VerifiedWorkloadV2,
};

use super::common::valid_common;

pub fn validate_command_authorization(
    config: &CertificateManagerConfig,
    workload: &VerifiedWorkloadV2,
    command: &CertificateCommandV2,
    value: &VerifiedCertificateExecutionAuthorizationV2,
    now: u64,
) -> Result<(), ManagerError> {
    let command_binding = value.command_digest_sha256 == command.digest_sha256()
        && value.operation_id == command.request_id
        && value.operation_binding.is_none()
        && value.action == CertificateAuthorizedActionV2::from(command.operation)
        && value.target_resource_id == command.resource_id
        && value.expected_resource_version == command.expected_resource_version;
    let lifecycle_binding = value.previous_lifecycle_revocation_epoch
        == command.previous_lifecycle_revocation_epoch
        && value.lifecycle_revocation_epoch == command.lifecycle_revocation_epoch;
    (valid_common(config, workload, value, now) && command_binding && lifecycle_binding)
        .then_some(())
        .ok_or(ManagerError::AuthorizationBindingRejected)
}

pub fn validate_reconcile_authorization(
    config: &CertificateManagerConfig,
    workload: &VerifiedWorkloadV2,
    query: &ReconciliationQueryV2,
    value: &VerifiedCertificateExecutionAuthorizationV2,
    now: u64,
) -> Result<(), ManagerError> {
    let expected = CertificateAuthorizationOperationBindingV2::ReconcileUnknown {
        original_action: query.original_action,
        target_operation_id: query.target_request_id.clone(),
        lifecycle_reservation_id: query.expected_lifecycle_reservation_id.clone(),
        authority_command_digest_sha256: query.expected_authority_command_digest_sha256.clone(),
        unknown_evidence_digest_sha256: query.expected_unknown_evidence_digest_sha256.clone(),
        locked_previous_fence: query.expected_previous_fence,
        locked_current_fence: query.expected_current_fence,
        locked_previous_lifecycle_revocation_epoch: query
            .locked_previous_lifecycle_revocation_epoch,
        locked_lifecycle_revocation_epoch: query.locked_lifecycle_revocation_epoch,
    };
    let exact = value.command_digest_sha256 == query.digest_sha256()
        && value.operation_id == query.query_id
        && value.operation_binding == Some(expected)
        && value.action == CertificateAuthorizedActionV2::ReconcileUnknown
        && value.target_resource_id == query.resource_id
        && value.expected_resource_version == query.expected_resource_version
        && value.previous_lifecycle_revocation_epoch
            == query.locked_previous_lifecycle_revocation_epoch
        && value.lifecycle_revocation_epoch == query.locked_lifecycle_revocation_epoch
        && value.unknown_evidence_digest_sha256.as_deref()
            == Some(query.expected_unknown_evidence_digest_sha256.as_str())
        && value.pairwise_subject == query.owner_subject
        && value.requester_profile == query.owner_profile;
    (valid_common(config, workload, value, now) && exact)
        .then_some(())
        .ok_or(ManagerError::ReconciliationRejected)
}

pub fn validate_operation_status_authorization(
    config: &CertificateManagerConfig,
    workload: &VerifiedWorkloadV2,
    query: &OperationStatusQueryV2,
    value: &VerifiedCertificateExecutionAuthorizationV2,
    now: u64,
) -> Result<(), ManagerError> {
    let expected = CertificateAuthorizationOperationBindingV2::OperationStatus {
        target_operation_id: query.target_request_id.clone(),
    };
    let exact = value.command_digest_sha256 == query.digest_sha256()
        && value.operation_id == query.query_id
        && value.operation_binding == Some(expected)
        && value.action == CertificateAuthorizedActionV2::OperationStatus
        && value.target_resource_id == query.resource_id
        && value.expected_resource_version == query.expected_resource_version
        && value.previous_lifecycle_revocation_epoch == query.expected_lifecycle_revocation_epoch
        && value.lifecycle_revocation_epoch == query.expected_lifecycle_revocation_epoch
        && value.pairwise_subject == query.owner_subject
        && value.requester_profile == query.owner_profile;
    (valid_common(config, workload, value, now) && exact)
        .then_some(())
        .ok_or(ManagerError::ReconciliationRejected)
}
