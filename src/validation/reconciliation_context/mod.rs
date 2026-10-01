mod command;
mod shape;

use crate::{
    AuditOperationState, CertificateManagerConfig, ManagerError, ReconciliationBeginV2,
    ReconciliationContextV2,
};

use super::{
    audit_status::validate_audit_status, common::valid_digest,
    state::validate_operation_reservation,
};

pub fn validate_reconciliation_context(
    config: &CertificateManagerConfig,
    expected: &ReconciliationBeginV2,
    value: &ReconciliationContextV2,
) -> Result<(), ManagerError> {
    validate_audit_status(&expected.status_query, &value.status)?;
    validate_operation_reservation(&value.original_begin, &value.reservation)
        .map_err(|_| ManagerError::ReconciliationRejected)?;
    let exact = value.reconciliation_begin == *expected
        && valid_digest(&expected.query_digest_sha256)
        && valid_digest(&expected.authorization_command_digest_sha256)
        && expected.authorization_command_digest_sha256 == expected.query_digest_sha256
        && valid_digest(&expected.expected_unknown_evidence_digest_sha256)
        && expected.expected_resource_version
            == value.original_begin.lifecycle.expected_resource_version
        && expected.status_query.target_request_id == value.original_begin.request_id
        && expected.status_query.resource_id == value.original_begin.lifecycle.resource_id
        && expected.status_query.owner_service_id
            == value.original_begin.lifecycle.owner_service_id
        && expected.status_query.owner_workload_id
            == value.original_begin.lifecycle.owner_workload_id
        && expected.status_query.owner_subject == value.original_begin.lifecycle.owner_subject
        && expected.status_query.owner_profile == value.original_begin.lifecycle.owner_profile
        && expected.status_query.operation_expected_resource_version
            == value.original_begin.lifecycle.expected_resource_version
        && shape::original_action_matches(
            expected.original_action,
            value.original_begin.lifecycle.operation,
        )
        && expected.authorization.identity_revocation_epoch
            >= value
                .original_begin
                .audit
                .authorization
                .identity_revocation_epoch
        && expected.expected_lifecycle_reservation_id == value.reservation.lifecycle.reservation_id
        && expected.expected_previous_fence == value.reservation.lifecycle.previous_fence
        && expected.expected_current_fence == value.reservation.lifecycle.current_fence
        && expected.locked_previous_lifecycle_revocation_epoch
            == value.reservation.lifecycle.prior_lifecycle_revocation_epoch
        && expected.locked_lifecycle_revocation_epoch
            == value
                .reservation
                .lifecycle
                .intent
                .lifecycle_revocation_epoch
        && expected.status_query.operation_lifecycle_revocation_epoch
            == value.original_begin.lifecycle.lifecycle_revocation_epoch
        && value.reservation.lifecycle.reservation_id == value.status.reservation_id;
    let command_shape = command::validate_original_command(config, expected, value);
    let finalized_shape = shape::validate_finalized_receipt(value);
    (exact && command_shape && finalized_shape)
        .then_some(())
        .ok_or(ManagerError::ReconciliationRejected)
}

pub(super) fn has_authority_invocation(state: AuditOperationState) -> bool {
    matches!(
        state,
        AuditOperationState::Invoked
            | AuditOperationState::ResultUnknown
            | AuditOperationState::Finalized
            | AuditOperationState::ReconciledNotExecuted
    )
}
