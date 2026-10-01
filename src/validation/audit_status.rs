use crate::{AuditOperationState, AuditOperationStatusV2, AuditStatusQueryV2, ManagerError};

use super::common::{valid_digest, valid_id};

pub fn validate_audit_status(
    query: &AuditStatusQueryV2,
    value: &AuditOperationStatusV2,
) -> Result<(), ManagerError> {
    let exact = value.request_id == query.target_request_id
        && value.resource_id == query.resource_id
        && value.owner_service_id == query.owner_service_id
        && value.owner_workload_id == query.owner_workload_id
        && value.owner_subject == query.owner_subject
        && value.owner_profile == query.owner_profile
        && value.operation_expected_resource_version == query.operation_expected_resource_version
        && value.operation_lifecycle_revocation_epoch == query.operation_lifecycle_revocation_epoch
        && value.state_revision > 0
        && valid_id(&value.reservation_id)
        && valid_id(&value.policy_authorization_ref)
        && valid_digest(&value.policy_authorization_digest_sha256)
        && valid_id(&value.operator_approval_evidence_ref)
        && valid_digest(&value.operator_approval_evidence_digest_sha256)
        && value.operator_approval_verified_at_epoch_s > 0;
    let shape = match value.state {
        AuditOperationState::Reserved => {
            no_invocation(value)
                && value.abandon_reason.is_none()
                && value.abandon_receipt_digest_sha256.is_none()
                && no_reconciliation(value)
        }
        AuditOperationState::Abandoned => {
            no_invocation(value)
                && value.abandon_reason.is_some()
                && digest(value.abandon_receipt_digest_sha256.as_deref())
                && no_reconciliation(value)
        }
        AuditOperationState::Invoked => {
            invoked(value) && value.event_digest_sha256.is_none() && no_reconciliation(value)
        }
        AuditOperationState::ResultUnknown => {
            invoked(value) && value.event_digest_sha256.is_none() && reconciliation_shape(value)
        }
        AuditOperationState::Finalized => {
            invoked(value)
                && digest(value.event_digest_sha256.as_deref())
                && reconciliation_shape(value)
        }
        AuditOperationState::ReconciledNotExecuted => {
            invoked(value) && value.event_digest_sha256.is_none() && complete_reconciliation(value)
        }
    };
    (exact && shape)
        .then_some(())
        .ok_or(ManagerError::ReconciliationRejected)
}

fn no_invocation(value: &AuditOperationStatusV2) -> bool {
    value.event_digest_sha256.is_none() && value.authority_command_digest_sha256.is_none()
}

fn invoked(value: &AuditOperationStatusV2) -> bool {
    digest(value.authority_command_digest_sha256.as_deref())
        && value.abandon_reason.is_none()
        && value.abandon_receipt_digest_sha256.is_none()
}

fn reconciliation_shape(value: &AuditOperationStatusV2) -> bool {
    no_reconciliation(value) || complete_reconciliation(value)
}

fn no_reconciliation(value: &AuditOperationStatusV2) -> bool {
    value.reconciliation_receipt_digest_sha256.is_none()
        && value.reconciliation_authorization_digest_sha256.is_none()
        && value.reconciliation_query_digest_sha256.is_none()
}

fn complete_reconciliation(value: &AuditOperationStatusV2) -> bool {
    digest(value.reconciliation_receipt_digest_sha256.as_deref())
        && digest(value.reconciliation_authorization_digest_sha256.as_deref())
        && digest(value.reconciliation_query_digest_sha256.as_deref())
}

fn digest(value: Option<&str>) -> bool {
    value.is_some_and(valid_digest)
}
