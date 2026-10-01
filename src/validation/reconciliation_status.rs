use crate::{
    AuditOperationState, AuditOperationStatusV2, AuthorityReconciliationDispositionV2,
    ManagerError, ReconciliationContextV2, VerifiedAuthorityReconciliationV2,
};

use super::audit_status::validate_audit_status;

pub fn validate_reconciliation_status(
    context: &ReconciliationContextV2,
    verified: &VerifiedAuthorityReconciliationV2,
    status: &AuditOperationStatusV2,
) -> Result<(), ManagerError> {
    validate_audit_status(&context.reconciliation_begin.status_query, status)?;
    let expected_state = match verified.disposition {
        AuthorityReconciliationDispositionV2::NotExecuted => {
            AuditOperationState::ReconciledNotExecuted
        }
        AuthorityReconciliationDispositionV2::StillUnknown => AuditOperationState::ResultUnknown,
        AuthorityReconciliationDispositionV2::Completed => AuditOperationState::Finalized,
    };
    let next_revision = context.status.state_revision.checked_add(1);
    let exact = status.state == expected_state
        && status.request_id == context.status.request_id
        && status.reservation_id == context.status.reservation_id
        && status.resource_id == context.status.resource_id
        && status.owner_service_id == context.status.owner_service_id
        && status.owner_workload_id == context.status.owner_workload_id
        && status.owner_subject == context.status.owner_subject
        && status.owner_profile == context.status.owner_profile
        && status.operation_expected_resource_version
            == context.status.operation_expected_resource_version
        && status.operation_lifecycle_revocation_epoch
            == context.status.operation_lifecycle_revocation_epoch
        && status.policy_authorization_ref
            == context.reconciliation_begin.authorization.decision_id
        && status.policy_authorization_digest_sha256
            == context
                .reconciliation_begin
                .authorization
                .decision_digest_sha256
        && context
            .reconciliation_begin
            .authorization
            .approval_id
            .as_deref()
            == Some(status.operator_approval_evidence_ref.as_str())
        && context
            .reconciliation_begin
            .authorization
            .approval_evidence_digest_sha256
            .as_deref()
            == Some(status.operator_approval_evidence_digest_sha256.as_str())
        && context.reconciliation_begin.authorization.approval_method
            == Some(status.operator_approval_method)
        && context
            .reconciliation_begin
            .authorization
            .approval_assurance
            == Some(status.operator_approval_assurance)
        && context
            .reconciliation_begin
            .authorization
            .approval_verified_at_epoch_s
            == Some(status.operator_approval_verified_at_epoch_s)
        && Some(status.state_revision) == next_revision
        && status.event_digest_sha256
            == if verified.disposition == AuthorityReconciliationDispositionV2::Completed {
                context.status.event_digest_sha256.clone()
            } else {
                None
            }
        && status.authority_command_digest_sha256 == context.status.authority_command_digest_sha256
        && status.reconciliation_receipt_digest_sha256.as_deref()
            == Some(verified.receipt_digest_sha256.as_str())
        && status.reconciliation_authorization_digest_sha256.as_deref()
            == Some(
                context
                    .reconciliation_begin
                    .authorization
                    .digest_sha256()
                    .as_str(),
            )
        && status.reconciliation_query_digest_sha256.as_deref()
            == Some(context.reconciliation_begin.query_digest_sha256.as_str());
    exact
        .then_some(())
        .ok_or(ManagerError::ReconciliationRejected)
}
