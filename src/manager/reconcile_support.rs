use crate::{
    AuditOperationState, AuditOperationStatusV2, AuditStatusQueryV2, IntegrityViolationKindV2,
    IntegrityViolationV2, ManagerError, ReconciliationContextV2, TrustedClock,
};

use super::CertificateManager;

impl<A, R, W, P, K, C, V, O, S, T> CertificateManager<A, R, W, P, K, C, V, O, S, T>
where
    T: TrustedClock,
{
    pub(super) fn current_reconciliation_time(
        &mut self,
        previous: u64,
    ) -> Result<u64, ManagerError> {
        let current = self
            .clock
            .now_epoch_s()
            .map_err(|_| ManagerError::TrustedTimeRejected)?;
        (current >= previous)
            .then_some(current)
            .ok_or(ManagerError::TrustedTimeRejected)
    }

    pub(super) fn report_reconciliation_mismatch(
        &mut self,
        context: &ReconciliationContextV2,
        verified: &crate::VerifiedAuthorityReconciliationV2,
        status: &AuditOperationStatusV2,
    ) -> Result<(), ManagerError> {
        let violation = IntegrityViolationV2 {
            kind: IntegrityViolationKindV2::ReconciliationProjectionMismatch,
            request_id: context.status.request_id.clone(),
            reservation_id: context.status.reservation_id.clone(),
            authority_command_digest_sha256: context
                .status
                .authority_command_digest_sha256
                .clone()
                .unwrap_or_else(|| "00".repeat(32)),
            expected_receipt_digest_sha256: verified.receipt_digest_sha256.clone(),
            observed_receipt_digest_sha256: status
                .reconciliation_receipt_digest_sha256
                .clone()
                .unwrap_or_else(|| "00".repeat(32)),
        };
        self.integrity_sink
            .emit(&violation)
            .map_err(|_| ManagerError::AuditUnavailable)
    }
}

pub(super) fn finalized_status(
    query: &AuditStatusQueryV2,
    context: &ReconciliationContextV2,
    receipt: &crate::ReceiptDraftV2,
    state_revision: u64,
) -> AuditOperationStatusV2 {
    AuditOperationStatusV2 {
        request_id: query.target_request_id.clone(),
        reservation_id: context.reservation.audit.reservation_id.clone(),
        resource_id: query.resource_id.clone(),
        owner_service_id: query.owner_service_id.clone(),
        owner_workload_id: query.owner_workload_id.clone(),
        owner_subject: query.owner_subject.clone(),
        owner_profile: query.owner_profile.clone(),
        operation_expected_resource_version: query.operation_expected_resource_version,
        operation_lifecycle_revocation_epoch: query.operation_lifecycle_revocation_epoch,
        policy_authorization_ref: receipt.policy_authorization_ref.clone(),
        policy_authorization_digest_sha256: receipt.policy_authorization_digest_sha256.clone(),
        operator_approval_evidence_ref: receipt.operator_approval_evidence_ref.clone(),
        operator_approval_evidence_digest_sha256: receipt
            .operator_approval_evidence_digest_sha256
            .clone(),
        operator_approval_method: receipt.operator_approval_method,
        operator_approval_assurance: receipt.operator_approval_assurance,
        operator_approval_verified_at_epoch_s: receipt.operator_approval_verified_at_epoch_s,
        state_revision,
        state: AuditOperationState::Finalized,
        event_digest_sha256: Some(receipt.digest_sha256()),
        authority_command_digest_sha256: context.status.authority_command_digest_sha256.clone(),
        abandon_reason: None,
        abandon_receipt_digest_sha256: None,
        reconciliation_receipt_digest_sha256: receipt.reconciliation_receipt_digest_sha256.clone(),
        reconciliation_authorization_digest_sha256: receipt
            .reconciliation_authorization_ancestry_digest_sha256
            .clone(),
        reconciliation_query_digest_sha256: receipt.reconciliation_query_digest_sha256.clone(),
    }
}
