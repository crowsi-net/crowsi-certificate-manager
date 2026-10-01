use crate::{
    AuthorityReconciliationOutcomeV2, OperationFinalizeV2, ReceiptDraftV2, ReconciliationContextV2,
    VerifiedAuthorityOutcomeReceiptV2, VerifiedAuthorityReconciliationV2,
};

pub fn recovered_receipt(
    context: &ReconciliationContextV2,
    outcome: &crate::AuthorityOutcomeV2,
    authority: &VerifiedAuthorityOutcomeReceiptV2,
    reconciliation: &VerifiedAuthorityReconciliationV2,
    now: u64,
) -> ReceiptDraftV2 {
    let begin = &context.original_begin;
    let original = context
        .authority_command
        .as_ref()
        .expect("validated context");
    let approval = &context.reconciliation_begin.authorization;
    ReceiptDraftV2 {
        request_id: begin.request_id.clone(),
        authorization_id: begin.authorization_id.clone(),
        authorization_ancestry_digest_sha256: begin.audit.authorization.digest_sha256(),
        policy_authorization_ref: approval.decision_id.clone(),
        policy_authorization_digest_sha256: approval.decision_digest_sha256.clone(),
        operator_approval_evidence_ref: approval
            .approval_id
            .clone()
            .expect("validated reconciliation approval"),
        operator_approval_evidence_digest_sha256: approval
            .approval_evidence_digest_sha256
            .clone()
            .expect("validated reconciliation approval"),
        operator_approval_method: approval
            .approval_method
            .expect("validated reconciliation approval"),
        operator_approval_assurance: approval
            .approval_assurance
            .expect("validated reconciliation approval"),
        operator_approval_verified_at_epoch_s: approval
            .approval_verified_at_epoch_s
            .expect("validated reconciliation approval"),
        command_digest_sha256: begin.lifecycle.command_digest_sha256.clone(),
        operation: begin.lifecycle.operation,
        resource_id: begin.lifecycle.resource_id.clone(),
        owner_service_id: begin.lifecycle.owner_service_id.clone(),
        owner_workload_id: begin.lifecycle.owner_workload_id.clone(),
        lifecycle_reservation_id: context.reservation.lifecycle.reservation_id.clone(),
        lifecycle_fence: context.reservation.lifecycle.current_fence,
        authority_command_digest_sha256: original.digest_sha256(),
        authority_outcome_digest_sha256: outcome.digest_sha256(),
        authority_receipt_digest_sha256: authority.receipt_digest_sha256.clone(),
        reconciliation_receipt_digest_sha256: Some(reconciliation.receipt_digest_sha256.clone()),
        reconciliation_authorization_ancestry_digest_sha256: Some(approval.digest_sha256()),
        reconciliation_query_digest_sha256: Some(
            context.reconciliation_begin.query_digest_sha256.clone(),
        ),
        result_certificate_id: outcome.metadata.certificate_id.clone(),
        result_metadata_digest_sha256: outcome.metadata.digest_sha256(),
        state: outcome.metadata.state,
        recorded_at_epoch_s: now,
        private_key_received: false,
        private_key_returned: false,
    }
}

pub fn recovered_finalize(
    context: &ReconciliationContextV2,
    outcome: &crate::AuthorityOutcomeV2,
    receipt: ReceiptDraftV2,
    completion_evidence: &crowsi_control_contracts::CertificateAuthorityOutcomeEvidenceV2,
) -> OperationFinalizeV2 {
    let original = context
        .authority_command
        .as_ref()
        .expect("validated context");
    super::result::operation_finalize(
        &context.reservation,
        original,
        outcome,
        receipt,
        completion_evidence,
    )
}

pub fn recovered_outcome(
    value: &AuthorityReconciliationOutcomeV2,
) -> Option<&crate::AuthorityOutcomeV2> {
    value.authority_outcome.as_ref()
}
