use crate::{
    AuthorityCommandV2, AuthorityOutcomeV2, CertificateCommandV2, CertificateResponseV2,
    LifecycleCommitV2, OperationCommitV2, OperationFinalizeV2, OperationReceiptV2,
    OperationReservationV2, ReceiptDraftV2, VerifiedAuthorityOutcomeReceiptV2,
    VerifiedCertificateExecutionAuthorizationV2, VerifiedWorkloadV2, validation::lifecycle_state,
};

#[allow(clippy::too_many_arguments)]
pub fn receipt(
    command: &CertificateCommandV2,
    workload: &VerifiedWorkloadV2,
    authorization: &VerifiedCertificateExecutionAuthorizationV2,
    reservation: &OperationReservationV2,
    authority_command: &AuthorityCommandV2,
    outcome: &AuthorityOutcomeV2,
    verified: &VerifiedAuthorityOutcomeReceiptV2,
    now: u64,
) -> ReceiptDraftV2 {
    ReceiptDraftV2 {
        request_id: command.request_id.clone(),
        authorization_id: authority_command.authorization_id.clone(),
        authorization_ancestry_digest_sha256:
            crate::CertificateAuthorizationAncestryV2::from_verified(authorization, workload)
                .digest_sha256(),
        policy_authorization_ref: authorization.decision_id.clone(),
        policy_authorization_digest_sha256: authorization.decision_digest_sha256.clone(),
        operator_approval_evidence_ref: authorization
            .approval_id
            .clone()
            .expect("validated mutation approval"),
        operator_approval_evidence_digest_sha256: authorization
            .approval_evidence_digest_sha256
            .clone()
            .expect("validated mutation approval"),
        operator_approval_method: authorization
            .approval_method
            .expect("validated mutation approval"),
        operator_approval_assurance: authorization
            .approval_assurance
            .expect("validated mutation approval"),
        operator_approval_verified_at_epoch_s: authorization
            .approval_verified_at_epoch_s
            .expect("validated mutation approval"),
        command_digest_sha256: command.digest_sha256(),
        operation: command.operation,
        resource_id: command.resource_id.clone(),
        owner_service_id: workload.service_id.clone(),
        owner_workload_id: workload.workload_id.clone(),
        lifecycle_reservation_id: reservation.lifecycle.reservation_id.clone(),
        lifecycle_fence: reservation.lifecycle.current_fence,
        authority_command_digest_sha256: authority_command.digest_sha256(),
        authority_outcome_digest_sha256: outcome.digest_sha256(),
        authority_receipt_digest_sha256: verified.receipt_digest_sha256.clone(),
        reconciliation_receipt_digest_sha256: None,
        reconciliation_authorization_ancestry_digest_sha256: None,
        reconciliation_query_digest_sha256: None,
        result_certificate_id: outcome.metadata.certificate_id.clone(),
        result_metadata_digest_sha256: outcome.metadata.digest_sha256(),
        state: outcome.metadata.state,
        recorded_at_epoch_s: now,
        private_key_received: false,
        private_key_returned: false,
    }
}

pub fn operation_finalize(
    reservation: &OperationReservationV2,
    authority_command: &AuthorityCommandV2,
    outcome: &AuthorityOutcomeV2,
    receipt: ReceiptDraftV2,
    completion_evidence: &crowsi_control_contracts::CertificateAuthorityOutcomeEvidenceV2,
) -> OperationFinalizeV2 {
    OperationFinalizeV2 {
        lifecycle: LifecycleCommitV2 {
            reservation_id: reservation.lifecycle.reservation_id.clone(),
            authority_command_digest_sha256: authority_command.digest_sha256(),
            authority_outcome_digest_sha256: outcome.digest_sha256(),
            resulting_metadata: outcome.metadata.clone(),
            resulting_state: lifecycle_state(outcome.metadata.state),
            resulting_resource_version: reservation.lifecycle.reserved_resource_version,
        },
        receipt,
        completion_evidence: completion_evidence.clone(),
    }
}

pub fn response(
    command: &CertificateCommandV2,
    outcome: AuthorityOutcomeV2,
    commit: OperationCommitV2,
    receipt: ReceiptDraftV2,
) -> CertificateResponseV2 {
    CertificateResponseV2 {
        request_id: command.request_id.clone(),
        operation: command.operation,
        state: outcome.metadata.state,
        metadata: outcome.metadata,
        public_certificate: outcome.public_certificate,
        lifecycle: commit.lifecycle,
        receipt: OperationReceiptV2 {
            event: receipt,
            audit: commit.audit,
        },
    }
}
