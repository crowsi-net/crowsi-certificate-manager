use super::{
    AuditCommitV2, AuditIntentV2, AuditInvocationV2, AuditOperationStatusV2, AuditReservationV2,
    AuditStatusQueryV2, AuditUnknownV2, LifecycleCommitV2, LifecycleRecordV2,
    LifecycleReservationIntentV2, LifecycleReservationV2, LifecycleUnknownV2, ReceiptDraftV2,
};

#[derive(Clone, Eq, PartialEq)]
pub struct OperationBeginV2 {
    pub request_id: String,
    pub nonce: String,
    pub authorization_id: String,
    pub authorization_jti: String,
    pub reservation_expires_at_epoch_s: u64,
    pub lifecycle: LifecycleReservationIntentV2,
    pub audit: AuditIntentV2,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OperationReservationV2 {
    pub phase: super::AuditOperationState,
    pub state_revision: u64,
    pub invoked_authority_command_digest_sha256: Option<String>,
    pub invoked_at_epoch_s: Option<u64>,
    pub lifecycle: LifecycleReservationV2,
    pub audit: AuditReservationV2,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OperationAbandonV2 {
    pub reservation_id: String,
    pub reason: super::AbandonReasonV2,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OperationInvocationV2 {
    pub audit: AuditInvocationV2,
    pub authority_command: super::AuthorityCommandV2,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OperationFinalizeV2 {
    pub lifecycle: LifecycleCommitV2,
    pub receipt: ReceiptDraftV2,
    pub completion_evidence: crowsi_control_contracts::CertificateAuthorityOutcomeEvidenceV2,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OperationCommitV2 {
    pub lifecycle: LifecycleRecordV2,
    pub audit: AuditCommitV2,
    pub state_revision: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OperationUnknownV2 {
    pub lifecycle: LifecycleUnknownV2,
    pub audit: AuditUnknownV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrityViolationKindV2 {
    CommitProjectionMismatch,
    ReconciliationProjectionMismatch,
    UnknownTransitionMismatch,
}

#[derive(Clone, Eq, PartialEq)]
pub struct IntegrityViolationV2 {
    pub kind: IntegrityViolationKindV2,
    pub request_id: String,
    pub reservation_id: String,
    pub authority_command_digest_sha256: String,
    pub expected_receipt_digest_sha256: String,
    pub observed_receipt_digest_sha256: String,
}

/// Durable transaction/outbox adapters own all replay, lifecycle, and audit state.
pub trait OperationStateSnapshotV2 {
    fn status(&self, query: &AuditStatusQueryV2) -> Option<AuditOperationStatusV2>;
}
