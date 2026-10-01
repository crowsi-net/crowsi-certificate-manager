use std::collections::BTreeSet;

use crowsi_certificate_manager::*;

/// Mutable durable-state projection used to exercise adapter failure modes.
#[derive(Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct StoreData {
    pub phase: Option<AuditOperationState>,
    pub state_revision: u64,
    pub begin: Option<OperationBeginV2>,
    pub reservation: Option<OperationReservationV2>,
    pub handoff_pending: Option<OperationHandoffPendingV2>,
    pub handoff_accepted: Option<VerifiedManagerHandoffV2>,
    pub authority_command: Option<AuthorityCommandV2>,
    pub last_reconciliation_begin: Option<ReconciliationBeginV2>,
    pub replay_keys: BTreeSet<String>,
    pub event_digest_sha256: Option<String>,
    pub finalized_receipt: Option<ReceiptDraftV2>,
    pub abandon_reason: Option<AbandonReasonV2>,
    pub abandon_receipt_digest_sha256: Option<String>,
    pub reconciliation_receipt_digest_sha256: Option<String>,
    pub reconciliation_authorization_digest_sha256: Option<String>,
    pub reconciliation_query_digest_sha256: Option<String>,
    pub fail_finalize: bool,
    pub lose_finalize_ack: bool,
    pub fail_begin: bool,
    pub fail_mark_unknown: bool,
    pub conflict_mark_unknown: bool,
    pub corrupt_commit_projection: bool,
    pub corrupt_commit_revision: bool,
    pub corrupt_invocation_digest: bool,
    pub corrupt_invocation_phase: bool,
    pub corrupt_invocation_projection: bool,
    pub lose_invocation_ack: bool,
    pub corrupt_reconciliation_projection: bool,
    pub completion_commits: Vec<CompletionCommitReadbackV2>,
    pub completion_work: Option<CompletionSigningWorkV2>,
    pub completion_deliveries: Vec<CompletionDeliveryItemV2>,
    pub completion_delivery_work: Option<CompletionDeliveryWorkV2>,
    pub completion_receipts: Vec<CompletionDeliveryReceiptV2>,
    pub fail_completion_stage: bool,
    pub lose_handoff_accept_ack: bool,
    pub corrupt_handoff_accept_projection: bool,
}
