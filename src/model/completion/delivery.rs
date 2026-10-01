use std::fmt;

use super::CompletionDeliveryItemV2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionDeliveryModeV2 {
    Submit,
    Recover,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CompletionDeliveryWorkV2 {
    pub claim_id: String,
    pub item: CompletionDeliveryItemV2,
    pub mode: CompletionDeliveryModeV2,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CompletionDeliveryReceiptV2 {
    pub authorization_jti: String,
    pub commit_id: String,
    pub authority_evidence_digest_sha256: String,
    pub manager_commit_digest_sha256: String,
    pub disposition: String,
    pub received_at_epoch_s: u64,
    pub completed_at_epoch_s: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionDeliveryWorkerOutcomeV2 {
    Idle,
    Acknowledged,
    DeliveryResultUnknown,
}

impl fmt::Debug for CompletionDeliveryWorkV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionDeliveryWorkV2")
            .field("claim_id", &"[REDACTED]")
            .field("item", &self.item)
            .field("mode", &self.mode)
            .finish()
    }
}

impl fmt::Debug for CompletionDeliveryReceiptV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionDeliveryReceiptV2")
            .field("commit", &"[REDACTED]")
            .field("disposition", &self.disposition)
            .field("authorization", &"[REDACTED]")
            .field("evidence", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
