use std::fmt;

use crowsi_control_contracts::{
    CertificateAuthorityOutcomeEvidenceV2, CertificateManagerCommitEvidenceV2,
};

use super::ManagerCommitEvidenceDraftV2;

#[derive(Clone, Eq, PartialEq)]
pub struct CompletionCommitReadbackV2 {
    pub completion_id: String,
    pub state_record_id: String,
    pub state_event_digest_sha256: String,
    pub state_revision: u64,
    pub resource_version: u64,
    pub committed_at_epoch_s: u64,
    pub authority_evidence: CertificateAuthorityOutcomeEvidenceV2,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CompletionChallengeV2 {
    pub commit_id: String,
    pub nonce_base64: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionSigningModeV2 {
    Sign,
    Recover,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CompletionSigningWorkV2 {
    pub claim_id: String,
    pub commit: CompletionCommitReadbackV2,
    pub draft: ManagerCommitEvidenceDraftV2,
    pub mode: CompletionSigningModeV2,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CompletionDeliveryItemV2 {
    pub delivery_id: String,
    pub authority_evidence: CertificateAuthorityOutcomeEvidenceV2,
    pub manager_evidence: CertificateManagerCommitEvidenceV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionWorkerOutcomeV2 {
    Idle,
    Staged,
    SigningResultUnknown,
}

impl fmt::Debug for CompletionCommitReadbackV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionCommitReadbackV2")
            .field("state_revision", &self.state_revision)
            .field("completion", &"[REDACTED]")
            .field("state_record", &"[REDACTED]")
            .field("authority_evidence", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for CompletionChallengeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionChallengeV2")
            .field("commit", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for CompletionSigningWorkV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionSigningWorkV2")
            .field("claim_id", &"[REDACTED]")
            .field("commit", &self.commit)
            .field("draft", &"[REDACTED]")
            .field("mode", &self.mode)
            .finish()
    }
}

impl fmt::Debug for CompletionDeliveryItemV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionDeliveryItemV2")
            .field("delivery", &"[REDACTED]")
            .field("authority_evidence", &"[REDACTED]")
            .field("manager_evidence", &"[REDACTED]")
            .finish()
    }
}
