use crowsi_control_contracts::CertificateManagerCommitEvidenceV2;

use crate::{
    CompletionChallengeError, CompletionChallengeV2, CompletionCommitReadbackV2,
    CompletionDeliveryError, CompletionDeliveryItemV2, CompletionDeliveryReceiptV2,
    CompletionDeliveryWorkV2, CompletionEvidenceError, CompletionSigningWorkV2,
    CompletionStateError, ManagerCommitEvidenceDraftV2,
};

pub trait CertificateCompletionDeliveryPort {
    /// Submits an evidence pair under a durable idempotency identity.
    ///
    /// # Errors
    ///
    /// Returns `ResultUnknown` when submission may have reached the PA. The
    /// caller must recover the same item instead of submitting new evidence.
    fn submit(
        &mut self,
        item: &CompletionDeliveryItemV2,
    ) -> Result<CompletionDeliveryReceiptV2, CompletionDeliveryError>;

    /// Recovers the exact receipt for an ambiguous prior submission.
    ///
    /// # Errors
    ///
    /// Fails closed when the PA cannot prove the exact prior submission.
    fn recover(
        &mut self,
        item: &CompletionDeliveryItemV2,
    ) -> Result<CompletionDeliveryReceiptV2, CompletionDeliveryError>;
}

pub trait CompletionChallengeSourcePort {
    /// Creates a cryptographically random 256-bit canonical Base64 nonce.
    ///
    /// # Errors
    ///
    /// Fails rather than returning predictable, reused, or malformed material.
    fn issue(
        &mut self,
        commit: &CompletionCommitReadbackV2,
    ) -> Result<CompletionChallengeV2, CompletionChallengeError>;
}

pub trait CertificateCompletionEvidenceSignerPort {
    /// Signs the exact persisted draft with the manager-commit hardware key.
    ///
    /// # Errors
    ///
    /// A hardware timeout after invocation is returned as `ResultUnknown`.
    fn sign(
        &mut self,
        draft: &ManagerCommitEvidenceDraftV2,
    ) -> Result<CertificateManagerCommitEvidenceV2, CompletionEvidenceError>;

    /// Recovers an earlier ambiguous signing operation without signing again.
    ///
    /// # Errors
    ///
    /// Fails closed unless the signer journal proves the exact draft result.
    fn recover(
        &mut self,
        draft: &ManagerCommitEvidenceDraftV2,
    ) -> Result<CertificateManagerCommitEvidenceV2, CompletionEvidenceError>;
}

pub trait CertificateCompletionEvidenceVerifierPort {
    /// Independently verifies the exact P1363 low-S signature and pinned key.
    ///
    /// # Errors
    ///
    /// Rejects DER, high-S, wrong-role, stale-version, or changed-SPKI evidence.
    fn verify(
        &mut self,
        evidence: &CertificateManagerCommitEvidenceV2,
    ) -> Result<(), CompletionEvidenceError>;
}

pub trait CompletionOutboxStorePort {
    /// Reads an exact durable state-commit projection awaiting completion.
    ///
    /// # Errors
    ///
    /// Rejects partial or corrupted commit/authority-evidence projections.
    fn next_completion_commit(
        &mut self,
    ) -> Result<Option<CompletionCommitReadbackV2>, CompletionStateError>;

    /// Returns an existing exact signing attempt before any new challenge.
    ///
    /// # Errors
    ///
    /// Rejects a changed commit or corrupted attempt journal.
    fn recover_completion_signing(
        &mut self,
        commit: &CompletionCommitReadbackV2,
    ) -> Result<Option<CompletionSigningWorkV2>, CompletionStateError>;

    /// Persists the exact signing draft before any hardware invocation.
    ///
    /// The transaction changes a new attempt to signer-result-unknown before
    /// returning `Sign`. A concurrent attempt is a conflict; callers then retry
    /// through `recover_completion_signing` without generating a challenge.
    ///
    /// # Errors
    ///
    /// Rejects a stale readback, changed draft, or concurrent claim.
    fn begin_completion_signing(
        &mut self,
        commit: &CompletionCommitReadbackV2,
        draft: &ManagerCommitEvidenceDraftV2,
    ) -> Result<CompletionSigningWorkV2, CompletionStateError>;

    /// Atomically stores both signed proofs and appends the PA delivery outbox.
    ///
    /// # Errors
    ///
    /// Rejects mismatched evidence or a stale signing claim.
    fn stage_completion_delivery(
        &mut self,
        work: &CompletionSigningWorkV2,
        evidence: &CertificateManagerCommitEvidenceV2,
    ) -> Result<(), CompletionStateError>;

    /// Reads the oldest durable evidence pair awaiting PA completion.
    ///
    /// # Errors
    ///
    /// Rejects corrupted or partially committed outbox state.
    fn next_completion_delivery(
        &mut self,
    ) -> Result<Option<CompletionDeliveryItemV2>, CompletionStateError>;

    /// Durably claims an exact delivery attempt as submit or recovery work.
    ///
    /// # Errors
    ///
    /// Rejects a stale item, competing claim, or altered evidence pair.
    fn begin_completion_delivery(
        &mut self,
        item: &CompletionDeliveryItemV2,
    ) -> Result<CompletionDeliveryWorkV2, CompletionStateError>;

    /// Atomically stores the exact PA receipt and removes its outbox item.
    ///
    /// # Errors
    ///
    /// Rejects a receipt or work token that does not bind the claimed item.
    fn acknowledge_completion_delivery(
        &mut self,
        work: &CompletionDeliveryWorkV2,
        receipt: &CompletionDeliveryReceiptV2,
    ) -> Result<(), CompletionStateError>;
}
