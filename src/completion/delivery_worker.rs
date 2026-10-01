use crowsi_control_contracts::CertificatePayloadV2;

use crate::{
    CertificateCompletionDeliveryPort, CompletionDeliveryError, CompletionDeliveryModeV2,
    CompletionDeliveryReceiptV2, CompletionDeliveryWorkerError, CompletionDeliveryWorkerOutcomeV2,
    CompletionOutboxStorePort,
};

pub struct CertificateCompletionDeliveryWorker<S, D> {
    store: S,
    delivery: D,
}

impl<S, D> CertificateCompletionDeliveryWorker<S, D>
where
    S: CompletionOutboxStorePort,
    D: CertificateCompletionDeliveryPort,
{
    #[must_use]
    pub const fn new(store: S, delivery: D) -> Self {
        Self { store, delivery }
    }

    /// Advances one durable completion delivery or reports that no work exists.
    ///
    /// # Errors
    ///
    /// Fails closed when durable state is unavailable, the delivery endpoint
    /// rejects the exact evidence pair, or its receipt does not bind that pair.
    pub fn process_next(
        &mut self,
    ) -> Result<CompletionDeliveryWorkerOutcomeV2, CompletionDeliveryWorkerError> {
        let Some(item) = self
            .store
            .next_completion_delivery()
            .map_err(|_| CompletionDeliveryWorkerError::StateUnavailable)?
        else {
            return Ok(CompletionDeliveryWorkerOutcomeV2::Idle);
        };
        let work = self
            .store
            .begin_completion_delivery(&item)
            .map_err(|_| CompletionDeliveryWorkerError::StateUnavailable)?;
        if work.item != item {
            return Err(CompletionDeliveryWorkerError::StateUnavailable);
        }
        let receipt = match work.mode {
            CompletionDeliveryModeV2::Submit => self.delivery.submit(&item),
            CompletionDeliveryModeV2::Recover => self.delivery.recover(&item),
        };
        let receipt = match receipt {
            Ok(value) => value,
            Err(CompletionDeliveryError::ResultUnknown) => {
                return Ok(CompletionDeliveryWorkerOutcomeV2::DeliveryResultUnknown);
            }
            Err(CompletionDeliveryError::Unavailable) => {
                return Err(CompletionDeliveryWorkerError::DeliveryUnavailable);
            }
            Err(CompletionDeliveryError::Rejected) => {
                return Err(CompletionDeliveryWorkerError::DeliveryRejected);
            }
        };
        validate_receipt(&item, &receipt)?;
        self.store
            .acknowledge_completion_delivery(&work, &receipt)
            .map_err(|_| CompletionDeliveryWorkerError::StateUnavailable)?;
        Ok(CompletionDeliveryWorkerOutcomeV2::Acknowledged)
    }
}

fn validate_receipt(
    item: &crate::CompletionDeliveryItemV2,
    value: &CompletionDeliveryReceiptV2,
) -> Result<(), CompletionDeliveryWorkerError> {
    let authority = &item.authority_evidence;
    let manager = &item.manager_evidence;
    let exact = value.authorization_jti == authority.authorization_jti
        && value.commit_id == manager.commit_id
        && value.authority_evidence_digest_sha256 == authority.certificate_digest_sha256()
        && value.manager_commit_digest_sha256 == manager.certificate_digest_sha256()
        && value.disposition == authority.disposition.as_str()
        && value.received_at_epoch_s >= manager.evidence_issued_at_epoch_s
        && value.received_at_epoch_s <= value.completed_at_epoch_s
        && value.completed_at_epoch_s <= manager.submission_recovery_deadline_epoch_s;
    exact
        .then_some(())
        .ok_or(CompletionDeliveryWorkerError::DeliveryRejected)
}
