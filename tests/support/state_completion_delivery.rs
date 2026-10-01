use std::sync::{Arc, Mutex};

use crowsi_certificate_manager::*;
use crowsi_control_contracts::CertificatePayloadV2;

use super::StoreData;

pub(super) fn next(
    shared: &Arc<Mutex<StoreData>>,
) -> Result<Option<CompletionDeliveryItemV2>, CompletionStateError> {
    Ok(shared
        .lock()
        .map_err(|_| CompletionStateError::Unavailable)?
        .completion_deliveries
        .first()
        .cloned())
}

pub(super) fn begin(
    shared: &Arc<Mutex<StoreData>>,
    item: &CompletionDeliveryItemV2,
) -> Result<CompletionDeliveryWorkV2, CompletionStateError> {
    let mut data = shared
        .lock()
        .map_err(|_| CompletionStateError::Unavailable)?;
    if data.completion_deliveries.first() != Some(item) {
        return Err(CompletionStateError::Conflict);
    }
    if let Some(stored) = &data.completion_delivery_work {
        return (stored.item == *item)
            .then(|| CompletionDeliveryWorkV2 {
                mode: CompletionDeliveryModeV2::Recover,
                ..stored.clone()
            })
            .ok_or(CompletionStateError::Conflict);
    }
    let stored = CompletionDeliveryWorkV2 {
        claim_id: format!("claim.{}", item.delivery_id),
        item: item.clone(),
        mode: CompletionDeliveryModeV2::Recover,
    };
    data.completion_delivery_work = Some(stored.clone());
    Ok(CompletionDeliveryWorkV2 {
        mode: CompletionDeliveryModeV2::Submit,
        ..stored
    })
}

pub(super) fn acknowledge(
    shared: &Arc<Mutex<StoreData>>,
    work: &CompletionDeliveryWorkV2,
    receipt: &CompletionDeliveryReceiptV2,
) -> Result<(), CompletionStateError> {
    let mut data = shared
        .lock()
        .map_err(|_| CompletionStateError::Unavailable)?;
    let item = &work.item;
    let exact = data.completion_deliveries.first() == Some(item)
        && data
            .completion_delivery_work
            .as_ref()
            .is_some_and(|stored| stored.claim_id == work.claim_id && stored.item == *item)
        && receipt.commit_id == item.manager_evidence.commit_id
        && receipt.authority_evidence_digest_sha256
            == item.authority_evidence.certificate_digest_sha256()
        && receipt.manager_commit_digest_sha256
            == item.manager_evidence.certificate_digest_sha256();
    if !exact {
        return Err(CompletionStateError::Conflict);
    }
    data.completion_receipts.push(receipt.clone());
    data.completion_deliveries.remove(0);
    data.completion_delivery_work = None;
    Ok(())
}
