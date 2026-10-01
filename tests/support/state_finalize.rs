use std::sync::{Arc, Mutex};

use crowsi_certificate_manager::*;

use super::{
    StoreData,
    state_helpers::{advance_reservation, commit, current_reservation, next_revision},
};

pub(super) fn finalize(
    shared: &Arc<Mutex<StoreData>>,
    reservation: &OperationReservationV2,
    finalize: &OperationFinalizeV2,
) -> Result<OperationCommitV2, OperationStateError> {
    let mut data = shared.lock().expect("state");
    if !current_reservation(&data, reservation)
        || !matches!(
            data.phase,
            Some(AuditOperationState::Invoked | AuditOperationState::ResultUnknown)
        )
    {
        return Err(OperationStateError::Conflict);
    }
    if data.fail_finalize {
        return Err(OperationStateError::Unavailable);
    }
    let next = next_revision(&data)?;
    validate_reconciliation_proofs(&data, finalize)?;
    data.phase = Some(AuditOperationState::Finalized);
    advance_reservation(&mut data)?;
    debug_assert_eq!(data.state_revision, next);
    data.event_digest_sha256 = Some(finalize.receipt.digest_sha256());
    data.finalized_receipt = Some(finalize.receipt.clone());
    data.reconciliation_receipt_digest_sha256
        .clone_from(&finalize.receipt.reconciliation_receipt_digest_sha256);
    data.reconciliation_authorization_digest_sha256.clone_from(
        &finalize
            .receipt
            .reconciliation_authorization_ancestry_digest_sha256,
    );
    data.reconciliation_query_digest_sha256
        .clone_from(&finalize.receipt.reconciliation_query_digest_sha256);
    let mut committed = commit(reservation, finalize, data.state_revision);
    data.completion_commits.push(CompletionCommitReadbackV2 {
        completion_id: format!("completion.{}", reservation.lifecycle.reservation_id),
        state_record_id: committed.audit.record_id.clone(),
        state_event_digest_sha256: committed.audit.event_digest_sha256.clone(),
        state_revision: committed.state_revision,
        resource_version: committed.lifecycle.resource_version,
        committed_at_epoch_s: finalize.receipt.recorded_at_epoch_s,
        authority_evidence: finalize.completion_evidence.clone(),
    });
    if data.corrupt_commit_projection {
        committed.audit.event_digest_sha256 = "ff".repeat(32);
    }
    if data.corrupt_commit_revision {
        committed.state_revision = committed.state_revision.saturating_add(1);
    }
    if data.lose_finalize_ack {
        return Err(OperationStateError::Unavailable);
    }
    Ok(committed)
}

fn validate_reconciliation_proofs(
    data: &StoreData,
    finalize: &OperationFinalizeV2,
) -> Result<(), OperationStateError> {
    let proofs = [
        finalize
            .receipt
            .reconciliation_receipt_digest_sha256
            .as_ref(),
        finalize
            .receipt
            .reconciliation_authorization_ancestry_digest_sha256
            .as_ref(),
        finalize.receipt.reconciliation_query_digest_sha256.as_ref(),
    ];
    if proofs.iter().all(Option::is_none) {
        return Ok(());
    }
    let begin = data
        .last_reconciliation_begin
        .as_ref()
        .ok_or(OperationStateError::Rejected)?;
    let valid = proofs
        .iter()
        .all(|value| value.is_some_and(|item| item.len() == 64))
        && proofs[1].map(String::as_str) == Some(begin.authorization.digest_sha256().as_str())
        && proofs[2].map(String::as_str) == Some(begin.query_digest_sha256.as_str());
    valid.then_some(()).ok_or(OperationStateError::Rejected)
}
