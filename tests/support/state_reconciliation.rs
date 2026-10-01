use std::sync::{Arc, Mutex};

use crowsi_certificate_manager::*;

use super::{
    StoreData,
    state_helpers::{advance_reservation, next_revision},
    state_query,
};

pub fn begin(
    shared: &Arc<Mutex<StoreData>>,
    begin: &ReconciliationBeginV2,
) -> Result<ReconciliationContextV2, OperationStateError> {
    let mut data = shared.lock().expect("state");
    let original = data.begin.clone().ok_or(OperationStateError::Rejected)?;
    let reservation = data
        .reservation
        .clone()
        .ok_or(OperationStateError::Rejected)?;
    let status = state_query::status(&data, &begin.status_query)?;
    super::state_helpers::reserve_keys(
        &mut data.replay_keys,
        &[
            &begin.query_id,
            &begin.nonce,
            &begin.authorization_id,
            &begin.authorization_jti,
            &begin.authorization.lease_digest_sha256,
        ],
    )?;
    data.last_reconciliation_begin = Some(begin.clone());
    Ok(ReconciliationContextV2 {
        status,
        original_begin: original,
        reconciliation_begin: begin.clone(),
        reservation,
        authority_command: data.authority_command.clone(),
        finalized_receipt: data.finalized_receipt.clone(),
    })
}

pub fn resolve(
    shared: &Arc<Mutex<StoreData>>,
    context: &ReconciliationContextV2,
    resolution: &ReconciliationStateResolutionV2,
) -> Result<AuditOperationStatusV2, OperationStateError> {
    let mut data = shared.lock().expect("state");
    if stale_context(&data, context) {
        return Err(OperationStateError::Conflict);
    }
    next_revision(&data)?;
    data.phase = Some(match resolution.verified.disposition {
        AuthorityReconciliationDispositionV2::NotExecuted => {
            AuditOperationState::ReconciledNotExecuted
        }
        AuthorityReconciliationDispositionV2::StillUnknown => AuditOperationState::ResultUnknown,
        AuthorityReconciliationDispositionV2::Completed => {
            if data.phase != Some(AuditOperationState::Finalized) {
                return Err(OperationStateError::Rejected);
            }
            AuditOperationState::Finalized
        }
    });
    data.reconciliation_receipt_digest_sha256 =
        Some(resolution.verified.receipt_digest_sha256.clone());
    data.reconciliation_authorization_digest_sha256 =
        Some(context.reconciliation_begin.authorization.digest_sha256());
    data.reconciliation_query_digest_sha256 =
        Some(context.reconciliation_begin.query_digest_sha256.clone());
    advance_reservation(&mut data)?;
    super::state_reconciliation_completion::record(&mut data, context, resolution);
    state_query::status(&data, &status_query(context))
}

pub fn resolve_projected(
    shared: &Arc<Mutex<StoreData>>,
    context: &ReconciliationContextV2,
    resolution: &ReconciliationStateResolutionV2,
) -> Result<AuditOperationStatusV2, OperationStateError> {
    let mut status = resolve(shared, context, resolution)?;
    if shared
        .lock()
        .expect("state")
        .corrupt_reconciliation_projection
    {
        status.reconciliation_receipt_digest_sha256 = Some("ff".repeat(32));
    }
    Ok(status)
}

fn stale_context(data: &StoreData, context: &ReconciliationContextV2) -> bool {
    data.phase != Some(context.status.state)
        || data.state_revision != context.status.state_revision
        || data
            .authority_command
            .as_ref()
            .map(AuthorityCommandV2::digest_sha256)
            != context.status.authority_command_digest_sha256
        || data.begin.as_ref() != Some(&context.original_begin)
        || data.reservation.as_ref() != Some(&context.reservation)
        || data.last_reconciliation_begin.as_ref() != Some(&context.reconciliation_begin)
}

fn status_query(context: &ReconciliationContextV2) -> AuditStatusQueryV2 {
    let status = &context.status;
    AuditStatusQueryV2 {
        target_request_id: status.request_id.clone(),
        resource_id: status.resource_id.clone(),
        owner_service_id: status.owner_service_id.clone(),
        owner_workload_id: status.owner_workload_id.clone(),
        owner_subject: status.owner_subject.clone(),
        owner_profile: status.owner_profile.clone(),
        operation_expected_resource_version: status.operation_expected_resource_version,
        operation_lifecycle_revocation_epoch: status.operation_lifecycle_revocation_epoch,
    }
}
