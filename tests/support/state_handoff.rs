use std::sync::{Arc, Mutex};

use crowsi_certificate_manager::*;

use super::{
    StoreData,
    state_helpers::{advance_reservation, current_reservation, next_revision},
};

pub fn find(
    shared: &Arc<Mutex<StoreData>>,
    query: &HandoffResumeQueryV2,
) -> Result<Option<HandoffResumeContextV2>, OperationStateError> {
    let data = shared.lock().expect("state");
    if !matches!(
        data.phase,
        Some(AuditOperationState::Reserved | AuditOperationState::Invoked)
    ) {
        return Ok(None);
    }
    let Some(pending) = &data.handoff_pending else {
        return Ok(None);
    };
    if &pending.query != query {
        return Err(OperationStateError::Replay);
    }
    Ok(Some(context(&data, pending)))
}

pub fn stage(
    shared: &Arc<Mutex<StoreData>>,
    reservation: &OperationReservationV2,
    pending: &OperationHandoffPendingV2,
) -> Result<HandoffResumeContextV2, OperationStateError> {
    let mut data = shared.lock().expect("state");
    if let Some(stored) = &data.handoff_pending {
        return (stored == pending)
            .then(|| context(&data, stored))
            .ok_or(OperationStateError::Replay);
    }
    if data.phase != Some(AuditOperationState::Reserved)
        || !current_reservation(&data, reservation)
        || pending.source_state_revision != reservation.state_revision
        || data.handoff_accepted.is_some()
    {
        return Err(OperationStateError::Conflict);
    }
    next_revision(&data)?;
    data.handoff_pending = Some(pending.clone());
    advance_reservation(&mut data)?;
    Ok(context(&data, pending))
}

pub fn accept(
    shared: &Arc<Mutex<StoreData>>,
    context_value: &HandoffResumeContextV2,
    accepted: &VerifiedManagerHandoffV2,
) -> Result<HandoffResumeContextV2, OperationStateError> {
    let mut data = shared.lock().expect("state");
    let pending = data
        .handoff_pending
        .as_ref()
        .ok_or(OperationStateError::Conflict)?
        .clone();
    if data.phase != Some(AuditOperationState::Reserved)
        || context_value.pending != pending
        || !current_reservation(&data, &context_value.reservation)
    {
        return Err(OperationStateError::Conflict);
    }
    if let Some(stored) = &data.handoff_accepted {
        return (stored == accepted)
            .then(|| context(&data, &pending))
            .ok_or(OperationStateError::Replay);
    }
    next_revision(&data)?;
    data.handoff_accepted = Some(accepted.clone());
    advance_reservation(&mut data)?;
    let result = context(&data, &pending);
    if data.lose_handoff_accept_ack {
        return Err(OperationStateError::Unavailable);
    }
    Ok(result)
}

pub fn reject(
    shared: &Arc<Mutex<StoreData>>,
    context_value: &HandoffResumeContextV2,
    rejected: &VerifiedManagerHandoffV2,
) -> Result<OperationReservationV2, OperationStateError> {
    let mut data = shared.lock().expect("state");
    let pending = data
        .handoff_pending
        .as_ref()
        .ok_or(OperationStateError::Conflict)?;
    let exact = data.phase == Some(AuditOperationState::Reserved)
        && data.handoff_accepted.is_none()
        && pending == &context_value.pending
        && current_reservation(&data, &context_value.reservation)
        && context_value.accepted.is_none()
        && super::state_handoff_rejection::exact(context_value, rejected);
    if !exact {
        return Err(OperationStateError::Conflict);
    }
    next_revision(&data)?;
    data.phase = Some(AuditOperationState::Abandoned);
    data.abandon_reason = Some(AbandonReasonV2::AuthorizationExpired);
    data.abandon_receipt_digest_sha256 =
        Some(rejected.acknowledgement.evidence_digest_sha256.clone());
    let mut reservation = advance_reservation(&mut data)?;
    reservation.phase = AuditOperationState::Abandoned;
    data.reservation = Some(reservation.clone());
    Ok(reservation)
}

fn context(data: &StoreData, pending: &OperationHandoffPendingV2) -> HandoffResumeContextV2 {
    HandoffResumeContextV2 {
        reservation: data.reservation.clone().expect("reservation"),
        pending: pending.clone(),
        accepted: data.handoff_accepted.clone(),
    }
}
