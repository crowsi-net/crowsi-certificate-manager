use std::sync::{Arc, Mutex};

use crowsi_certificate_manager::*;

use super::{
    StoreData,
    state_helpers::{advance_reservation, current_reservation, next_revision},
    state_query::status,
};

pub(super) fn mark_invoked(
    shared: &Arc<Mutex<StoreData>>,
    supplied: &OperationReservationV2,
    invocation: &OperationInvocationV2,
) -> Result<OperationReservationV2, OperationStateError> {
    let mut data = shared.lock().expect("state");
    let command_digest = invocation.authority_command.digest_sha256();
    let exact = data.phase == Some(AuditOperationState::Reserved)
        && current_reservation(&data, supplied)
        && data.handoff_accepted.is_some()
        && data
            .handoff_pending
            .as_ref()
            .is_some_and(|pending| pending.authority_command == invocation.authority_command)
        && invocation.audit.reservation_id == supplied.audit.reservation_id
        && invocation.audit.authority_command_digest_sha256 == command_digest
        && invocation.audit.execution_time_epoch_s
            >= invocation.authority_command.execution_time_epoch_s;
    if !exact {
        return Err(OperationStateError::Conflict);
    }
    next_revision(&data)?;
    data.phase = Some(AuditOperationState::Invoked);
    data.authority_command = Some(invocation.authority_command.clone());
    let mut reservation = advance_reservation(&mut data)?;
    reservation.phase = AuditOperationState::Invoked;
    reservation.invoked_authority_command_digest_sha256 = Some(command_digest);
    reservation.invoked_at_epoch_s = Some(invocation.audit.execution_time_epoch_s);
    data.reservation = Some(reservation.clone());
    Ok(reservation)
}

pub(super) fn abandon_pre_handoff(
    shared: &Arc<Mutex<StoreData>>,
    supplied: &OperationReservationV2,
    abandon: &OperationAbandonV2,
) -> Result<OperationReservationV2, OperationStateError> {
    let mut data = shared.lock().expect("state");
    let exact = data.phase == Some(AuditOperationState::Reserved)
        && current_reservation(&data, supplied)
        && data.handoff_pending.is_none()
        && data.handoff_accepted.is_none()
        && data.authority_command.is_none()
        && abandon.reservation_id == supplied.lifecycle.reservation_id;
    if !exact {
        return Err(OperationStateError::Conflict);
    }
    next_revision(&data)?;
    data.phase = Some(AuditOperationState::Abandoned);
    data.abandon_reason = Some(abandon.reason);
    data.abandon_receipt_digest_sha256 = Some("82".repeat(32));
    let mut reservation = advance_reservation(&mut data)?;
    reservation.phase = AuditOperationState::Abandoned;
    data.reservation = Some(reservation.clone());
    Ok(reservation)
}

pub(super) fn mark_unknown(
    shared: &Arc<Mutex<StoreData>>,
    supplied: &OperationReservationV2,
    unknown: &OperationUnknownV2,
) -> Result<(), OperationStateError> {
    let mut data = shared.lock().expect("state");
    let command_digest = data
        .authority_command
        .as_ref()
        .map(AuthorityCommandV2::digest_sha256);
    let exact = data.phase == Some(AuditOperationState::Invoked)
        && current_reservation(&data, supplied)
        && unknown.lifecycle.reservation_id == supplied.lifecycle.reservation_id
        && unknown.audit.reservation_id == supplied.audit.reservation_id
        && Some(unknown.lifecycle.authority_command_digest_sha256.as_str())
            == command_digest.as_deref()
        && unknown.lifecycle.authority_command_digest_sha256
            == unknown.audit.authority_command_digest_sha256
        && unknown.lifecycle.reason == unknown.audit.reason;
    if !exact {
        return Err(OperationStateError::Conflict);
    }
    if data.fail_mark_unknown {
        return Err(OperationStateError::Unavailable);
    }
    if data.conflict_mark_unknown {
        return Err(OperationStateError::Conflict);
    }
    next_revision(&data)?;
    data.phase = Some(AuditOperationState::ResultUnknown);
    advance_reservation(&mut data)?;
    Ok(())
}

pub(super) fn confirm_unknown(
    shared: &Arc<Mutex<StoreData>>,
    reservation: &OperationReservationV2,
    _: &OperationUnknownV2,
) -> Result<AuditOperationStatusV2, OperationStateError> {
    let data = shared.lock().expect("state");
    let intent = &reservation.lifecycle.intent;
    status(
        &data,
        &AuditStatusQueryV2 {
            target_request_id: intent.request_id.clone(),
            resource_id: intent.resource_id.clone(),
            owner_service_id: intent.owner_service_id.clone(),
            owner_workload_id: intent.owner_workload_id.clone(),
            owner_subject: intent.owner_subject.clone(),
            owner_profile: intent.owner_profile.clone(),
            operation_expected_resource_version: intent.expected_resource_version,
            operation_lifecycle_revocation_epoch: intent.lifecycle_revocation_epoch,
        },
    )
}
