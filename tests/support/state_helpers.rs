use std::collections::BTreeSet;

use crowsi_certificate_manager::*;

use super::StoreData;

pub fn next_revision(data: &StoreData) -> Result<u64, OperationStateError> {
    data.state_revision
        .checked_add(1)
        .ok_or(OperationStateError::Conflict)
}

pub fn current_reservation(data: &StoreData, value: &OperationReservationV2) -> bool {
    data.state_revision == value.state_revision && data.reservation.as_ref() == Some(value)
}

pub fn advance_reservation(
    data: &mut StoreData,
) -> Result<OperationReservationV2, OperationStateError> {
    let next = next_revision(data)?;
    data.state_revision = next;
    let reservation = data
        .reservation
        .as_mut()
        .ok_or(OperationStateError::Conflict)?;
    reservation.state_revision = next;
    Ok(reservation.clone())
}

pub fn reserve_keys(
    replay: &mut BTreeSet<String>,
    values: &[&String],
) -> Result<(), OperationStateError> {
    if values.iter().any(|value| replay.contains(value.as_str()))
        || values
            .iter()
            .enumerate()
            .any(|(index, value)| values[..index].contains(value))
    {
        return Err(OperationStateError::Replay);
    }
    replay.extend(values.iter().map(|value| (*value).clone()));
    Ok(())
}

pub fn commit(
    reservation: &OperationReservationV2,
    finalize: &OperationFinalizeV2,
    state_revision: u64,
) -> OperationCommitV2 {
    let intent = &reservation.lifecycle.intent;
    OperationCommitV2 {
        lifecycle: LifecycleRecordV2 {
            resource_id: intent.resource_id.clone(),
            owner_service_id: intent.owner_service_id.clone(),
            owner_workload_id: intent.owner_workload_id.clone(),
            owner_subject: intent.owner_subject.clone(),
            owner_profile: intent.owner_profile.clone(),
            certificate_id: Some(finalize.lifecycle.resulting_metadata.certificate_id.clone()),
            state: finalize.lifecycle.resulting_state,
            resource_version: finalize.lifecycle.resulting_resource_version,
            fence: intent.current_fence,
            lifecycle_revocation_epoch: intent.lifecycle_revocation_epoch,
        },
        audit: AuditCommitV2 {
            reservation_id: reservation.audit.reservation_id.clone(),
            record_id: "audit.record.certificate.0001".into(),
            event_digest_sha256: finalize.receipt.digest_sha256(),
            previous_digest_sha256: Some("81".repeat(32)),
        },
        state_revision,
    }
}
