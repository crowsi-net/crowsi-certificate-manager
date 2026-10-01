use std::sync::{Arc, Mutex};

use crowsi_certificate_manager::*;

use super::{StoreData, prior_metadata, state_helpers::reserve_keys};

pub(super) fn begin(
    shared: &Arc<Mutex<StoreData>>,
    begin: &OperationBeginV2,
) -> Result<OperationReservationV2, OperationStateError> {
    let mut data = shared.lock().expect("state");
    if let Some(existing) = &data.begin {
        if existing != begin {
            return Err(OperationStateError::Replay);
        }
        return match data.phase {
            Some(
                AuditOperationState::Reserved
                | AuditOperationState::Invoked
                | AuditOperationState::ResultUnknown,
            ) => Ok(data.reservation.clone().expect("reservation")),
            _ => Err(OperationStateError::Replay),
        };
    }
    if data.fail_begin {
        return Err(OperationStateError::Unavailable);
    }
    let prior = (begin.lifecycle.operation != CertificateOperation::Issue).then(prior_metadata);
    let reserved_resource_version = match begin.lifecycle.operation {
        CertificateOperation::Status => begin.lifecycle.expected_resource_version,
        _ => begin
            .lifecycle
            .expected_resource_version
            .checked_add(1)
            .ok_or(OperationStateError::Conflict)?,
    };
    let reservation = OperationReservationV2 {
        phase: AuditOperationState::Reserved,
        state_revision: 1,
        invoked_authority_command_digest_sha256: None,
        invoked_at_epoch_s: None,
        lifecycle: LifecycleReservationV2 {
            reservation_id: begin.lifecycle.required_reservation_id.clone(),
            intent: begin.lifecycle.clone(),
            prior_state: prior
                .as_ref()
                .map_or(LifecycleStateV2::Absent, |_| LifecycleStateV2::Active),
            prior_certificate_id: prior.as_ref().map(|value| value.certificate_id.clone()),
            prior_metadata: prior,
            prior_resource_version: begin.lifecycle.expected_resource_version,
            prior_lifecycle_revocation_epoch: begin.lifecycle.previous_lifecycle_revocation_epoch,
            reserved_resource_version,
            previous_fence: begin.lifecycle.previous_fence,
            current_fence: begin.lifecycle.current_fence,
        },
        audit: AuditReservationV2 {
            reservation_id: begin.lifecycle.required_reservation_id.clone(),
            request_id: begin.request_id.clone(),
            intent_digest_sha256: begin.audit.digest_sha256(),
        },
    };
    reserve_keys(
        &mut data.replay_keys,
        &[
            &begin.request_id,
            &begin.nonce,
            &begin.authorization_id,
            &begin.authorization_jti,
            &begin.audit.authorization.lease_digest_sha256,
            &begin.lifecycle.required_reservation_id,
        ],
    )?;
    data.phase = Some(AuditOperationState::Reserved);
    data.state_revision = 1;
    data.begin = Some(begin.clone());
    data.reservation = Some(reservation.clone());
    Ok(reservation)
}
