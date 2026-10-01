use crowsi_control_contracts::CertificateManagerHandoffDispositionV2;

use crate::{
    AuditOperationState, CertificateManagerConfig, HandoffResumeContextV2, HandoffResumeQueryV2,
    ManagerError,
};

use super::{common::valid_digest, handoff::validate_manager_handoff};

pub fn validate_handoff_resume(
    config: &CertificateManagerConfig,
    query: &HandoffResumeQueryV2,
    context: &HandoffResumeContextV2,
) -> Result<(), ManagerError> {
    let pending = &context.pending;
    let reservation = &context.reservation;
    let readback = &pending.readback;
    let command = &pending.authority_command;
    let authority_command_digest = command.digest_sha256();
    let authorization = &pending.authorization;
    let workload = &pending.workload;
    let exact = &pending.query == query
        && query.request_id == reservation.audit.request_id
        && query.command_digest_sha256 == reservation.lifecycle.intent.command_digest_sha256;
    let binding = query.authorization_lease_digest_sha256 == authorization.lease_digest_sha256
        && reservation.lifecycle.intent.authorization_id == authorization.authorization_id
        && query.command_digest_sha256 == command.management_command_digest_sha256
        && query.request_id == command.request_id
        && readback.reservation_id == reservation.lifecycle.reservation_id
        && readback.authorization_jti == command.authorization_jti
        && readback.operation_id == command.authorization_operation_id
        && readback.lease_digest_sha256 == command.authorization_lease_digest_sha256
        && readback.authorization_command_digest_sha256 == authorization.command_digest_sha256
        && readback.target_resource_id == command.resource_id
        && readback.expected_resource_version == command.expected_resource_version
        && readback.previous_fence == command.previous_fence
        && readback.current_fence == command.current_fence
        && readback.previous_lifecycle_revocation_epoch
            == command.previous_lifecycle_revocation_epoch
        && readback.lifecycle_revocation_epoch == command.lifecycle_revocation_epoch;
    let owner = command.service_id == workload.service_id
        && command.workload_id == workload.workload_id
        && command.device_id == workload.device
        && authorization.service_id == workload.service_id
        && authorization.workload == workload.workload_id
        && authorization.pairwise_subject == workload.pairwise_subject;
    let timing = pending.staged_at_epoch_s >= readback.reserved_at_epoch_s
        && pending.staged_at_epoch_s < readback.expires_at_epoch_s
        && readback
            .expires_at_epoch_s
            .checked_add(config.max_handoff_recovery_seconds)
            == Some(pending.recovery_deadline_epoch_s);
    let phase = match reservation.phase {
        AuditOperationState::Reserved => {
            reservation
                .invoked_authority_command_digest_sha256
                .is_none()
                && reservation.invoked_at_epoch_s.is_none()
        }
        AuditOperationState::Invoked => {
            reservation
                .invoked_authority_command_digest_sha256
                .as_deref()
                == Some(authority_command_digest.as_str())
                && reservation
                    .invoked_at_epoch_s
                    .is_some_and(|value| value >= pending.staged_at_epoch_s)
        }
        _ => false,
    };
    let accepted = context.accepted.as_ref().is_none_or(|value| {
        value.evidence.disposition == CertificateManagerHandoffDispositionV2::Accepted
            && validate_manager_handoff(config, readback, value).is_ok()
    });
    let staged_revision = pending.source_state_revision.checked_add(1);
    let accepted_revision = staged_revision.and_then(|value| value.checked_add(1));
    let invoked_revision = accepted_revision.and_then(|value| value.checked_add(1));
    let revision = match reservation.phase {
        AuditOperationState::Reserved if context.accepted.is_none() => {
            Some(reservation.state_revision) == staged_revision
        }
        AuditOperationState::Reserved => Some(reservation.state_revision) == accepted_revision,
        AuditOperationState::Invoked => {
            context.accepted.is_some() && Some(reservation.state_revision) == invoked_revision
        }
        _ => false,
    };
    (exact
        && binding
        && owner
        && timing
        && phase
        && accepted
        && revision
        && valid_digest(&query.command_digest_sha256)
        && valid_digest(&query.authorization_lease_digest_sha256))
    .then_some(())
    .ok_or(ManagerError::HandoffResultUnknown)
}
