use crate::{
    AuditOperationState, CertificateOperation, LifecycleStateV2, ManagerError, OperationAbandonV2,
    OperationCommitV2, OperationInvocationV2, OperationReservationV2, ReceiptDraftV2,
};

use super::common::{valid_digest, valid_id};

pub fn validate_operation_commit(
    reservation: &OperationReservationV2,
    receipt: &ReceiptDraftV2,
    value: &OperationCommitV2,
) -> Result<(), ManagerError> {
    let record = &value.lifecycle;
    let intent = &reservation.lifecycle.intent;
    let state = expected_state(intent.operation, reservation.lifecycle.prior_state);
    let exact = record.resource_id == intent.resource_id
        && record.owner_service_id == intent.owner_service_id
        && record.owner_workload_id == intent.owner_workload_id
        && record.owner_subject == intent.owner_subject
        && record.owner_profile == intent.owner_profile
        && record.state == state
        && record.resource_version == reservation.lifecycle.reserved_resource_version
        && record.fence == reservation.lifecycle.current_fence
        && record.lifecycle_revocation_epoch == intent.lifecycle_revocation_epoch
        && record.certificate_id.as_deref() == Some(receipt.result_certificate_id.as_str())
        && value.audit.reservation_id == reservation.audit.reservation_id
        && exact_next_revision(reservation.state_revision, value.state_revision)
        && value.audit.event_digest_sha256 == receipt.digest_sha256()
        && valid_id(&value.audit.record_id)
        && value
            .audit
            .previous_digest_sha256
            .as_deref()
            .is_none_or(valid_digest);
    exact
        .then_some(())
        .ok_or(ManagerError::AuthorityResultUnknown)
}

pub fn validate_invocation_commit(
    reservation: &OperationReservationV2,
    invocation: &OperationInvocationV2,
    value: &OperationReservationV2,
) -> Result<(), ManagerError> {
    let command_digest = invocation.authority_command.digest_sha256();
    let next = reservation
        .state_revision
        .checked_add(1)
        .ok_or(ManagerError::AuditUnavailable)?;
    let exact = reservation.phase == AuditOperationState::Reserved
        && reservation
            .invoked_authority_command_digest_sha256
            .is_none()
        && reservation.invoked_at_epoch_s.is_none()
        && value.phase == AuditOperationState::Invoked
        && value.state_revision == next
        && value.lifecycle == reservation.lifecycle
        && value.audit == reservation.audit
        && value.invoked_authority_command_digest_sha256.as_deref()
            == Some(command_digest.as_str())
        && value.invoked_at_epoch_s == Some(invocation.audit.execution_time_epoch_s)
        && invocation.audit.reservation_id == reservation.audit.reservation_id
        && invocation.audit.authority_command_digest_sha256 == command_digest
        && invocation.audit.execution_time_epoch_s
            >= invocation.authority_command.execution_time_epoch_s
        && invocation.authority_command.lifecycle_reservation_id
            == reservation.lifecycle.reservation_id;
    exact.then_some(()).ok_or(ManagerError::AuditUnavailable)
}

pub fn validate_abandon_commit(
    reservation: &OperationReservationV2,
    abandon: &OperationAbandonV2,
    value: &OperationReservationV2,
) -> Result<(), ManagerError> {
    let next = reservation
        .state_revision
        .checked_add(1)
        .ok_or(ManagerError::AuditUnavailable)?;
    let exact = reservation.phase == AuditOperationState::Reserved
        && reservation
            .invoked_authority_command_digest_sha256
            .is_none()
        && reservation.invoked_at_epoch_s.is_none()
        && abandon.reservation_id == reservation.lifecycle.reservation_id
        && value.phase == AuditOperationState::Abandoned
        && value.state_revision == next
        && value.invoked_authority_command_digest_sha256.is_none()
        && value.invoked_at_epoch_s.is_none()
        && value.lifecycle == reservation.lifecycle
        && value.audit == reservation.audit;
    exact.then_some(()).ok_or(ManagerError::AuditUnavailable)
}

const fn expected_state(
    operation: CertificateOperation,
    prior: LifecycleStateV2,
) -> LifecycleStateV2 {
    match operation {
        CertificateOperation::Issue | CertificateOperation::Renew => LifecycleStateV2::Active,
        CertificateOperation::Revoke => LifecycleStateV2::Revoked,
        CertificateOperation::Status => prior,
    }
}

const fn exact_next_revision(current: u64, observed: u64) -> bool {
    matches!(current.checked_add(1), Some(expected) if expected == observed)
}

#[cfg(test)]
mod tests {
    use super::exact_next_revision;

    #[test]
    fn revision_must_be_exact_and_cannot_overflow() {
        assert!(exact_next_revision(7, 8));
        assert!(!exact_next_revision(7, 7));
        assert!(!exact_next_revision(7, 9));
        assert!(!exact_next_revision(u64::MAX, u64::MAX));
    }
}
