use crate::{
    AuthorityCommandV2, CertificateCommandV2, CertificateManagerConfig, HandoffResumeQueryV2,
    ManagerError, OperationBeginV2, OperationHandoffPendingV2, OperationReservationV2,
    SignedCertificateExecutionAuthorizationV2,
};

use super::super::PreparedV2;

pub fn handoff_query(
    command: &CertificateCommandV2,
    authorization: &SignedCertificateExecutionAuthorizationV2,
) -> HandoffResumeQueryV2 {
    HandoffResumeQueryV2 {
        request_id: command.request_id.clone(),
        command_digest_sha256: command.digest_sha256(),
        authorization_lease_digest_sha256: authorization.lease_digest_sha256().into(),
    }
}

pub fn handoff_pending(
    config: &CertificateManagerConfig,
    query: HandoffResumeQueryV2,
    begin: &OperationBeginV2,
    reservation: &OperationReservationV2,
    command: AuthorityCommandV2,
    prepared: &PreparedV2,
    staged_at_epoch_s: u64,
) -> Result<OperationHandoffPendingV2, ManagerError> {
    let recovery_deadline_epoch_s = begin
        .reservation_expires_at_epoch_s
        .checked_add(config.max_handoff_recovery_seconds)
        .ok_or(ManagerError::HandoffResultUnknown)?;
    Ok(OperationHandoffPendingV2 {
        source_state_revision: reservation.state_revision,
        query,
        readback: handoff_readback(begin, reservation),
        authority_command: command,
        workload: prepared.workload.clone(),
        authorization: prepared.authorization.clone(),
        enrollment: prepared.enrollment.clone(),
        custody: prepared.custody.clone(),
        initial_readiness: prepared.initial_readiness.clone(),
        readiness: prepared.readiness.clone(),
        staged_at_epoch_s,
        recovery_deadline_epoch_s,
    })
}

pub fn handoff_readback(
    begin: &OperationBeginV2,
    reservation: &OperationReservationV2,
) -> crate::ManagerHandoffReadbackV2 {
    let authorization = &begin.audit.authorization;
    crate::ManagerHandoffReadbackV2 {
        reservation_id: reservation.lifecycle.reservation_id.clone(),
        receipt_id: format!("handoff.{}", reservation.lifecycle.reservation_id),
        action: handoff_action(begin.lifecycle.operation),
        authorization_jti: begin.authorization_jti.clone(),
        operation_id: authorization.operation_id.clone(),
        lease_digest_sha256: authorization.lease_digest_sha256.clone(),
        authorization_command_digest_sha256: authorization
            .authorization_command_digest_sha256
            .clone(),
        security_domain: authorization.security_domain.clone(),
        deployment_id: authorization.deployment_id.clone(),
        trust_revision: authorization.trust_revision,
        target_resource_id: begin.lifecycle.resource_id.clone(),
        expected_resource_version: begin.lifecycle.expected_resource_version,
        previous_fence: begin.lifecycle.previous_fence,
        current_fence: begin.lifecycle.current_fence,
        previous_lifecycle_revocation_epoch: begin.lifecycle.previous_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch: begin.lifecycle.lifecycle_revocation_epoch,
        reserved_at_epoch_s: begin.audit.reserved_at_epoch_s,
        expires_at_epoch_s: begin.reservation_expires_at_epoch_s,
    }
}

const fn handoff_action(
    value: crate::CertificateOperation,
) -> crowsi_control_contracts::CertificateActionV2 {
    match value {
        crate::CertificateOperation::Issue => crowsi_control_contracts::CertificateActionV2::Issue,
        crate::CertificateOperation::Renew => crowsi_control_contracts::CertificateActionV2::Renew,
        crate::CertificateOperation::Revoke => {
            crowsi_control_contracts::CertificateActionV2::Revoke
        }
        crate::CertificateOperation::Status => {
            crowsi_control_contracts::CertificateActionV2::CertificateStatus
        }
    }
}
