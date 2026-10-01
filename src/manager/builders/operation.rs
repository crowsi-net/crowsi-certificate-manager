use crate::{
    AuditIntentV2, AuditInvocationV2, AuditUnknownV2, CertificateCommandV2, LifecycleUnknownV2,
    OperationBeginV2, OperationInvocationV2, OperationReservationV2, OperationUnknownV2,
    UnknownReasonV2,
};

use super::super::PreparedV2;

pub fn operation_begin(
    command: &CertificateCommandV2,
    prepared: &PreparedV2,
    _now: u64,
) -> OperationBeginV2 {
    let authorization = &prepared.authorization;
    let workload = &prepared.workload;
    let lifecycle = crate::LifecycleReservationIntentV2 {
        request_id: command.request_id.clone(),
        authorization_id: authorization.authorization_id.clone(),
        required_reservation_id: authorization.pa_reservation_id.clone(),
        command_digest_sha256: command.digest_sha256(),
        operation: command.operation,
        resource_id: command.resource_id.clone(),
        target_certificate_id: command.target_certificate_id.clone(),
        owner_service_id: workload.service_id.clone(),
        owner_workload_id: workload.workload_id.clone(),
        owner_subject: workload.pairwise_subject.clone(),
        owner_profile: workload.profile.clone(),
        certificate_subject: command.subject.clone(),
        certificate_profile: command.profile_id.clone(),
        expected_resource_version: command.expected_resource_version,
        previous_fence: authorization.previous_fence,
        current_fence: authorization.current_fence,
        previous_lifecycle_revocation_epoch: command.previous_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch: command.lifecycle_revocation_epoch,
    };
    let audit = AuditIntentV2 {
        request_id: command.request_id.clone(),
        authorization_id: authorization.authorization_id.clone(),
        authorization: crate::CertificateAuthorizationAncestryV2::from_verified(
            authorization,
            workload,
        ),
        command_digest_sha256: command.digest_sha256(),
        operation: command.operation,
        resource_id: command.resource_id.clone(),
        lifecycle_reservation_id: authorization.pa_reservation_id.clone(),
        lifecycle_fence: authorization.current_fence,
        owner_service_id: workload.service_id.clone(),
        owner_workload_id: workload.workload_id.clone(),
        owner_subject: workload.pairwise_subject.clone(),
        owner_profile: workload.profile.clone(),
        certificate_subject: command.subject.clone(),
        certificate_profile: command.profile_id.clone(),
        reserved_at_epoch_s: authorization.issued_at_epoch_s,
    };
    OperationBeginV2 {
        request_id: command.request_id.clone(),
        nonce: command.nonce.clone(),
        authorization_id: authorization.authorization_id.clone(),
        authorization_jti: authorization.jti.clone(),
        reservation_expires_at_epoch_s: reservation_expiry(prepared),
        lifecycle,
        audit,
    }
}

fn reservation_expiry(prepared: &PreparedV2) -> u64 {
    let mut expiry = prepared
        .authorization
        .expires_at_epoch_s
        .min(prepared.workload.expires_at_epoch_s)
        .min(prepared.initial_readiness.lease.expires_at_epoch_s);
    if let Some(custody) = &prepared.custody {
        expiry = expiry.min(custody.expires_at_epoch_s);
    }
    expiry
}

pub fn operation_invocation(
    reservation: &OperationReservationV2,
    authority_command: &crate::AuthorityCommandV2,
    now: u64,
) -> OperationInvocationV2 {
    let authority_command_digest = authority_command.digest_sha256();
    OperationInvocationV2 {
        audit: AuditInvocationV2 {
            reservation_id: reservation.audit.reservation_id.clone(),
            authority_command_digest_sha256: authority_command_digest,
            execution_time_epoch_s: now,
        },
        authority_command: authority_command.clone(),
    }
}

pub fn operation_unknown(
    reservation: &OperationReservationV2,
    authority_command_digest: String,
    reason: UnknownReasonV2,
    now: u64,
) -> OperationUnknownV2 {
    OperationUnknownV2 {
        lifecycle: LifecycleUnknownV2 {
            reservation_id: reservation.lifecycle.reservation_id.clone(),
            authority_command_digest_sha256: authority_command_digest.clone(),
            reason,
        },
        audit: AuditUnknownV2 {
            reservation_id: reservation.audit.reservation_id.clone(),
            authority_command_digest_sha256: authority_command_digest,
            reason,
            recorded_at_epoch_s: now,
        },
    }
}
