use crate::{
    AuditOperationState, CertificateLifecycleActionV2, CertificateOperation,
    ReconciliationContextV2,
};

pub(super) fn original_action_matches(
    expected: CertificateLifecycleActionV2,
    operation: CertificateOperation,
) -> bool {
    matches!(
        (expected, operation),
        (
            CertificateLifecycleActionV2::Issue,
            CertificateOperation::Issue
        ) | (
            CertificateLifecycleActionV2::Renew,
            CertificateOperation::Renew
        ) | (
            CertificateLifecycleActionV2::Revoke,
            CertificateOperation::Revoke
        )
    )
}

pub(super) fn validate_finalized_receipt(value: &ReconciliationContextV2) -> bool {
    let receipt = value.finalized_receipt.as_ref();
    if value.status.state != AuditOperationState::Finalized {
        return receipt.is_none();
    }
    let Some((receipt, command)) = receipt.zip(value.authority_command.as_ref()) else {
        return false;
    };
    let begin = &value.original_begin;
    value.status.event_digest_sha256.as_deref() == Some(receipt.digest_sha256().as_str())
        && receipt.request_id == begin.request_id
        && receipt.authorization_id == begin.authorization_id
        && receipt.authorization_ancestry_digest_sha256 == begin.audit.authorization.digest_sha256()
        && receipt.command_digest_sha256 == begin.lifecycle.command_digest_sha256
        && receipt.operation == begin.lifecycle.operation
        && receipt.resource_id == begin.lifecycle.resource_id
        && receipt.owner_service_id == begin.lifecycle.owner_service_id
        && receipt.owner_workload_id == begin.lifecycle.owner_workload_id
        && receipt.lifecycle_reservation_id == value.reservation.lifecycle.reservation_id
        && receipt.lifecycle_fence == value.reservation.lifecycle.current_fence
        && receipt.authority_command_digest_sha256 == command.digest_sha256()
        && !receipt.private_key_received
        && !receipt.private_key_returned
}
