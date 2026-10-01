use crate::{
    CertificateCommandV2, CertificateManagerConfig, CertificateOperation, KeyEnrollmentV2,
    ManagerError, OperationStatusQueryV2, ReconciliationQueryV2,
};

use super::common::{
    valid_canonical_resource_id, valid_encoded, valid_id, valid_scopes, valid_spiffe_id,
};

pub fn validate_command(
    config: &CertificateManagerConfig,
    command: &CertificateCommandV2,
) -> Result<(), ManagerError> {
    let common = command.schema == "crowsi://certificates/management-command/v2"
        && valid_id(&command.request_id)
        && valid_id(&command.nonce)
        && valid_canonical_resource_id(&command.resource_id)
        && valid_id(&command.profile_id)
        && config.allowed_purposes.contains(&command.purpose)
        && command.subject.starts_with(&config.subject_spiffe_prefix)
        && valid_spiffe_id(&command.subject)
        && config.allowed_audiences.contains(&command.audience)
        && valid_scopes(&command.scopes, config.max_scopes);
    let shape = match command.operation {
        CertificateOperation::Issue => {
            command.expected_resource_version == 0
                && command.previous_lifecycle_revocation_epoch == 0
                && command.lifecycle_revocation_epoch == 0
                && command.target_certificate_id.is_none()
                && valid_enrollment(config, command)
                && valid_ttl(config, command)
        }
        CertificateOperation::Renew => {
            valid_target(command)
                && command.previous_lifecycle_revocation_epoch == command.lifecycle_revocation_epoch
                && valid_enrollment(config, command)
                && valid_ttl(config, command)
                && command.expected_resource_version.checked_add(1).is_some()
        }
        CertificateOperation::Revoke => {
            valid_target(command)
                && command.previous_lifecycle_revocation_epoch.checked_add(1)
                    == Some(command.lifecycle_revocation_epoch)
                && command.key_enrollment.is_none()
                && command.requested_ttl_seconds == 0
                && command.expected_resource_version.checked_add(1).is_some()
        }
        CertificateOperation::Status => {
            valid_target(command)
                && command.previous_lifecycle_revocation_epoch == command.lifecycle_revocation_epoch
                && command.key_enrollment.is_none()
                && command.requested_ttl_seconds == 0
        }
    };
    (common && shape)
        .then_some(())
        .ok_or(ManagerError::InvalidCommand)
}

fn valid_enrollment(config: &CertificateManagerConfig, command: &CertificateCommandV2) -> bool {
    command.key_enrollment.as_ref().is_some_and(|value| {
        let limit = config.max_key_enrollment_bytes;
        value.encoded_len() <= limit
            && match value {
                KeyEnrollmentV2::CsrDerBase64 { csr_der_base64 } => {
                    valid_encoded(csr_der_base64, limit)
                }
                KeyEnrollmentV2::PublicKeyDerBase64 {
                    public_key_der_base64,
                    proof_of_possession_base64,
                } => {
                    valid_encoded(public_key_der_base64, limit)
                        && valid_encoded(proof_of_possession_base64, limit)
                }
            }
    })
}

fn valid_ttl(config: &CertificateManagerConfig, command: &CertificateCommandV2) -> bool {
    (1..=config.max_certificate_ttl_seconds).contains(&command.requested_ttl_seconds)
}

fn valid_target(command: &CertificateCommandV2) -> bool {
    command
        .target_certificate_id
        .as_deref()
        .is_some_and(valid_id)
}

pub fn validate_reconciliation_query(query: &ReconciliationQueryV2) -> Result<(), ManagerError> {
    let valid = [
        &query.query_id,
        &query.nonce,
        &query.target_request_id,
        &query.owner_profile,
        &query.expected_lifecycle_reservation_id,
    ]
    .into_iter()
    .all(|value| valid_id(value))
        && valid_id(&query.owner_subject)
        && valid_canonical_resource_id(&query.resource_id)
        && super::common::valid_digest(&query.expected_authority_command_digest_sha256)
        && super::common::valid_digest(&query.expected_unknown_evidence_digest_sha256)
        && query.expected_previous_fence.checked_add(1) == Some(query.expected_current_fence)
        && valid_locked_lifecycle_epoch(query);
    valid
        .then_some(())
        .ok_or(ManagerError::ReconciliationRejected)
}

fn valid_locked_lifecycle_epoch(query: &ReconciliationQueryV2) -> bool {
    let previous = query.locked_previous_lifecycle_revocation_epoch;
    let current = query.locked_lifecycle_revocation_epoch;
    match query.original_action {
        crate::CertificateLifecycleActionV2::Issue => previous == 0 && current == 0,
        crate::CertificateLifecycleActionV2::Renew => previous == current,
        crate::CertificateLifecycleActionV2::Revoke => previous.checked_add(1) == Some(current),
    }
}

pub fn validate_operation_status_query(query: &OperationStatusQueryV2) -> Result<(), ManagerError> {
    let valid = [
        &query.query_id,
        &query.nonce,
        &query.target_request_id,
        &query.owner_profile,
        &query.owner_subject,
    ]
    .into_iter()
    .all(|value| valid_id(value))
        && valid_canonical_resource_id(&query.resource_id);
    valid
        .then_some(())
        .ok_or(ManagerError::ReconciliationRejected)
}
