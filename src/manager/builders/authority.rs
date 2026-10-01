use crate::{
    AuthorityCommandV2, CertificateCommandV2, ManagerError, OperationReservationV2,
    VerifiedCertificateExecutionAuthorizationV2, VerifiedKeyCustodyAttestationV2,
    VerifiedKeyEnrollmentV2, VerifiedWorkloadV2,
};

use super::super::PreparedV2;

pub fn authority_command(
    command: &CertificateCommandV2,
    prepared: &PreparedV2,
    reservation: &OperationReservationV2,
    execution_time: u64,
) -> Result<AuthorityCommandV2, ManagerError> {
    let certificate_expires_at = if command.operation.requires_key_enrollment() {
        execution_time
            .checked_add(command.requested_ttl_seconds)
            .ok_or(ManagerError::InvalidCommand)?
    } else {
        reservation
            .lifecycle
            .prior_metadata
            .as_ref()
            .map_or(0, |value| value.expires_at_epoch_s)
    };
    Ok(build(
        command,
        &prepared.workload,
        &prepared.authorization,
        prepared.enrollment.as_ref(),
        prepared.custody.as_ref(),
        reservation,
        &prepared.readiness.lease,
        execution_time,
        certificate_expires_at,
    ))
}

#[allow(clippy::too_many_arguments)]
fn build(
    command: &CertificateCommandV2,
    workload: &VerifiedWorkloadV2,
    authorization: &VerifiedCertificateExecutionAuthorizationV2,
    enrollment: Option<&VerifiedKeyEnrollmentV2>,
    custody: Option<&VerifiedKeyCustodyAttestationV2>,
    reservation: &OperationReservationV2,
    lease: &crate::AuthorityAttestationLeaseV2,
    execution_time: u64,
    certificate_expires_at: u64,
) -> AuthorityCommandV2 {
    AuthorityCommandV2 {
        request_id: command.request_id.clone(),
        management_command_digest_sha256: command.digest_sha256(),
        authorization_id: authorization.authorization_id.clone(),
        authorization_jti: authorization.jti.clone(),
        authorization_operation_id: authorization.operation_id.clone(),
        authorization_lease_digest_sha256: authorization.lease_digest_sha256.clone(),
        operation: command.operation,
        security_domain: authorization.security_domain.clone(),
        deployment_id: authorization.deployment_id.clone(),
        service_id: workload.service_id.clone(),
        workload_id: workload.workload_id.clone(),
        device_id: workload.device.clone(),
        profile_id: command.profile_id.clone(),
        purpose: command.purpose.clone(),
        subject: command.subject.clone(),
        audience: command.audience.clone(),
        scopes: command.scopes.clone(),
        resource_id: command.resource_id.clone(),
        target_certificate_id: command.target_certificate_id.clone(),
        prior_metadata_digest_sha256: reservation
            .lifecycle
            .prior_metadata
            .as_ref()
            .map(crate::CertificateMetadataV2::digest_sha256),
        public_key_spki_der: enrollment.map(|value| value.public_key_spki_der.clone()),
        public_key_sha256: enrollment.map(|value| value.public_key_sha256.clone()),
        public_key_algorithm: enrollment.map(|value| value.algorithm.clone()),
        custody_attestation_digest_sha256: custody
            .map(|value| value.attestation_digest_sha256.clone()),
        expected_resource_version: command.expected_resource_version,
        previous_lifecycle_revocation_epoch: reservation.lifecycle.prior_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch: reservation.lifecycle.intent.lifecycle_revocation_epoch,
        identity_revocation_epoch: authorization.identity_revocation_epoch,
        lifecycle_reservation_id: reservation.lifecycle.reservation_id.clone(),
        previous_fence: reservation.lifecycle.previous_fence,
        current_fence: reservation.lifecycle.current_fence,
        authority_lease_id: lease.lease_id.clone(),
        authority_attestation_digest_sha256: lease.attestation_digest_sha256.clone(),
        authority_fence: lease.fence,
        authority_id: lease.authority_id.clone(),
        authority_key_id: lease.key_id.clone(),
        authority_key_version: lease.authority_key_version.clone(),
        authority_public_key_spki_sha256: lease.authority_public_key_spki_sha256.clone(),
        authority_signature_algorithm: lease.signature_algorithm.clone(),
        authority_key_provider_signature_profile: lease.key_provider_signature_profile.clone(),
        authority_key_purpose: lease.key_purpose.clone(),
        authority_receipt_key_id: lease.authority_receipt_key_id.clone(),
        authority_receipt_key_version: lease.authority_receipt_key_version.clone(),
        authority_receipt_public_key_spki_sha256: lease
            .authority_receipt_public_key_spki_sha256
            .clone(),
        authority_receipt_signature_algorithm: lease.authority_receipt_signature_algorithm.clone(),
        authority_receipt_key_purpose: lease.authority_receipt_key_purpose.clone(),
        authority_trust_revision: lease.trust_revision,
        authorization_expires_at_epoch_s: authorization.expires_at_epoch_s,
        custody_expires_at_epoch_s: custody.map(|value| value.expires_at_epoch_s),
        authority_lease_expires_at_epoch_s: lease.expires_at_epoch_s,
        execution_time_epoch_s: execution_time,
        certificate_expires_at_epoch_s: certificate_expires_at,
    }
}
