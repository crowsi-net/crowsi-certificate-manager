use crate::{
    AuthorityCommandV2, CertificateManagerConfig, ReconciliationBeginV2, ReconciliationContextV2,
};

use super::super::common::{valid_digest, valid_id, valid_key_version};

pub(super) fn validate_original_command(
    config: &CertificateManagerConfig,
    expected: &ReconciliationBeginV2,
    value: &ReconciliationContextV2,
) -> bool {
    match (
        super::has_authority_invocation(value.status.state),
        value.authority_command.as_ref(),
    ) {
        (true, Some(command)) => {
            value.status.authority_command_digest_sha256.as_deref()
                == Some(command.digest_sha256().as_str())
                && expected.expected_authority_command_digest_sha256 == command.digest_sha256()
                && expected.status_query.target_request_id == command.request_id
                && valid_authority_shape(config, command)
                && command_bound_to_operation(command, value)
        }
        (false, None) => true,
        _ => false,
    }
}

fn valid_authority_shape(config: &CertificateManagerConfig, value: &AuthorityCommandV2) -> bool {
    value.security_domain == config.security_domain
        && value.deployment_id == config.deployment_id
        && value.authority_signature_algorithm == "ecdsa-p256-sha256"
        && value.authority_key_provider_signature_profile == "ecdsa-p256-sha256-p1363-low-s"
        && value.authority_key_purpose == "workload-certificate-issuance"
        && value.authority_receipt_key_id != value.authority_key_id
        && valid_key_version(&value.authority_key_version)
        && valid_key_version(&value.authority_receipt_key_version)
        && valid_digest(&value.authority_public_key_spki_sha256)
        && valid_digest(&value.authority_receipt_public_key_spki_sha256)
        && value.authority_public_key_spki_sha256 != value.authority_receipt_public_key_spki_sha256
        && valid_id(&value.authority_id)
        && valid_id(&value.authority_key_id)
        && valid_id(&value.authority_receipt_key_id)
        && valid_id(&value.authority_lease_id)
        && valid_digest(&value.authority_attestation_digest_sha256)
        && value.authority_fence > 0
        && value.authority_trust_revision > 0
}

fn command_bound_to_operation(
    command: &AuthorityCommandV2,
    value: &ReconciliationContextV2,
) -> bool {
    let begin = &value.original_begin;
    let lifecycle = &value.reservation.lifecycle;
    command.management_command_digest_sha256 == begin.lifecycle.command_digest_sha256
        && command.authorization_id == begin.authorization_id
        && command.authorization_jti == begin.authorization_jti
        && command.authorization_operation_id == begin.audit.authorization.operation_id
        && command.authorization_lease_digest_sha256
            == begin.audit.authorization.lease_digest_sha256
        && command.operation == begin.lifecycle.operation
        && command.service_id == begin.lifecycle.owner_service_id
        && command.workload_id == begin.lifecycle.owner_workload_id
        && command.profile_id == begin.lifecycle.certificate_profile
        && command.subject == begin.lifecycle.certificate_subject
        && command.resource_id == begin.lifecycle.resource_id
        && command.target_certificate_id == begin.lifecycle.target_certificate_id
        && command.expected_resource_version == begin.lifecycle.expected_resource_version
        && command.previous_lifecycle_revocation_epoch == lifecycle.prior_lifecycle_revocation_epoch
        && command.lifecycle_revocation_epoch == begin.lifecycle.lifecycle_revocation_epoch
        && command.identity_revocation_epoch == begin.audit.authorization.identity_revocation_epoch
        && command.lifecycle_reservation_id == lifecycle.reservation_id
        && command.previous_fence == lifecycle.previous_fence
        && command.current_fence == lifecycle.current_fence
        && command.prior_metadata_digest_sha256
            == lifecycle
                .prior_metadata
                .as_ref()
                .map(crate::CertificateMetadataV2::digest_sha256)
        && value
            .reservation
            .invoked_authority_command_digest_sha256
            .as_deref()
            == Some(command.digest_sha256().as_str())
}
