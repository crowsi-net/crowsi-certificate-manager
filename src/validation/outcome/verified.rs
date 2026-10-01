use crate::{
    AuthorityCommandV2, AuthorityOutcomeV2, CertificateManagerConfig, CertificateOperation,
    CertificateState, LifecycleReservationV2, LifecycleStateV2, ManagerError,
    OperationReservationV2, VerifiedAuthorityOutcomeReceiptV2,
};

use super::super::common::{valid_digest, valid_encoded};

pub fn validate_outcome(
    config: &CertificateManagerConfig,
    command: &AuthorityCommandV2,
    reservation: &OperationReservationV2,
    outcome: &AuthorityOutcomeV2,
    verified: &VerifiedAuthorityOutcomeReceiptV2,
) -> Result<(), ManagerError> {
    let signed = &outcome.signed_receipt;
    let receipt_shape = signed.schema == "crowsi://certificates/authority-outcome-receipt/v2"
        && signed.key_id == config.authority_receipt_verifier_key_id
        && valid_encoded(&signed.payload_base64, 262_144)
        && valid_encoded(&signed.signature_base64, 16_384);
    let echo = verified.signature_verified
        && verified.request_id == command.request_id
        && verified.management_command_digest_sha256 == command.management_command_digest_sha256
        && verified.authority_command_digest_sha256 == command.digest_sha256()
        && verified.authority_outcome_digest_sha256 == outcome.digest_sha256()
        && verified.authority_id == command.authority_id
        && verified.authority_key_id == command.authority_key_id
        && verified.authority_key_version == command.authority_key_version
        && verified.authority_public_key_spki_sha256 == command.authority_public_key_spki_sha256
        && verified.signature_key_id == command.authority_receipt_key_id
        && verified.authority_receipt_key_version == command.authority_receipt_key_version
        && verified.authority_receipt_public_key_spki_sha256
            == command.authority_receipt_public_key_spki_sha256
        && verified.signature_key_id != command.authority_key_id
        && verified.signature_algorithm == command.authority_receipt_signature_algorithm
        && verified.signature_algorithm == "ecdsa-p256-sha256-p1363-low-s"
        && verified.key_purpose == command.authority_receipt_key_purpose
        && verified.authority_lease_id == command.authority_lease_id
        && verified.authority_attestation_digest_sha256
            == command.authority_attestation_digest_sha256
        && verified.authority_fence == command.authority_fence
        && verified.authority_trust_revision == command.authority_trust_revision
        && verified.lifecycle_reservation_id == command.lifecycle_reservation_id
        && verified.lifecycle_fence == command.current_fence
        && reservation
            .invoked_at_epoch_s
            .is_some_and(|invoked| verified.executed_at_epoch_s >= invoked)
        && verified.executed_at_epoch_s >= command.execution_time_epoch_s
        && verified.executed_at_epoch_s < command.authority_lease_expires_at_epoch_s
        && command
            .custody_expires_at_epoch_s
            .is_none_or(|expires| verified.executed_at_epoch_s < expires)
        && valid_digest(&verified.receipt_digest_sha256);
    (receipt_shape
        && echo
        && super::super::completion_evidence::valid_outcome_evidence(
            config, command, outcome, verified,
        )
        && valid_metadata(
            command,
            &reservation.lifecycle,
            outcome,
            verified.executed_at_epoch_s,
        ))
    .then_some(())
    .ok_or(ManagerError::AuthorityResultUnknown)
}

fn valid_metadata(
    command: &AuthorityCommandV2,
    lifecycle: &LifecycleReservationV2,
    outcome: &AuthorityOutcomeV2,
    executed_at_epoch_s: u64,
) -> bool {
    let value = &outcome.metadata;
    let prior_binding = command.prior_metadata_digest_sha256
        == lifecycle
            .prior_metadata
            .as_ref()
            .map(crate::CertificateMetadataV2::digest_sha256);
    let common = crate::validation::common::valid_id(&value.certificate_id)
        && (1..=128).contains(&value.serial_number.len())
        && valid_digest(&value.fingerprint_sha256)
        && valid_digest(&value.public_key_sha256)
        && value.not_before_epoch_s <= executed_at_epoch_s
        && value.expires_at_epoch_s > value.not_before_epoch_s;
    common && prior_binding && operation_metadata(command, lifecycle, outcome, executed_at_epoch_s)
}

fn operation_metadata(
    command: &AuthorityCommandV2,
    lifecycle: &LifecycleReservationV2,
    outcome: &AuthorityOutcomeV2,
    executed_at_epoch_s: u64,
) -> bool {
    let value = &outcome.metadata;
    match command.operation {
        CertificateOperation::Issue | CertificateOperation::Renew => {
            value.state == CertificateState::Active
                && executed_at_epoch_s.saturating_sub(value.not_before_epoch_s) <= 300
                && executed_at_epoch_s < value.expires_at_epoch_s
                && command.public_key_sha256.as_deref() == Some(&value.public_key_sha256)
                && command.public_key_algorithm.as_deref() == Some(&value.public_key_algorithm)
                && value.expires_at_epoch_s <= command.certificate_expires_at_epoch_s
                && outcome.public_certificate.is_some()
        }
        CertificateOperation::Revoke => {
            lifecycle
                .prior_metadata
                .as_ref()
                .is_some_and(|prior| same_certificate_fields(prior, value))
                && value.state == CertificateState::Revoked
                && command.target_certificate_id.as_deref() == Some(&value.certificate_id)
                && outcome.public_certificate.is_none()
        }
        CertificateOperation::Status => {
            lifecycle.prior_metadata.as_ref() == Some(value)
                && value.state == state_for(lifecycle.prior_state)
                && command.target_certificate_id.as_deref() == Some(&value.certificate_id)
                && outcome.public_certificate.is_none()
        }
    }
}

const fn state_for(value: LifecycleStateV2) -> CertificateState {
    match value {
        LifecycleStateV2::Active => CertificateState::Active,
        LifecycleStateV2::Revoked => CertificateState::Revoked,
        LifecycleStateV2::Expired => CertificateState::Expired,
        LifecycleStateV2::Absent => CertificateState::Unknown,
    }
}

fn same_certificate_fields(
    prior: &crate::CertificateMetadataV2,
    current: &crate::CertificateMetadataV2,
) -> bool {
    prior.certificate_id == current.certificate_id
        && prior.serial_number == current.serial_number
        && prior.fingerprint_sha256 == current.fingerprint_sha256
        && prior.public_key_sha256 == current.public_key_sha256
        && prior.public_key_algorithm == current.public_key_algorithm
        && prior.not_before_epoch_s == current.not_before_epoch_s
        && prior.expires_at_epoch_s == current.expires_at_epoch_s
}
