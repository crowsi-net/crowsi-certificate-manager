use crate::{
    AuthorityReconciliationCommandV2, AuthorityReconciliationDispositionV2,
    AuthorityReconciliationOutcomeV2, CertificateManagerConfig, ManagerError,
    VerifiedAuthorityReconciliationV2,
};

use super::{
    common::{valid_digest, valid_encoded, valid_key_version},
    outcome::validate_outcome_envelope,
};

pub fn validate_reconciliation_envelope(
    config: &CertificateManagerConfig,
    value: &AuthorityReconciliationOutcomeV2,
) -> Result<(), ManagerError> {
    let signed = &value.signed_receipt;
    let receipt = signed.schema == "crowsi://certificates/authority-reconciliation-receipt/v2"
        && signed.key_id == config.authority_receipt_verifier_key_id
        && valid_encoded(&signed.payload_base64, 262_144)
        && valid_encoded(&signed.signature_base64, 16_384);
    let result = match value.disposition {
        AuthorityReconciliationDispositionV2::Completed => value
            .authority_outcome
            .as_ref()
            .is_some_and(|outcome| validate_outcome_envelope(config, outcome).is_ok()),
        AuthorityReconciliationDispositionV2::NotExecuted
        | AuthorityReconciliationDispositionV2::StillUnknown => value.authority_outcome.is_none(),
    };
    (receipt && result)
        .then_some(())
        .ok_or(ManagerError::ReconciliationRejected)
}

pub fn validate_authority_reconciliation(
    config: &CertificateManagerConfig,
    command: &AuthorityReconciliationCommandV2,
    outcome: &AuthorityReconciliationOutcomeV2,
    verified: &VerifiedAuthorityReconciliationV2,
    now: u64,
) -> Result<(), ManagerError> {
    let signed = &outcome.signed_receipt;
    let shape = signed.schema == "crowsi://certificates/authority-reconciliation-receipt/v2"
        && signed.key_id == config.authority_receipt_verifier_key_id
        && valid_encoded(&signed.payload_base64, 262_144)
        && valid_encoded(&signed.signature_base64, 16_384);
    let exact = verified.query_id == command.query_id
        && verified.original_action == command.original_action
        && verified.reconciliation_command_digest_sha256 == command.digest_sha256()
        && verified.authority_command_digest_sha256 == command.authority_command_digest_sha256
        && verified.unknown_evidence_digest_sha256 == command.unknown_evidence_digest_sha256
        && verified.reconciliation_authorization_ancestry_digest_sha256
            == command.reconciliation_authorization_ancestry_digest_sha256
        && verified.reconciliation_query_digest_sha256
            == command.reconciliation_query_digest_sha256
        && verified.expected_resource_version == command.expected_resource_version
        && verified.disposition == outcome.disposition
        && verified.original_execution == command.original_execution
        && verified.current_reconciliation == command.current_reconciliation
        && verified.security_domain == command.security_domain
        && verified.deployment_id == command.deployment_id
        && verified.signature_key_id == command.current_reconciliation.receipt_signing_key_id
        && verified.signature_key_id != command.current_reconciliation.certificate_signing_key_id
        && verified.signature_algorithm
            == command.current_reconciliation.receipt_signature_algorithm
        && verified.signature_algorithm == "ecdsa-p256-sha256-p1363-low-s"
        && verified.key_purpose == command.current_reconciliation.receipt_key_purpose
        && verified.lifecycle_reservation_id == command.lifecycle_reservation_id
        && verified.lifecycle_previous_fence == command.lifecycle_previous_fence
        && verified.lifecycle_fence == command.lifecycle_fence
        && verified.previous_lifecycle_revocation_epoch
            == command.previous_lifecycle_revocation_epoch
        && verified.lifecycle_revocation_epoch == command.lifecycle_revocation_epoch;
    let result = match outcome.disposition {
        AuthorityReconciliationDispositionV2::Completed => {
            outcome.authority_outcome.as_ref().is_some_and(|value| {
                verified.authority_outcome_digest_sha256.as_deref()
                    == Some(value.digest_sha256().as_str())
            })
        }
        AuthorityReconciliationDispositionV2::NotExecuted
        | AuthorityReconciliationDispositionV2::StillUnknown => {
            outcome.authority_outcome.is_none()
                && verified.authority_outcome_digest_sha256.is_none()
        }
    };
    let fresh = verified.signature_verified
        && valid_digest(&verified.receipt_digest_sha256)
        && command.requested_at_epoch_s <= verified.observed_at_epoch_s
        && verified.observed_at_epoch_s <= now
        && verified.observed_at_epoch_s < command.current_reconciliation.expires_at_epoch_s
        && now.saturating_sub(verified.observed_at_epoch_s)
            <= config.max_reconciliation_receipt_age_seconds;
    (shape
        && exact
        && result
        && fresh
        && super::completion_evidence::valid_reconciliation_evidence(
            config, command, outcome, verified,
        )
        && valid_key_bindings(command))
    .then_some(())
    .ok_or(ManagerError::ReconciliationRejected)
}

fn valid_key_bindings(value: &AuthorityReconciliationCommandV2) -> bool {
    let original = &value.original_execution;
    let current = &value.current_reconciliation;
    [
        &original.certificate_signing_public_key_spki_sha256,
        &original.receipt_signing_public_key_spki_sha256,
        &current.certificate_signing_public_key_spki_sha256,
        &current.receipt_signing_public_key_spki_sha256,
    ]
    .into_iter()
    .all(|digest| valid_digest(digest))
        && [
            &original.certificate_signing_key_version,
            &original.receipt_signing_key_version,
            &current.certificate_signing_key_version,
            &current.receipt_signing_key_version,
        ]
        .into_iter()
        .all(|version| valid_key_version(version))
        && original.certificate_signing_public_key_spki_sha256
            != original.receipt_signing_public_key_spki_sha256
        && current.certificate_signing_public_key_spki_sha256
            != current.receipt_signing_public_key_spki_sha256
        && original.certificate_signing_public_key_spki_sha256
            != current.receipt_signing_public_key_spki_sha256
        && original.receipt_signing_public_key_spki_sha256
            != current.certificate_signing_public_key_spki_sha256
}
