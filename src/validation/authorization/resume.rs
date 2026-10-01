use crate::{
    CertificateAuthorizedActionV2, CertificateCommandV2, CertificateManagerConfig, ManagerError,
    SignedCertificateExecutionAuthorizationV2, VerifiedCertificateExecutionAuthorizationV2,
};

use super::super::common::valid_digest;

pub fn validate_handoff_recovery_authorization(
    config: &CertificateManagerConfig,
    command: &CertificateCommandV2,
    signed: &SignedCertificateExecutionAuthorizationV2,
    stored: &VerifiedCertificateExecutionAuthorizationV2,
    current: &VerifiedCertificateExecutionAuthorizationV2,
    now: u64,
) -> Result<(), ManagerError> {
    let immutable = current == stored
        && signed.lease_digest_sha256() == current.lease_digest_sha256
        && current.command_digest_sha256 == command.digest_sha256()
        && current.operation_id == command.request_id
        && current.action == CertificateAuthorizedActionV2::from(command.operation)
        && current.target_resource_id == command.resource_id
        && current.expected_resource_version == command.expected_resource_version
        && current.previous_lifecycle_revocation_epoch
            == command.previous_lifecycle_revocation_epoch
        && current.lifecycle_revocation_epoch == command.lifecycle_revocation_epoch;
    let trust = current.issuer == config.authorization_issuer
        && current.audience == config.authorization_audience
        && current.signature_key_id == config.authorization_verifier_key_id
        && current.signature_key_version == config.authorization_key_version
        && current.signature_public_key_spki_sha256 == config.authorization_public_key_spki_sha256
        && current.signature_algorithm == config.authorization_signature_algorithm
        && current.signature_key_purpose == config.authorization_key_purpose
        && current.trust_revision == config.trust_revision
        && current.security_domain == config.security_domain
        && current.deployment_id == config.deployment_id
        && current.policy_id == config.authorization_policy_id
        && current.policy_digest_sha256 == config.authorization_policy_digest_sha256
        && current.one_use
        && current.signature_verified;
    let revocation = current.authoritative_identity_revocation_snapshot
        && current.previous_identity_revocation_epoch <= current.identity_revocation_epoch
        && current.identity_revocation_snapshot_epoch == current.identity_revocation_epoch
        && current.identity_revocation_snapshot_verified_at_epoch_s <= now
        && now.saturating_sub(current.identity_revocation_snapshot_verified_at_epoch_s)
            <= config.max_revocation_snapshot_age_seconds
        && valid_digest(&current.identity_revocation_snapshot_digest_sha256);
    (immutable && trust && revocation)
        .then_some(())
        .ok_or(ManagerError::AuthorizationBindingRejected)
}
