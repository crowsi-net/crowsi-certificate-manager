use crate::{
    CertificateAuthorizedActionV2, CertificateManagerConfig,
    VerifiedCertificateExecutionAuthorizationV2, VerifiedWorkloadV2,
};

use super::{
    super::common::{valid_canonical_resource_id, valid_digest, valid_id, valid_key_version},
    approval::{separation_of_duties, valid_approval},
    transition::{valid_fence, valid_lifecycle_epoch},
};

pub fn valid_common(
    config: &CertificateManagerConfig,
    workload: &VerifiedWorkloadV2,
    value: &VerifiedCertificateExecutionAuthorizationV2,
    now: u64,
) -> bool {
    let policy = value.issuer == config.authorization_issuer
        && valid_digest(&value.lease_digest_sha256)
        && value.audience == config.authorization_audience
        && value.signature_key_id == config.authorization_verifier_key_id
        && value.signature_key_version == config.authorization_key_version
        && value.signature_public_key_spki_sha256 == config.authorization_public_key_spki_sha256
        && valid_key_version(&value.signature_key_version)
        && valid_digest(&value.signature_public_key_spki_sha256)
        && value.signature_algorithm == config.authorization_signature_algorithm
        && value.signature_key_purpose == config.authorization_key_purpose
        && value.trust_revision == config.trust_revision
        && value.channel == config.authorization_channel
        && value.provider == config.authorization_provider_id
        && value.target_resource_normalizer_id == config.target_resource_normalizer_id
        && value.target_resource_normalizer_version == config.target_resource_normalizer_version
        && value.policy_id == config.authorization_policy_id
        && value.policy_digest_sha256 == config.authorization_policy_digest_sha256;
    let identity = value.service_id == workload.service_id
        && value.workload == workload.workload_id
        && value.pairwise_subject == workload.pairwise_subject
        && value.requester_actor == workload.actor
        && value.requester_device == workload.device
        && value.requester_profile == workload.profile
        && value.requester_proof_key_ref == workload.proof_key_ref
        && value.identity_revocation_epoch == workload.identity_revocation_epoch;
    policy && identity && separation_of_duties(value) && structural(config, value, now)
}

fn structural(
    config: &CertificateManagerConfig,
    value: &VerifiedCertificateExecutionAuthorizationV2,
    now: u64,
) -> bool {
    let ids = [
        &value.authorization_id,
        &value.jti,
        &value.operation_id,
        &value.release_id,
        &value.checkpoint_id,
        &value.deployment_provenance_ref,
        &value.pa_reservation_id,
        &value.decision_id,
        &value.grant_id,
        &value.identity_revocation_snapshot_id,
        &value.target_resource_normalizer_id,
        &value.requester_profile,
        &value.requester_device,
        &value.requester_actor,
        &value.requester_proof_key_ref,
    ]
    .into_iter()
    .all(|item| valid_id(item));
    let digests = [
        &value.command_digest_sha256,
        &value.release_digest_sha256,
        &value.checkpoint_digest_sha256,
        &value.policy_digest_sha256,
        &value.decision_digest_sha256,
        &value.grant_digest_sha256,
        &value.identity_revocation_snapshot_digest_sha256,
        &value.target_resource_normalization_digest_sha256,
    ]
    .into_iter()
    .all(|item| valid_digest(item));
    ids && digests
        && valid_canonical_resource_id(&value.target_resource_id)
        && valid_key_version(&value.target_resource_normalizer_version)
        && value.target_resource_normalization_verified
        && value.security_domain == config.security_domain
        && value.deployment_id == config.deployment_id
        && value.checkpoint_sequence > 0
        && valid_fence(value)
        && valid_lifecycle_epoch(value)
        && value.one_use
        && value.signature_verified
        && valid_time(config, value, now)
        && valid_revocation(config, value, now)
        && valid_approval(value, now)
        && valid_unknown(value)
}

fn valid_time(
    config: &CertificateManagerConfig,
    value: &VerifiedCertificateExecutionAuthorizationV2,
    now: u64,
) -> bool {
    value.issued_at_epoch_s <= now
        && now < value.expires_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= config.max_authorization_ttl_seconds
}

fn valid_revocation(
    config: &CertificateManagerConfig,
    value: &VerifiedCertificateExecutionAuthorizationV2,
    now: u64,
) -> bool {
    value.authoritative_identity_revocation_snapshot
        && value.previous_identity_revocation_epoch <= value.identity_revocation_epoch
        && value.identity_revocation_snapshot_epoch == value.identity_revocation_epoch
        && value.identity_revocation_snapshot_verified_at_epoch_s <= now
        && now.saturating_sub(value.identity_revocation_snapshot_verified_at_epoch_s)
            <= config.max_revocation_snapshot_age_seconds
}

fn valid_unknown(value: &VerifiedCertificateExecutionAuthorizationV2) -> bool {
    if value.action == CertificateAuthorizedActionV2::ReconcileUnknown {
        value
            .unknown_evidence_digest_sha256
            .as_deref()
            .is_some_and(valid_digest)
    } else {
        value.unknown_evidence_digest_sha256.is_none()
    }
}
