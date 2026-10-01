use std::collections::BTreeSet;

use crate::{CertificateManagerConfig, ManagerError};

use super::common::{
    valid_authority_uri, valid_digest, valid_https_uri, valid_id, valid_key_version,
    valid_service_uri, valid_spiffe_prefix,
};

#[allow(clippy::too_many_lines)]
pub fn validate_config(config: &CertificateManagerConfig) -> Result<(), ManagerError> {
    let identifiers = [
        &config.service_id,
        &config.security_domain,
        &config.deployment_id,
        &config.authority_id,
        &config.authority_key_id,
        &config.authority_receipt_verifier_key_id,
        &config.authority_attestation_verifier_key_id,
        &config.authorization_provider_id,
        &config.authorization_policy_id,
        &config.authorization_verifier_key_id,
        &config.authorization_channel,
        &config.target_resource_normalizer_id,
        &config.custody_verifier_key_id,
        &config.manager_commit_key_id,
        &config.manager_handoff_key_id,
    ]
    .into_iter()
    .all(|value| valid_id(value));
    let algorithms = config.authority_signature_algorithm == "ecdsa-p256-sha256"
        && config.authority_key_provider_signature_profile == "ecdsa-p256-sha256-p1363-low-s"
        && config.authority_key_purpose == "workload-certificate-issuance"
        && config.authority_receipt_signature_algorithm == "ecdsa-p256-sha256-p1363-low-s"
        && config.authority_receipt_key_purpose == "certificate-authority-receipt"
        && matches!(
            config.authority_attestation_signature_algorithm.as_str(),
            "ed25519" | "ecdsa-p256-sha256"
        )
        && matches!(
            config.authorization_signature_algorithm.as_str(),
            "ed25519" | "ecdsa-p256-sha256"
        )
        && matches!(
            config.custody_signature_algorithm.as_str(),
            "ed25519" | "ecdsa-p256-sha256"
        )
        && config.authority_attestation_key_purpose == "authority-readiness-attestation"
        && config.authorization_key_purpose == "certificate-execution-authorization"
        && config.custody_key_purpose == "leaf-key-custody-attestation"
        && config.manager_commit_signature_algorithm == "ecdsa-p256-sha256-p1363-low-s"
        && config.manager_commit_key_purpose == "certificate-manager-commit-receipt"
        && config.manager_handoff_signature_algorithm == "ecdsa-p256-sha256-p1363-low-s"
        && config.manager_handoff_key_purpose == "certificate-manager-handoff-receipt";
    let key_roles = BTreeSet::from([
        config.authority_key_id.as_str(),
        config.authority_receipt_verifier_key_id.as_str(),
        config.authority_attestation_verifier_key_id.as_str(),
        config.authorization_verifier_key_id.as_str(),
        config.custody_verifier_key_id.as_str(),
        config.manager_commit_key_id.as_str(),
        config.manager_handoff_key_id.as_str(),
    ])
    .len()
        == 7;
    let key_versions = [
        &config.authority_key_version,
        &config.authority_receipt_key_version,
        &config.authority_attestation_key_version,
        &config.authorization_key_version,
        &config.custody_key_version,
        &config.manager_commit_key_version,
        &config.manager_handoff_key_version,
    ]
    .into_iter()
    .all(|value| valid_key_version(value));
    let key_material = [
        &config.authority_public_key_spki_sha256,
        &config.authority_receipt_public_key_spki_sha256,
        &config.authority_attestation_public_key_spki_sha256,
        &config.authorization_public_key_spki_sha256,
        &config.custody_public_key_spki_sha256,
        &config.manager_commit_public_key_spki_sha256,
        &config.manager_handoff_public_key_spki_sha256,
    ];
    let key_identity = key_material.iter().all(|value| valid_digest(value))
        && key_material.into_iter().collect::<BTreeSet<_>>().len() == 7;
    let normalizer = valid_key_version(&config.target_resource_normalizer_version);
    let policy = valid_https_uri(&config.authorization_issuer)
        && valid_service_uri(&config.authorization_audience)
        && valid_authority_uri(&config.authority_outcome_issuer)
        && valid_service_uri(&config.authority_outcome_audience)
        && valid_digest(&config.authorization_policy_digest_sha256)
        && valid_service_uri(&config.manager_commit_issuer)
        && valid_service_uri(&config.manager_commit_audience)
        && valid_service_uri(&config.manager_handoff_issuer)
        && valid_service_uri(&config.manager_handoff_audience)
        && config
            .manager_commit_workload
            .starts_with(&config.workload_spiffe_prefix)
        && config
            .manager_handoff_workload
            .starts_with(&config.workload_spiffe_prefix)
        && config.trust_revision > 0;
    let local = config.accepted_transport == "native-ipc"
        && valid_spiffe_prefix(&config.workload_spiffe_prefix)
        && valid_spiffe_prefix(&config.subject_spiffe_prefix)
        && !config.allowed_audiences.is_empty()
        && config
            .allowed_audiences
            .iter()
            .all(|value| valid_service_uri(value))
        && !config.allowed_purposes.is_empty()
        && config.allowed_purposes.iter().all(|value| valid_id(value))
        && !config.allowed_leaf_key_algorithms.is_empty()
        && config
            .allowed_leaf_key_algorithms
            .iter()
            .all(|value| matches!(value.as_str(), "ed25519" | "ecdsa-p256-sha256"))
        && !config.allowed_custody_providers.is_empty()
        && config
            .allowed_custody_providers
            .iter()
            .all(|value| valid_id(value));
    let limits = (1..=604_800).contains(&config.max_certificate_ttl_seconds)
        && (1..=900).contains(&config.max_authorization_ttl_seconds)
        && (1..=900).contains(&config.max_workload_identity_ttl_seconds)
        && (1..=900).contains(&config.max_custody_attestation_ttl_seconds)
        && (1..=300).contains(&config.max_authority_lease_ttl_seconds)
        && (1..=300).contains(&config.max_revocation_snapshot_age_seconds)
        && (1..=300).contains(&config.max_reconciliation_receipt_age_seconds)
        && (1..=300).contains(&config.max_handoff_recovery_seconds)
        && config.max_handoff_recovery_seconds <= config.max_revocation_snapshot_age_seconds
        && (1..=60).contains(&config.max_completion_evidence_ttl_seconds)
        && (60..=86_400).contains(&config.max_completion_recovery_seconds)
        && config.max_completion_recovery_seconds > config.max_completion_evidence_ttl_seconds
        && (1..=64).contains(&config.max_scopes)
        && (1_024..=1_048_576).contains(&config.max_key_enrollment_bytes)
        && (1_024..=4_194_304).contains(&config.max_public_certificate_bytes);
    (identifiers
        && algorithms
        && key_roles
        && key_versions
        && key_identity
        && normalizer
        && policy
        && local
        && limits)
        .then_some(())
        .ok_or(ManagerError::InvalidConfiguration)
}
