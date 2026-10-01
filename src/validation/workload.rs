use crate::{
    CertificateManagerConfig, ManagerError, VerifiedKeyEnrollmentV2, VerifiedWorkloadV2,
    WorkloadEvidenceV2,
};

use super::common::{valid_digest, valid_encoded, valid_id, valid_spiffe_id};

pub fn validate_workload_evidence(
    config: &CertificateManagerConfig,
    evidence: &WorkloadEvidenceV2,
) -> Result<(), ManagerError> {
    let (schema, transport, encoded) = evidence.parts();
    let valid = schema == "crowsi://certificates/workload-evidence/v2"
        && transport == config.accepted_transport
        && valid_encoded(encoded, 262_144);
    valid
        .then_some(())
        .ok_or(ManagerError::InvalidWorkloadEvidence)
}

pub fn validate_workload(
    config: &CertificateManagerConfig,
    claims: &VerifiedWorkloadV2,
    now: u64,
) -> Result<(), ManagerError> {
    let valid = valid_id(&claims.service_id)
        && claims
            .workload_id
            .starts_with(&config.workload_spiffe_prefix)
        && valid_spiffe_id(&claims.workload_id)
        && [
            &claims.pairwise_subject,
            &claims.actor,
            &claims.device,
            &claims.profile,
            &claims.proof_key_ref,
        ]
        .into_iter()
        .all(|value| valid_id(value))
        && claims.identity_revocation_epoch > 0
        && claims.authenticated_at_epoch_s <= now
        && now < claims.expires_at_epoch_s
        && claims
            .expires_at_epoch_s
            .saturating_sub(claims.authenticated_at_epoch_s)
            <= config.max_workload_identity_ttl_seconds
        && claims.transport == config.accepted_transport
        && valid_digest(&claims.evidence_sha256);
    valid
        .then_some(())
        .ok_or(ManagerError::WorkloadClaimsRejected)
}

pub fn validate_key_enrollment(
    config: &CertificateManagerConfig,
    value: &VerifiedKeyEnrollmentV2,
) -> Result<(), ManagerError> {
    let computed = crate::digest::sha256(&value.public_key_spki_der);
    let valid = value.proof_of_possession_verified
        && !value.public_key_spki_der.is_empty()
        && value.public_key_spki_der.len() <= config.max_key_enrollment_bytes
        && computed == value.public_key_sha256
        && valid_digest(&value.public_key_sha256)
        && config
            .allowed_leaf_key_algorithms
            .contains(&value.algorithm);
    valid
        .then_some(())
        .ok_or(ManagerError::KeyEnrollmentRejected)
}
