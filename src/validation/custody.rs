use crate::{
    CertificateManagerConfig, KeyCustodyStateV2, ManagerError, SignedKeyCustodyAttestationV2,
    VerifiedKeyCustodyAttestationV2, VerifiedKeyEnrollmentV2, VerifiedWorkloadV2,
};

use super::common::{valid_digest, valid_encoded, valid_id, valid_key_version};

pub fn validate_signed_custody(
    config: &CertificateManagerConfig,
    value: &SignedKeyCustodyAttestationV2,
) -> Result<(), ManagerError> {
    let (schema, key, payload, signature) = value.parts();
    let valid = schema == "crowsi://certificates/key-custody-attestation/v2"
        && key == config.custody_verifier_key_id
        && valid_encoded(payload, 262_144)
        && valid_encoded(signature, 16_384);
    valid.then_some(()).ok_or(ManagerError::KeyCustodyRejected)
}

pub fn validate_custody(
    config: &CertificateManagerConfig,
    workload: &VerifiedWorkloadV2,
    enrollment: &VerifiedKeyEnrollmentV2,
    command_digest: &str,
    value: &VerifiedKeyCustodyAttestationV2,
    now: u64,
) -> Result<(), ManagerError> {
    let exact = value.security_domain == config.security_domain
        && value.deployment_id == config.deployment_id
        && value.service_id == workload.service_id
        && value.workload_id == workload.workload_id
        && value.pairwise_subject == workload.pairwise_subject
        && value.device_id == workload.device
        && value.profile == workload.profile
        && value.proof_key_ref == workload.proof_key_ref
        && value.identity_revocation_epoch == workload.identity_revocation_epoch
        && value.public_key_sha256 == enrollment.public_key_sha256
        && value.command_digest_sha256 == command_digest
        && config
            .allowed_custody_providers
            .contains(&value.provider_id)
        && value.signature_key_id == config.custody_verifier_key_id
        && value.signature_key_version == config.custody_key_version
        && value.signature_public_key_spki_sha256 == config.custody_public_key_spki_sha256
        && valid_key_version(&value.signature_key_version)
        && valid_digest(&value.signature_public_key_spki_sha256)
        && value.signature_algorithm == config.custody_signature_algorithm
        && value.signature_key_purpose == config.custody_key_purpose
        && value.trust_revision == config.trust_revision;
    let validity = valid_id(&value.attestation_id)
        && valid_digest(&value.attestation_digest_sha256)
        && value.custody == KeyCustodyStateV2::NonExportable
        && value.signature_verified
        && value.issued_at_epoch_s <= now
        && now < value.expires_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= config.max_custody_attestation_ttl_seconds;
    (exact && validity)
        .then_some(())
        .ok_or(ManagerError::KeyCustodyRejected)
}
