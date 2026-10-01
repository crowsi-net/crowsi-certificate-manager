use crate::{
    AttestationState, AuthorityReadinessV2, CertificateManagerConfig, ManagerError, ReadinessState,
    SignedAuthorityReadinessAttestationV2,
};

use super::common::{valid_digest, valid_encoded, valid_id, valid_key_version};

pub fn validate_signed_readiness(
    config: &CertificateManagerConfig,
    value: &SignedAuthorityReadinessAttestationV2,
) -> Result<(), ManagerError> {
    let (schema, key, payload, signature) = value.parts();
    let valid = schema == "crowsi://certificates/authority-readiness-attestation/v2"
        && key == config.authority_attestation_verifier_key_id
        && valid_encoded(payload, 262_144)
        && valid_encoded(signature, 16_384);
    valid
        .then_some(())
        .ok_or(ManagerError::AuthorityUnavailable)
}

pub fn validate_readiness(
    config: &CertificateManagerConfig,
    readiness: &AuthorityReadinessV2,
    now: u64,
) -> Result<(), ManagerError> {
    let lease = &readiness.lease;
    let exact = readiness.authority_state == ReadinessState::Ready
        && readiness.key_provider_state == ReadinessState::Ready
        && readiness.attestation_state == AttestationState::Verified
        && lease.security_domain == config.security_domain
        && lease.deployment_id == config.deployment_id
        && lease.authority_id == config.authority_id
        && lease.key_id == config.authority_key_id
        && lease.authority_key_version == config.authority_key_version
        && lease.authority_public_key_spki_sha256 == config.authority_public_key_spki_sha256
        && valid_key_version(&lease.authority_key_version)
        && valid_digest(&lease.authority_public_key_spki_sha256)
        && lease.signature_algorithm == "ecdsa-p256-sha256"
        && lease.signature_algorithm == config.authority_signature_algorithm
        && lease.key_provider_signature_profile == config.authority_key_provider_signature_profile
        && lease.key_provider_signature_profile == "ecdsa-p256-sha256-p1363-low-s"
        && lease.key_purpose == "workload-certificate-issuance"
        && lease.key_purpose == config.authority_key_purpose
        && lease.authority_receipt_key_id == config.authority_receipt_verifier_key_id
        && lease.authority_receipt_key_version == config.authority_receipt_key_version
        && lease.authority_receipt_public_key_spki_sha256
            == config.authority_receipt_public_key_spki_sha256
        && lease.authority_receipt_key_id != lease.key_id
        && valid_key_version(&lease.authority_receipt_key_version)
        && valid_digest(&lease.authority_receipt_public_key_spki_sha256)
        && lease.authority_receipt_public_key_spki_sha256 != lease.authority_public_key_spki_sha256
        && lease.authority_receipt_signature_algorithm
            == config.authority_receipt_signature_algorithm
        && lease.authority_receipt_signature_algorithm == "ecdsa-p256-sha256-p1363-low-s"
        && lease.authority_receipt_key_purpose == config.authority_receipt_key_purpose
        && lease.verifier_key_id == config.authority_attestation_verifier_key_id
        && lease.verifier_key_version == config.authority_attestation_key_version
        && lease.verifier_public_key_spki_sha256
            == config.authority_attestation_public_key_spki_sha256
        && valid_key_version(&lease.verifier_key_version)
        && valid_digest(&lease.verifier_public_key_spki_sha256)
        && lease.verifier_signature_algorithm == config.authority_attestation_signature_algorithm
        && lease.verifier_key_purpose == config.authority_attestation_key_purpose
        && lease.trust_revision == config.trust_revision;
    let valid = valid_id(&lease.lease_id)
        && valid_digest(&lease.attestation_digest_sha256)
        && lease.fence > 0
        && lease.issued_at_epoch_s <= now
        && now < lease.expires_at_epoch_s
        && lease
            .expires_at_epoch_s
            .saturating_sub(lease.issued_at_epoch_s)
            <= config.max_authority_lease_ttl_seconds;
    (exact && valid)
        .then_some(())
        .ok_or(ManagerError::AuthorityUnavailable)
}
