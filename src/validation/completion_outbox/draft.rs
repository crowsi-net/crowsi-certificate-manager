use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{CertificatePayloadV2, CertificateReceiptSignatureAlgorithmV2};

use crate::{
    CertificateManagerConfig, CompletionCommitReadbackV2, CompletionSigningWorkV2,
    CompletionWorkerError, ManagerCommitEvidenceDraftV2,
    validation::common::{valid_digest, valid_id},
};

pub fn validate_completion_draft(
    config: &CertificateManagerConfig,
    commit: &CompletionCommitReadbackV2,
    value: &ManagerCommitEvidenceDraftV2,
    now: u64,
) -> Result<(), CompletionWorkerError> {
    let authority = &commit.authority_evidence;
    let valid = valid_id(&value.commit_id)
        && value.commit_id == commit.completion_id
        && canonical_nonce(&value.nonce_base64)
        && value.issuer == config.manager_commit_issuer
        && value.audience == config.manager_commit_audience
        && value.action == authority.action
        && value.authorization_jti == authority.authorization_jti
        && value.operation_id == authority.operation_id
        && value.lease_digest_sha256 == authority.lease_digest_sha256
        && value.authorization_command_digest_sha256
            == authority.authorization_command_digest_sha256
        && value.target_resource_id == authority.target_resource_id
        && value.state_revision == commit.state_revision
        && value.resource_version == commit.resource_version
        && value.previous_fence == authority.previous_fence
        && value.current_fence == authority.current_fence
        && value.previous_lifecycle_revocation_epoch
            == authority.previous_lifecycle_revocation_epoch
        && value.lifecycle_revocation_epoch == authority.lifecycle_revocation_epoch
        && value.disposition == authority.disposition
        && value.authority_evidence_id == authority.evidence_id
        && value.authority_evidence_digest_sha256 == authority.certificate_digest_sha256()
        && valid_digest(&value.authority_evidence_digest_sha256)
        && key_binding(config, value)
        && value.committed_at_epoch_s == commit.committed_at_epoch_s
        && value.committed_at_epoch_s <= value.evidence_issued_at_epoch_s
        && value.evidence_issued_at_epoch_s == now
        && value.expires_at_epoch_s > value.evidence_issued_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.evidence_issued_at_epoch_s)
            <= config.max_completion_evidence_ttl_seconds
        && value.submission_recovery_deadline_epoch_s
            == value
                .committed_at_epoch_s
                .checked_add(config.max_completion_recovery_seconds)
                .unwrap_or(0)
        && value.expires_at_epoch_s <= value.submission_recovery_deadline_epoch_s
        && now < value.submission_recovery_deadline_epoch_s;
    valid
        .then_some(())
        .ok_or(CompletionWorkerError::EvidenceRejected)
}

pub fn validate_completion_work(
    commit: &CompletionCommitReadbackV2,
    value: &CompletionSigningWorkV2,
) -> Result<(), CompletionWorkerError> {
    (valid_id(&value.claim_id) && &value.commit == commit)
        .then_some(())
        .ok_or(CompletionWorkerError::StateUnavailable)
}

fn key_binding(config: &CertificateManagerConfig, value: &ManagerCommitEvidenceDraftV2) -> bool {
    value.security_domain == config.security_domain
        && value.deployment_id == config.deployment_id
        && value.trust_revision == config.trust_revision
        && value.manager_workload == config.manager_commit_workload
        && value.commit_key_id == config.manager_commit_key_id
        && value.commit_key_version == config.manager_commit_key_version
        && value.commit_public_key_spki_sha256 == config.manager_commit_public_key_spki_sha256
        && value.commit_signature_algorithm
            == CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS
        && value.commit_signature_algorithm.as_str() == config.manager_commit_signature_algorithm
        && value.commit_key_purpose == config.manager_commit_key_purpose
}

fn canonical_nonce(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&bytes) == value)
}
