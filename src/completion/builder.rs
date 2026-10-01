use crowsi_control_contracts::{CertificatePayloadV2, CertificateReceiptSignatureAlgorithmV2};

use crate::{
    CertificateManagerConfig, CompletionChallengeV2, CompletionCommitReadbackV2,
    CompletionWorkerError, ManagerCommitEvidenceDraftV2,
};

pub fn draft(
    config: &CertificateManagerConfig,
    commit: &CompletionCommitReadbackV2,
    challenge: CompletionChallengeV2,
    now: u64,
) -> Result<ManagerCommitEvidenceDraftV2, CompletionWorkerError> {
    let authority = &commit.authority_evidence;
    let expires_at_epoch_s = now
        .checked_add(config.max_completion_evidence_ttl_seconds)
        .ok_or(CompletionWorkerError::InvalidConfiguration)?;
    let submission_recovery_deadline_epoch_s = commit
        .committed_at_epoch_s
        .checked_add(config.max_completion_recovery_seconds)
        .ok_or(CompletionWorkerError::InvalidConfiguration)?;
    Ok(ManagerCommitEvidenceDraftV2 {
        commit_id: challenge.commit_id,
        nonce_base64: challenge.nonce_base64,
        issuer: config.manager_commit_issuer.clone(),
        audience: config.manager_commit_audience.clone(),
        action: authority.action,
        authorization_jti: authority.authorization_jti.clone(),
        operation_id: authority.operation_id.clone(),
        lease_digest_sha256: authority.lease_digest_sha256.clone(),
        authorization_command_digest_sha256: authority.authorization_command_digest_sha256.clone(),
        target_resource_id: authority.target_resource_id.clone(),
        state_revision: commit.state_revision,
        resource_version: commit.resource_version,
        previous_fence: authority.previous_fence,
        current_fence: authority.current_fence,
        previous_lifecycle_revocation_epoch: authority.previous_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch: authority.lifecycle_revocation_epoch,
        disposition: authority.disposition,
        authority_evidence_id: authority.evidence_id.clone(),
        authority_evidence_digest_sha256: authority.certificate_digest_sha256(),
        security_domain: config.security_domain.clone(),
        deployment_id: config.deployment_id.clone(),
        trust_revision: config.trust_revision,
        manager_workload: config.manager_commit_workload.clone(),
        commit_key_id: config.manager_commit_key_id.clone(),
        commit_key_version: config.manager_commit_key_version.clone(),
        commit_public_key_spki_sha256: config.manager_commit_public_key_spki_sha256.clone(),
        commit_signature_algorithm:
            CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        commit_key_purpose: config.manager_commit_key_purpose.clone(),
        committed_at_epoch_s: commit.committed_at_epoch_s,
        evidence_issued_at_epoch_s: now,
        expires_at_epoch_s,
        submission_recovery_deadline_epoch_s,
    })
}
