use crowsi_control_contracts::{
    CERTIFICATE_MANAGER_COMMIT_EVIDENCE_SCHEMA_V2, CertificateManagerCommitEvidenceV2, Validate,
};

use crate::{
    CertificateManagerConfig, CompletionSigningWorkV2, CompletionWorkerError,
    ManagerCommitEvidenceDraftV2,
};

pub fn validate_manager_commit_evidence(
    config: &CertificateManagerConfig,
    work: &CompletionSigningWorkV2,
    value: &CertificateManagerCommitEvidenceV2,
) -> Result<(), CompletionWorkerError> {
    let valid = value.schema == CERTIFICATE_MANAGER_COMMIT_EVIDENCE_SCHEMA_V2
        && value.validate().is_ok()
        && fields(&work.draft, value)
        && value
            .expires_at_epoch_s
            .saturating_sub(value.evidence_issued_at_epoch_s)
            <= config.max_completion_evidence_ttl_seconds
        && value
            .submission_recovery_deadline_epoch_s
            .saturating_sub(value.committed_at_epoch_s)
            <= config.max_completion_recovery_seconds;
    valid
        .then_some(())
        .ok_or(CompletionWorkerError::EvidenceRejected)
}

fn fields(
    draft: &ManagerCommitEvidenceDraftV2,
    value: &CertificateManagerCommitEvidenceV2,
) -> bool {
    value.commit_id == draft.commit_id
        && value.nonce_base64 == draft.nonce_base64
        && value.issuer == draft.issuer
        && value.audience == draft.audience
        && value.action == draft.action
        && value.authorization_jti == draft.authorization_jti
        && value.operation_id == draft.operation_id
        && value.lease_digest_sha256 == draft.lease_digest_sha256
        && value.authorization_command_digest_sha256 == draft.authorization_command_digest_sha256
        && value.target_resource_id == draft.target_resource_id
        && value.state_revision == draft.state_revision
        && value.resource_version == draft.resource_version
        && value.previous_fence == draft.previous_fence
        && value.current_fence == draft.current_fence
        && value.previous_lifecycle_revocation_epoch == draft.previous_lifecycle_revocation_epoch
        && value.lifecycle_revocation_epoch == draft.lifecycle_revocation_epoch
        && value.disposition == draft.disposition
        && value.authority_evidence_id == draft.authority_evidence_id
        && value.authority_evidence_digest_sha256 == draft.authority_evidence_digest_sha256
        && value.security_domain == draft.security_domain
        && value.deployment_id == draft.deployment_id
        && value.trust_revision == draft.trust_revision
        && value.manager_workload == draft.manager_workload
        && value.commit_key_id == draft.commit_key_id
        && value.commit_key_version == draft.commit_key_version
        && value.commit_public_key_spki_sha256 == draft.commit_public_key_spki_sha256
        && value.commit_signature_algorithm == draft.commit_signature_algorithm
        && value.commit_key_purpose == draft.commit_key_purpose
        && value.committed_at_epoch_s == draft.committed_at_epoch_s
        && value.evidence_issued_at_epoch_s == draft.evidence_issued_at_epoch_s
        && value.expires_at_epoch_s == draft.expires_at_epoch_s
        && value.submission_recovery_deadline_epoch_s == draft.submission_recovery_deadline_epoch_s
}
