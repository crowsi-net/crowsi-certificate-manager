use crowsi_control_contracts::Validate;

use crate::{
    CertificateManagerConfig, CompletionCommitReadbackV2, CompletionWorkerError,
    validation::{
        common::{valid_digest, valid_id},
        completion_evidence::valid_completion_authority_trust,
    },
};

pub fn validate_completion_readback(
    config: &CertificateManagerConfig,
    value: &CompletionCommitReadbackV2,
    now: u64,
) -> Result<(), CompletionWorkerError> {
    let authority = &value.authority_evidence;
    let valid = valid_id(&value.completion_id)
        && valid_id(&value.state_record_id)
        && valid_digest(&value.state_event_digest_sha256)
        && value.state_revision > 0
        && authority.validate().is_ok()
        && valid_completion_authority_trust(config, authority)
        && authority.issued_at_epoch_s <= value.committed_at_epoch_s
        && value.committed_at_epoch_s < authority.expires_at_epoch_s
        && value.committed_at_epoch_s <= now
        && authority
            .expires_at_epoch_s
            .saturating_sub(authority.issued_at_epoch_s)
            <= config.max_completion_evidence_ttl_seconds;
    valid
        .then_some(())
        .ok_or(CompletionWorkerError::EvidenceRejected)
}
