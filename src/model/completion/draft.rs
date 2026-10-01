use std::fmt;

use crowsi_control_contracts::{
    CertificateActionV2, CertificateExecutionDispositionV2, CertificateReceiptSignatureAlgorithmV2,
};

#[derive(Clone, Eq, PartialEq)]
pub struct ManagerCommitEvidenceDraftV2 {
    pub commit_id: String,
    pub nonce_base64: String,
    pub issuer: String,
    pub audience: String,
    pub action: CertificateActionV2,
    pub authorization_jti: String,
    pub operation_id: String,
    pub lease_digest_sha256: String,
    pub authorization_command_digest_sha256: String,
    pub target_resource_id: String,
    pub state_revision: u64,
    pub resource_version: u64,
    pub previous_fence: u64,
    pub current_fence: u64,
    pub previous_lifecycle_revocation_epoch: u64,
    pub lifecycle_revocation_epoch: u64,
    pub disposition: CertificateExecutionDispositionV2,
    pub authority_evidence_id: String,
    pub authority_evidence_digest_sha256: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub trust_revision: u64,
    pub manager_workload: String,
    pub commit_key_id: String,
    pub commit_key_version: String,
    pub commit_public_key_spki_sha256: String,
    pub commit_signature_algorithm: CertificateReceiptSignatureAlgorithmV2,
    pub commit_key_purpose: String,
    pub committed_at_epoch_s: u64,
    pub evidence_issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub submission_recovery_deadline_epoch_s: u64,
}

impl fmt::Debug for ManagerCommitEvidenceDraftV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagerCommitEvidenceDraftV2")
            .field("action", &self.action)
            .field("disposition", &self.disposition)
            .field("state_revision", &self.state_revision)
            .field("commit", &"[REDACTED]")
            .field("authorization", &"[REDACTED]")
            .field("authority_evidence", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
