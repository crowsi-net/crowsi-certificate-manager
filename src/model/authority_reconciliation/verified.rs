use super::{
    AuthorityReconciliationDispositionV2, OriginalAuthorityExecutionBindingV2,
    ReconciliationAuthorityBindingV2,
};

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedAuthorityReconciliationV2 {
    pub completion_evidence: crowsi_control_contracts::CertificateAuthorityOutcomeEvidenceV2,
    pub query_id: String,
    pub original_action: super::super::CertificateLifecycleActionV2,
    pub reconciliation_command_digest_sha256: String,
    pub authority_command_digest_sha256: String,
    pub unknown_evidence_digest_sha256: String,
    pub disposition: AuthorityReconciliationDispositionV2,
    pub authority_outcome_digest_sha256: Option<String>,
    pub reconciliation_authorization_ancestry_digest_sha256: String,
    pub reconciliation_query_digest_sha256: String,
    pub expected_resource_version: u64,
    pub original_execution: OriginalAuthorityExecutionBindingV2,
    pub current_reconciliation: ReconciliationAuthorityBindingV2,
    pub security_domain: String,
    pub deployment_id: String,
    pub signature_key_id: String,
    pub signature_algorithm: String,
    pub key_purpose: String,
    pub lifecycle_reservation_id: String,
    pub lifecycle_previous_fence: u64,
    pub lifecycle_fence: u64,
    pub previous_lifecycle_revocation_epoch: u64,
    pub lifecycle_revocation_epoch: u64,
    pub observed_at_epoch_s: u64,
    pub receipt_digest_sha256: String,
    pub signature_verified: bool,
}
