use crate::digest::DigestBuilder;
use serde::{Deserialize, Serialize};

use super::{AbandonReasonV2, AuditOperationState};
use super::{
    AuthorityCommandV2, AuthorityOutcomeV2, OperationBeginV2, OperationReservationV2,
    VerifiedAuthorityReconciliationV2,
};

#[derive(Clone, Eq, PartialEq)]
pub struct ReconciliationQueryV2 {
    pub query_id: String,
    pub nonce: String,
    pub original_action: super::CertificateLifecycleActionV2,
    pub target_request_id: String,
    pub resource_id: String,
    pub owner_subject: String,
    pub owner_profile: String,
    pub expected_resource_version: u64,
    pub expected_authority_command_digest_sha256: String,
    pub expected_unknown_evidence_digest_sha256: String,
    pub expected_lifecycle_reservation_id: String,
    pub expected_previous_fence: u64,
    pub expected_current_fence: u64,
    pub locked_previous_lifecycle_revocation_epoch: u64,
    pub locked_lifecycle_revocation_epoch: u64,
}

impl ReconciliationQueryV2 {
    #[must_use]
    pub fn digest_sha256(&self) -> String {
        let mut digest = DigestBuilder::new("crowsi-certificate-reconciliation-query-v2");
        for value in [
            &self.query_id,
            &self.nonce,
            self.original_action.as_str(),
            &self.target_request_id,
            &self.resource_id,
            &self.owner_subject,
            &self.owner_profile,
            &self.expected_authority_command_digest_sha256,
            &self.expected_unknown_evidence_digest_sha256,
            &self.expected_lifecycle_reservation_id,
        ] {
            digest.text(value);
        }
        digest.number(self.expected_resource_version);
        digest.number(self.expected_previous_fence);
        digest.number(self.expected_current_fence);
        digest.number(self.locked_previous_lifecycle_revocation_epoch);
        digest.number(self.locked_lifecycle_revocation_epoch);
        digest.finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuditStatusQueryV2 {
    pub target_request_id: String,
    pub resource_id: String,
    pub owner_service_id: String,
    pub owner_workload_id: String,
    pub owner_subject: String,
    pub owner_profile: String,
    pub operation_expected_resource_version: u64,
    pub operation_lifecycle_revocation_epoch: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReconciliationBeginV2 {
    pub query_id: String,
    pub original_action: super::CertificateLifecycleActionV2,
    pub nonce: String,
    pub authorization_id: String,
    pub authorization_jti: String,
    pub authorization: super::CertificateAuthorizationAncestryV2,
    pub authorization_command_digest_sha256: String,
    pub query_digest_sha256: String,
    pub expected_resource_version: u64,
    pub expected_authority_command_digest_sha256: String,
    pub expected_unknown_evidence_digest_sha256: String,
    pub expected_lifecycle_reservation_id: String,
    pub expected_previous_fence: u64,
    pub expected_current_fence: u64,
    pub locked_previous_lifecycle_revocation_epoch: u64,
    pub locked_lifecycle_revocation_epoch: u64,
    pub status_query: AuditStatusQueryV2,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReconciliationContextV2 {
    pub status: AuditOperationStatusV2,
    pub original_begin: OperationBeginV2,
    pub reconciliation_begin: ReconciliationBeginV2,
    pub reservation: OperationReservationV2,
    pub authority_command: Option<AuthorityCommandV2>,
    pub finalized_receipt: Option<super::ReceiptDraftV2>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReconciliationStateResolutionV2 {
    pub verified: VerifiedAuthorityReconciliationV2,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationResultV2 {
    pub status: AuditOperationStatusV2,
    pub recovered_outcome: Option<AuthorityOutcomeV2>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditOperationStatusV2 {
    pub request_id: String,
    pub reservation_id: String,
    pub resource_id: String,
    pub owner_service_id: String,
    pub owner_workload_id: String,
    pub owner_subject: String,
    pub owner_profile: String,
    pub operation_expected_resource_version: u64,
    pub operation_lifecycle_revocation_epoch: u64,
    pub policy_authorization_ref: String,
    pub policy_authorization_digest_sha256: String,
    pub operator_approval_evidence_ref: String,
    pub operator_approval_evidence_digest_sha256: String,
    pub operator_approval_method: super::CertificateApprovalMethodV2,
    pub operator_approval_assurance: super::CertificateApprovalAssuranceV2,
    pub operator_approval_verified_at_epoch_s: u64,
    pub state_revision: u64,
    pub state: AuditOperationState,
    pub event_digest_sha256: Option<String>,
    pub authority_command_digest_sha256: Option<String>,
    pub abandon_reason: Option<AbandonReasonV2>,
    pub abandon_receipt_digest_sha256: Option<String>,
    pub reconciliation_receipt_digest_sha256: Option<String>,
    pub reconciliation_authorization_digest_sha256: Option<String>,
    pub reconciliation_query_digest_sha256: Option<String>,
}
