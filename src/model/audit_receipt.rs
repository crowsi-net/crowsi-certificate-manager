use crate::digest::DigestBuilder;
use serde::{Deserialize, Serialize};

use super::{AuditCommitV2, CertificateOperation, CertificateState};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptDraftV2 {
    pub request_id: String,
    pub authorization_id: String,
    pub authorization_ancestry_digest_sha256: String,
    pub policy_authorization_ref: String,
    pub policy_authorization_digest_sha256: String,
    pub operator_approval_evidence_ref: String,
    pub operator_approval_evidence_digest_sha256: String,
    pub operator_approval_method: super::CertificateApprovalMethodV2,
    pub operator_approval_assurance: super::CertificateApprovalAssuranceV2,
    pub operator_approval_verified_at_epoch_s: u64,
    pub command_digest_sha256: String,
    pub operation: CertificateOperation,
    pub resource_id: String,
    pub owner_service_id: String,
    pub owner_workload_id: String,
    pub lifecycle_reservation_id: String,
    pub lifecycle_fence: u64,
    pub authority_command_digest_sha256: String,
    pub authority_outcome_digest_sha256: String,
    pub authority_receipt_digest_sha256: String,
    pub reconciliation_receipt_digest_sha256: Option<String>,
    pub reconciliation_authorization_ancestry_digest_sha256: Option<String>,
    pub reconciliation_query_digest_sha256: Option<String>,
    pub result_certificate_id: String,
    pub result_metadata_digest_sha256: String,
    pub state: CertificateState,
    pub recorded_at_epoch_s: u64,
    pub private_key_received: bool,
    pub private_key_returned: bool,
}

impl ReceiptDraftV2 {
    #[must_use]
    pub fn digest_sha256(&self) -> String {
        let mut digest = DigestBuilder::new("crowsi-certificate-audit-receipt-v2");
        for value in [
            &self.request_id,
            &self.authorization_id,
            &self.authorization_ancestry_digest_sha256,
            &self.policy_authorization_ref,
            &self.policy_authorization_digest_sha256,
            &self.operator_approval_evidence_ref,
            &self.operator_approval_evidence_digest_sha256,
            self.operator_approval_method.as_str(),
            self.operator_approval_assurance.as_str(),
            &self.command_digest_sha256,
            self.operation.as_str(),
            &self.resource_id,
            &self.owner_service_id,
            &self.owner_workload_id,
            &self.lifecycle_reservation_id,
            &self.authority_command_digest_sha256,
            &self.authority_outcome_digest_sha256,
            &self.authority_receipt_digest_sha256,
            &self.result_certificate_id,
            &self.result_metadata_digest_sha256,
            self.state.as_str(),
        ] {
            digest.text(value);
        }
        digest.optional(self.reconciliation_receipt_digest_sha256.as_deref());
        digest.optional(
            self.reconciliation_authorization_ancestry_digest_sha256
                .as_deref(),
        );
        digest.optional(self.reconciliation_query_digest_sha256.as_deref());
        digest.number(self.lifecycle_fence);
        digest.number(self.recorded_at_epoch_s);
        digest.number(self.operator_approval_verified_at_epoch_s);
        digest.number(u64::from(self.private_key_received));
        digest.number(u64::from(self.private_key_returned));
        digest.finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationReceiptV2 {
    pub event: ReceiptDraftV2,
    pub audit: AuditCommitV2,
}
