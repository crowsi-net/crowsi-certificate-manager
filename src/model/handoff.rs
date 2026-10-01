use std::fmt;

use crowsi_control_contracts::{CertificateActionV2, CertificateManagerHandoffEvidenceV2};

#[derive(Clone, Eq, PartialEq)]
pub struct ManagerHandoffReadbackV2 {
    pub reservation_id: String,
    pub receipt_id: String,
    pub action: CertificateActionV2,
    pub authorization_jti: String,
    pub operation_id: String,
    pub lease_digest_sha256: String,
    pub authorization_command_digest_sha256: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub trust_revision: u64,
    pub target_resource_id: String,
    pub expected_resource_version: u64,
    pub previous_fence: u64,
    pub current_fence: u64,
    pub previous_lifecycle_revocation_epoch: u64,
    pub lifecycle_revocation_epoch: u64,
    pub reserved_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CertificateHandoffReceiptAckV2 {
    pub authorization_jti: String,
    pub receipt_id: String,
    pub evidence_digest_sha256: String,
    pub disposition: String,
    pub resulting_state: String,
    pub recorded_at_epoch_s: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedManagerHandoffV2 {
    pub evidence: CertificateManagerHandoffEvidenceV2,
    pub acknowledgement: CertificateHandoffReceiptAckV2,
}

impl fmt::Debug for ManagerHandoffReadbackV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagerHandoffReadbackV2")
            .field("action", &self.action)
            .field("reservation", &"[REDACTED]")
            .field("authorization", &"[REDACTED]")
            .field("target", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for CertificateHandoffReceiptAckV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateHandoffReceiptAckV2")
            .field("disposition", &self.disposition)
            .field("resulting_state", &self.resulting_state)
            .field("authorization", &"[REDACTED]")
            .field("evidence", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for VerifiedManagerHandoffV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedManagerHandoffV2")
            .field("disposition", &self.evidence.disposition)
            .field("evidence", &"[REDACTED]")
            .field("acknowledgement", &"[REDACTED]")
            .finish()
    }
}
