use serde::{Deserialize, Serialize};

use crate::digest::DigestBuilder;

use super::{CertificateAuthorizationAncestryV2, CertificateOperation};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditOperationState {
    Reserved,
    Invoked,
    Finalized,
    ResultUnknown,
    Abandoned,
    ReconciledNotExecuted,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuditIntentV2 {
    pub request_id: String,
    pub authorization_id: String,
    pub authorization: CertificateAuthorizationAncestryV2,
    pub command_digest_sha256: String,
    pub operation: CertificateOperation,
    pub resource_id: String,
    pub lifecycle_reservation_id: String,
    pub lifecycle_fence: u64,
    pub owner_service_id: String,
    pub owner_workload_id: String,
    pub owner_subject: String,
    pub owner_profile: String,
    pub certificate_subject: String,
    pub certificate_profile: String,
    pub reserved_at_epoch_s: u64,
}

impl AuditIntentV2 {
    #[must_use]
    pub fn digest_sha256(&self) -> String {
        let mut digest = DigestBuilder::new("crowsi-certificate-audit-intent-v2");
        for value in [
            &self.request_id,
            &self.authorization_id,
            &self.authorization.digest_sha256(),
            &self.command_digest_sha256,
            self.operation.as_str(),
            &self.resource_id,
            &self.lifecycle_reservation_id,
            &self.owner_service_id,
            &self.owner_workload_id,
            &self.owner_subject,
            &self.owner_profile,
            &self.certificate_subject,
            &self.certificate_profile,
        ] {
            digest.text(value);
        }
        digest.number(self.lifecycle_fence);
        digest.number(self.reserved_at_epoch_s);
        digest.finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuditReservationV2 {
    pub reservation_id: String,
    pub request_id: String,
    pub intent_digest_sha256: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuditInvocationV2 {
    pub reservation_id: String,
    pub authority_command_digest_sha256: String,
    pub execution_time_epoch_s: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownReasonV2 {
    AuthorityUnavailable,
    AuthorityRejected,
    AuthorityAmbiguous,
    OutcomeVerificationFailed,
    CertificateVerificationFailed,
    LifecycleCommitFailed,
    AuditCommitFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AbandonReasonV2 {
    AuthorizationExpired,
    IdentityExpired,
    CustodyExpired,
    AuthorityLeaseExpired,
    TrustChanged,
    TrustedClockRejected,
}

impl UnknownReasonV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityUnavailable => "authority-unavailable",
            Self::AuthorityRejected => "authority-rejected",
            Self::AuthorityAmbiguous => "authority-ambiguous",
            Self::OutcomeVerificationFailed => "outcome-verification-failed",
            Self::CertificateVerificationFailed => "certificate-verification-failed",
            Self::LifecycleCommitFailed => "lifecycle-commit-failed",
            Self::AuditCommitFailed => "audit-commit-failed",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuditUnknownV2 {
    pub reservation_id: String,
    pub authority_command_digest_sha256: String,
    pub reason: UnknownReasonV2,
    pub recorded_at_epoch_s: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCommitV2 {
    pub reservation_id: String,
    pub record_id: String,
    pub event_digest_sha256: String,
    pub previous_digest_sha256: Option<String>,
}
